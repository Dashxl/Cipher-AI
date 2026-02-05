import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { createHash } from "node:crypto";
import { kvGet, kvSet } from "@/lib/cache/store";
import { env } from "@/lib/env";

const baseDir = path.join(os.tmpdir(), "cipher-ai-zips");

// Upstash limits (Free / Pay-as-you-go):
// - max request size ~10MB ⇒ chunk payloads must stay well below this. :contentReference[oaicite:1]{index=1}
const ZIP_TTL_DEFAULT = 60 * 60 * 6; // 6h (mantén esto alineado con tu TTL de repo meta)
const CHUNK_BYTES = 5_000_000; // 5MB raw ≈ 6.7MB base64 (safe under 10MB/request)

// Persistente “best effort” in-process cache (solo performance).
const g = globalThis as unknown as { __cipherZipMem?: Map<string, Buffer> };
const mem = (g.__cipherZipMem ??= new Map<string, Buffer>());

const hasUpstash = Boolean(env.UPSTASH_REDIS_REST_URL && env.UPSTASH_REDIS_REST_TOKEN);

type ZipManifestV1 = {
  v: 1;
  size: number;
  sha256: string;
  chunkBytes: number;
  chunks: number;
  createdAt: number;
};

function kManifest(id: string) {
  return `zip:${id}:manifest`;
}
function kChunk(id: string, i: number) {
  return `zip:${id}:chunk:${i}`;
}
function kLegacy(id: string) {
  // Compat: si antes guardaban el ZIP completo en una sola key
  return `zip:${id}`;
}

function sha256Hex(buf: Buffer) {
  return createHash("sha256").update(buf).digest("hex");
}

async function writeTmpBestEffort(id: string, buf: Buffer) {
  try {
    await fs.mkdir(baseDir, { recursive: true });
    await fs.writeFile(path.join(baseDir, `${id}.zip`), buf);
  } catch {
    // best effort
  }
}

async function readTmp(id: string): Promise<Buffer> {
  return await fs.readFile(path.join(baseDir, `${id}.zip`));
}

export class ZipNotReadyError extends Error {
  code = "ZIP_NOT_READY" as const;
  constructor(message: string) {
    super(message);
    this.name = "ZipNotReadyError";
  }
}

export class ZipCorruptError extends Error {
  code = "ZIP_CORRUPT" as const;
  constructor(message: string) {
    super(message);
    this.name = "ZipCorruptError";
  }
}

export class ZipChunkMissingError extends Error {
  code = "ZIP_CHUNK_MISSING" as const;
  missing: number[];
  constructor(missing: number[]) {
    super(`Missing zip chunks: ${missing.join(",")}`);
    this.name = "ZipChunkMissingError";
    this.missing = missing;
  }
}

async function saveZipToRedis(id: string, buf: Buffer, ttlSeconds: number) {
  const hash = sha256Hex(buf);
  const chunks = Math.max(1, Math.ceil(buf.length / CHUNK_BYTES));

  // 1) write chunks first
  for (let i = 0; i < chunks; i++) {
    const start = i * CHUNK_BYTES;
    const end = Math.min(buf.length, (i + 1) * CHUNK_BYTES);
    const b64 = buf.subarray(start, end).toString("base64");
    await kvSet<string>(kChunk(id, i), b64, ttlSeconds);
  }

  // 2) write manifest last (this is the "ready" signal)
  const manifest: ZipManifestV1 = {
    v: 1,
    size: buf.length,
    sha256: hash,
    chunkBytes: CHUNK_BYTES,
    chunks,
    createdAt: Date.now(),
  };

  await kvSet<ZipManifestV1>(kManifest(id), manifest, ttlSeconds);
}

async function loadZipFromRedis(id: string): Promise<Buffer | null> {
  const manifest = await kvGet<ZipManifestV1>(kManifest(id));
  if (!manifest) {
    // Compat: ZIP completo en una key (si existía en versiones previas)
    const legacy = await kvGet<string>(kLegacy(id));
    if (legacy && typeof legacy === "string" && legacy.startsWith("UEs")) {
      // "PK" zip signature in base64 usually starts with "UEs"
      return Buffer.from(legacy, "base64");
    }
    return null;
  }

  if (manifest.v !== 1 || !manifest.size || !manifest.sha256 || !manifest.chunks) {
    throw new ZipCorruptError("Invalid zip manifest");
  }

  const parts = new Array<Buffer>(manifest.chunks);
  const missing: number[] = [];

  // Batching to reduce tail latency
  const CONCURRENCY = 6;

  for (let i = 0; i < manifest.chunks; i += CONCURRENCY) {
    const idxs = Array.from(
      { length: Math.min(CONCURRENCY, manifest.chunks - i) },
      (_, k) => i + k
    );

    const vals = await Promise.all(idxs.map((j) => kvGet<string>(kChunk(id, j))));

    for (let n = 0; n < idxs.length; n++) {
      const j = idxs[n];
      const b64 = vals[n];
      if (!b64 || typeof b64 !== "string") {
        missing.push(j);
        continue;
      }
      parts[j] = Buffer.from(b64, "base64");
    }
  }

  if (missing.length) throw new ZipChunkMissingError(missing);

  const total = parts.reduce((s, b) => s + (b?.length ?? 0), 0);
  if (total !== manifest.size) {
    throw new ZipCorruptError(`Zip size mismatch (expected ${manifest.size}, got ${total})`);
  }

  const buf = Buffer.concat(parts, total);
  const hash = sha256Hex(buf);
  if (hash !== manifest.sha256) {
    throw new ZipCorruptError("Zip sha256 mismatch");
  }

  return buf;
}

export async function saveZip(id: string, buf: Buffer, ttlSeconds = ZIP_TTL_DEFAULT) {
  if (!id) throw new Error("saveZip: missing id");
  if (!Buffer.isBuffer(buf)) throw new Error("saveZip: buf must be a Buffer");

  if (hasUpstash) {
    // En prod esto DEBE ser la fuente de verdad
    await saveZipToRedis(id, buf, ttlSeconds);
  }

  // Caches locales (performance only)
  mem.set(id, buf);
  await writeTmpBestEffort(id, buf);
}

export async function loadZip(id: string): Promise<Buffer> {
  if (!id) throw new Error("loadZip: missing id");

  const fromMem = mem.get(id);
  if (fromMem) return fromMem;

  if (hasUpstash) {
    const buf = await loadZipFromRedis(id);
    if (!buf) {
      // No manifest/legacy -> no está listo o expiró
      // Intentamos tmp solo como fallback (útil en local)
      try {
        const tmp = await readTmp(id);
        mem.set(id, tmp);
        return tmp;
      } catch {
        throw new ZipNotReadyError("Zip not ready or expired (missing manifest)");
      }
    }
    mem.set(id, buf);
    await writeTmpBestEffort(id, buf);
    return buf;
  }

  // No Upstash: dev fallback a tmp
  const tmp = await readTmp(id);
  mem.set(id, tmp);
  return tmp;
}
