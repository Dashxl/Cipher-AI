import { createHash } from "crypto";
import { kvGet, kvSet } from "@/lib/cache/store";

/**
 * ZIP persistence for Vercel (serverless): store ZIP bytes in Upstash Redis (or in-memory fallback).
 *
 * Keys:
 * - zip:<id>:manifest
 * - zip:<id>:chunk:<i>
 */

export class ZipNotReadyError extends Error {
  code = "ZIP_NOT_READY" as const;
  constructor(message = "ZIP not ready") {
    super(message);
    this.name = "ZipNotReadyError";
  }
}

export class ZipChunkMissingError extends Error {
  code = "ZIP_CHUNK_MISSING" as const;
  missingChunk: number;
  constructor(chunkIndex: number, message = "ZIP chunk missing") {
    super(`${message}: ${chunkIndex}`);
    this.name = "ZipChunkMissingError";
    this.missingChunk = chunkIndex;
  }
}

export class ZipCorruptError extends Error {
  code = "ZIP_CORRUPT" as const;
  constructor(message = "ZIP corrupt") {
    super(message);
    this.name = "ZipCorruptError";
  }
}

type ZipManifest = {
  v: 1;
  size: number;
  sha256: string;
  chunks: number;
  chunkBytes: number;
  createdAt: string;
};

const DEFAULT_TTL_SECONDS = 60 * 60 * 6; // 6h

// Raw bytes per chunk before base64 encoding.
// 480KB -> base64 ~ 640KB, stays under common KV value limits.
const CHUNK_BYTES = 480_000;

const g = globalThis as unknown as { __cipherZipMem?: Map<string, Buffer> };
const mem = (g.__cipherZipMem ??= new Map<string, Buffer>());

function sha256(buf: Buffer) {
  return createHash("sha256").update(buf).digest("hex");
}

function manifestKey(id: string) {
  return `zip:${id}:manifest`;
}

function chunkKey(id: string, i: number) {
  return `zip:${id}:chunk:${i}`;
}

export async function saveZip(id: string, buf: Buffer, ttlSeconds = DEFAULT_TTL_SECONDS) {
  if (!id) throw new Error("Missing id");
  if (!Buffer.isBuffer(buf)) throw new Error("saveZip expects a Buffer");

  // hot cache (best-effort)
  mem.set(id, buf);

  const total = buf.length;
  const chunks = Math.max(1, Math.ceil(total / CHUNK_BYTES));

  // Store chunks first; only write manifest at the end (prevents partial reads).
  for (let i = 0; i < chunks; i++) {
    const start = i * CHUNK_BYTES;
    const end = Math.min(total, start + CHUNK_BYTES);
    const slice = buf.subarray(start, end);
    const b64 = slice.toString("base64");
    await kvSet(chunkKey(id, i), b64, ttlSeconds);
  }

  const manifest: ZipManifest = {
    v: 1,
    size: total,
    sha256: sha256(buf),
    chunks,
    chunkBytes: CHUNK_BYTES,
    createdAt: new Date().toISOString(),
  };

  await kvSet(manifestKey(id), manifest, ttlSeconds);
}

export async function loadZip(id: string): Promise<Buffer> {
  if (!id) throw new ZipNotReadyError("Missing id");

  const fromMem = mem.get(id);
  if (fromMem) return fromMem;

  const manifest = await kvGet<ZipManifest>(manifestKey(id));
  if (!manifest || manifest.v !== 1 || !manifest.chunks) {
    throw new ZipNotReadyError(`ZIP manifest missing for id: ${id}`);
  }

  const parts: Buffer[] = [];
  for (let i = 0; i < manifest.chunks; i++) {
    const b64 = await kvGet<string>(chunkKey(id, i));
    if (!b64) {
      throw new ZipChunkMissingError(i, `ZIP chunk missing for id: ${id}`);
    }
    parts.push(Buffer.from(b64, "base64"));
  }

  const buf = Buffer.concat(parts);

  if (buf.length !== manifest.size) {
    throw new ZipCorruptError(`ZIP size mismatch (got ${buf.length}, expected ${manifest.size})`);
  }

  const got = sha256(buf);
  if (got !== manifest.sha256) {
    throw new ZipCorruptError("ZIP checksum mismatch");
  }

  mem.set(id, buf);
  return buf;
}
