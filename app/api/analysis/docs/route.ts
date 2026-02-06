import { NextResponse } from "next/server";
import { z } from "zod";
import JSZip from "jszip";
import { createHash } from "crypto";
import { kvGet, kvSet } from "@/lib/cache/store";
import {
  loadZip,
  saveZip,
  ZipNotReadyError,
  ZipChunkMissingError,
  ZipCorruptError,
} from "@/lib/repo/zip-store";
import { withRotatingKey } from "@/lib/genai/keyring";
import { makeGenAI } from "@/lib/genai/rotating-client";
import { MODELS } from "@/lib/genai/models";
import { env } from "@/lib/env";
import { ThinkingLevel } from "@google/genai";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

const TTL = 60 * 60 * 6; // 6h
const MAX_CHARS = 18_000;

const BodySchema = z.object({
  analysisId: z.string().min(1),
  mode: z.enum(["index", "file"]).default("file"),
  path: z.string().optional(),
  maxFiles: z.number().int().min(5).max(40).optional(),
});

type DocsIndexItem = {
  path: string;
  title: string;
  purpose: string;
  updatedAt: string;
};

type FileDoc = {
  path: string;
  title: string;
  purpose: string;
  inputs?: string[];
  outputs?: string[];
  sideEffects?: string[];
  usedBy?: string[];
  uses?: string[];
  examples?: string[];
  risks?: string[];
  notes?: string[];
  updatedAt: string;
};

function hashPath(p: string) {
  return createHash("sha1").update(p).digest("hex").slice(0, 16);
}

function truncate(s: string, max: number) {
  if (s.length <= max) return s;
  return s.slice(0, max) + "\n\n/* …truncated… */\n";
}

function safeJsonParse(raw: string) {
  const t = String(raw || "").trim();
  const cleaned = t
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/```$/i, "")
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    return {};
  }
}

function asStringArray(v: any): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const arr = v.map((x) => String(x)).filter(Boolean);
  return arr.length ? arr.slice(0, 40) : undefined;
}

function rankFiles(files: string[]) {
  const score = (p: string) => {
    const x = p.toLowerCase();
    let s = 0;

    if (x === "package.json") s += 100;
    if (x.endsWith("/package.json")) s += 80;

    if (x.includes("/app/api/")) s += 90;
    if (x.includes("/app/") && x.endsWith(".tsx")) s += 70;
    if (x.includes("/lib/")) s += 60;
    if (x.includes("/types/")) s += 55;

    if (x.endsWith("route.ts")) s += 65;
    if (x.endsWith(".ts") || x.endsWith(".tsx")) s += 40;

    if (x.includes("auth")) s += 10;
    if (x.includes("security")) s += 10;
    if (x.includes("analysis")) s += 12;

    if (x.endsWith(".png") || x.endsWith(".jpg") || x.endsWith(".jpeg") || x.endsWith(".pdf")) s -= 200;
    return s;
  };

  return files
    .slice()
    .sort((a, b) => score(b) - score(a))
    .filter((p) => score(p) > -100);
}


function parseOwnerRepo(repoName: string): { owner: string; repo: string } | null {
  const s = String(repoName || "").trim();
  // Expected: owner/repo
  if (!/^[^\s/]+\/[^\s/]+$/.test(s)) return null;
  const [owner, repo] = s.split("/");
  if (!owner || !repo) return null;
  return { owner, repo };
}

async function getDefaultBranch(owner: string, repo: string): Promise<string | null> {
  try {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "User-Agent": "cipher-ai",
    };
    if (env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${env.GITHUB_TOKEN}`;

    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
    if (!res.ok) return null;
    const data = (await res.json()) as { default_branch?: string };
    return data.default_branch ?? null;
  } catch {
    return null;
  }
}

async function downloadGitHubZip(owner: string, repo: string): Promise<Buffer> {
  const def = await getDefaultBranch(owner, repo);

  const candidates = [def, "main", "master", "canary", "develop", "dev", "trunk"].filter(Boolean) as string[];

  const tried: { branch: string; status: number; url: string }[] = [];
  const seen = new Set<string>();

  for (const branch of candidates) {
    if (seen.has(branch)) continue;
    seen.add(branch);

    // Prefer GitHub API zipball when we have a token (works for private repos + avoids codeload quirks).
    const url = env.GITHUB_TOKEN
      ? `https://api.github.com/repos/${owner}/${repo}/zipball/${branch}`
      : `https://codeload.github.com/${owner}/${repo}/zip/refs/heads/${branch}`;

    const headers: Record<string, string> = { "User-Agent": "cipher-ai" };
    if (env.GITHUB_TOKEN) {
      headers["Accept"] = "application/vnd.github+json";
      headers["Authorization"] = `Bearer ${env.GITHUB_TOKEN}`;
    }

    const res = await fetch(url, { headers });
    tried.push({ branch, status: res.status, url });

    if (res.ok) {
      const arr = await res.arrayBuffer();
      return Buffer.from(arr);
    }
  }

  throw new Error(
    `Failed to download repo ZIP. Tried: ${tried.map((t) => `${t.branch}(${t.status})`).join(", ")}`
  );
}
async function ensureZipBuffer(analysisId: string, meta: RepoMeta): Promise<Buffer> {
  try {
    return await loadZip(analysisId);
  } catch (err: any) {
    const code = err?.code;
    const isZipMissing =
      err instanceof ZipNotReadyError ||
      err instanceof ZipChunkMissingError ||
      err instanceof ZipCorruptError ||
      code === "ENOENT";

    if (!isZipMissing) throw err;

    const parsed = parseOwnerRepo(meta.repoName);
    if (!parsed) throw err;

    // Fallback: re-download from GitHub and (best-effort) persist.
    const zipBuf = await downloadGitHubZip(parsed.owner, parsed.repo);
    try {
      await saveZip(analysisId, zipBuf, TTL);
    } catch {
      // best-effort only
    }
    return zipBuf;
  }
}
async function readFileFromZip(zip: JSZip, meta: RepoMeta, relPath: string) {
  const actualPath = meta.root ? `${meta.root}/${relPath}` : relPath;

  let entry = zip.file(actualPath);
  if (!entry) {
    const all = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
    const alt =
      all.find((p) => p.toLowerCase().endsWith(`/${relPath.toLowerCase()}`)) ??
      all.find((p) => p.toLowerCase() === relPath.toLowerCase());
    if (alt) entry = zip.file(alt) ?? null;
  }
  if (!entry) throw new Error(`File not found in ZIP: ${relPath}`);

  const raw = await entry.async("string");
  return String(raw ?? "");
}

async function generateDocWithGemini(meta: RepoMeta, path: string, content: string): Promise<FileDoc> {
  const prompt = [
    "You are a senior software engineer writing INTERNAL documentation for a codebase.",
    "Return ONLY valid JSON (no markdown, no code fences).",
    "Be concise and accurate. If unknown, omit field or use empty array.",
    "",
    "JSON schema:",
    `{
      "path": string,
      "title": string,
      "purpose": string,
      "inputs": string[],
      "outputs": string[],
      "sideEffects": string[],
      "usedBy": string[],
      "uses": string[],
      "examples": string[],
      "risks": string[],
      "notes": string[],
      "updatedAt": string
    }`,
    "",
    `Repository: ${meta.repoName}`,
    `File path: ${path}`,
    "",
    "File content:",
    content,
  ].join("\n");

  const resp = await withRotatingKey(async (apiKey) => {
    const genai = makeGenAI(apiKey);

    return await genai.models.generateContent({
      model: MODELS.fast,
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: {
        responseMimeType: "application/json",
        temperature: 0.2,
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      },
    });
  });

  const parsed = safeJsonParse(resp.text ?? "");

  return {
    path,
    title: String(parsed?.title ?? path.split("/").pop() ?? path),
    purpose: String(parsed?.purpose ?? "No purpose provided."),
    inputs: asStringArray(parsed?.inputs),
    outputs: asStringArray(parsed?.outputs),
    sideEffects: asStringArray(parsed?.sideEffects),
    usedBy: asStringArray(parsed?.usedBy),
    uses: asStringArray(parsed?.uses),
    examples: asStringArray(parsed?.examples),
    risks: asStringArray(parsed?.risks),
    notes: asStringArray(parsed?.notes),
    updatedAt: new Date().toISOString(),
  };
}

function zipErrorResponse(err: unknown, analysisId: string) {
  const code = (err as any)?.code;

  if (code === "ENOENT") {
    return NextResponse.json(
      {
        code: "ZIP_NOT_READY",
        error:
          "Repository ZIP is not available on the server (ENOENT). This analysis likely expired or was created before ZIP persistence. Please re-run the analysis.",
        detail: err instanceof Error ? err.message : String(err),
        analysisId,
      },
      { status: 410 }
    );
  }

  if (err instanceof ZipNotReadyError || err instanceof ZipChunkMissingError) {
    return NextResponse.json(
      {
        code: code ?? "ZIP_NOT_READY",
        error:
          "Repository ZIP is not available on the server. This analysis likely expired or was created before ZIP persistence. Please re-run the analysis.",
        detail: err instanceof Error ? err.message : String(err),
        analysisId,
      },
      { status: 410 }
    );
  }

  if (err instanceof ZipCorruptError) {
    return NextResponse.json(
      {
        code: code ?? "ZIP_CORRUPT",
        error:
          "Repository ZIP appears corrupted/incomplete on the server. Please re-run the analysis.",
        detail: err instanceof Error ? err.message : String(err),
        analysisId,
      },
      { status: 500 }
    );
  }

  return null;
}

export async function POST(req: Request) {
  try {
    const body = BodySchema.parse(await req.json());
    const analysisId = body.analysisId;
    const mode = body.mode;
    const maxFiles = body.maxFiles ?? 18;
    const path = String(body.path ?? "");

    const meta = await kvGet<RepoMeta>(`repo:${analysisId}`);
    if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

    let zipBuf: Buffer;
    try {
      zipBuf = await ensureZipBuffer(analysisId, meta);
    } catch (e) {
      const resp = zipErrorResponse(e, analysisId);
      if (resp) return resp;
      throw e;
    }

    let zip: JSZip;
    try {
      zip = await JSZip.loadAsync(zipBuf as any);
    } catch (e) {
      return NextResponse.json(
        {
          code: "ZIP_PARSE_FAILED",
          error: "Failed to parse repository ZIP on the server. Please re-run analysis.",
          detail: e instanceof Error ? e.message : String(e),
          analysisId,
        },
        { status: 500 }
      );
    }

    if (mode === "index") {
      const cacheKey = `docs:index:${analysisId}:${maxFiles}`;
      const cached = await kvGet<{ items: DocsIndexItem[] }>(cacheKey);
      if (cached) return NextResponse.json(cached);

      const ranked = rankFiles(meta.files).slice(0, maxFiles);
      const items: DocsIndexItem[] = [];

      for (const rel of ranked) {
        const docKey = `docs:file:${analysisId}:${hashPath(rel)}`;
        let doc = await kvGet<FileDoc>(docKey);

        if (!doc) {
          const raw = await readFileFromZip(zip, meta, rel);
          const clipped = truncate(raw, MAX_CHARS);
          doc = await generateDocWithGemini(meta, rel, clipped);
          await kvSet(docKey, doc, TTL);
        }

        items.push({ path: doc.path, title: doc.title, purpose: doc.purpose, updatedAt: doc.updatedAt });
      }

      const payload = { items };
      await kvSet(cacheKey, payload, TTL);
      return NextResponse.json(payload);
    }

    if (!path) return NextResponse.json({ error: "Missing path" }, { status: 400 });

    const docKey = `docs:file:${analysisId}:${hashPath(path)}`;
    const cached = await kvGet<FileDoc>(docKey);
    if (cached) return NextResponse.json({ doc: cached });

    const raw = await readFileFromZip(zip, meta, path);
    const clipped = truncate(raw, MAX_CHARS);

    const doc = await generateDocWithGemini(meta, path, clipped);
    await kvSet(docKey, doc, TTL);

    return NextResponse.json({ doc });
  } catch (err: any) {
    const msg = String(err?.message ?? "Docs failed");
    const lower = msg.toLowerCase();

    const isQuota =
      lower.includes("resource_exhausted") ||
      lower.includes("429") ||
      lower.includes("quota exceeded") ||
      lower.includes("exceeded your current quota") ||
      lower.includes("rate limit");

    if (isQuota) {
      return NextResponse.json(
        {
          errorCode: "RATE_LIMIT",
          error: "Gemini rate limit reached while generating docs. Try again in ~60s.",
          detail: msg,
        },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
