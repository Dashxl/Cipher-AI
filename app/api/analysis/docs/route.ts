import { NextResponse } from "next/server";
import { z } from "zod";
import JSZip from "jszip";
import { createHash } from "crypto";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";
import { genai } from "@/lib/genai/client";
import { MODELS } from "@/lib/genai/models";
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
  const cleaned = t.replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
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

    if (x.includes("/src/app/api/")) s += 90;
    if (x.includes("/src/app/") && x.endsWith(".tsx")) s += 70;
    if (x.includes("/src/lib/")) s += 60;
    if (x.includes("/src/types/")) s += 55;

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

  // ✅ FIX: contents tipado correcto + config correcto (NO generationConfig)
  const resp = await genai.models.generateContent({
    model: MODELS.fast,
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    config: {
      responseMimeType: "application/json",
      temperature: 0.2,
      thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
    },
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

export async function POST(req: Request) {
  try {
    const body = BodySchema.parse(await req.json());
    const analysisId = body.analysisId;
    const mode = body.mode;
    const maxFiles = body.maxFiles ?? 18;
    const path = String(body.path ?? "");

    const meta = await kvGet<RepoMeta>(`repo:${analysisId}`);
    if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

    const zipBuf = await loadZip(analysisId);
    if (!zipBuf) return NextResponse.json({ error: "Missing ZIP for analysisId" }, { status: 404 });

    const zip = await JSZip.loadAsync(zipBuf as any);

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
    return NextResponse.json({ error: err?.message ?? "Docs failed" }, { status: 500 });
  }
}
