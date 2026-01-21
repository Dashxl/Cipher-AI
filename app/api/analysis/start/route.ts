// src/app/api/analysis/start/route.ts
import { NextResponse } from "next/server";
import JSZip from "jszip";
import { z } from "zod";
import { genai } from "@/lib/genai/client";
import { MODELS } from "@/lib/genai/models";
import { kvSet } from "@/lib/cache/store";
import type { AnalysisResult, AnalysisStatus } from "@/types/analysis";
import { ThinkingLevel } from "@google/genai";
import { env } from "@/lib/env";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** JSON payload for GitHub URL analysis */
const JsonBodySchema = z.object({
  githubUrl: z.string().url(),
});

/** Expected model output */
const ResultSchema = z.object({
  repoName: z.string(),
  fileCount: z.number().int().nonnegative(),
  keyFiles: z.array(z.string()).max(30),
  mermaid: z.string(),
  summary: z.array(z.string()).min(1).max(10),
  risks: z
    .array(
      z.object({
        severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
        title: z.string(),
        details: z.string(),
      })
    )
    .max(20),
  quickWins: z.array(z.string()).max(20),
  nextSteps: z.array(z.string()).max(20),
});

function isProbablyText(path: string) {
  const lower = path.toLowerCase();
  const blocked = [
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".rar",
    ".7z",
    ".mp4",
    ".mov",
    ".mp3",
    ".wav",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".exe",
    ".dll",
  ];
  return !blocked.some((ext) => lower.endsWith(ext));
}

function pickKeyFiles(allPaths: string[]) {
  const priority = [
    "package.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",
    "tsconfig.json",
    "next.config.js",
    "next.config.mjs",
    "tailwind.config.js",
    "tailwind.config.ts",
    "requirements.txt",
    "pyproject.toml",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "cargo.toml",
    "dockerfile",
    "docker-compose.yml",
    "readme.md",
  ];

  const lowerMap = new Map(allPaths.map((p) => [p.toLowerCase(), p]));
  const chosen: string[] = [];

  // exact name matches
  for (const p of priority) {
    const found = lowerMap.get(p);
    if (found) chosen.push(found);
  }

  // entrypoint hints
  const entryHints = allPaths.filter((p) => {
    const pl = p.toLowerCase();
    return (
      pl.endsWith("src/app/page.tsx") ||
      pl.endsWith("src/pages/index.tsx") ||
      pl.endsWith("pages/index.js") ||
      pl.endsWith("index.js") ||
      pl.endsWith("server.js") ||
      pl.endsWith("app.js") ||
      pl.endsWith("main.py") ||
      pl.endsWith("index.php")
    );
  });

  for (const p of entryHints) if (!chosen.includes(p)) chosen.push(p);

  return chosen.slice(0, 16);
}

function extractJson(text: string) {
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) return null;
  return text.slice(first, last + 1);
}

function isQuotaError(err: unknown) {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.includes("429") ||
    msg.includes("Quota exceeded") ||
    msg.includes("exceeded your current quota")
  );
}

async function callGemini(model: string, prompt: string) {
  const res = await genai.models.generateContent({
    model,
    contents: prompt,
    config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
  });
  return res.text ?? "";
}

function parseGitHubUrl(url: string): { owner: string; repo: string } {
  const u = new URL(url);
  if (u.hostname !== "github.com") throw new Error("Only github.com URLs are supported.");
  const parts = u.pathname.split("/").filter(Boolean);
  if (parts.length < 2) throw new Error("Invalid GitHub URL. Expected https://github.com/owner/repo");
  return { owner: parts[0], repo: parts[1].replace(/\.git$/, "") };
}

/** Works for public repos without token; token improves rate limits and supports private repos */
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

/**
 * Download a repository ZIP from GitHub via codeload. We try:
 * 1) default branch (from GitHub API) (canary, trunk, etc.)
 * 2) common fallbacks: main/master/canary/develop/...
 */
async function downloadGitHubZip(owner: string, repo: string): Promise<Buffer> {
  const def = await getDefaultBranch(owner, repo);

  const candidates = [
    def,
    "main",
    "master",
    "canary",
    "develop",
    "dev",
    "trunk",
  ].filter(Boolean) as string[];

  const tried: { branch: string; status: number }[] = [];
  const seen = new Set<string>();

  for (const branch of candidates) {
    if (seen.has(branch)) continue;
    seen.add(branch);

    const url = `https://codeload.github.com/${owner}/${repo}/zip/refs/heads/${branch}`;
    const res = await fetch(url, { headers: { "User-Agent": "cipher-ai" } });

    tried.push({ branch, status: res.status });

    if (res.ok) {
      const arr = await res.arrayBuffer();
      return Buffer.from(arr);
    }
  }

  throw new Error(
    `Failed to download repo ZIP. Tried branches: ${tried
      .map((t) => `${t.branch}(${t.status})`)
      .join(", ")}`
  );
}

/**
 * GitHub zipballs include a single top folder like repo-branch-hash/.
 * We normalize paths by stripping that root so keyFiles match.
 */
function buildNormalizedPathMap(paths: string[]) {
  const firstSegments = new Set<string>();
  for (const p of paths) {
    const seg = p.split("/")[0];
    if (seg) firstSegments.add(seg);
  }

  const hasSingleRoot = firstSegments.size === 1;
  const root = hasSingleRoot ? [...firstSegments][0] : null;

  const normToActual = new Map<string, string>();
  const normalizedPaths = paths.map((p) => {
    const norm = root ? p.replace(new RegExp(`^${root}/`), "") : p;
    normToActual.set(norm, p);
    return norm;
  });

  return { root, normalizedPaths, normToActual };
}

async function analyzeZipBuffer(
  id: string,
  baseStatus: AnalysisStatus,
  zipBuf: Buffer,
  repoName: string
) {
  const zip = await JSZip.loadAsync(zipBuf);

  const allActual = Object.keys(zip.files).filter((p) => !zip.files[p]?.dir);
  const { normalizedPaths, normToActual } = buildNormalizedPathMap(allActual);

  const textPaths = normalizedPaths.filter(isProbablyText);
  const keyFiles = pickKeyFiles(textPaths);

  // Token saving: small tree preview + small snippets
  const treePreview = textPaths.slice(0, 80).join("\n");

  const keyFileSnippets: { path: string; content: string }[] = [];
  for (const normPath of keyFiles) {
    const actual = normToActual.get(normPath);
    if (!actual) continue;
    const f = zip.file(actual);
    if (!f) continue;
    const raw = await f.async("string");
    keyFileSnippets.push({ path: normPath, content: raw.slice(0, 2500) });
  }

  await kvSet(`analysis:${id}`, {
    ...baseStatus,
    stage: "calling_gemini",
    progress: 60,
    message: "Generating architecture with Gemini 3…",
    updatedAt: new Date().toISOString(),
  } satisfies AnalysisStatus);

  const prompt = [
    "You are Cipher AI, a code archaeology tool.",
    "Analyze this repository structure and key files, then output ONLY valid JSON matching this shape:",
    `{
  "repoName": string,
  "fileCount": number,
  "keyFiles": string[],
  "mermaid": string,
  "summary": string[],
  "risks": [{"severity":"CRITICAL|HIGH|MEDIUM|LOW","title":string,"details":string}],
  "quickWins": string[],
  "nextSteps": string[]
}`,
    "",
    "Rules:",
    "- Output ONLY JSON. No markdown, no backticks, no commentary.",
    "- Mermaid must be a single diagram (flowchart/graph).",
    "- Be specific and technical.",
    "",
    "=== FILE TREE (first 80 text files) ===",
    treePreview,
    "",
    "=== KEY FILE SNIPPETS ===",
    ...keyFileSnippets.flatMap((s) => [`--- ${s.path} ---`, s.content, ""]),
  ].join("\n");

  // Prefer Pro → fallback Flash if quota exceeded
  let rawText = "";
  let usedModel = MODELS.deep;

  try {
    rawText = await callGemini(MODELS.deep, prompt);
  } catch (err) {
    if (isQuotaError(err) && MODELS.fast && MODELS.fast !== MODELS.deep) {
      usedModel = MODELS.fast;

      await kvSet(`analysis:${id}`, {
        ...baseStatus,
        stage: "calling_gemini",
        progress: 70,
        message: "Pro quota exceeded. Falling back to Gemini 3 Flash…",
        updatedAt: new Date().toISOString(),
      } satisfies AnalysisStatus);

      rawText = await callGemini(MODELS.fast, prompt);
    } else {
      throw err;
    }
  }

  const jsonText = extractJson(rawText);
  if (!jsonText) throw new Error("Gemini did not return valid JSON.");

  const parsed = ResultSchema.parse(JSON.parse(jsonText)) as AnalysisResult;

  parsed.summary = [`(Model used: ${usedModel})`, ...parsed.summary].slice(0, 10);

  const done: AnalysisStatus = {
    id,
    stage: "done",
    progress: 100,
    message: "Done",
    startedAt: baseStatus.startedAt,
    updatedAt: new Date().toISOString(),
    result: {
      ...parsed,
      repoName,
      fileCount: textPaths.length,
      keyFiles,
    },
  };

  await kvSet(`analysis:${id}`, done);
}

export async function POST(req: Request) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const baseStatus: AnalysisStatus = {
    id,
    stage: "exploring_structure",
    progress: 10,
    message: "Exploring structure…",
    startedAt: now,
    updatedAt: now,
  };

  await kvSet(`analysis:${id}`, baseStatus);

  try {
    const contentType = req.headers.get("content-type") ?? "";

    // B) GitHub URL (application/json)
    if (contentType.includes("application/json")) {
      const body = JsonBodySchema.parse(await req.json());
      const { owner, repo } = parseGitHubUrl(body.githubUrl);

      await kvSet(`analysis:${id}`, {
        ...baseStatus,
        progress: 20,
        message: "Downloading GitHub ZIP…",
        updatedAt: new Date().toISOString(),
      } satisfies AnalysisStatus);

      const zipBuf = await downloadGitHubZip(owner, repo);

      await kvSet(`analysis:${id}`, {
        ...baseStatus,
        progress: 35,
        message: "Reading ZIP…",
        updatedAt: new Date().toISOString(),
      } satisfies AnalysisStatus);

      await analyzeZipBuffer(id, baseStatus, zipBuf, `${owner}/${repo}`);
      return NextResponse.json({ analysisId: id });
    }

    // A) ZIP upload (multipart/form-data)
    if (contentType.includes("multipart/form-data")) {
      const form = await req.formData();
      const zipFile = form.get("zip");

      if (!(zipFile instanceof File)) {
        throw new Error("Missing 'zip' file field in form-data.");
      }

      const MAX_BYTES = 25 * 1024 * 1024;
      if (zipFile.size > MAX_BYTES) {
        throw new Error("ZIP file too large. Please upload a ZIP under 25MB for MVP.");
      }

      await kvSet(`analysis:${id}`, {
        ...baseStatus,
        progress: 25,
        message: "Reading ZIP…",
        updatedAt: new Date().toISOString(),
      } satisfies AnalysisStatus);

      const zipBuf = Buffer.from(await zipFile.arrayBuffer());
      const repoName = zipFile.name.replace(/\.zip$/i, "") || "Uploaded ZIP";

      await analyzeZipBuffer(id, baseStatus, zipBuf, repoName);
      return NextResponse.json({ analysisId: id });
    }

    return NextResponse.json(
      { analysisId: id, error: "Send either JSON {githubUrl} or multipart/form-data with 'zip'." },
      { status: 400 }
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    await kvSet(`analysis:${id}`, {
      ...baseStatus,
      stage: "error",
      progress: 100,
      message: "Error",
      updatedAt: new Date().toISOString(),
      error: message,
    } satisfies AnalysisStatus);

    return NextResponse.json({ analysisId: id, error: message }, { status: 500 });
  }
}
