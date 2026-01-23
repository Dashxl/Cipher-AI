import { NextResponse } from "next/server";
import { z } from "zod";
import JSZip from "jszip";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";
import { genai } from "@/lib/genai/client";
import { MODELS } from "@/lib/genai/models";
import { ThinkingLevel } from "@google/genai";
import type { DebtIssue, Severity } from "@/types/scan";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

const BodySchema = z.object({
  analysisId: z.string().min(1),
  maxFiles: z.number().int().min(10).max(500).default(220),
  maxIssues: z.number().int().min(5).max(200).default(90),
});

function sevRank(s: Severity) {
  return s === "CRITICAL" ? 0 : s === "HIGH" ? 1 : s === "MEDIUM" ? 2 : 3;
}

function mkId(file: string, line: number, type: string) {
  return `${type}:${file}:${line}`;
}

function isQuota(msg: string) {
  return (
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.includes("429") ||
    msg.includes("Quota exceeded") ||
    msg.includes("exceeded your current quota")
  );
}

function maxIndentDepth(lines: string[]) {
  let max = 0;
  for (const l of lines) {
    const m = l.match(/^\s+/);
    if (!m) continue;
    max = Math.max(max, m[0].replace(/\t/g, "    ").length);
  }
  return max;
}

function guessSeverity(type: string): Severity {
  if (type === "god_function") return "HIGH";
  if (type === "duplicate_code") return "HIGH";
  if (type === "deep_nesting") return "MEDIUM";
  if (type === "large_file") return "MEDIUM";
  if (type === "todo") return "LOW";
  return "MEDIUM";
}

function normalizeLine(s: string) {
  return s
    .replace(/\/\/.*$/g, "")
    .replace(/#.*$/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function windowHashes(lines: string[], win = 8) {
  const hashes: Array<{ key: string; startLine: number }> = [];
  for (let i = 0; i + win <= lines.length; i++) {
    const chunk = lines.slice(i, i + win).map(normalizeLine).filter(Boolean);
    if (chunk.length < win) continue;
    const key = chunk.join("|");
    hashes.push({ key, startLine: i + 1 });
  }
  return hashes;
}

async function enrichWithGemini(repoName: string, issues: DebtIssue[]) {
  const top = issues.slice(0, 10);

  const prompt = [
    "You are a senior code reviewer and refactoring expert.",
    `Repository: ${repoName}`,
    "For each issue below, propose a concrete refactor (short) and a confidence score 0..1.",
    "Respond ONLY as JSON array with items:",
    `{ "id": string, "fix": string, "confidence": number }`,
    "",
    "Issues:",
    ...top.map((i) =>
      [
        `ID: ${i.id}`,
        `Type: ${i.type}`,
        `Severity: ${i.severity}`,
        `Location: ${i.file}:${i.line}`,
        `Details: ${i.details}`,
        "---",
      ].join("\n")
    ),
  ].join("\n");

  const res = await genai.models.generateContent({
    model: MODELS.fast,
    contents: prompt,
    config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
  });

  const text = res.text ?? "[]";
  const first = text.indexOf("[");
  const last = text.lastIndexOf("]");
  const json = first !== -1 && last !== -1 ? text.slice(first, last + 1) : "[]";

  const arr = JSON.parse(json) as Array<{ id: string; fix: string; confidence: number }>;
  const map = new Map(arr.map((x) => [x.id, x]));

  for (const it of issues) {
    const e = map.get(it.id);
    if (e) {
      it.fix = String(e.fix ?? "").slice(0, 1200);
      const c = Number(e.confidence);
      it.confidence = Number.isFinite(c) ? Math.max(0, Math.min(1, c)) : undefined;
    }
  }
}

export async function POST(req: Request) {
  const body = BodySchema.parse(await req.json());
  const cacheKey = `scan:debt:${body.analysisId}:${body.maxFiles}:${body.maxIssues}`;

  const cached = await kvGet<{ issues: DebtIssue[]; note?: string }>(cacheKey);
  if (cached) return NextResponse.json(cached);

  const meta = await kvGet<RepoMeta>(`repo:${body.analysisId}`);
  if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

  const zipBuf = await loadZip(body.analysisId);
  const zip = await JSZip.loadAsync(zipBuf);

  const files = (meta.files ?? []).slice(0, body.maxFiles);

  const issues: DebtIssue[] = [];
  const dupIndex = new Map<string, Array<{ file: string; line: number }>>();

  // 1) Build duplicate index (fast-ish)
  for (const file of files) {
    const actualPath = meta.root ? `${meta.root}/${file}` : file;
    const f = zip.file(actualPath);
    if (!f) continue;

    const content = (await f.async("string")).slice(0, 220_000);
    const lines = content.split("\n");

    for (const h of windowHashes(lines, 8)) {
      const arr = dupIndex.get(h.key) ?? [];
      arr.push({ file, line: h.startLine });
      dupIndex.set(h.key, arr);
    }
  }

  // 2) Per-file heuristics
  for (const file of files) {
    const actualPath = meta.root ? `${meta.root}/${file}` : file;
    const f = zip.file(actualPath);
    if (!f) continue;

    const content = (await f.async("string")).slice(0, 220_000);
    const lines = content.split("\n");

    // Large file
    if (lines.length >= 450) {
      issues.push({
        id: mkId(file, 1, "large_file"),
        severity: guessSeverity("large_file"),
        type: "large_file",
        title: "Large file",
        file,
        line: 1,
        details: `File has ${lines.length} lines.`,
        suggestion: "Split into smaller modules. Extract cohesive responsibilities into separate files.",
      });
    }

    // Deep nesting (indent-based heuristic)
    const depth = maxIndentDepth(lines);
    if (depth >= 24) {
      issues.push({
        id: mkId(file, 1, "deep_nesting"),
        severity: guessSeverity("deep_nesting"),
        type: "deep_nesting",
        title: "Deep nesting",
        file,
        line: 1,
        details: `Max indentation depth detected ~${depth} spaces.`,
        suggestion: "Refactor to early returns, smaller functions, and clearer control flow.",
      });
    }

    // TODO/FIXME
    const todoIdx = lines.findIndex((l) => /(TODO|FIXME)\b/i.test(l));
    if (todoIdx !== -1) {
      issues.push({
        id: mkId(file, todoIdx + 1, "todo"),
        severity: guessSeverity("todo"),
        type: "todo",
        title: "TODO/FIXME present",
        file,
        line: todoIdx + 1,
        details: lines[todoIdx].trim().slice(0, 200),
        suggestion: "Convert TODOs into tracked issues and implement or remove obsolete notes.",
      });
    }

    if (issues.length >= body.maxIssues) break;
  }

  // 3) Duplicate code issues (only strongest)
  const dupCandidates: DebtIssue[] = [];
  for (const [key, occ] of dupIndex.entries()) {
    if (occ.length < 4) continue; // require repetition
    const first = occ[0];
    dupCandidates.push({
      id: mkId(first.file, first.line, "duplicate_code"),
      severity: guessSeverity("duplicate_code"),
      type: "duplicate_code",
      title: "Duplicated code block",
      file: first.file,
      line: first.line,
      details: `Found similar 8-line blocks repeated ${occ.length} times across files.`,
      suggestion: "Extract a shared helper/function. Remove duplication to reduce bugs and improve maintainability.",
    });
    if (dupCandidates.length >= 20) break;
  }

  // Merge and prioritize
  const merged = [...issues, ...dupCandidates]
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
    .slice(0, body.maxIssues);

  let note: string | undefined;
  try {
    await enrichWithGemini(meta.repoName, merged);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    note = isQuota(msg)
      ? "Gemini quota exhausted: returning heuristic-only results."
      : `Gemini enrichment failed: ${msg}`;
  }

  const payload = { issues: merged, note };
  await kvSet(cacheKey, payload, 60 * 30);

  return NextResponse.json(payload);
}
