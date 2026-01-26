import { NextResponse } from "next/server";
import { z } from "zod";
import JSZip from "jszip";
import { kvGet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";
import { genai } from "@/lib/genai/client";
import { MODELS } from "@/lib/genai/models";
import { ThinkingLevel } from "@google/genai";
import { createTwoFilesPatch } from "diff";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

const BodySchema = z.object({
  analysisId: z.string().min(1),
  file: z.string().min(1),
  issueTitle: z.string().optional(),
  issueDetails: z.string().optional(),
});

function isSafePath(p: string) {
  return (
    p.length > 0 &&
    p.length < 500 &&
    !p.includes("..") &&
    !p.startsWith("/") &&
    !p.includes("\\") &&
    !p.includes("\0")
  );
}

function toMsg(err: unknown) {
  return err instanceof Error ? err.message : String(err);
}

function isQuota(msg: string) {
  return (
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.includes("429") ||
    msg.includes("Quota exceeded") ||
    msg.includes("exceeded your current quota")
  );
}

/**
 * Fallback unified diff generator (full-file replacement).
 */
function fullReplacementDiff(path: string, oldText: string, newText: string) {
  const oldLines = oldText.replace(/\r/g, "").split("\n");
  const newLines = newText.replace(/\r/g, "").split("\n");

  const header = [
    `diff --git a/${path} b/${path}`,
    `index 0000000..1111111 100644`,
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -1,${oldLines.length} +1,${newLines.length} @@`,
  ];

  const body: string[] = [];
  for (const l of oldLines) body.push(`-${l}`);
  for (const l of newLines) body.push(`+${l}`);

  return [...header, ...body].join("\n") + "\n";
}

/**
 * Line-level git-style unified diff using `diff` package.
 */
function lineLevelGitDiff(path: string, oldText: string, newText: string) {
  const a = (oldText ?? "").replace(/\r\n/g, "\n");
  const b = (newText ?? "").replace(/\r\n/g, "\n");

  let patch = createTwoFilesPatch(`a/${path}`, `b/${path}`, a, b, "", "", { context: 3 });

  patch = patch.replace(/^Index:.*\n/gm, "");
  patch = patch.replace(/^=+\n/gm, "");

  patch = `diff --git a/${path} b/${path}\n` + patch;

  patch = patch.replace(/\r\n/g, "\n");
  if (!patch.endsWith("\n")) patch += "\n";

  return patch;
}

export async function POST(req: Request) {
  try {
    const body = BodySchema.parse(await req.json());

    if (!isSafePath(body.file)) {
      return NextResponse.json({ error: "Invalid file path." }, { status: 400 });
    }

    const meta = await kvGet<RepoMeta>(`repo:${body.analysisId}`);
    if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

    const zipBuf = await loadZip(body.analysisId);
    const zip = await JSZip.loadAsync(zipBuf);

    const actualPath = meta.root ? `${meta.root}/${body.file}` : body.file;
    const f = zip.file(actualPath);
    if (!f) return NextResponse.json({ error: "File not found" }, { status: 404 });

    const original = await f.async("string");

    const MAX_CHARS = 18_000;
    const clipped = original.slice(0, MAX_CHARS);
    const truncatedNote =
      original.length > MAX_CHARS
        ? `NOTE: File was truncated to first ${MAX_CHARS} characters for patch generation.`
        : "";

    const prompt = [
      "You are a senior engineer generating a patch for a legacy codebase.",
      "Goal: keep EXACT functionality, only improve security/quality per the issue context.",
      "Return ONLY the full updated file content (no markdown, no explanations).",
      "If you need to add helper functions, keep them in the same file.",
      "",
      `Repository: ${meta.repoName}`,
      `File: ${body.file}`,
      body.issueTitle ? `Issue title: ${body.issueTitle}` : "",
      body.issueDetails ? `Issue details:\n${body.issueDetails}` : "",
      truncatedNote,
      "",
      "Current file content:",
      clipped,
    ]
      .filter(Boolean)
      .join("\n");

    const res = await genai.models.generateContent({
      model: MODELS.fast,
      contents: prompt,
      config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
    });

    const updated = (res.text ?? "").trim();
    if (!updated) {
      return NextResponse.json({ error: "Gemini returned empty patch." }, { status: 500 });
    }

    const normOld = original.replace(/\r\n/g, "\n").trimEnd();
    const normNew = updated.replace(/\r\n/g, "\n").trimEnd();
    if (normOld === normNew) {
      return NextResponse.json(
        { error: "Gemini returned no changes for this issue. Try re-running or adjust issue context." },
        { status: 422 }
      );
    }

    let diff = "";
    let note: string | undefined;

    try {
      diff = lineLevelGitDiff(body.file, original, updated);

      const MAX_DIFF_CHARS = 2_000_000;
      if (diff.length > MAX_DIFF_CHARS) {
        diff = fullReplacementDiff(body.file, original, updated);
        note = "Line-level diff was too large; returned full-file replacement diff instead.";
      }
    } catch (e) {
      diff = fullReplacementDiff(body.file, original, updated);
      note = `Line-level diff failed; returned full-file replacement diff. (${toMsg(e)})`;
    }

    const truncWarn =
      original.length > MAX_CHARS ? "Patch generated from truncated input; review carefully." : undefined;

    // For UI preview: return updated content too (cap to avoid huge responses)
    const MAX_RETURN_UPDATED = 250_000;
    const updatedTruncated = updated.length > MAX_RETURN_UPDATED;
    const updatedForClient = updatedTruncated ? updated.slice(0, MAX_RETURN_UPDATED) : updated;

    const combinedNote =
      note ??
      (updatedTruncated
        ? "Updated file content was truncated for preview (UI only)."
        : truncWarn);

    return NextResponse.json({
      file: body.file,
      diff,
      updated: updatedForClient,
      updatedTruncated,
      note: combinedNote,
    });
  } catch (err) {
    const msg = toMsg(err);
    const status = isQuota(msg) ? 429 : 500;
    return NextResponse.json({ error: msg }, { status });
  }
}
