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
  const m = msg.toLowerCase();
  return (
    m.includes("resource_exhausted") ||
    m.includes("429") ||
    m.includes("quota exceeded") ||
    m.includes("exceeded your current quota") ||
    m.includes("rate limit")
  );
}

function stripCodeFences(s: string) {
  const t = String(s ?? "").trim();
  if (t.startsWith("```")) {
    return t.replace(/^```[a-z]*\s*/i, "").replace(/```$/i, "").trim();
  }
  return t;
}

/**
 * Unified diff REAL por líneas (con contexto).
 * Evita el "full-file replacement diff" que hace parecer que TODO cambió.
 */
function makeUnifiedPatch(path: string, oldText: string, newText: string) {
  const a = `a/${path}`;
  const b = `b/${path}`;

  const patch = createTwoFilesPatch(a, b, oldText, newText, "", "", { context: 3 });

  const header = `diff --git ${a} ${b}\n`;
  const cleaned = patch.replace(/^Index:.*\n/gm, "").replace(/^=+\n/gm, "");

  return header + cleaned.trim() + "\n";
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
    if (!zipBuf) return NextResponse.json({ error: "Missing ZIP for analysisId" }, { status: 404 });

    const zip = await JSZip.loadAsync(zipBuf as any);

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
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: {
        temperature: 0.2,
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      },
    });

    const updated = stripCodeFences(res.text ?? "").trim();
    if (!updated) {
      return NextResponse.json({ error: "Gemini returned empty patch." }, { status: 500 });
    }

    const diff = makeUnifiedPatch(body.file, original, updated);

    return NextResponse.json({
      file: body.file,
      diff,
      original,
      updated,
      note: original.length > MAX_CHARS ? "Patch generated from truncated input; review carefully." : undefined,
    });
  } catch (err) {
    const msg = toMsg(err);
    if (isQuota(msg)) {
      return NextResponse.json(
        {
          errorCode: "RATE_LIMIT",
          error: "Gemini rate limit reached. Try again in ~60s.",
          detail: msg,
        },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
