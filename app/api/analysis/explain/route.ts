import { NextResponse } from "next/server";
import { z } from "zod";
import JSZip from "jszip";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";
import { genai } from "@/lib/genai/client";
import { MODELS } from "@/lib/genai/models";
import { ThinkingLevel } from "@google/genai";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

const BodySchema = z.object({
  analysisId: z.string().min(1),
  path: z.string().min(1),
  mode: z.enum(["tech", "eli5"]).default("tech"),
});

const TTL = 60 * 60; // 1h
const MAX_CHARS = 10_000;

function isSafePath(p: string) {
  return (
    p.length > 0 &&
    p.length < 400 &&
    !p.includes("..") &&
    !p.startsWith("/") &&
    !p.includes("\\") &&
    !p.includes("\0")
  );
}

function normalizePath(p: string) {
  return String(p || "").replaceAll("\\", "/").trim();
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

export async function POST(req: Request) {
  try {
    const body = BodySchema.parse(await req.json());
    const relPath = normalizePath(body.path);

    if (!isSafePath(relPath)) {
      return NextResponse.json({ error: "Invalid path" }, { status: 400 });
    }

    const cacheKey = `explain:${body.analysisId}:${body.mode}:${relPath}`;
    const cached = await kvGet<{ text: string }>(cacheKey);
    if (cached) return NextResponse.json(cached);

    const meta = await kvGet<RepoMeta>(`repo:${body.analysisId}`);
    if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

    const zipBuf = await loadZip(body.analysisId);
    if (!zipBuf) return NextResponse.json({ error: "Missing ZIP for analysisId" }, { status: 404 });

    const zip = await JSZip.loadAsync(zipBuf as any);

    const actualPath = meta.root ? `${meta.root}/${relPath}` : relPath;
    const f = zip.file(actualPath);
    if (!f) return NextResponse.json({ error: "File not found" }, { status: 404 });

    const raw = await f.async("string");
    const code = String(raw ?? "").slice(0, MAX_CHARS);

    const prompt =
      body.mode === "eli5"
        ? [
            "Explain this code like I'm 5 using a real-world analogy.",
            "Then give a simple step-by-step flow of what it does.",
            "Keep it short and clear.",
            `File: ${relPath}`,
            "Code:",
            code,
          ].join("\n")
        : [
            "You are a senior engineer. Explain this file for onboarding.",
            "Return sections:",
            "1) Purpose",
            "2) How it works",
            "3) Key inputs/outputs & dependencies",
            "4) Risks/tech debt",
            "5) Suggested tests",
            `File: ${relPath}`,
            "Code:",
            code,
          ].join("\n");

    const res = await genai.models.generateContent({
      model: MODELS.fast,
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: {
        temperature: 0.2,
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      },
    });

    const text = res.text ?? "(No text returned)";
    await kvSet(cacheKey, { text }, TTL);

    return NextResponse.json({ text });
  } catch (err) {
    // Zod
    if (err instanceof z.ZodError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }

    const msg = toMsg(err);

    if (isQuota(msg)) {
      return NextResponse.json(
        {
          errorCode: "RATE_LIMIT",
          error: "Gemini rate limit reached while explaining. Try again in ~60s.",
          detail: msg,
        },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
