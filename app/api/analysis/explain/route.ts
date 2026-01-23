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

function toMsg(err: unknown) {
  if (err instanceof Error) return err.message;
  return String(err);
}

function isQuota(msg: string) {
  return (
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.includes("429") ||
    msg.includes("Quota exceeded") ||
    msg.includes("exceeded your current quota")
  );
}

export async function POST(req: Request) {
  try {
    const body = BodySchema.parse(await req.json());

    if (!isSafePath(body.path)) {
      return NextResponse.json({ error: "Invalid path" }, { status: 400 });
    }

    const cacheKey = `explain:${body.analysisId}:${body.mode}:${body.path}`;
    const cached = await kvGet<{ text: string }>(cacheKey);
    if (cached) return NextResponse.json(cached);

    const meta = await kvGet<RepoMeta>(`repo:${body.analysisId}`);
    if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

    const zipBuf = await loadZip(body.analysisId);
    const zip = await JSZip.loadAsync(zipBuf);

    const actualPath = meta.root ? `${meta.root}/${body.path}` : body.path;
    const f = zip.file(actualPath);
    if (!f) return NextResponse.json({ error: "File not found" }, { status: 404 });

    const raw = await f.async("string");
    const code = raw.slice(0, 10_000);

    const prompt =
      body.mode === "eli5"
        ? [
            "Explain this code like I'm 5 using a real-world analogy.",
            "Then give a simple step-by-step flow of what it does.",
            "Keep it short and clear.",
            `File: ${body.path}`,
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
            `File: ${body.path}`,
            "Code:",
            code,
          ].join("\n");

    const res = await genai.models.generateContent({
      model: MODELS.fast, // Gemini 3 Flash
      contents: prompt,
      config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
    });

    const text = res.text ?? "(No text returned)";
    await kvSet(cacheKey, { text }, 60 * 60);

    return NextResponse.json({ text });
  } catch (err) {
    // Zod
    if (err instanceof z.ZodError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }

    const msg = toMsg(err);
    const status = isQuota(msg) ? 429 : 500;
    return NextResponse.json({ error: msg }, { status });
  }
}
