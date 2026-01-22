import { NextResponse } from "next/server";
import { z } from "zod";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";
import JSZip from "jszip";
import { genai } from "@/lib/genai/client";
import { MODELS } from "@/lib/genai/models";
import { ThinkingLevel } from "@google/genai";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

const Body = z.object({
  analysisId: z.string().min(1),
  path: z.string().min(1),
  mode: z.enum(["tech", "eli5"]).default("tech"),
});

export async function POST(req: Request) {
  const body = Body.parse(await req.json());
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

  const content = (await f.async("string")).slice(0, 9000);

  const prompt =
    body.mode === "eli5"
      ? [
          "Explain this code like I'm 5 using a real-world analogy.",
          "Then provide a simple step-by-step flow.",
          "Keep it short and clear.",
          `File: ${body.path}`,
          "Code:",
          content,
        ].join("\n")
      : [
          "You are a senior engineer. Explain this file for onboarding.",
          "Return:",
          "1) Purpose",
          "2) How it works",
          "3) Key dependencies / inputs / outputs",
          "4) Risks & technical debt",
          "5) Suggested tests",
          `File: ${body.path}`,
          "Code:",
          content,
        ].join("\n");

  const res = await genai.models.generateContent({
    model: MODELS.fast, // Gemini 3 Flash
    contents: prompt,
    config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
  });

  const text = res.text ?? "(No text returned)";
  await kvSet(cacheKey, { text }, 60 * 60);

  return NextResponse.json({ text });
}
