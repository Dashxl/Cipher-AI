import { NextResponse } from "next/server";
import { z } from "zod";
import { kvSet } from "@/lib/cache/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const BodySchema = z.object({
  analysisId: z.string().min(1),
  patchedFiles: z.array(z.string().min(1)).max(200),
});

function isSafePath(p: string) {
  return (
    typeof p === "string" &&
    p.length > 0 &&
    p.length < 500 &&
    !p.includes("..") &&
    !p.startsWith("/") &&
    !p.includes("\\") &&
    !p.includes("\0")
  );
}

export async function POST(req: Request) {
  try {
    const body = BodySchema.parse(await req.json());
    const analysisId = body.analysisId.trim();

    const patchedFiles = body.patchedFiles
      .map((p) => String(p || "").trim().replaceAll("\\", "/"))
      .filter((p) => isSafePath(p))
      .slice(0, 200);

    await kvSet(
      `patches:${analysisId}`,
      {
        analysisId,
        patchedCount: patchedFiles.length,
        patchedFiles,
        updatedAt: new Date().toISOString(),
        source: "ui_apply_preview",
      },
      60 * 60 * 6 // 6h
    );

    return NextResponse.json({ ok: true, patchedCount: patchedFiles.length, patchedFiles });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message ?? "Failed" }, { status: 400 });
  }
}
