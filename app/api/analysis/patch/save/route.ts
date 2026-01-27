import { NextResponse } from "next/server";
import { z } from "zod";
import { kvSet } from "@/lib/cache/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const PatchedFileSchema = z.object({
  path: z.string().min(1).max(500),
  content: z.string().optional(), // opcional para permitir payload “ligero”
});

const BodySchema = z.object({
  analysisId: z.string().min(1),
  patchedFiles: z.array(PatchedFileSchema).max(200),
  truncated: z.boolean().optional(),
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
    const analysisId = String(body.analysisId || "").trim();
    if (!analysisId) return NextResponse.json({ error: "Missing analysisId" }, { status: 400 });

    const safe = (body.patchedFiles ?? [])
      .map((f) => ({
        path: String(f.path ?? "").trim().replaceAll("\\", "/"),
        content: typeof f.content === "string" ? f.content : "",
      }))
      .filter((f) => isSafePath(f.path))
      .slice(0, 200);

    const meta = {
      analysisId,
      patchedCount: safe.length,
      patchedFiles: safe.map((x) => x.path),
      truncated: !!body.truncated,
      updatedAt: new Date().toISOString(),
    };

    // Lo que más nos importa para el reporte:
    await kvSet(`patches:${analysisId}`, meta, 60 * 60 * 6);

    // Opcional: podrías guardar contents si algún día quieres “re-export” desde servidor.
    // Por ahora lo omitimos para no reventar KV con textos grandes.

    return NextResponse.json({ ok: true, ...meta });
  } catch (e: any) {
    const msg = e?.message ?? "Save patches failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
