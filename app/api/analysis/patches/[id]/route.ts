// src/app/api/analysis/patches/[id]/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import { kvGet, kvSet } from "@/lib/cache/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const TTL = 60 * 60 * 6; // 6h

type PatchCache = {
  analysisId: string;
  patchedCount: number;
  patchedFiles: string[];
  updatedAt?: string | null;
  exportedAt?: string | null;
  source?: string | null;
};

const BodySchema = z.object({
  patchedCount: z.number().int().nonnegative().optional(),
  patchedFiles: z.array(z.string()).max(300).optional(),
  source: z.string().max(80).optional(),
  exportedAt: z.string().optional(),
});

function normalizePath(p: string) {
  return String(p || "").replaceAll("\\", "/").trim();
}

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

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const patches = await kvGet<PatchCache>(`patches:${id}`);

    return NextResponse.json(
      patches ?? { analysisId: id, patchedCount: 0, patchedFiles: [], updatedAt: null, source: null },
      { headers: { "Cache-Control": "no-store" } }
    );
  } catch (e: any) {
    return NextResponse.json({ error: e?.message ?? "Failed" }, { status: 500 });
  }
}

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;

    const body = BodySchema.parse(await req.json());

    const files = Array.isArray(body.patchedFiles) ? body.patchedFiles : [];
    const patchedFiles = files
      .map(normalizePath)
      .filter((p) => p && isSafePath(p))
      .slice(0, 200);

    const patchedCount =
      typeof body.patchedCount === "number" ? body.patchedCount : patchedFiles.length;

    const now = new Date().toISOString();

    const payload: PatchCache = {
      analysisId: id,
      patchedCount,
      patchedFiles,
      updatedAt: now,
      exportedAt: body.exportedAt ?? null,
      source: body.source ?? "ui",
    };

    await kvSet(`patches:${id}`, payload, TTL);

    return NextResponse.json(payload, { headers: { "Cache-Control": "no-store" } });
  } catch (e: any) {
    const msg = e?.message ?? "Failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
