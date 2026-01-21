import { NextResponse } from "next/server";
import { kvGet } from "@/lib/cache/store";
import type { AnalysisStatus } from "@/types/analysis";

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;

  const status = await kvGet<AnalysisStatus>(`analysis:${id}`);
  if (!status) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json(status);
}
