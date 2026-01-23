import { NextResponse } from "next/server";
import { kvGet } from "@/lib/cache/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = {
  repoName: string;
  root: string | null;
  files: string[];
};

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;

  const meta = await kvGet<RepoMeta>(`repo:${id}`);
  if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

  return NextResponse.json(meta);
}
