import { NextResponse } from "next/server";
import JSZip from "jszip";
import { kvGet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

function isSafePath(p: string) {
  return (
    p.length > 0 &&
    p.length < 300 &&
    !p.includes("..") &&
    !p.startsWith("/") &&
    !p.includes("\0")
  );
}

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;

  const url = new URL(req.url);
  const filePath = url.searchParams.get("path") ?? "";

  if (!isSafePath(filePath)) {
    return NextResponse.json({ error: "Invalid path" }, { status: 400 });
  }

  const meta = await kvGet<RepoMeta>(`repo:${id}`);
  if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

  const zipBuf = await loadZip(id);
  const zip = await JSZip.loadAsync(zipBuf);

  const actualPath = meta.root ? `${meta.root}/${filePath}` : filePath;
  const f = zip.file(actualPath);
  if (!f) return NextResponse.json({ error: "File not found in zip" }, { status: 404 });

  const content = await f.async("string");

  // Cap para no matar el navegador
  const MAX = 200_000;
  const safe = content.length > MAX ? content.slice(0, MAX) + "\n\n/* truncated */" : content;

  return NextResponse.json({ path: filePath, content: safe });
}
