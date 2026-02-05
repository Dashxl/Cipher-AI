import { NextResponse } from "next/server";
import JSZip from "jszip";
import { kvGet } from "@/lib/cache/store";
import {
  loadZip,
  ZipNotReadyError,
  ZipCorruptError,
  ZipChunkMissingError,
} from "@/lib/repo/zip-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = {
  repoName: string;
  root: string | null;
  files: string[];
};

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

function errJson(status: number, code: string, error: string, extra?: Record<string, unknown>) {
  return NextResponse.json({ code, error, ...extra }, { status });
}

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;

  const url = new URL(req.url);
  const filePath = url.searchParams.get("path") ?? "";

  if (!isSafePath(filePath)) {
    return errJson(400, "INVALID_PATH", "Invalid path");
  }

  const meta = await kvGet<RepoMeta>(`repo:${id}`);
  if (!meta) return errJson(404, "REPO_NOT_FOUND", "Repo not found");

  let zipBuf: Buffer;
  try {
    zipBuf = await loadZip(id);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);

    if (e instanceof ZipNotReadyError || e instanceof ZipChunkMissingError) {
      console.error("[file] zip not ready", { id, filePath, msg });
      return errJson(410, (e as any).code ?? "ZIP_NOT_READY", "Analysis zip not ready or expired", {
        analysisId: id,
        hint: "Re-run analysis or wait for ingestion to finish.",
      });
    }

    if (e instanceof ZipCorruptError) {
      console.error("[file] zip corrupt", { id, filePath, msg });
      return errJson(500, "ZIP_CORRUPT", "Analysis zip is corrupt. Re-run analysis.", {
        analysisId: id,
      });
    }

    console.error("[file] zip load failed", { id, filePath, msg });
    return errJson(500, "ZIP_LOAD_FAILED", "Failed to load analysis zip", { analysisId: id });
  }

  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(zipBuf);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[file] JSZip.loadAsync failed", { id, filePath, msg });
    return errJson(500, "ZIP_PARSE_FAILED", "Failed to parse zip (corrupt). Re-run analysis.", {
      analysisId: id,
    });
  }

  const actualPath = meta.root ? `${meta.root}/${filePath}` : filePath;
  const f = zip.file(actualPath);
  if (!f) return errJson(404, "FILE_NOT_IN_ZIP", "File not found in zip", { path: filePath });

  let content = "";
  try {
    content = await f.async("string");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[file] read file failed", { id, filePath, actualPath, msg });
    return errJson(500, "FILE_READ_FAILED", "Failed to read file from zip", { path: filePath });
  }

  // Cap para no reventar el navegador
  const MAX = 200_000;
  const safe = content.length > MAX ? content.slice(0, MAX) + "\n\n/* truncated */" : content;

  return NextResponse.json({ path: filePath, content: safe });
}
