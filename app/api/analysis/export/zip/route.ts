import { NextResponse } from "next/server";
import JSZip from "jszip";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };
type PatchedFile = { path: string; content: string };

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

function safeName(s: string) {
  return (s || "cipher-ai").replace(/[^\w\-\.]+/g, "_").slice(0, 60);
}

/**
 * Convierte cualquier Uint8Array (posiblemente con ArrayBufferLike/SharedArrayBuffer)
 * a un ArrayBuffer REAL, para evitar errores de TS con BodyInit.
 */
function toStrictArrayBuffer(bytes: Uint8Array) {
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return ab;
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as { analysisId?: string; patchedFiles?: PatchedFile[] };

    const analysisId = String(body?.analysisId ?? "").trim();
    if (!analysisId) return NextResponse.json({ error: "Missing analysisId" }, { status: 400 });

    const meta = await kvGet<RepoMeta>(`repo:${analysisId}`);
    if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

    // loadZip() normalmente lanza error si no existe, pero lo dejamos bajo try/catch
    const zipBuf = await loadZip(analysisId);

    const incoming = Array.isArray(body?.patchedFiles) ? body.patchedFiles : [];

    // ✅ sanitizar y limitar
    const safe = incoming
      .filter((f) => f && typeof f.path === "string" && typeof f.content === "string")
      .map((f) => ({ path: f.path.trim().replaceAll("\\", "/"), content: f.content }))
      .filter((f) => isSafePath(f.path))
      .slice(0, 200);

    if (safe.length === 0) {
      return NextResponse.json({ error: "No patched files provided" }, { status: 400 });
    }

    const zip = await JSZip.loadAsync(zipBuf as any);

    // Aplicar parches (incluyendo root del zip si existe)
    for (const f of safe) {
      const actualPath = meta.root ? `${meta.root}/${f.path}` : f.path;
      zip.file(actualPath, f.content);
    }

    // metadata dentro del zip (mejor dentro del root si existe)
    const patchMeta = {
      analysisId,
      patchedCount: safe.length,
      patchedFiles: safe.map((x) => x.path),
      exportedAt: new Date().toISOString(),
    };

    const metaPath = meta.root ? `${meta.root}/cipherai.patches.json` : "cipherai.patches.json";
    zip.file(metaPath, JSON.stringify(patchMeta, null, 2));

    // ✅ guardar meta en KV para que export/[id] lo muestre en el reporte
    await kvSet(`patches:${analysisId}`, patchMeta, 60 * 60 * 6);

    // Generar ZIP en bytes
    const bytes = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE" });

    // ✅ “hard fix” TS: forzar ArrayBuffer real + Blob
    const ab = toStrictArrayBuffer(bytes as unknown as Uint8Array);
    const blob = new Blob([ab], { type: "application/zip" });

    const filename = `cipherai-${safeName(meta.repoName)}-${analysisId}-patched.zip`;

    return new NextResponse(blob, {
      status: 200,
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Cache-Control": "no-store",
      },
    });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message ?? "Export failed" }, { status: 500 });
  }
}
