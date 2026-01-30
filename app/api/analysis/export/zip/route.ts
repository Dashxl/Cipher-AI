import { NextResponse } from "next/server";
import JSZip from "jszip";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };
type PatchedFile = { path: string; content: string };

const TTL = 60 * 60 * 6; // 6h

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

// ✅ fuerza un ArrayBuffer REAL (no ArrayBufferLike) para que TS no llore
function toStrictArrayBuffer(bytes: Uint8Array): ArrayBuffer {
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

    const zipBuf = await loadZip(analysisId);
    if (!zipBuf) return NextResponse.json({ error: "Missing ZIP for analysisId" }, { status: 404 });

    const incoming = Array.isArray(body?.patchedFiles) ? body.patchedFiles : [];

    const safe = incoming
      .filter((f) => f && typeof f.path === "string" && typeof f.content === "string")
      .map((f) => ({ path: f.path.trim().replaceAll("\\", "/"), content: f.content }))
      .filter((f) => isSafePath(f.path))
      .slice(0, 200);

    if (safe.length === 0) {
      return NextResponse.json({ error: "No patched files provided" }, { status: 400 });
    }

    const zip = await JSZip.loadAsync(zipBuf as any);

    // ✅ escribir archivos parcheados (respetar root)
    for (const f of safe) {
      const actualPath = meta.root ? `${meta.root}/${f.path}` : f.path;
      zip.file(actualPath, f.content);
    }

    // metadata dentro del zip
    const metaPath = meta.root ? `${meta.root}/cipherai.patches.json` : "cipherai.patches.json";
    const now = new Date().toISOString();

    zip.file(
      metaPath,
      JSON.stringify(
        {
          analysisId,
          patchedCount: safe.length,
          patchedFiles: safe.map((x) => x.path),
          exportedAt: now,
        },
        null,
        2
      )
    );

    // ✅ guardar en KV patches:${id} para que el reporte lo lea SIEMPRE
    await kvSet(
      `patches:${analysisId}`,
      {
        analysisId,
        patchedCount: safe.length,
        patchedFiles: safe.map((x) => x.path),
        updatedAt: now,
        exportedAt: now,
        source: "zip_export",
      },
      TTL
    );

    const bytes = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE" });
    const ab = toStrictArrayBuffer(bytes);

    const filename = `cipherai-${safeName(meta.repoName)}-${analysisId}-patched.zip`;

    // ✅ usa Response directo (evita typings raros de NextResponse con Buffer/Uint8Array)
    return new Response(ab, {
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
