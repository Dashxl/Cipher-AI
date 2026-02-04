"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";

type MermaidViewProps = {
  /** Preferido */
  code?: string;
  /** Alias backward-compatible */
  chart?: string;
  className?: string;
  /** Show zoom/fit/export controls */
  controls?: boolean;
};

type VB = { x: number; y: number; w: number; h: number };

function cssVarHsl(varName: string, fallback: string) {
  if (typeof window === "undefined") return fallback;
  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue(varName)
    .trim();
  if (!raw) return fallback;
  // shadcn-style vars often store "222.2 84% 4.9%" (without the hsl())
  return raw.includes("%") ? `hsl(${raw})` : raw;
}

function clamp(n: number, a: number, b: number) {
  return Math.max(a, Math.min(b, n));
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function stripMermaidInit(src: string) {
  // Remove any %%{init: ... }%% directive blocks that might force htmlLabels=true
  // (We want to control htmlLabels for PNG export)
  return src.replace(/%%\{\s*init\s*:[\s\S]*?\}%%/g, "").trim();
}

function asNum(v: string | null | undefined, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function convertForeignObjectLabelsToSvgText(svgEl: SVGSVGElement, textFill: string) {
  const foreigns = Array.from(svgEl.querySelectorAll("foreignObject"));
  if (foreigns.length === 0) return;

  for (const fo of foreigns) {
    const text = (fo.textContent || "").replace(/\s+/g, " ").trim();
    if (!text) {
      fo.remove();
      continue;
    }

    const x = asNum(fo.getAttribute("x"));
    const y = asNum(fo.getAttribute("y"));
    const w = asNum(fo.getAttribute("width"), 120);
    const h = asNum(fo.getAttribute("height"), 40);

    // Create <text> centered in the foreignObject box
    const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
    t.setAttribute("x", String(x + w / 2));
    t.setAttribute("y", String(y + h / 2));
    t.setAttribute("text-anchor", "middle");
    t.setAttribute("dominant-baseline", "middle");
    t.setAttribute("fill", textFill);
    t.setAttribute("font-family", 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial');
    t.setAttribute("font-size", "16");

    // Basic wrapping into multiple tspans (very simple, but better than blank)
    const maxChars = Math.max(10, Math.floor(w / 10));
    const words = text.split(" ");
    const lines: string[] = [];
    let line = "";

    for (const word of words) {
      const next = line ? `${line} ${word}` : word;
      if (next.length > maxChars && line) {
        lines.push(line);
        line = word;
      } else {
        line = next;
      }
    }
    if (line) lines.push(line);

    const lineHeight = 18;
    const startY = (y + h / 2) - ((lines.length - 1) * lineHeight) / 2;

    t.setAttribute("y", String(startY));

    lines.forEach((ln, i) => {
      const sp = document.createElementNS("http://www.w3.org/2000/svg", "tspan");
      sp.setAttribute("x", String(x + w / 2));
      if (i === 0) {
        sp.setAttribute("dy", "0");
      } else {
        sp.setAttribute("dy", String(lineHeight));
      }
      sp.textContent = ln;
      t.appendChild(sp);
    });

    fo.parentNode?.insertBefore(t, fo);
    fo.remove();
  }
}

export default function MermaidView({ code, chart, className, controls = false }: MermaidViewProps) {
  const src = code ?? chart ?? "";

  const hostRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const baseVB = useRef<VB | null>(null);

  const [ready, setReady] = useState(false);
  const [exportMsg, setExportMsg] = useState<string | null>(null);

  // Stable-ish id for render() (avoid crypto dependency)
  const renderId = useMemo(() => {
    const h = Math.abs(
      Array.from(src).reduce((acc, c) => ((acc << 5) - acc + c.charCodeAt(0)) | 0, 0),
    );
    return `mmd-${h}`;
  }, [src]);

  useEffect(() => {
    let cancelled = false;

    async function run() {
      setReady(false);
      setExportMsg(null);

      const mermaid = (await import("mermaid")).default;

      const fg = cssVarHsl("--foreground", "#0b1220");
      const muted = cssVarHsl("--muted-foreground", "rgba(15,23,42,.7)");
      const card = cssVarHsl("--card", "rgba(255,255,255,.04)");
      const border = cssVarHsl("--border", "rgba(255,255,255,.12)");
      const accent = cssVarHsl("--primary", "hsl(262 83% 58%)");
      const accent2 = cssVarHsl("--secondary", "hsl(190 95% 39%)");

      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: "base",
        themeVariables: {
          fontFamily:
            'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji","Segoe UI Emoji"',
          background: "transparent",

          textColor: fg,
          primaryTextColor: fg,
          secondaryTextColor: fg,

          primaryColor: card,
          secondaryColor: card,
          tertiaryColor: card,

          primaryBorderColor: border,
          secondaryBorderColor: border,

          lineColor: muted,
          edgeLabelBackground: "transparent",

          titleColor: fg,

          accent1: accent,
          accent2: accent2,
          accent3: border,
        },
        flowchart: {
          curve: "basis",
          padding: 10,
          htmlLabels: true, // pretty labels in-app
        },
      });

      if (!hostRef.current) return;

      try {
        const { svg, bindFunctions } = await mermaid.render(renderId, src);
        if (cancelled) return;

        hostRef.current.innerHTML = svg;

        const s = hostRef.current.querySelector("svg") as SVGSVGElement | null;
        if (!s) return;

        if (!s.getAttribute("xmlns")) s.setAttribute("xmlns", "http://www.w3.org/2000/svg");
        if (!s.getAttribute("xmlns:xlink")) s.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");

        s.style.display = "block";
        s.style.maxWidth = "100%";
        s.style.height = "auto";
        s.style.shapeRendering = "geometricPrecision";

        if (!s.getAttribute("viewBox")) {
          try {
            const bb = s.getBBox();
            const pad = 16;
            s.setAttribute(
              "viewBox",
              `${bb.x - pad} ${bb.y - pad} ${bb.width + pad * 2} ${bb.height + pad * 2}`,
            );
          } catch {
            // ignore
          }
        }

        const vb = s.viewBox?.baseVal;
        if (vb) baseVB.current = { x: vb.x, y: vb.y, w: vb.width, h: vb.height };
        svgRef.current = s;

        bindFunctions?.(s);
        setReady(true);
      } catch {
        if (hostRef.current) {
          hostRef.current.innerHTML =
            `<div style="opacity:.75;font-size:12px;padding:8px">No se pudo renderizar Mermaid.</div>`;
        }
        setReady(true);
      }
    }

    run();
    return () => {
      cancelled = true;
    };
  }, [src, renderId]);

  function setViewBox(next: VB) {
    const s = svgRef.current;
    if (!s) return;
    s.setAttribute("viewBox", `${next.x} ${next.y} ${next.w} ${next.h}`);
  }

  function zoom(factor: number) {
    const s = svgRef.current;
    if (!s) return;
    const vb = s.viewBox?.baseVal;
    if (!vb) return;

    const cx = vb.x + vb.width / 2;
    const cy = vb.y + vb.height / 2;

    const nw = clamp(vb.width / factor, 50, 20000);
    const nh = clamp(vb.height / factor, 50, 20000);

    setViewBox({ x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh });
  }

  function fit() {
    const base = baseVB.current;
    if (!base) return;
    setViewBox(base);
  }

  function exportSVG() {
    const s = svgRef.current;
    if (!s) return;
    const xml = new XMLSerializer().serializeToString(s);
    const blob = new Blob([`<?xml version="1.0" encoding="UTF-8"?>\n${xml}`], {
      type: "image/svg+xml;charset=utf-8",
    });
    downloadBlob(blob, "diagram.svg");
  }

  /**
   * PNG export (with text):
   * - strip any diagram init directives (they can force htmlLabels=true)
   * - render with htmlLabels=false for a pure-SVG label output
   * - if foreignObject still exists, convert them into <text>/<tspan> so text stays visible.
   * - paint a real background so the PNG doesn't look "black" in viewers.
   */
  async function exportPNG() {
    try {
      setExportMsg("Exporting PNG…");

      const s = svgRef.current;
      if (!s) throw new Error("No SVG");
      const vb = s.viewBox?.baseVal;
      if (!vb) throw new Error("No viewBox");

      const mermaid = (await import("mermaid")).default as any;
      const api = mermaid?.mermaidAPI;
      const prevConfig = api?.getConfig?.();

      const exportSrc = stripMermaidInit(src);

      // Use same theme colors for export
      const fg = cssVarHsl("--foreground", "#0b1220");
      const bg = cssVarHsl("--background", "#ffffff");
      const muted = cssVarHsl("--muted-foreground", "rgba(15,23,42,.7)");
      const card = cssVarHsl("--card", "rgba(255,255,255,.04)");
      const border = cssVarHsl("--border", "rgba(255,255,255,.12)");
      const accent = cssVarHsl("--primary", "hsl(262 83% 58%)");
      const accent2 = cssVarHsl("--secondary", "hsl(190 95% 39%)");

      mermaid.initialize({
        ...(prevConfig ?? {}),
        startOnLoad: false,
        securityLevel: "strict",
        theme: "base",
        themeVariables: {
          fontFamily:
            'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji","Segoe UI Emoji"',
          background: "transparent",

          textColor: fg,
          primaryTextColor: fg,
          secondaryTextColor: fg,

          primaryColor: card,
          secondaryColor: card,
          tertiaryColor: card,

          primaryBorderColor: border,
          secondaryBorderColor: border,

          lineColor: muted,
          edgeLabelBackground: "transparent",
          titleColor: fg,
          accent1: accent,
          accent2: accent2,
          accent3: border,
        },
        flowchart: {
          ...(prevConfig?.flowchart ?? {}),
          htmlLabels: false,
        },
      });

      const { svg: cleanSvg } = await mermaid.render(`${renderId}-png`, exportSrc);

      // Restore previous config
      if (prevConfig) mermaid.initialize(prevConfig);

      // Parse SVG for manipulation
      const parser = new DOMParser();
      const doc = parser.parseFromString(cleanSvg, "image/svg+xml");
      const svgEl = doc.querySelector("svg") as SVGSVGElement | null;
      if (!svgEl) throw new Error("SVG parse failed");

      svgEl.setAttribute("xmlns", "http://www.w3.org/2000/svg");
      svgEl.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.width} ${vb.height}`);
      svgEl.setAttribute("width", String(vb.width));
      svgEl.setAttribute("height", String(vb.height));

      // If Mermaid still used foreignObject (due to directives), convert them to SVG text
      if (svgEl.querySelector("foreignObject")) {
        convertForeignObjectLabelsToSvgText(svgEl, fg);
      }

      const xml = new XMLSerializer().serializeToString(svgEl);
      const svgBlob = new Blob([xml], { type: "image/svg+xml;charset=utf-8" });
      const url = URL.createObjectURL(svgBlob);

      const img = new Image();
      img.decoding = "async";
      img.crossOrigin = "anonymous";
      img.src = url;

      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve();
        img.onerror = () => reject(new Error("Image load failed"));
      });

      // Canvas sizing (cap huge exports)
      const dpr = window.devicePixelRatio || 2;
      let scale = Math.max(2, Math.ceil(dpr));
      let w = Math.floor(vb.width * scale);
      let h = Math.floor(vb.height * scale);

      const MAX = 8192;
      if (w > MAX || h > MAX) {
        const k = Math.min(MAX / w, MAX / h);
        w = Math.floor(w * k);
        h = Math.floor(h * k);
        scale = scale * k;
      }

      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;

      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("No canvas context");

      // Fill background so PNG doesn't look black in viewers
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      ctx.drawImage(img, 0, 0);

      const blob: Blob | null = await new Promise((resolve) =>
        canvas.toBlob((b) => resolve(b), "image/png"),
      );

      URL.revokeObjectURL(url);

      if (!blob) throw new Error("PNG blob failed");
      downloadBlob(blob, "diagram.png");

      setExportMsg("PNG downloaded ✓");
      setTimeout(() => setExportMsg(null), 1500);
    } catch (err: any) {
      console.error("[Mermaid PNG export] failed:", err);
      setExportMsg(err?.message ? `PNG export failed: ${err.message}` : "PNG export failed. Use SVG export.");
      setTimeout(() => setExportMsg(null), 3500);
    }
  }

  return (
    <div className={className}>
      {controls && (
        <div className="mb-2 flex items-center gap-2">
          <button
            type="button"
            className="rounded-lg border px-2 py-1 text-xs hover:bg-white/5 disabled:opacity-50"
            onClick={() => zoom(1.15)}
            disabled={!ready}
          >
            Zoom +
          </button>
          <button
            type="button"
            className="rounded-lg border px-2 py-1 text-xs hover:bg-white/5 disabled:opacity-50"
            onClick={() => zoom(1 / 1.15)}
            disabled={!ready}
          >
            Zoom –
          </button>
          <button
            type="button"
            className="rounded-lg border px-2 py-1 text-xs hover:bg-white/5 disabled:opacity-50"
            onClick={fit}
            disabled={!ready}
          >
            Fit
          </button>

          <div className="ml-auto flex items-center gap-2">
            {exportMsg && <span className="text-xs opacity-70">{exportMsg}</span>}
            <button
              type="button"
              className="rounded-lg border px-2 py-1 text-xs hover:bg-white/5 disabled:opacity-50"
              onClick={exportSVG}
              disabled={!ready}
            >
              Export SVG
            </button>
            <button
              type="button"
              className="rounded-lg border px-2 py-1 text-xs hover:bg-white/5 disabled:opacity-50"
              onClick={exportPNG}
              disabled={!ready}
            >
              Export PNG
            </button>
          </div>
        </div>
      )}

      <div ref={hostRef} className="rounded-2xl border bg-white/[0.02] p-3" aria-busy={!ready} />
    </div>
  );
}

// Backward-compatible named export if you had: import { MermaidView } ...
export { MermaidView };
