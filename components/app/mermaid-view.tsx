"use client";

import { useEffect, useId, useState } from "react";
import mermaid from "mermaid";

export function MermaidView({ chart }: { chart: string }) {
  const [svg, setSvg] = useState<string>("");
  const rid = useId().replace(/:/g, "_");

  useEffect(() => {
    let cancelled = false;

    const isDark = document.documentElement.classList.contains("dark");

    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: isDark ? "dark" : "base",
      themeVariables: {
        primaryColor: "#7C3AED",
        primaryTextColor: isDark ? "#F4F1FF" : "#181523",
        lineColor: isDark ? "#6b5aa6" : "#b9a9e6",
        fontFamily: "var(--font-geist-sans)",
      },
    });

    (async () => {
      try {
        const { svg } = await mermaid.render(`m_${rid}`, chart);
        if (!cancelled) setSvg(svg);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!cancelled) setSvg(`<pre>Mermaid render error: ${msg}</pre>`);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [chart, rid]);

  return (
    <div
      className="w-full overflow-auto rounded-xl border bg-card/60 backdrop-blur p-3"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
