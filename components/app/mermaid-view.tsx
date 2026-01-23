"use client";

import { useEffect, useId, useState } from "react";
import mermaid from "mermaid";

export function MermaidView({ chart }: { chart: string }) {
  const [svg, setSvg] = useState<string>("");
  const rid = useId().replace(/:/g, "_"); // estable SSR/CSR

  useEffect(() => {
    let cancelled = false;

    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "dark",
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
      className="w-full overflow-auto rounded-md border bg-muted/20 p-3"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
