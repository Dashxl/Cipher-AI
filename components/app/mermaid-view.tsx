"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import mermaid from "mermaid";

export function MermaidView({ chart }: { chart: string }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [svg, setSvg] = useState<string>("");

  const id = useMemo(() => `m_${Math.random().toString(36).slice(2)}`, []);

  useEffect(() => {
    let cancelled = false;

    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "dark",
    });

    async function render() {
      try {
        const { svg } = await mermaid.render(id, chart);
        if (!cancelled) setSvg(svg);
      } catch (e) {
        if (!cancelled) setSvg(`<pre>Mermaid render error: ${(e as Error).message}</pre>`);
      }
    }

    render();
    return () => {
      cancelled = true;
    };
  }, [chart, id]);

  return (
    <div
      ref={ref}
      className="w-full overflow-auto rounded-md border bg-muted/20 p-3"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
