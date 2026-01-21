"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import type { AnalysisStatus } from "@/types/analysis";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { MermaidView } from "@/components/app/mermaid-view";

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const [status, setStatus] = useState<AnalysisStatus | null>(null);

  useEffect(() => {
    let alive = true;

    async function tick() {
      const res = await fetch(`/api/analysis/status/${id}`, { cache: "no-store" });
      if (!res.ok) return;
      const data = (await res.json()) as AnalysisStatus;
      if (alive) setStatus(data);
    }

    tick();
    const t = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id]);

  if (!status) return <main className="p-6">Loading…</main>;

  return (
    <main className="min-h-screen p-6 flex items-start justify-center">
      <Card className="w-full max-w-4xl">
        <CardHeader className="space-y-2">
          <CardTitle>Analysis</CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant="secondary">{status.stage}</Badge>
            <span className="text-sm text-muted-foreground">{status.message}</span>
          </div>
          <Progress value={status.progress} />
        </CardHeader>

        <CardContent className="space-y-6">
          {status.error && (
            <pre className="whitespace-pre-wrap text-sm p-4 rounded-md border border-red-500/40">
              {status.error}
            </pre>
          )}

          {status.result && (
            <>
              <div className="space-y-2">
                <h2 className="text-lg font-semibold">Architecture Diagram</h2>
                <MermaidView chart={status.result.mermaid} />
              </div>

              <div className="space-y-2">
                <h2 className="text-lg font-semibold">Summary</h2>
                <ul className="list-disc pl-5 text-sm space-y-1">
                  {status.result.summary.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>

              <div className="space-y-2">
                <h2 className="text-lg font-semibold">Risks</h2>
                <ul className="space-y-2">
                  {status.result.risks.map((r, i) => (
                    <li key={i} className="rounded-md border p-3 text-sm">
                      <div className="flex items-center gap-2">
                        <Badge>{r.severity}</Badge>
                        <span className="font-medium">{r.title}</span>
                      </div>
                      <p className="text-muted-foreground mt-1">{r.details}</p>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-2">
                  <h2 className="text-lg font-semibold">Quick wins</h2>
                  <ul className="list-disc pl-5 text-sm space-y-1">
                    {status.result.quickWins.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ul>
                </div>
                <div className="space-y-2">
                  <h2 className="text-lg font-semibold">Next steps</h2>
                  <ul className="list-disc pl-5 text-sm space-y-1">
                    {status.result.nextSteps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
