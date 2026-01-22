"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import type { AnalysisStatus } from "@/types/analysis";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { MermaidView } from "@/components/app/mermaid-view";
import Editor from "@monaco-editor/react";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const [status, setStatus] = useState<AnalysisStatus | null>(null);

  const [repo, setRepo] = useState<RepoMeta | null>(null);
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string>("");
  const [code, setCode] = useState<string>("");
  const [explain, setExplain] = useState<string>("");
  const [tab, setTab] = useState<"overview" | "explore">("overview");
  const [busyExplain, setBusyExplain] = useState(false);

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

  // Load file list once analysis is done
  useEffect(() => {
    if (!status || status.stage !== "done") return;
    if (repo) return;

    (async () => {
      const res = await fetch(`/api/analysis/files/${id}`, { cache: "no-store" });
      if (!res.ok) return;
      const data = (await res.json()) as RepoMeta;
      setRepo(data);
    })();
  }, [status, repo, id]);

  const filtered = useMemo(() => {
    const files = repo?.files ?? [];
    const qq = q.trim().toLowerCase();
    if (!qq) return files.slice(0, 400);
    return files.filter((f) => f.toLowerCase().includes(qq)).slice(0, 400);
  }, [repo, q]);

  async function openFile(path: string) {
    setSelected(path);
    setExplain("");
    const res = await fetch(`/api/analysis/file/${id}?path=${encodeURIComponent(path)}`, {
      cache: "no-store",
    });
    const data = (await res.json()) as { content?: string; error?: string };
    setCode(data.content ?? data.error ?? "");
  }

  async function runExplain(mode: "tech" | "eli5") {
    if (!selected) return;
    setBusyExplain(true);
    try {
      const res = await fetch("/api/analysis/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysisId: id, path: selected, mode }),
      });
      const data = (await res.json()) as { text?: string; error?: string };
      setExplain(data.text ?? data.error ?? "");
    } finally {
      setBusyExplain(false);
    }
  }

  if (!status) return <main className="p-6">Loading…</main>;

  return (
    <main className="min-h-screen p-6 flex items-start justify-center">
      <Card className="w-full max-w-6xl">
        <CardHeader className="space-y-2">
          <CardTitle>Analysis</CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant="secondary">{status.stage}</Badge>
            <span className="text-sm text-muted-foreground">{status.message}</span>
          </div>
          <Progress value={status.progress} />

          <div className="flex gap-2 pt-2">
            <Button variant={tab === "overview" ? "default" : "secondary"} onClick={() => setTab("overview")}>
              Overview
            </Button>
            <Button variant={tab === "explore" ? "default" : "secondary"} onClick={() => setTab("explore")}>
              Explore
            </Button>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {status.error && (
            <pre className="whitespace-pre-wrap text-sm p-4 rounded-md border border-red-500/40">
              {status.error}
            </pre>
          )}

          {tab === "overview" && status.result && (
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
            </>
          )}

          {tab === "explore" && (
            <div className="grid gap-4 md:grid-cols-[320px_1fr]">
              <div className="space-y-3">
                <div className="text-sm text-muted-foreground">
                  Repo: <span className="font-medium text-foreground">{repo?.repoName ?? "…"}</span>
                </div>
                <Input
                  placeholder="Search files…"
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                />
                <div className="h-[520px] overflow-auto rounded-md border">
                  {filtered.map((f) => (
                    <button
                      key={f}
                      onClick={() => openFile(f)}
                      className={`w-full text-left text-sm px-3 py-2 border-b hover:bg-muted/30 ${
                        selected === f ? "bg-muted/40" : ""
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                  {!repo && <div className="p-3 text-sm text-muted-foreground">Loading file list…</div>}
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm text-muted-foreground truncate">
                    {selected ? selected : "Select a file to view"}
                  </div>
                  <div className="flex gap-2">
                    <Button variant="secondary" disabled={!selected || busyExplain} onClick={() => runExplain("tech")}>
                      Explain
                    </Button>
                    <Button variant="secondary" disabled={!selected || busyExplain} onClick={() => runExplain("eli5")}>
                      ELI5
                    </Button>
                  </div>
                </div>

                <div className="rounded-md border overflow-hidden">
                  <Editor
                    height="420px"
                    language={guessLanguage(selected)}
                    value={code}
                    options={{
                      readOnly: true,
                      minimap: { enabled: false },
                      scrollBeyondLastLine: false,
                      wordWrap: "on",
                    }}
                  />
                </div>

                {explain && (
                  <pre className="whitespace-pre-wrap text-sm p-4 rounded-md border bg-muted/20">
                    {explain}
                  </pre>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

function guessLanguage(path: string) {
  const p = path.toLowerCase();
  if (p.endsWith(".ts") || p.endsWith(".tsx")) return "typescript";
  if (p.endsWith(".js") || p.endsWith(".jsx")) return "javascript";
  if (p.endsWith(".py")) return "python";
  if (p.endsWith(".java")) return "java";
  if (p.endsWith(".go")) return "go";
  if (p.endsWith(".php")) return "php";
  if (p.endsWith(".md")) return "markdown";
  if (p.endsWith(".json")) return "json";
  if (p.endsWith(".yml") || p.endsWith(".yaml")) return "yaml";
  return "plaintext";
}
