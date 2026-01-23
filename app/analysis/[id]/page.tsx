"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import type { AnalysisStatus } from "@/types/analysis";
import type { DebtIssue, VulnFinding, Severity } from "@/types/scan";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { MermaidView } from "@/components/app/mermaid-view";
import Editor from "@monaco-editor/react";

type RepoMeta = { repoName: string; root: string | null; files: string[] };
type Tab = "overview" | "explore" | "vuln" | "debt";

async function safeJson(res: Response): Promise<any> {
  const raw = await res.text();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { error: raw || `Request failed (${res.status})` };
  }
}

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();

  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [tab, setTab] = useState<Tab>("overview");

  // Explore state
  const [repo, setRepo] = useState<RepoMeta | null>(null);
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string>("");
  const [code, setCode] = useState<string>("");
  const [explain, setExplain] = useState<string>("");
  const [busyExplain, setBusyExplain] = useState(false);

  // Vulnerability scan state
  const [vulnBusy, setVulnBusy] = useState(false);
  const [vulnNote, setVulnNote] = useState<string>("");
  const [vulns, setVulns] = useState<VulnFinding[]>([]);

  // Tech debt scan state
  const [debtBusy, setDebtBusy] = useState(false);
  const [debtNote, setDebtNote] = useState<string>("");
  const [debt, setDebt] = useState<DebtIssue[]>([]);

  // Patch state
  const [patchBusyId, setPatchBusyId] = useState<string>("");

  // Poll analysis status
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

  // Load repo meta for Explore as soon as possible
  useEffect(() => {
    if (!status) return;
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
    setCode("Loading…");

    const res = await fetch(`/api/analysis/file/${id}?path=${encodeURIComponent(path)}`, {
      cache: "no-store",
    });

    const data = await safeJson(res);
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

      const data = await safeJson(res);
      setExplain(data.text ?? data.error ?? `Request failed (${res.status})`);
    } finally {
      setBusyExplain(false);
    }
  }

  async function runVulnScan() {
    setVulnBusy(true);
    setVulnNote("");
    try {
      const res = await fetch("/api/analysis/scan/vuln", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysisId: id }),
      });

      const data = await safeJson(res);
      setVulns(Array.isArray(data.findings) ? data.findings : []);
      setVulnNote(data.note ?? data.error ?? "");
    } finally {
      setVulnBusy(false);
    }
  }

  async function runDebtScan() {
    setDebtBusy(true);
    setDebtNote("");
    try {
      const res = await fetch("/api/analysis/scan/debt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysisId: id }),
      });

      const data = await safeJson(res);
      setDebt(Array.isArray(data.issues) ? data.issues : []);
      setDebtNote(data.note ?? data.error ?? "");
    } finally {
      setDebtBusy(false);
    }
  }

  function exportMd() {
    // Use location.href to avoid popup blockers
    window.location.href = `/api/analysis/export/${id}?format=md`;
  }

  function exportPdf() {
    window.location.href = `/api/analysis/export/${id}?format=pdf`;
  }

  async function generatePatch(
    file: string,
    issueTitle: string,
    issueDetails: string,
    idForBusy: string
  ) {
    setPatchBusyId(idForBusy);
    try {
      const res = await fetch("/api/analysis/patch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysisId: id, file, issueTitle, issueDetails }),
      });

      const data = await safeJson(res);

      if (!res.ok) {
        alert(data.error ?? `Patch failed (${res.status})`);
        return;
      }

      const diff = String(data.diff ?? "");
      if (!diff.trim()) {
        alert("Patch endpoint returned empty diff.");
        return;
      }

      const blob = new Blob([diff], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = `cipher-ai-${file.replace(/[\/\\]/g, "_")}.diff`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      if (data.note) {
        // Optional: show note about truncation
        console.warn(data.note);
      }
    } finally {
      setPatchBusyId("");
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

          <div className="flex flex-wrap items-center gap-2 pt-2">
            <Button
              variant={tab === "overview" ? "default" : "secondary"}
              onClick={() => setTab("overview")}
            >
              Overview
            </Button>
            <Button
              variant={tab === "explore" ? "default" : "secondary"}
              onClick={() => setTab("explore")}
            >
              Explore
            </Button>
            <Button
              variant={tab === "vuln" ? "default" : "secondary"}
              onClick={() => setTab("vuln")}
            >
              Vulnerabilities
            </Button>
            <Button
              variant={tab === "debt" ? "default" : "secondary"}
              onClick={() => setTab("debt")}
            >
              Tech Debt
            </Button>

            <div className="flex-1" />

            <Button variant="secondary" onClick={exportMd}>
              Export Markdown
            </Button>
            <Button variant="secondary" onClick={exportPdf}>
              Export PDF
            </Button>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {status.error && (
            <pre className="whitespace-pre-wrap text-sm p-4 rounded-md border border-red-500/40">
              {status.error}
            </pre>
          )}

          {tab === "overview" && (
            <>
              {status.result ? (
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
              ) : (
                <p className="text-sm text-muted-foreground">
                  Overview will appear once the global analysis completes.
                </p>
              )}
            </>
          )}

          {tab === "explore" && (
            <div className="grid gap-4 md:grid-cols-[320px_1fr]">
              <div className="space-y-3">
                <div className="text-sm text-muted-foreground">
                  Repo:{" "}
                  <span className="font-medium text-foreground">
                    {repo?.repoName ?? "Loading…"}
                  </span>
                </div>

                <Input
                  placeholder="Search files…"
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                />

                <div className="h-[520px] overflow-auto rounded-md border">
                  {!repo && (
                    <div className="p-3 text-sm text-muted-foreground">
                      Loading file list…
                    </div>
                  )}

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

                  {repo && filtered.length === 0 && (
                    <div className="p-3 text-sm text-muted-foreground">
                      No files match that search.
                    </div>
                  )}
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm text-muted-foreground truncate">
                    {selected ? selected : "Select a file to view"}
                  </div>

                  <div className="flex gap-2">
                    <Button
                      variant="secondary"
                      disabled={!selected || busyExplain}
                      onClick={() => runExplain("tech")}
                    >
                      Explain
                    </Button>
                    <Button
                      variant="secondary"
                      disabled={!selected || busyExplain}
                      onClick={() => runExplain("eli5")}
                    >
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

          {tab === "vuln" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-lg font-semibold">Vulnerabilities</h2>
                <Button onClick={runVulnScan} disabled={vulnBusy}>
                  {vulnBusy ? "Scanning…" : "Run scan"}
                </Button>
              </div>

              {vulnNote && (
                <div className="text-sm text-muted-foreground border rounded-md p-3">
                  {vulnNote}
                </div>
              )}

              {vulns.length === 0 ? (
                <div className="text-sm text-muted-foreground">
                  No results yet. Click “Run scan”.
                </div>
              ) : (
                <div className="space-y-3">
                  {vulns.map((v) => (
                    <div key={v.id} className="rounded-md border p-3 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-medium">{v.title}</div>

                        <div className="flex items-center gap-2">
                          <SeverityBadge s={v.severity} />
                          <Button
                            variant="secondary"
                            disabled={patchBusyId === v.id}
                            onClick={() =>
                              generatePatch(
                                v.file,
                                v.title,
                                `Severity: ${v.severity}\nType: ${v.type}\nRecommendation: ${v.recommendation}\nLocation: ${v.file}:${v.line}\n\nSnippet:\n${v.snippet}`,
                                v.id
                              )
                            }
                          >
                            {patchBusyId === v.id ? "Generating…" : "Generate patch"}
                          </Button>
                        </div>
                      </div>

                      <div className="text-sm text-muted-foreground">
                        {v.file}:{v.line} • {v.type}
                      </div>

                      <pre className="text-sm whitespace-pre-wrap bg-muted/20 rounded-md p-3">
                        {v.snippet}
                      </pre>

                      <div className="text-sm">
                        <span className="font-medium">Recommendation: </span>
                        {v.recommendation}
                      </div>

                      {v.fix && (
                        <div className="text-sm">
                          <span className="font-medium">Suggested fix: </span>
                          {v.fix}
                          {typeof v.confidence === "number" && (
                            <span className="text-muted-foreground">
                              {" "}
                              (confidence {v.confidence.toFixed(2)})
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === "debt" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-lg font-semibold">Tech Debt</h2>
                <Button onClick={runDebtScan} disabled={debtBusy}>
                  {debtBusy ? "Scanning…" : "Run scan"}
                </Button>
              </div>

              {debtNote && (
                <div className="text-sm text-muted-foreground border rounded-md p-3">
                  {debtNote}
                </div>
              )}

              {debt.length === 0 ? (
                <div className="text-sm text-muted-foreground">
                  No results yet. Click “Run scan”.
                </div>
              ) : (
                <div className="space-y-3">
                  {debt.map((d) => (
                    <div key={d.id} className="rounded-md border p-3 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-medium">{d.title}</div>

                        <div className="flex items-center gap-2">
                          <SeverityBadge s={d.severity} />
                          <Button
                            variant="secondary"
                            disabled={patchBusyId === d.id}
                            onClick={() =>
                              generatePatch(
                                d.file,
                                d.title,
                                `Severity: ${d.severity}\nType: ${d.type}\nLocation: ${d.file}:${d.line}\n\nDetails: ${d.details}\nSuggestion: ${d.suggestion}`,
                                d.id
                              )
                            }
                          >
                            {patchBusyId === d.id ? "Generating…" : "Generate patch"}
                          </Button>
                        </div>
                      </div>

                      <div className="text-sm text-muted-foreground">
                        {d.file}:{d.line} • {d.type}
                      </div>

                      <div className="text-sm">
                        <span className="font-medium">Details: </span>
                        {d.details}
                      </div>

                      <div className="text-sm">
                        <span className="font-medium">Suggestion: </span>
                        {d.suggestion}
                      </div>

                      {d.fix && (
                        <div className="text-sm">
                          <span className="font-medium">Suggested refactor: </span>
                          {d.fix}
                          {typeof d.confidence === "number" && (
                            <span className="text-muted-foreground">
                              {" "}
                              (confidence {d.confidence.toFixed(2)})
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

function SeverityBadge({ s }: { s: Severity }) {
  const variant =
    s === "CRITICAL"
      ? "destructive"
      : s === "HIGH"
      ? "default"
      : s === "MEDIUM"
      ? "secondary"
      : "outline";
  return <Badge variant={variant as any}>{s}</Badge>;
}

function guessLanguage(path: string) {
  const p = (path || "").toLowerCase();
  if (p.endsWith(".ts") || p.endsWith(".tsx")) return "typescript";
  if (p.endsWith(".js") || p.endsWith(".jsx")) return "javascript";
  if (p.endsWith(".py")) return "python";
  if (p.endsWith(".java")) return "java";
  if (p.endsWith(".go")) return "go";
  if (p.endsWith(".php")) return "php";
  if (p.endsWith(".md")) return "markdown";
  if (p.endsWith(".json")) return "json";
  if (p.endsWith(".yml") || p.endsWith(".yaml")) return "yaml";
  if (p.endsWith(".css")) return "css";
  if (p.endsWith(".html")) return "html";
  return "plaintext";
}
