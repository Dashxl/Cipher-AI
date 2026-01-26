"use client";

import { useEffect, useMemo, useRef, useState } from "react";
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

// Local type to avoid depending on scan.ts having DepCveFinding exported
type DepCveFinding = {
  id: string;
  ecosystem: "npm" | "PyPI" | string;
  name: string;
  version: string;
  vulnId: string;
  severity: Severity;
  summary: string;
  details?: string;
  fixedVersion?: string;
  references?: string[];
};

type DepsScanPayload = {
  findings: DepCveFinding[];
  note?: string;
  scannedDeps?: number;
  totalParsedDeps?: number;
  manifestsUsed?: string[];
  uniqueVulnIds?: number;
  totalVulnHits?: number;
  truncated?: boolean;
};

type PatchPreview = {
  open: boolean;
  file: string;
  line?: number;
  diff: string;
  note?: string;
};

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

  // Vulnerability scan state (heuristic)
  const [vulnBusy, setVulnBusy] = useState(false);
  const [vulnNote, setVulnNote] = useState<string>("");
  const [vulns, setVulns] = useState<VulnFinding[]>([]);
  const [vulnRan, setVulnRan] = useState(false);

  // Dependency CVEs (OSV)
  const [depsBusy, setDepsBusy] = useState(false);
  const [depsNote, setDepsNote] = useState<string>("");
  const [deps, setDeps] = useState<DepCveFinding[]>([]);
  const [depsRan, setDepsRan] = useState(false);
  const [depsMeta, setDepsMeta] = useState<
    Pick<
      DepsScanPayload,
      | "scannedDeps"
      | "totalParsedDeps"
      | "uniqueVulnIds"
      | "totalVulnHits"
      | "truncated"
      | "manifestsUsed"
    > | null
  >(null);

  // Tech debt scan state
  const [debtBusy, setDebtBusy] = useState(false);
  const [debtNote, setDebtNote] = useState<string>("");
  const [debt, setDebt] = useState<DebtIssue[]>([]);
  const [debtRan, setDebtRan] = useState(false);

  // Patch state
  const [patchBusyId, setPatchBusyId] = useState<string>("");
  const [patchPreview, setPatchPreview] = useState<PatchPreview | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");

  // Monaco refs for jump-to-line
  const editorRef = useRef<any>(null);
  const decoIdsRef = useRef<string[]>([]);
  const [pendingReveal, setPendingReveal] = useState<{ path: string; line: number } | null>(null);

  // Inject CSS for Monaco decorations (line highlight)
  useEffect(() => {
    const styleId = "cipher-monaco-highlight-style";
    if (document.getElementById(styleId)) return;
    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      .cipher-line-highlight { background: rgba(255, 215, 0, 0.16); }
      .cipher-line-gutter { border-left: 3px solid rgba(255, 215, 0, 0.85); margin-left: 2px; }
    `;
    document.head.appendChild(style);
  }, []);

  // Patch modal: ESC close + scroll lock
  useEffect(() => {
    const open = Boolean(patchPreview?.open);
    if (!open) return;

    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPatchPreview(null);
    };
    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [patchPreview?.open]);

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

  async function openFile(path: string, opts?: { revealLine?: number }) {
    setSelected(path);
    setExplain("");
    setCode("Loading…");

    if (opts?.revealLine && Number.isFinite(opts.revealLine)) {
      setPendingReveal({ path, line: Math.max(1, Math.floor(opts.revealLine)) });
    } else {
      setPendingReveal(null);
    }

    const res = await fetch(`/api/analysis/file/${id}?path=${encodeURIComponent(path)}`, {
      cache: "no-store",
    });

    const data = await safeJson(res);
    setCode(data.content ?? data.error ?? "");
  }

  async function jumpToFileLine(path: string, line: number) {
    setTab("explore");
    await openFile(path, { revealLine: line });
  }

  // Perform reveal + decoration once Monaco has code loaded
  useEffect(() => {
    const p = pendingReveal;
    const editor = editorRef.current;
    if (!p || !editor) return;
    if (selected !== p.path) return;
    if (!code || code === "Loading…") return;

    try {
      const model = editor.getModel?.();
      if (!model) return;

      const maxLine = model.getLineCount?.() ?? 1;
      const targetLine = Math.min(Math.max(1, p.line), maxLine);

      // Clear old decorations
      decoIdsRef.current = editor.deltaDecorations(decoIdsRef.current, []);

      const monaco = (window as any).monaco;
      if (!monaco?.Range) {
        setPendingReveal(null);
        return;
      }

      // Add highlight decoration to the target line
      const newDecos = [
        {
          range: new monaco.Range(targetLine, 1, targetLine, 1),
          options: {
            isWholeLine: true,
            className: "cipher-line-highlight",
            linesDecorationsClassName: "cipher-line-gutter",
          },
        },
      ];

      decoIdsRef.current = editor.deltaDecorations([], newDecos);

      editor.revealLineInCenter?.(targetLine);
      editor.setPosition?.({ lineNumber: targetLine, column: 1 });
      editor.focus?.();

      const t = setTimeout(() => {
        try {
          decoIdsRef.current = editor.deltaDecorations(decoIdsRef.current, []);
        } catch {}
      }, 2200);

      setPendingReveal(null);
      return () => clearTimeout(t);
    } catch {
      setPendingReveal(null);
    }
  }, [pendingReveal, selected, code]);

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
      setVulnRan(true);
    } finally {
      setVulnBusy(false);
    }
  }

  async function runDepsScan() {
    setDepsBusy(true);
    setDepsNote("");
    try {
      const res = await fetch("/api/analysis/scan/deps", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysisId: id, maxDeps: 300, maxVulns: 300 }),
      });

      const data = (await safeJson(res)) as DepsScanPayload & { error?: string };

      if (!res.ok) {
        setDeps([]);
        setDepsMeta(null);
        setDepsNote(data.error ?? `Dependency scan failed (${res.status})`);
        setDepsRan(true);
        return;
      }

      setDeps(Array.isArray(data.findings) ? data.findings : []);
      setDepsNote(data.note ?? "");
      setDepsMeta({
        scannedDeps: data.scannedDeps,
        totalParsedDeps: data.totalParsedDeps,
        uniqueVulnIds: data.uniqueVulnIds,
        totalVulnHits: data.totalVulnHits,
        truncated: data.truncated,
        manifestsUsed: data.manifestsUsed,
      });
      setDepsRan(true);
    } finally {
      setDepsBusy(false);
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
      setDebtRan(true);
    } finally {
      setDebtBusy(false);
    }
  }

  function exportMd() {
    window.location.href = `/api/analysis/export/${id}?format=md`;
  }

  function exportPdf() {
    window.location.href = `/api/analysis/export/${id}?format=pdf`;
  }

  function downloadDiff(file: string, diff: string) {
    const blob = new Blob([diff], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `cipher-ai-${file.replace(/[\/\\]/g, "_")}.diff`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function copyToClipboard(text: string) {
    setCopyState("idle");
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setCopyState("copied");
        setTimeout(() => setCopyState("idle"), 1200);
        return;
      }

      // Fallback
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();

      setCopyState("copied");
      setTimeout(() => setCopyState("idle"), 1200);
    } catch {
      setCopyState("error");
      setTimeout(() => setCopyState("idle"), 1400);
    }
  }

  async function generatePatch(
    file: string,
    line: number | undefined,
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

      setCopyState("idle");
      setPatchPreview({
        open: true,
        file,
        line,
        diff,
        note: data.note ? String(data.note) : undefined,
      });
    } finally {
      setPatchBusyId("");
    }
  }

  if (!status) return <main className="p-6">Loading…</main>;

  return (
    <>
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
                      onMount={(editor, monaco) => {
                        editorRef.current = editor;
                        (window as any).monaco = monaco;
                      }}
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

                {/* Dependency CVEs (OSV) */}
                <div className="rounded-md border p-4 space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-semibold">Dependency CVEs (OSV)</div>
                      <div className="text-sm text-muted-foreground">
                        Scans pinned deps from package-lock.json and/or requirements.txt
                      </div>
                    </div>

                    <Button variant="secondary" onClick={runDepsScan} disabled={depsBusy}>
                      {depsBusy ? "Scanning…" : "Scan dependencies"}
                    </Button>
                  </div>

                  {(depsNote || depsMeta) && (
                    <div className="text-sm text-muted-foreground border rounded-md p-3">
                      {depsNote ? <div>{depsNote}</div> : null}
                      {depsMeta ? (
                        <div className={depsNote ? "mt-2" : ""}>
                          <span className="font-medium text-foreground">Stats:</span>{" "}
                          {[
                            typeof depsMeta.totalParsedDeps === "number"
                              ? `parsed=${depsMeta.totalParsedDeps}`
                              : null,
                            typeof depsMeta.scannedDeps === "number"
                              ? `scanned=${depsMeta.scannedDeps}`
                              : null,
                            depsMeta.truncated ? "truncated" : null,
                            typeof depsMeta.totalVulnHits === "number"
                              ? `hits=${depsMeta.totalVulnHits}`
                              : null,
                            typeof depsMeta.uniqueVulnIds === "number"
                              ? `unique=${depsMeta.uniqueVulnIds}`
                              : null,
                          ]
                            .filter(Boolean)
                            .join(", ")}
                        </div>
                      ) : null}
                    </div>
                  )}

                  {!depsRan ? (
                    <div className="text-sm text-muted-foreground">
                      No dependency CVE results yet. Click “Scan dependencies”.
                    </div>
                  ) : deps.length === 0 ? (
                    <div className="text-sm text-muted-foreground">
                      No dependency CVEs found ✅ (good news).
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {deps.slice(0, 40).map((d) => (
                        <div key={d.id} className="rounded-md border p-3">
                          <div className="flex items-center justify-between gap-2">
                            <div className="font-medium">
                              {d.name}@{d.version}{" "}
                              <span className="text-sm text-muted-foreground">
                                ({d.ecosystem})
                              </span>
                            </div>
                            <SeverityBadge s={d.severity} />
                          </div>

                          <div className="text-sm text-muted-foreground mt-1">
                            {d.vulnId}
                            {d.fixedVersion ? (
                              <>
                                {" "}
                                • <span className="font-medium">Fixed:</span>{" "}
                                {d.fixedVersion}
                              </>
                            ) : null}
                          </div>

                          <div className="text-sm mt-2">{d.summary}</div>

                          {d.references?.length ? (
                            <div className="text-sm text-muted-foreground mt-2">
                              Refs:{" "}
                              {d.references.slice(0, 4).map((r, i) => (
                                <span key={r}>
                                  {i ? " • " : ""}
                                  {r}
                                </span>
                              ))}
                            </div>
                          ) : null}
                        </div>
                      ))}

                      {deps.length > 40 && (
                        <div className="text-sm text-muted-foreground">
                          Showing first 40 dependency CVEs.
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Heuristic vuln scan */}
                {vulnNote && (
                  <div className="text-sm text-muted-foreground border rounded-md p-3">
                    {vulnNote}
                  </div>
                )}

                {!vulnRan ? (
                  <div className="text-sm text-muted-foreground">
                    No results yet. Click “Run scan”.
                  </div>
                ) : vulns.length === 0 ? (
                  <div className="text-sm text-muted-foreground">
                    No vulnerabilities found ✅ (good news).
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
                                  v.line,
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

                        <button
                          onClick={() => jumpToFileLine(v.file, v.line)}
                          className="text-sm text-muted-foreground underline underline-offset-2 hover:text-foreground"
                          title="Open in Explore and jump to line"
                        >
                          {v.file}:{v.line} • {v.type}
                        </button>

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

                {!debtRan ? (
                  <div className="text-sm text-muted-foreground">
                    No results yet. Click “Run scan”.
                  </div>
                ) : debt.length === 0 ? (
                  <div className="text-sm text-muted-foreground">
                    No tech debt issues found ✅ (good news).
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
                                  d.line,
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

                        <button
                          onClick={() => jumpToFileLine(d.file, d.line)}
                          className="text-sm text-muted-foreground underline underline-offset-2 hover:text-foreground"
                          title="Open in Explore and jump to line"
                        >
                          {d.file}:{d.line} • {d.type}
                        </button>

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

      {/* Patch Preview Modal */}
      {patchPreview?.open ? (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center p-4"
          aria-modal="true"
          role="dialog"
        >
          <button
            className="absolute inset-0 bg-black/50"
            aria-label="Close patch preview"
            onClick={() => setPatchPreview(null)}
          />

          <div className="relative w-full max-w-5xl rounded-xl border bg-background shadow-lg">
            <div className="p-4 border-b flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="font-semibold truncate">
                  Patch preview — <span className="text-muted-foreground">{patchPreview.file}</span>
                </div>
                {patchPreview.note ? (
                  <div className="text-sm text-muted-foreground mt-1">
                    {patchPreview.note}
                  </div>
                ) : null}
              </div>

              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  onClick={() => copyToClipboard(patchPreview.diff)}
                >
                  {copyState === "copied"
                    ? "Copied ✅"
                    : copyState === "error"
                    ? "Copy failed"
                    : "Copy diff"}
                </Button>

                <Button
                  variant="secondary"
                  onClick={() => downloadDiff(patchPreview.file, patchPreview.diff)}
                >
                  Download diff
                </Button>

                <Button
                  variant="secondary"
                  onClick={() => {
                    const f = patchPreview.file;
                    const ln = patchPreview.line;
                    setPatchPreview(null);
                    if (typeof ln === "number" && Number.isFinite(ln)) jumpToFileLine(f, ln);
                    else setTab("explore"), openFile(f);
                  }}
                >
                  Open file
                </Button>

                <Button onClick={() => setPatchPreview(null)}>Close</Button>
              </div>
            </div>

            <div className="p-4">
              <pre className="text-xs leading-5 font-mono whitespace-pre overflow-auto max-h-[70vh] rounded-md border bg-muted/20 p-3">
                {patchPreview.diff}
              </pre>
            </div>
          </div>
        </div>
      ) : null}
    </>
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
