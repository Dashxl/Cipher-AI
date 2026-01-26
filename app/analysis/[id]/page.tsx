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

type PatchView = "diff" | "updated" | "original";

type PatchPreview = {
  open: boolean;
  file: string;
  line?: number;
  diff: string;
  note?: string;

  // returned by /api/analysis/patch
  updated?: string;
  updatedTruncated?: boolean;

  // fetched from /api/analysis/file/:id?path=
  original?: string;
  originalTruncated?: boolean;
};

type PreviewApplied = { file: string; content: string; truncated?: boolean };

async function safeJson(res: Response): Promise<any> {
  const raw = await res.text();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { error: raw || `Request failed (${res.status})` };
  }
}

function computeDiffStats(diff: string) {
  const lines = String(diff || "").replace(/\r/g, "").split("\n");
  let added = 0;
  let removed = 0;
  for (const l of lines) {
    if (!l) continue;
    if (l.startsWith("+++ ") || l.startsWith("--- ")) continue;
    if (l.startsWith("+")) added++;
    else if (l.startsWith("-")) removed++;
  }
  return { added, removed };
}

function isDiffHeader(line: string) {
  return (
    line.startsWith("diff --git") ||
    line.startsWith("index ") ||
    line.startsWith("--- ") ||
    line.startsWith("+++ ") ||
    line.startsWith("@@") ||
    line.startsWith("new file mode") ||
    line.startsWith("deleted file mode")
  );
}

function DiffBlock({ diff }: { diff: string }) {
  const raw = String(diff || "").replace(/\r/g, "");
  const lines = raw.split("\n");

  // safety cap for very large diffs
  const MAX_LINES = 12_000;
  const slice = lines.length > MAX_LINES ? lines.slice(0, MAX_LINES) : lines;

  return (
    <pre className="text-xs leading-5 font-mono whitespace-pre overflow-auto max-h-[70vh] rounded-md border bg-muted/20 p-3">
      <code>
        {slice.map((line, i) => {
          const isHeader = isDiffHeader(line);

          // real additions/removals (ignore +++/---)
          const isAdd = line.startsWith("+") && !line.startsWith("+++ ");
          const isDel = line.startsWith("-") && !line.startsWith("--- ");
          const isHunk = line.startsWith("@@");

          const cls = isHeader
            ? isHunk
              ? "text-muted-foreground font-semibold"
              : "text-muted-foreground"
            : isAdd
            ? "text-emerald-700 dark:text-emerald-300 bg-emerald-500/10"
            : isDel
            ? "text-red-700 dark:text-red-300 bg-red-500/10"
            : "";

          // Keep empty lines visible
          const content = line.length ? line : " ";

          return (
            <span key={i} className={cls}>
              {content}
              {"\n"}
            </span>
          );
        })}
        {lines.length > MAX_LINES ? (
          <span className="text-muted-foreground">
            {"\n"}(Diff truncated to {MAX_LINES} lines for UI performance)
            {"\n"}
          </span>
        ) : null}
      </code>
    </pre>
  );
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

  // Preview-applied state (Monaco shows patched content, not saved)
  const [previewApplied, setPreviewApplied] = useState<PreviewApplied | null>(null);

  // Vulnerability scan state
  const [vulnBusy, setVulnBusy] = useState(false);
  const [vulnNote, setVulnNote] = useState<string>("");
  const [vulns, setVulns] = useState<VulnFinding[]>([]);
  const [vulnRan, setVulnRan] = useState(false);

  // Dependency CVEs
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
  const [patchView, setPatchView] = useState<PatchView>("diff");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");

  // Monaco refs for jump-to-line + highlight
  const editorRef = useRef<any>(null);
  const decoIdsRef = useRef<string[]>([]);
  const [pendingReveal, setPendingReveal] = useState<{ path: string; line: number } | null>(null);

  const isPreviewFile = Boolean(previewApplied && selected && previewApplied.file === selected);

  // Inject CSS for Monaco decorations
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

  // Load repo meta for Explore
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
    setPreviewApplied(null);

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

  // Reveal + decorate once Monaco has code loaded
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

      decoIdsRef.current = editor.deltaDecorations(decoIdsRef.current, []);

      const monaco = (window as any).monaco;
      if (!monaco?.Range) {
        setPendingReveal(null);
        return;
      }

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

  async function fetchOriginalForModal(file: string) {
    try {
      const res = await fetch(`/api/analysis/file/${id}?path=${encodeURIComponent(file)}`, {
        cache: "no-store",
      });
      const data = await safeJson(res);

      const raw = String(data.content ?? "");
      if (!raw) return;

      const MAX_MODAL_CHARS = 250_000;
      const truncated = raw.length > MAX_MODAL_CHARS;
      const clipped = truncated ? raw.slice(0, MAX_MODAL_CHARS) : raw;

      setPatchPreview((prev) => {
        if (!prev || prev.file !== file) return prev;
        return {
          ...prev,
          original: clipped,
          originalTruncated: truncated,
        };
      });
    } catch {
      // best-effort
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
      setPatchView("diff");

      const pv: PatchPreview = {
        open: true,
        file,
        line,
        diff,
        note: data.note ? String(data.note) : undefined,
        updated: typeof data.updated === "string" ? data.updated : undefined,
        updatedTruncated: Boolean(data.updatedTruncated),
      };

      setPatchPreview(pv);

      // load original for "Before" tab
      fetchOriginalForModal(file);
    } finally {
      setPatchBusyId("");
    }
  }

  function applyPreviewFromPatch(p: PatchPreview) {
    if (!p.updated) return;

    setTab("explore");
    setSelected(p.file);
    setExplain("");
    setPreviewApplied({ file: p.file, content: p.updated, truncated: p.updatedTruncated });
    setCode(p.updated);

    if (typeof p.line === "number" && Number.isFinite(p.line)) {
      setPendingReveal({ path: p.file, line: Math.max(1, Math.floor(p.line)) });
    } else {
      setPendingReveal(null);
    }

    setPatchPreview(null);
  }

  async function revertPreview() {
    if (!selected) return;
    setPreviewApplied(null);
    await openFile(selected);
  }

  const modalText =
    patchPreview && patchPreview.open
      ? patchView === "diff"
        ? patchPreview.diff
        : patchView === "updated"
        ? patchPreview.updated ?? ""
        : patchPreview.original ?? ""
      : "";

  const modalHint =
    patchPreview && patchPreview.open
      ? patchView === "updated" && patchPreview.updatedTruncated
        ? "Updated file content is truncated (preview-only)."
        : patchView === "original" && patchPreview.originalTruncated
        ? "Original file content is truncated (preview-only)."
        : patchView === "original" && !patchPreview.original
        ? "Loading original file…"
        : ""
      : "";

  const modalStats =
    patchPreview && patchPreview.open ? computeDiffStats(patchPreview.diff) : null;

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

                  {isPreviewFile ? (
                    <div className="rounded-md border bg-muted/10 p-3 flex items-center justify-between gap-3">
                      <div className="text-sm">
                        <span className="font-medium">Preview mode:</span>{" "}
                        <span className="text-muted-foreground">
                          showing patched content (not saved)
                        </span>
                        {previewApplied?.truncated ? (
                          <span className="text-muted-foreground"> • (preview truncated)</span>
                        ) : null}
                      </div>

                      <div className="flex gap-2">
                        <Button size="sm" variant="secondary" onClick={() => copyToClipboard(code)}>
                          {copyState === "copied"
                            ? "Copied ✅"
                            : copyState === "error"
                            ? "Copy failed"
                            : "Copy content"}
                        </Button>
                        <Button size="sm" variant="secondary" onClick={revertPreview}>
                          Revert
                        </Button>
                      </div>
                    </div>
                  ) : null}

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

                {/* Dependency CVEs */}
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
                    <div className="text-sm text-muted-foreground">No dependency CVEs found ✅</div>
                  ) : (
                    <div className="space-y-2">
                      {deps.slice(0, 40).map((d) => (
                        <div key={d.id} className="rounded-md border p-3">
                          <div className="flex items-center justify-between gap-2">
                            <div className="font-medium">
                              {d.name}@{d.version}{" "}
                              <span className="text-sm text-muted-foreground">({d.ecosystem})</span>
                            </div>
                            <SeverityBadge s={d.severity} />
                          </div>

                          <div className="text-sm text-muted-foreground mt-1">
                            {d.vulnId}
                            {d.fixedVersion ? (
                              <>
                                {" "}
                                • <span className="font-medium">Fixed:</span> {d.fixedVersion}
                              </>
                            ) : null}
                          </div>

                          <div className="text-sm mt-2">{d.summary}</div>
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

                {vulnNote && (
                  <div className="text-sm text-muted-foreground border rounded-md p-3">{vulnNote}</div>
                )}

                {!vulnRan ? (
                  <div className="text-sm text-muted-foreground">No results yet. Click “Run scan”.</div>
                ) : vulns.length === 0 ? (
                  <div className="text-sm text-muted-foreground">No vulnerabilities found ✅</div>
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
                  <div className="text-sm text-muted-foreground border rounded-md p-3">{debtNote}</div>
                )}

                {!debtRan ? (
                  <div className="text-sm text-muted-foreground">No results yet. Click “Run scan”.</div>
                ) : debt.length === 0 ? (
                  <div className="text-sm text-muted-foreground">No tech debt issues found ✅</div>
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
            <div className="p-4 border-b space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-semibold truncate">
                    Patch preview —{" "}
                    <span className="text-muted-foreground">{patchPreview.file}</span>
                    {modalStats ? (
                      <span className="ml-2 text-xs text-muted-foreground">
                        (+{modalStats.added} / -{modalStats.removed})
                      </span>
                    ) : null}
                  </div>
                  {patchPreview.note ? (
                    <div className="text-sm text-muted-foreground mt-1">{patchPreview.note}</div>
                  ) : null}
                </div>

                <div className="flex items-center gap-2">
                  <Button variant="secondary" onClick={() => copyToClipboard(modalText)}>
                    {copyState === "copied"
                      ? "Copied ✅"
                      : copyState === "error"
                      ? "Copy failed"
                      : "Copy"}
                  </Button>

                  <Button
                    variant="secondary"
                    onClick={() => downloadDiff(patchPreview.file, patchPreview.diff)}
                  >
                    Download diff
                  </Button>

                  <Button
                    variant="secondary"
                    disabled={!patchPreview.updated}
                    onClick={() => applyPreviewFromPatch(patchPreview)}
                    title={!patchPreview.updated ? "Patch endpoint did not return updated content" : ""}
                  >
                    Open patched
                  </Button>

                  <Button
                    variant="secondary"
                    onClick={() => {
                      const f = patchPreview.file;
                      const ln = patchPreview.line;
                      setPatchPreview(null);
                      if (typeof ln === "number" && Number.isFinite(ln)) jumpToFileLine(f, ln);
                      else (setTab("explore"), openFile(f));
                    }}
                  >
                    Open file
                  </Button>

                  <Button onClick={() => setPatchPreview(null)}>Close</Button>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  variant={patchView === "diff" ? "default" : "secondary"}
                  onClick={() => setPatchView("diff")}
                >
                  Diff
                </Button>

                <Button
                  size="sm"
                  variant={patchView === "updated" ? "default" : "secondary"}
                  disabled={!patchPreview.updated}
                  onClick={() => setPatchView("updated")}
                  title={!patchPreview.updated ? "No updated file returned" : ""}
                >
                  Updated file
                </Button>

                <Button
                  size="sm"
                  variant={patchView === "original" ? "default" : "secondary"}
                  onClick={() => setPatchView("original")}
                >
                  Original file
                </Button>

                <div className="flex-1" />

                {modalHint ? <div className="text-xs text-muted-foreground">{modalHint}</div> : null}
              </div>
            </div>

            <div className="p-4">
              {patchView === "diff" ? (
                <DiffBlock diff={patchPreview.diff} />
              ) : (
                <pre className="text-xs leading-5 font-mono whitespace-pre overflow-auto max-h-[70vh] rounded-md border bg-muted/20 p-3">
                  {modalText || (patchView === "original" ? "Loading…" : "")}
                </pre>
              )}
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
