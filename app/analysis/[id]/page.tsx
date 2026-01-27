"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import type { AnalysisStatus } from "@/types/analysis";
import type { DebtIssue, VulnFinding, Severity, DepCveFinding } from "@/types/scan";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { MermaidView } from "@/components/app/mermaid-view";
import Editor, { DiffEditor } from "@monaco-editor/react";

type RepoMeta = { repoName: string; root: string | null; files: string[] };
type Tab = "overview" | "explore" | "vuln" | "debt" | "docs";

type PatchPreview = {
  file: string;
  diff: string; // smart unified diff
  original: string;
  updated: string;
  note?: string;
  issueId?: string;
  targetLine?: number;
};

type RevealTarget = { file: string; line: number; endLine?: number; note?: string };

// ✅ Docs (Priority C)
type DocsIndexItem = {
  path: string;
  title: string;
  purpose: string;
  updatedAt: string;
};

type FileDoc = {
  path: string;
  title: string;
  purpose: string;
  inputs?: string[];
  outputs?: string[];
  sideEffects?: string[];
  usedBy?: string[];
  uses?: string[];
  examples?: string[];
  risks?: string[];
  notes?: string[];
  updatedAt: string;
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

function severityRank(s: Severity) {
  return s === "CRITICAL" ? 4 : s === "HIGH" ? 3 : s === "MEDIUM" ? 2 : 1;
}
function isHighPlus(s: Severity) {
  return s === "CRITICAL" || s === "HIGH";
}
function normalizePath(p: string) {
  return String(p || "").replaceAll("\\", "/");
}

const LS_PATCHED_PREFIX = "cipher:patched:";
const LS_MODE_PREFIX = "cipher:mode:";

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();

  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [tab, setTab] = useState<Tab>("overview");

  // Explore state
  const [repo, setRepo] = useState<RepoMeta | null>(null);
  const [q, setQ] = useState("");
  const [patchedOnly, setPatchedOnly] = useState(false); // ✅ demo-killer filter
  const [selected, setSelected] = useState<string>("");
  const [code, setCode] = useState<string>("");
  const [fileLoading, setFileLoading] = useState(false);
  const [explain, setExplain] = useState<string>("");
  const [busyExplain, setBusyExplain] = useState(false);
  const [goLine, setGoLine] = useState<string>("");

  // Apply patch preview + persistence
  const [originalByFile, setOriginalByFile] = useState<Record<string, string>>({});
  const [patchedByFile, setPatchedByFile] = useState<Record<string, string>>({});
  const [modeByFile, setModeByFile] = useState<Record<string, "original" | "patched">>({});
  const [viewMode, setViewMode] = useState<"original" | "patched">("original");

  // Jump-to-line
  const [pendingReveal, setPendingReveal] = useState<RevealTarget | null>(null);

  // Global “High+ only” toggle
  const [highPlusOnly, setHighPlusOnly] = useState(false);

  // Vulnerability scan state
  const [vulnBusy, setVulnBusy] = useState(false);
  const [vulnNote, setVulnNote] = useState<string>("");
  const [vulns, setVulns] = useState<VulnFinding[]>([]);
  const [vulnFilter, setVulnFilter] = useState<"ALL" | Severity>("ALL");
  const [vulnSearch, setVulnSearch] = useState("");
  const [vulnShowAll, setVulnShowAll] = useState(false);
  const [openVulnId, setOpenVulnId] = useState<string>("");

  // Dependency CVEs (OSV)
  const [depsBusy, setDepsBusy] = useState(false);
  const [depsNote, setDepsNote] = useState<string>("");
  const [deps, setDeps] = useState<DepCveFinding[]>([]);
  const [depsFilter, setDepsFilter] = useState<"ALL" | Severity>("ALL");
  const [depsSearch, setDepsSearch] = useState("");
  const [depsShowAll, setDepsShowAll] = useState(false);
  const [depsOpen, setDepsOpen] = useState(false);
  const [openDepGroupId, setOpenDepGroupId] = useState<string>(""); // ✅ grouped

  // Tech debt scan state
  const [debtBusy, setDebtBusy] = useState(false);
  const [debtNote, setDebtNote] = useState<string>("");
  const [debt, setDebt] = useState<DebtIssue[]>([]);
  const [debtFilter, setDebtFilter] = useState<"ALL" | Severity>("ALL");
  const [debtSearch, setDebtSearch] = useState("");
  const [debtShowAll, setDebtShowAll] = useState(false);
  const [openDebtId, setOpenDebtId] = useState<string>("");

  // ✅ Docs (Priority C)
  const [docsIndexBusy, setDocsIndexBusy] = useState(false);
  const [docsBusy, setDocsBusy] = useState(false);
  const [docsIndex, setDocsIndex] = useState<DocsIndexItem[]>([]);
  const [docsQ, setDocsQ] = useState("");
  const [docSelected, setDocSelected] = useState<string>("");
  const [doc, setDoc] = useState<FileDoc | null>(null);
  const [docsErr, setDocsErr] = useState<string>("");

  // Patch preview modal
  const [patchBusyId, setPatchBusyId] = useState<string>("");
  const [patchOpen, setPatchOpen] = useState(false);
  const [patch, setPatch] = useState<PatchPreview | null>(null);
  const [patchView, setPatchView] = useState<"compare" | "updated" | "diff">("compare");

  // Feedback UI
  const [copiedOk, setCopiedOk] = useState(false);
  const [downloadOk, setDownloadOk] = useState(false);
  const [actionMsg, setActionMsg] = useState<string>("");

  const copyTimer = useRef<number | null>(null);
  const downloadTimer = useRef<number | null>(null);
  const msgTimer = useRef<number | null>(null);

  function flashCopy() {
    if (copyTimer.current) window.clearTimeout(copyTimer.current);
    setCopiedOk(true);
    copyTimer.current = window.setTimeout(() => setCopiedOk(false), 1200);
  }
  function flashDownload() {
    if (downloadTimer.current) window.clearTimeout(downloadTimer.current);
    setDownloadOk(true);
    downloadTimer.current = window.setTimeout(() => setDownloadOk(false), 1200);
  }
  function flashMsg(msg: string) {
    if (msgTimer.current) window.clearTimeout(msgTimer.current);
    setActionMsg(msg);
    msgTimer.current = window.setTimeout(() => setActionMsg(""), 1600);
  }

  function toggleHighPlus() {
    setHighPlusOnly((prev) => {
      const next = !prev;
      if (next) {
        setVulnFilter("ALL");
        setDepsFilter("ALL");
        setDebtFilter("ALL");
        flashMsg("High+ filter enabled ✅");
      } else {
        flashMsg("High+ filter disabled ✅");
      }
      return next;
    });
  }

  // ✅ ENTERPRISE: al cambiar de tab, cerrar cualquier item abierto para que no “brinque”
  useEffect(() => {
    setOpenVulnId("");
    setOpenDebtId("");
    setOpenDepGroupId("");
    if (tab !== "vuln") setDepsOpen(false);
  }, [tab]);

  // Monaco refs
  const editorRef = useRef<any>(null);
  const monacoRef = useRef<any>(null);
  const decorationIdsRef = useRef<string[]>([]);

  function clearRevealDecorations() {
    const editor = editorRef.current;
    if (!editor) return;
    decorationIdsRef.current = editor.deltaDecorations(decorationIdsRef.current, []);
  }

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
  }

  function jumpToLocation(file: string, line: number, endLine?: number, note?: string) {
    const ln = Number.isFinite(Number(line)) ? Math.max(1, Number(line)) : 1;
    setTab("explore");
    setPendingReveal({ file, line: ln, endLine, note });
    openFile(file);
  }

  function revealLineInExplore(line: number) {
    const editor = editorRef.current;
    const monaco = monacoRef.current;
    if (!editor || !monaco) return;

    const ln = Math.max(1, Number(line || 1));
    decorationIdsRef.current = editor.deltaDecorations(decorationIdsRef.current, []);
    decorationIdsRef.current = editor.deltaDecorations([], [
      {
        range: new monaco.Range(ln, 1, ln, 1),
        options: {
          isWholeLine: true,
          className: "cipher-revealLine",
          linesDecorationsClassName: "cipher-revealLineGutter",
        },
      },
    ]);

    editor.revealLineInCenter(ln);
    editor.setPosition({ lineNumber: ln, column: 1 });
    editor.focus();
  }

  // Apply pending reveal once editor + file are ready
  useEffect(() => {
    if (!pendingReveal) return;
    if (tab !== "explore") return;
    if (!selected) return;
    if (normalizePath(selected) !== normalizePath(pendingReveal.file)) return;
    if (fileLoading) return;

    const editor = editorRef.current;
    const monaco = monacoRef.current;
    if (!editor || !monaco) return;

    const line = Math.max(1, Number(pendingReveal.line || 1));
    const endLine = Math.max(line, Number(pendingReveal.endLine || line));

    try {
      decorationIdsRef.current = editor.deltaDecorations(decorationIdsRef.current, []);
      decorationIdsRef.current = editor.deltaDecorations([], [
        {
          range: new monaco.Range(line, 1, endLine, 1),
          options: {
            isWholeLine: true,
            className: "cipher-revealLine",
            linesDecorationsClassName: "cipher-revealLineGutter",
          },
        },
      ]);

      editor.revealLineInCenter(line);
      editor.setPosition({ lineNumber: line, column: 1 });
      editor.focus();

      if (pendingReveal.note) flashMsg(pendingReveal.note);
    } finally {
      setPendingReveal(null);
    }
  }, [pendingReveal, tab, selected, fileLoading, code]);

  // ✅ Load patched state from localStorage
  useEffect(() => {
    try {
      const rawPatched = localStorage.getItem(`${LS_PATCHED_PREFIX}${id}`) || "";
      const rawMode = localStorage.getItem(`${LS_MODE_PREFIX}${id}`) || "";
      const patched = rawPatched ? (JSON.parse(rawPatched) as Record<string, string>) : {};
      const mode = rawMode ? (JSON.parse(rawMode) as Record<string, "original" | "patched">) : {};
      setPatchedByFile(patched || {});
      setModeByFile(mode || {});
    } catch {
      // ignore
    }
  }, [id]);

  // ✅ Persist patched state (guard size)
  useEffect(() => {
    try {
      const patchedJson = JSON.stringify(patchedByFile);
      if (patchedJson.length < 700_000) localStorage.setItem(`${LS_PATCHED_PREFIX}${id}`, patchedJson);
      const modeJson = JSON.stringify(modeByFile);
      if (modeJson.length < 80_000) localStorage.setItem(`${LS_MODE_PREFIX}${id}`, modeJson);
    } catch {
      // ignore
    }
  }, [patchedByFile, modeByFile, id]);

  function clearAllPreviews() {
    setPatchedByFile({});
    setModeByFile({});
    try {
      localStorage.removeItem(`${LS_PATCHED_PREFIX}${id}`);
      localStorage.removeItem(`${LS_MODE_PREFIX}${id}`);
    } catch {
      // ignore
    }

    if (selected) {
      const p = normalizePath(selected);
      const orig = originalByFile[p];
      setViewMode("original");
      if (typeof orig === "string") setCode(orig);
    }
    flashMsg("Cleared all patch previews ✅");
  }

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

  const patchedCount = useMemo(() => Object.keys(patchedByFile || {}).length, [patchedByFile]);

  const filteredFiles = useMemo(() => {
    let files = repo?.files ?? [];
    if (patchedOnly) files = files.filter((f) => !!patchedByFile[normalizePath(f)]);
    const qq = q.trim().toLowerCase();
    if (!qq) return files.slice(0, 500);
    return files.filter((f) => f.toLowerCase().includes(qq)).slice(0, 500);
  }, [repo, q, patchedOnly, patchedByFile]);

  function applyModeForFile(path: string, originalText: string) {
    const p = normalizePath(path);
    const patched = patchedByFile[p];
    const preferred = modeByFile[p] ?? (patched ? "patched" : "original");
    setViewMode(preferred);

    if (preferred === "patched" && patched) {
      setCode(patched);
    } else {
      setCode(originalText);
    }
  }

  async function openFile(path: string) {
    const p = normalizePath(path);
    setSelected(p);
    setExplain("");
    setFileLoading(true);
    clearRevealDecorations();

    const cachedOriginal = originalByFile[p];
    if (cachedOriginal) {
      setFileLoading(false);
      applyModeForFile(p, cachedOriginal);
      return;
    }

    setCode("Loading…");

    try {
      const res = await fetch(`/api/analysis/file/${id}?path=${encodeURIComponent(p)}`, { cache: "no-store" });
      const data = await safeJson(res);
      const content = String(data.content ?? data.error ?? "");

      setOriginalByFile((prev) => ({ ...prev, [p]: content }));
      setFileLoading(false);
      applyModeForFile(p, content);
    } finally {
      setFileLoading(false);
    }
  }

  function setExploreMode(mode: "original" | "patched") {
    if (!selected) return;
    const p = normalizePath(selected);
    setViewMode(mode);
    setModeByFile((prev) => ({ ...prev, [p]: mode }));

    if (mode === "patched" && patchedByFile[p]) {
      setCode(patchedByFile[p]);
    } else {
      const orig = originalByFile[p];
      if (typeof orig === "string") setCode(orig);
    }
  }

  function revertPatchForSelected() {
    if (!selected) return;
    const p = normalizePath(selected);
    setPatchedByFile((prev) => {
      const next = { ...prev };
      delete next[p];
      return next;
    });
    setModeByFile((prev) => ({ ...prev, [p]: "original" }));
    setViewMode("original");
    const orig = originalByFile[p];
    if (typeof orig === "string") setCode(orig);
    flashMsg("Reverted patch preview ✅");
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
      flashMsg("Vuln scan complete ✅");
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
        body: JSON.stringify({ analysisId: id }),
      });

      const data = await safeJson(res);
      setDeps(Array.isArray(data.findings) ? data.findings : []);
      setDepsNote(data.note ?? data.error ?? "");
      setDepsOpen(true);
      flashMsg("Dependency scan complete ✅");
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
      flashMsg("Tech debt scan complete ✅");
    } finally {
      setDebtBusy(false);
    }
  }

  // ✅ Docs (Priority C)
  const docsIndexFiltered = useMemo(() => {
    const qq = docsQ.trim().toLowerCase();
    if (!qq) return docsIndex;
    return docsIndex.filter((d) => `${d.path} ${d.title} ${d.purpose}`.toLowerCase().includes(qq));
  }, [docsIndex, docsQ]);

  async function generateDocsIndex() {
    setDocsIndexBusy(true);
    setDocsErr("");
    try {
      const res = await fetch("/api/analysis/docs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysisId: id, mode: "index", maxFiles: 5 }),
      });
      const data = await safeJson(res);
      if (!res.ok) {
        setDocsErr(data.error ?? `Docs index failed (${res.status})`);
        return;
      }
      setDocsIndex(Array.isArray(data.items) ? data.items : []);
      flashMsg("Docs index ready ✅");
    } finally {
      setDocsIndexBusy(false);
    }
  }

  async function openDoc(path: string) {
    setDocSelected(path);
    setDoc(null);
    setDocsErr("");
    setDocsBusy(true);
    try {
      const res = await fetch("/api/analysis/docs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysisId: id, mode: "file", path }),
      });
      const data = await safeJson(res);
      if (!res.ok) {
        setDocsErr(data.error ?? `Docs failed (${res.status})`);
        return;
      }
      setDoc(data.doc ?? null);
    } finally {
      setDocsBusy(false);
    }
  }

  function exportMd() {
    window.location.href = `/api/analysis/export/${id}?format=md`;
  }
  function exportPdf() {
    window.location.href = `/api/analysis/export/${id}?format=pdf`;
  }

  function downloadText(filename: string, text: string) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ✅ Smart unified diff
  function buildSmartDiff(file: string, oldText: string, newText: string) {
    const p = normalizePath(file);
    try {
      return unifiedDiffFromTexts(p, oldText ?? "", newText ?? "", 3);
    } catch {
      return `--- a/${p}\n+++ b/${p}\n@@ (diff unavailable) @@\n`;
    }
  }

  async function generatePatch(
    file: string,
    issueTitle: string,
    issueDetails: string,
    idForBusy: string,
    targetLine?: number
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

      const original = String(data.original ?? "");
      const updated = String(data.updated ?? "");
      if (!updated.trim()) {
        alert("Patch endpoint returned empty updated file.");
        return;
      }

      const p = normalizePath(file);
      setOriginalByFile((prev) => (prev[p] ? prev : { ...prev, [p]: original }));

      const smartDiff = buildSmartDiff(p, original, updated);

      setCopiedOk(false);
      setDownloadOk(false);
      setActionMsg("");

      setPatch({
        file: p,
        diff: smartDiff,
        original,
        updated,
        note: data.note ? String(data.note) : undefined,
        issueId: idForBusy,
        targetLine,
      });

      setPatchView("compare");
      setPatchOpen(true);
    } finally {
      setPatchBusyId("");
    }
  }

  function closePatchModal() {
    setPatchOpen(false);
  }

  function openPatchedInEditorOneOff() {
    if (!patch) return;
    closePatchModal();
    setTab("explore");
    setSelected(patch.file);
    setExplain("");
    setViewMode("patched");
    setCode(patch.updated || "");
    flashMsg("Opened patched content (one-off) ✅");
    if (patch.targetLine) setPendingReveal({ file: patch.file, line: patch.targetLine });
  }

  async function openOriginalFileInEditor() {
    if (!patch) return;
    closePatchModal();
    setTab("explore");
    await openFile(patch.file);
    flashMsg("Opened original file ✅");
    if (patch.targetLine) setPendingReveal({ file: patch.file, line: patch.targetLine });
  }

  // ✅ Apply patch preview (persist)
  function applyPatchPreview() {
    if (!patch) return;
    const p = normalizePath(patch.file);

    setPatchedByFile((prev) => ({ ...prev, [p]: patch.updated }));
    setModeByFile((prev) => ({ ...prev, [p]: "patched" }));
    setOriginalByFile((prev) => (prev[p] ? prev : { ...prev, [p]: patch.original }));

    closePatchModal();
    setTab("explore");
    setSelected(p);
    setExplain("");
    setViewMode("patched");
    setCode(patch.updated);

    flashMsg("Applied patch preview ✅");
    if (patch.targetLine) setPendingReveal({ file: p, line: patch.targetLine });
  }

  // counts
  const vulnCountsAll = useMemo(() => countBySeverity(vulns), [vulns]);
  const debtCountsAll = useMemo(() => countBySeverity(debt), [debt]);
  const depsCountsAll = useMemo(() => countBySeverity(deps), [deps]);

  const repoCountsAll = useMemo(() => {
    const combined = [
      ...vulns.map((x) => ({ severity: x.severity })),
      ...debt.map((x) => ({ severity: x.severity })),
      ...deps.map((x) => ({ severity: x.severity })),
    ];
    return countBySeverity(combined);
  }, [vulns, debt, deps]);

  const repoHighPlusTotal = repoCountsAll.CRITICAL + repoCountsAll.HIGH;

  const visibleVulns = useMemo(() => {
    const s = vulnSearch.trim().toLowerCase();
    const list = [...vulns]
      .filter((v) => (highPlusOnly ? isHighPlus(v.severity) : true))
      .filter((v) => (vulnFilter === "ALL" ? true : v.severity === vulnFilter))
      .filter((v) => {
        if (!s) return true;
        const hay = `${v.title} ${v.type} ${v.file} ${v.recommendation} ${v.snippet}`.toLowerCase();
        return hay.includes(s);
      })
      .sort((a, b) => {
        const d = severityRank(b.severity) - severityRank(a.severity);
        if (d) return d;
        const fa = normalizePath(a.file);
        const fb = normalizePath(b.file);
        if (fa !== fb) return fa.localeCompare(fb);
        return (a.line ?? 0) - (b.line ?? 0);
      });

    return list.slice(0, vulnShowAll ? 9999 : 30);
  }, [vulns, vulnFilter, vulnSearch, highPlusOnly, vulnShowAll]);

  const totalVulnsAfterFilter = useMemo(() => {
    const s = vulnSearch.trim().toLowerCase();
    return [...vulns]
      .filter((v) => (highPlusOnly ? isHighPlus(v.severity) : true))
      .filter((v) => (vulnFilter === "ALL" ? true : v.severity === vulnFilter))
      .filter((v) => {
        if (!s) return true;
        const hay = `${v.title} ${v.type} ${v.file} ${v.recommendation} ${v.snippet}`.toLowerCase();
        return hay.includes(s);
      }).length;
  }, [vulns, vulnFilter, vulnSearch, highPlusOnly]);

  const visibleDebt = useMemo(() => {
    const s = debtSearch.trim().toLowerCase();
    const list = [...debt]
      .filter((d) => (highPlusOnly ? isHighPlus(d.severity) : true))
      .filter((d) => (debtFilter === "ALL" ? true : d.severity === debtFilter))
      .filter((d) => {
        if (!s) return true;
        const hay = `${d.title} ${d.type} ${d.file} ${d.details} ${d.suggestion}`.toLowerCase();
        return hay.includes(s);
      })
      .sort((a, b) => {
        const d = severityRank(b.severity) - severityRank(a.severity);
        if (d) return d;
        const fa = normalizePath(a.file);
        const fb = normalizePath(b.file);
        if (fa !== fb) return fa.localeCompare(fb);
        return (a.line ?? 0) - (b.line ?? 0);
      });

    return list.slice(0, debtShowAll ? 9999 : 30);
  }, [debt, debtFilter, debtSearch, highPlusOnly, debtShowAll]);

  const totalDebtAfterFilter = useMemo(() => {
    const s = debtSearch.trim().toLowerCase();
    return [...debt]
      .filter((d) => (highPlusOnly ? isHighPlus(d.severity) : true))
      .filter((d) => (debtFilter === "ALL" ? true : d.severity === debtFilter))
      .filter((d) => {
        if (!s) return true;
        const hay = `${d.title} ${d.type} ${d.file} ${d.details} ${d.suggestion}`.toLowerCase();
        return hay.includes(s);
      }).length;
  }, [debt, debtFilter, debtSearch, highPlusOnly]);

  // ✅ PRIORIDAD B UI: agrupar deps por paquete/version para que no se vea saturado
  type DepGroup = {
    id: string;
    ecosystem: DepCveFinding["ecosystem"];
    name: string;
    version: string;
    maxSeverity: Severity;
    findings: DepCveFinding[];
    bestFixedVersion?: string;
    reference?: string;
  };

  const depGroupsAll = useMemo<DepGroup[]>(() => {
    const map = new Map<string, DepGroup>();
    for (const d of deps) {
      const key = `${d.ecosystem}:${d.name}@${d.version}`;
      const existing = map.get(key);
      if (!existing) {
        map.set(key, {
          id: key,
          ecosystem: d.ecosystem,
          name: d.name,
          version: d.version,
          maxSeverity: d.severity,
          findings: [d],
          bestFixedVersion: d.fixedVersion,
          reference: d.references?.[0],
        });
      } else {
        existing.findings.push(d);
        if (severityRank(d.severity) > severityRank(existing.maxSeverity)) existing.maxSeverity = d.severity;
        existing.bestFixedVersion = pickBestFixedVersion(existing.ecosystem, existing.bestFixedVersion, d.fixedVersion);
        existing.reference = existing.reference ?? d.references?.[0];
      }
    }
    return Array.from(map.values()).sort((a, b) => {
      const sd = severityRank(b.maxSeverity) - severityRank(a.maxSeverity);
      if (sd) return sd;
      return `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`);
    });
  }, [deps]);

  const depsGroupsFiltered = useMemo(() => {
    const s = depsSearch.trim().toLowerCase();
    const list = depGroupsAll
      .filter((g) => (highPlusOnly ? isHighPlus(g.maxSeverity) : true))
      .filter((g) => (depsFilter === "ALL" ? true : g.maxSeverity === depsFilter))
      .filter((g) => {
        if (!s) return true;
        const hay = `${g.name} ${g.version} ${g.ecosystem} ${g.findings
          .map((x) => `${x.vulnId} ${x.summary}`)
          .join(" ")}`.toLowerCase();
        return hay.includes(s);
      });

    return list.slice(0, depsShowAll ? 9999 : 30);
  }, [depGroupsAll, depsSearch, depsFilter, highPlusOnly, depsShowAll]);

  const totalDepsGroupsAfterFilter = useMemo(() => {
    const s = depsSearch.trim().toLowerCase();
    return depGroupsAll
      .filter((g) => (highPlusOnly ? isHighPlus(g.maxSeverity) : true))
      .filter((g) => (depsFilter === "ALL" ? true : g.maxSeverity === depsFilter))
      .filter((g) => {
        if (!s) return true;
        const hay = `${g.name} ${g.version} ${g.ecosystem} ${g.findings
          .map((x) => `${x.vulnId} ${x.summary}`)
          .join(" ")}`.toLowerCase();
        return hay.includes(s);
      }).length;
  }, [depGroupsAll, depsSearch, depsFilter, highPlusOnly]);

  if (!status) return <main className="p-6">Loading…</main>;

  const selectedHasPatch = selected && patchedByFile[normalizePath(selected)];
  const selectedMode = selected ? (modeByFile[normalizePath(selected)] ?? viewMode) : viewMode;

  return (
    <main className="min-h-screen p-6 flex items-start justify-center">
      <Card className="w-full max-w-6xl">
        <CardHeader className="space-y-3">
          <CardTitle>Analysis</CardTitle>

          <div className="flex items-center gap-2">
            <Badge variant="secondary">{status.stage}</Badge>
            <span className="text-sm text-muted-foreground">{status.message}</span>
          </div>

          <Progress value={status.progress} />

          {/* Repo-level overview bar */}
          <div className="rounded-md border bg-muted/10 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="text-sm font-medium">Repo Health</div>
              <div className="text-sm text-muted-foreground">
                Vulns <span className="font-medium text-foreground">{vulns.length}</span> • Deps{" "}
                <span className="font-medium text-foreground">{deps.length}</span> • Debt{" "}
                <span className="font-medium text-foreground">{debt.length}</span>
              </div>

              <div className="flex-1" />

              <Button
                size="sm"
                variant={highPlusOnly ? "default" : "secondary"}
                onClick={toggleHighPlus}
                className="h-8"
                title="Filter Vulns/Deps/Debt to CRITICAL + HIGH only"
              >
                {highPlusOnly ? "High+ only ✓" : "Show only High+"}
                <span className="ml-2 text-xs opacity-80">{repoHighPlusTotal}</span>
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-2 pt-2">
              <SeverityPill s="CRITICAL" n={repoCountsAll.CRITICAL} />
              <SeverityPill s="HIGH" n={repoCountsAll.HIGH} />
              <SeverityPill s="MEDIUM" n={repoCountsAll.MEDIUM} />
              <SeverityPill s="LOW" n={repoCountsAll.LOW} />

              <div className="flex-1" />

              {actionMsg && (
                <div className="text-xs text-muted-foreground" aria-live="polite">
                  {actionMsg}
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button variant={tab === "overview" ? "default" : "secondary"} onClick={() => setTab("overview")}>
              Overview
            </Button>
            <Button variant={tab === "explore" ? "default" : "secondary"} onClick={() => setTab("explore")}>
              Explore
            </Button>
            <Button variant={tab === "vuln" ? "default" : "secondary"} onClick={() => setTab("vuln")}>
              Vulnerabilities
            </Button>
            <Button variant={tab === "debt" ? "default" : "secondary"} onClick={() => setTab("debt")}>
              Tech Debt
            </Button>

            {/* ✅ NEW: Docs tab (Priority C) */}
            <Button variant={tab === "docs" ? "default" : "secondary"} onClick={() => setTab("docs")}>
              Docs
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
            <pre className="whitespace-pre-wrap text-sm p-4 rounded-md border border-red-500/40">{status.error}</pre>
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
                <p className="text-sm text-muted-foreground">Overview will appear once the global analysis completes.</p>
              )}
            </>
          )}

          {tab === "explore" && (
            <div className="grid gap-4 md:grid-cols-[320px_1fr]">
              <div className="space-y-3">
                <div className="text-sm text-muted-foreground">
                  Repo: <span className="font-medium text-foreground">{repo?.repoName ?? "Loading…"}</span>
                </div>

                {/* ✅ demo-killer controls */}
                <div className="flex flex-wrap gap-2 items-center">
                  <Button
                    size="sm"
                    variant={patchedOnly ? "default" : "secondary"}
                    onClick={() => setPatchedOnly((v) => !v)}
                    className="h-8"
                    title="Show only files with patch preview applied"
                  >
                    Patched only
                    <span className="ml-2 text-xs opacity-80">{patchedCount}</span>
                  </Button>

                  {patchedCount > 0 && (
                    <Button size="sm" variant="secondary" onClick={clearAllPreviews} className="h-8">
                      Reset previews
                    </Button>
                  )}
                </div>

                <Input placeholder="Search files…" value={q} onChange={(e) => setQ(e.target.value)} />

                <div className="h-[520px] overflow-auto rounded-md border">
                  {!repo && <div className="p-3 text-sm text-muted-foreground">Loading file list…</div>}

                  {filteredFiles.map((f) => {
                    const p = normalizePath(f);
                    const isSelected = normalizePath(selected) === p;
                    const isPatched = !!patchedByFile[p];

                    return (
                      <button
                        key={f}
                        onClick={() => openFile(f)}
                        className={`w-full text-left text-sm px-3 py-2 border-b hover:bg-muted/30 flex items-center gap-2 ${
                          isSelected ? "bg-muted/40" : ""
                        }`}
                      >
                        <span className="flex-1 min-w-0 truncate">{f}</span>
                        {isPatched && (
                          <Badge variant="secondary" title="Patch preview applied">
                            P
                          </Badge>
                        )}
                      </button>
                    );
                  })}

                  {repo && filteredFiles.length === 0 && (
                    <div className="p-3 text-sm text-muted-foreground">No files match that search.</div>
                  )}
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-sm text-muted-foreground truncate min-w-0">
                    {selected ? selected : "Select a file to view"}
                  </div>

                  <div className="flex flex-wrap gap-2 items-center">
                    {selected && selectedHasPatch && (
                      <div className="flex items-center gap-2">
                        <Badge variant={selectedMode === "patched" ? "default" : "secondary"}>
                          {selectedMode === "patched" ? "PATCHED (preview)" : "Original"}
                        </Badge>

                        <div className="flex items-center gap-1">
                          <Button
                            size="sm"
                            variant={selectedMode === "original" ? "default" : "secondary"}
                            onClick={() => setExploreMode("original")}
                          >
                            Original
                          </Button>
                          <Button
                            size="sm"
                            variant={selectedMode === "patched" ? "default" : "secondary"}
                            onClick={() => setExploreMode("patched")}
                          >
                            Patched
                          </Button>
                        </div>

                        <Button size="sm" variant="secondary" onClick={revertPatchForSelected}>
                          Revert
                        </Button>
                      </div>
                    )}

                    <div className="flex items-center gap-2">
                      <Input
                        className="w-[130px]"
                        placeholder="Go to line…"
                        value={goLine}
                        onChange={(e) => setGoLine(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            const ln = Number(goLine);
                            if (Number.isFinite(ln) && ln > 0) revealLineInExplore(ln);
                          }
                        }}
                        disabled={!selected}
                      />
                      <Button
                        variant="secondary"
                        disabled={!selected}
                        onClick={() => {
                          const ln = Number(goLine);
                          if (Number.isFinite(ln) && ln > 0) revealLineInExplore(ln);
                        }}
                      >
                        Go
                      </Button>
                    </div>

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
                    onMount={(editor, monaco) => {
                      editorRef.current = editor;
                      monacoRef.current = monaco;
                    }}
                    options={{
                      readOnly: true,
                      minimap: { enabled: false },
                      scrollBeyondLastLine: false,
                      wordWrap: "on",
                    }}
                  />
                </div>

                {explain && <pre className="whitespace-pre-wrap text-sm p-4 rounded-md border bg-muted/20">{explain}</pre>}
              </div>
            </div>
          )}

          {tab === "vuln" && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-lg font-semibold">Vulnerabilities</h2>
                <Button onClick={runVulnScan} disabled={vulnBusy}>
                  {vulnBusy ? "Scanning…" : "Run scan"}
                </Button>
              </div>

              {/* ✅ PRIORIDAD B UI: Dependency CVEs agrupado por paquete */}
              <div className="rounded-md border overflow-hidden">
                <button
                  className="w-full text-left p-3 hover:bg-muted/20 transition"
                  onClick={() => setDepsOpen((v) => !v)}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`cipher-chevron ${depsOpen ? "open" : ""}`} aria-hidden />
                    <div className="font-medium">Dependency CVEs (OSV)</div>
                    <div className="text-sm text-muted-foreground">
                      {deps.length === 0 ? "0 findings" : `${deps.length} findings`}
                      {highPlusOnly ? " • (High+ filter active)" : ""}
                    </div>
                    <div className="flex-1" />
                    <Badge variant="secondary">{depsOpen ? "Hide" : "Show"}</Badge>
                  </div>
                  {!!depsNote && !depsOpen && (
                    <div className="text-xs text-muted-foreground mt-1 truncate">{depsNote}</div>
                  )}
                </button>

                {depsOpen && (
                  <div className="border-t p-3 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-sm text-muted-foreground">
                        Scans pinned deps from package-lock/yarn.lock/pnpm-lock + requirements/poetry/pyproject
                      </div>
                      <Button variant="secondary" onClick={runDepsScan} disabled={depsBusy}>
                        {depsBusy ? "Scanning…" : "Scan dependencies"}
                      </Button>
                    </div>

                    <div className="border rounded-md p-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityFilter value={depsFilter} onChange={setDepsFilter} counts={depsCountsAll} total={deps.length} />
                        <div className="flex-1" />
                        <Input
                          className="w-[260px]"
                          placeholder="Search dependency findings…"
                          value={depsSearch}
                          onChange={(e) => setDepsSearch(e.target.value)}
                        />
                        <Button variant="secondary" onClick={() => setDepsShowAll((v) => !v)}>
                          {depsShowAll ? "Show 30" : "Show all"}
                          <span className="ml-2 text-xs opacity-80">{totalDepsGroupsAfterFilter}</span>
                        </Button>
                      </div>
                    </div>

                    {depsNote && <div className="text-sm text-muted-foreground border rounded-md p-3">{depsNote}</div>}

                    {depsGroupsFiltered.length === 0 ? (
                      <div className="text-sm text-muted-foreground">
                        {deps.length === 0 ? "No dependency CVEs found ✅ (good news)." : "No results match your filters."}
                      </div>
                    ) : (
                      <div className="rounded-md border overflow-hidden">
                        <div className="grid grid-cols-[120px_1fr_280px] gap-2 px-3 py-2 text-xs text-muted-foreground border-b bg-muted/10">
                          <div>Severity</div>
                          <div>Package</div>
                          <div className="text-right">Actions</div>
                        </div>

                        {depsGroupsFiltered.map((g) => {
                          const isOpen = openDepGroupId === g.id;

                          const upgradeCmd =
                            g.bestFixedVersion
                              ? g.ecosystem === "npm"
                                ? `npm i ${g.name}@${g.bestFixedVersion}`
                                : `pip install ${g.name}==${g.bestFixedVersion}`
                              : "";

                          return (
                            <div key={g.id} className="border-b">
                              <div
                                className={`px-3 py-2 grid grid-cols-[120px_1fr_280px] gap-2 items-center hover:bg-muted/20 cursor-pointer ${
                                  isOpen ? "bg-muted/15" : ""
                                }`}
                                onClick={() => setOpenDepGroupId((prev) => (prev === g.id ? "" : g.id))}
                              >
                                <div className="flex items-center gap-2">
                                  <SeverityBadge s={g.maxSeverity} />
                                  <span className={`cipher-chevron ${isOpen ? "open" : ""}`} aria-hidden />
                                </div>

                                <div className="min-w-0">
                                  <div className="text-sm font-medium truncate">
                                    {g.name}@{g.version} <span className="text-muted-foreground">({g.ecosystem})</span>
                                  </div>
                                  <div className="text-xs text-muted-foreground truncate">
                                    {g.findings.length} vuln(s)
                                    {g.bestFixedVersion ? ` • suggested: ${g.bestFixedVersion}` : ""}
                                  </div>
                                </div>

                                <div className="flex items-center justify-end gap-2">
                                  <Button
                                    size="sm"
                                    variant="secondary"
                                    onClick={async (e) => {
                                      e.stopPropagation();
                                      const target = g.ecosystem === "npm" ? "package-lock.json" : "requirements.txt";
                                      const match =
                                        repo?.files.find(
                                          (p) => p.toLowerCase().endsWith(`/${target}`) || p.toLowerCase() === target
                                        ) ?? "";
                                      if (match) jumpToLocation(match, 1, 1, "Opened manifest ✅");
                                    }}
                                  >
                                    Manifest
                                  </Button>

                                  <Button
                                    size="sm"
                                    variant="secondary"
                                    disabled={!g.bestFixedVersion}
                                    onClick={async (e) => {
                                      e.stopPropagation();
                                      if (!upgradeCmd) return;
                                      await copyToClipboard(upgradeCmd);
                                      flashCopy();
                                      flashMsg("Copied upgrade command ✅");
                                    }}
                                  >
                                    Upgrade cmd
                                  </Button>

                                  <Button
                                    size="sm"
                                    variant="secondary"
                                    disabled={!g.reference}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      if (g.reference) window.open(g.reference, "_blank");
                                    }}
                                  >
                                    Reference
                                  </Button>
                                </div>
                              </div>

                              {isOpen && (
                                <div className="px-3 pb-3 pt-1 space-y-2">
                                  {g.bestFixedVersion && (
                                    <div className="text-sm">
                                      <span className="font-medium">Suggested upgrade:</span> {g.bestFixedVersion}
                                      <span className="text-muted-foreground">
                                        {" "}
                                        ({g.ecosystem === "npm" ? "npm" : "pip"})
                                      </span>
                                    </div>
                                  )}

                                  <div className="rounded-md border overflow-hidden">
                                    <div className="grid grid-cols-[170px_1fr_130px] gap-2 px-3 py-2 text-xs text-muted-foreground border-b bg-muted/10">
                                      <div>Vuln</div>
                                      <div>Summary</div>
                                      <div>Fix</div>
                                    </div>

                                    {g.findings.slice(0, 40).map((d) => (
                                      <div
                                        key={d.id}
                                        className="px-3 py-2 grid grid-cols-[170px_1fr_130px] gap-2 border-b"
                                      >
                                        <div className="text-xs font-medium truncate">{d.vulnId}</div>
                                        <div className="text-xs text-muted-foreground">{d.summary}</div>
                                        <div className="text-xs">{d.fixedVersion ?? "—"}</div>
                                      </div>
                                    ))}

                                    {g.findings.length > 40 && (
                                      <div className="p-3 text-xs text-muted-foreground">
                                        Showing first 40 vulns for this package.
                                      </div>
                                    )}
                                  </div>

                                  <div className="flex flex-wrap gap-2">
                                    <Button
                                      size="sm"
                                      variant="secondary"
                                      onClick={async () => {
                                        await copyToClipboard(`${g.name}@${g.version} (${g.ecosystem})`);
                                        flashCopy();
                                        flashMsg("Copied package ✅");
                                      }}
                                    >
                                      Copy package
                                    </Button>

                                    {upgradeCmd && (
                                      <Button
                                        size="sm"
                                        variant="secondary"
                                        onClick={async () => {
                                          await copyToClipboard(upgradeCmd);
                                          flashCopy();
                                          flashMsg("Copied upgrade command ✅");
                                        }}
                                      >
                                        Copy upgrade cmd
                                      </Button>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}

                        {!depsShowAll && totalDepsGroupsAfterFilter > 30 && (
                          <div className="p-3 text-xs text-muted-foreground">
                            Showing first 30 results. Click “Show all”.
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Vulns list */}
              <div className="rounded-md border p-3 space-y-3">
                <div className="border rounded-md p-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityFilter value={vulnFilter} onChange={setVulnFilter} counts={vulnCountsAll} total={vulns.length} />
                    <div className="flex-1" />
                    <Input
                      className="w-[260px]"
                      placeholder="Search vulnerabilities…"
                      value={vulnSearch}
                      onChange={(e) => setVulnSearch(e.target.value)}
                    />
                    <Button variant="secondary" onClick={() => setVulnShowAll((v) => !v)}>
                      {vulnShowAll ? "Show 30" : "Show all"}
                      <span className="ml-2 text-xs opacity-80">{totalVulnsAfterFilter}</span>
                    </Button>
                  </div>
                </div>

                {vulnNote && <div className="text-sm text-muted-foreground border rounded-md p-3">{vulnNote}</div>}

                {visibleVulns.length === 0 ? (
                  <div className="text-sm text-muted-foreground">
                    {vulns.length === 0 ? "No results yet. Click “Run scan”." : "No results match your filters."}
                  </div>
                ) : (
                  <div className="rounded-md border overflow-hidden">
                    <div className="grid grid-cols-[150px_1fr_260px] gap-2 px-3 py-2 text-xs text-muted-foreground border-b bg-muted/10">
                      <div>Severity</div>
                      <div>Finding</div>
                      <div className="text-right">Actions</div>
                    </div>

                    {visibleVulns.map((v) => {
                      const isOpen = openVulnId === v.id;
                      return (
                        <div key={v.id} className="border-b">
                          <div
                            className={`px-3 py-2 grid grid-cols-[150px_1fr_260px] gap-2 items-center hover:bg-muted/20 cursor-pointer ${
                              isOpen ? "bg-muted/15" : ""
                            }`}
                            onClick={() => setOpenVulnId((prev) => (prev === v.id ? "" : v.id))}
                          >
                            <div className="flex items-center gap-2">
                              <SeverityBadge s={v.severity} />
                              <span className={`cipher-chevron ${isOpen ? "open" : ""}`} aria-hidden />
                            </div>

                            <div className="min-w-0">
                              <div className="text-sm font-medium truncate">{v.title}</div>
                              <div className="text-xs text-muted-foreground truncate">
                                <span
                                  className="cipher-link"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setOpenVulnId(v.id);
                                    jumpToLocation(v.file, v.line, v.line, "Jumped to finding ✅");
                                  }}
                                  role="button"
                                  title="Jump to code"
                                >
                                  {v.file}:{v.line}
                                </span>{" "}
                                • {v.type}
                              </div>
                            </div>

                            <div className="flex items-center justify-end gap-2">
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setOpenVulnId(v.id); // ✅ View expande también
                                  jumpToLocation(v.file, v.line, v.line);
                                }}
                              >
                                View
                              </Button>

                              <Button
                                size="sm"
                                variant="secondary"
                                disabled={patchBusyId === v.id}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setOpenVulnId(v.id);
                                  generatePatch(
                                    v.file,
                                    v.title,
                                    `Severity: ${v.severity}\nType: ${v.type}\nRecommendation: ${v.recommendation}\nLocation: ${v.file}:${v.line}\n\nSnippet:\n${v.snippet}`,
                                    v.id,
                                    v.line
                                  );
                                }}
                              >
                                {patchBusyId === v.id ? "Generating…" : "Patch"}
                              </Button>
                            </div>
                          </div>

                          {isOpen && (
                            <div className="px-3 pb-3 pt-1 space-y-2">
                              <pre className="text-xs whitespace-pre-wrap bg-muted/10 rounded-md p-3 border">{v.snippet}</pre>

                              <div className="text-sm">
                                <span className="font-medium">Recommendation: </span>
                                {v.recommendation}
                              </div>

                              {v.fix && (
                                <div className="text-sm">
                                  <span className="font-medium">Suggested fix: </span>
                                  {v.fix}
                                  {typeof v.confidence === "number" && (
                                    <span className="text-muted-foreground"> (confidence {v.confidence.toFixed(2)})</span>
                                  )}
                                </div>
                              )}

                              <div className="flex flex-wrap gap-2">
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  onClick={async () => {
                                    await copyToClipboard(`${v.file}:${v.line}`);
                                    flashCopy();
                                    flashMsg("Copied location ✅");
                                  }}
                                >
                                  Copy loc
                                </Button>
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  onClick={async () => {
                                    await copyToClipboard(v.snippet);
                                    flashCopy();
                                    flashMsg("Copied snippet ✅");
                                  }}
                                >
                                  Copy snippet
                                </Button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}

                    {!vulnShowAll && totalVulnsAfterFilter > 30 && (
                      <div className="p-3 text-xs text-muted-foreground">Showing first 30 results. Click “Show all”.</div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === "debt" && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-lg font-semibold">Tech Debt</h2>
                <Button onClick={runDebtScan} disabled={debtBusy}>
                  {debtBusy ? "Scanning…" : "Run scan"}
                </Button>
              </div>

              <div className="rounded-md border p-3 space-y-3">
                <div className="border rounded-md p-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityFilter value={debtFilter} onChange={setDebtFilter} counts={debtCountsAll} total={debt.length} />
                    <div className="flex-1" />
                    <Input
                      className="w-[260px]"
                      placeholder="Search tech debt…"
                      value={debtSearch}
                      onChange={(e) => setDebtSearch(e.target.value)}
                    />
                    <Button variant="secondary" onClick={() => setDebtShowAll((v) => !v)}>
                      {debtShowAll ? "Show 30" : "Show all"}
                      <span className="ml-2 text-xs opacity-80">{totalDebtAfterFilter}</span>
                    </Button>
                  </div>
                </div>

                {debtNote && <div className="text-sm text-muted-foreground border rounded-md p-3">{debtNote}</div>}

                {visibleDebt.length === 0 ? (
                  <div className="text-sm text-muted-foreground">
                    {debt.length === 0 ? "No results yet. Click “Run scan”." : "No results match your filters."}
                  </div>
                ) : (
                  <div className="rounded-md border overflow-hidden">
                    <div className="grid grid-cols-[150px_1fr_240px] gap-2 px-3 py-2 text-xs text-muted-foreground border-b bg-muted/10">
                      <div>Severity</div>
                      <div>Issue</div>
                      <div className="text-right">Actions</div>
                    </div>

                    {visibleDebt.map((d) => {
                      const isOpen = openDebtId === d.id;
                      return (
                        <div key={d.id} className="border-b">
                          <div
                            className={`px-3 py-2 grid grid-cols-[150px_1fr_240px] gap-2 items-center hover:bg-muted/20 cursor-pointer ${
                              isOpen ? "bg-muted/15" : ""
                            }`}
                            onClick={() => setOpenDebtId((prev) => (prev === d.id ? "" : d.id))}
                          >
                            <div className="flex items-center gap-2">
                              <SeverityBadge s={d.severity} />
                              <span className={`cipher-chevron ${isOpen ? "open" : ""}`} aria-hidden />
                            </div>

                            <div className="min-w-0">
                              <div className="text-sm font-medium truncate">{d.title}</div>
                              <div className="text-xs text-muted-foreground truncate">
                                <span
                                  className="cipher-link"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setOpenDebtId(d.id);
                                    jumpToLocation(d.file, d.line, d.line, "Jumped to issue ✅");
                                  }}
                                  role="button"
                                  title="Jump to code"
                                >
                                  {d.file}:{d.line}
                                </span>{" "}
                                • {d.type}
                              </div>
                            </div>

                            <div className="flex items-center justify-end gap-2">
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setOpenDebtId(d.id); // ✅ View expande
                                  jumpToLocation(d.file, d.line, d.line);
                                }}
                              >
                                View
                              </Button>

                              <Button
                                size="sm"
                                variant="secondary"
                                disabled={patchBusyId === d.id}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setOpenDebtId(d.id);
                                  generatePatch(
                                    d.file,
                                    d.title,
                                    `Severity: ${d.severity}\nType: ${d.type}\nLocation: ${d.file}:${d.line}\n\nDetails: ${d.details}\nSuggestion: ${d.suggestion}`,
                                    d.id,
                                    d.line
                                  );
                                }}
                              >
                                {patchBusyId === d.id ? "Generating…" : "Patch"}
                              </Button>
                            </div>
                          </div>

                          {isOpen && (
                            <div className="px-3 pb-3 pt-1 space-y-2">
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
                                    <span className="text-muted-foreground"> (confidence {d.confidence.toFixed(2)})</span>
                                  )}
                                </div>
                              )}

                              <div className="flex flex-wrap gap-2">
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  onClick={async () => {
                                    await copyToClipboard(`${d.file}:${d.line}`);
                                    flashCopy();
                                    flashMsg("Copied location ✅");
                                  }}
                                >
                                  Copy loc
                                </Button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}

                    {!debtShowAll && totalDebtAfterFilter > 30 && (
                      <div className="p-3 text-xs text-muted-foreground">Showing first 30 results. Click “Show all”.</div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ✅ NEW: DOCS (Priority C) — sin tocar tu diseño, solo nuevo tab */}
          {tab === "docs" && (
            <div className="grid gap-4 md:grid-cols-[340px_1fr]">
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <div className="text-sm font-medium">Docs</div>
                    <div className="text-xs text-muted-foreground">Auto-generated per file (cached)</div>
                  </div>

                  <Button variant="secondary" onClick={generateDocsIndex} disabled={docsIndexBusy}>
                    {docsIndexBusy ? "Generating…" : "Generate index"}
                  </Button>
                </div>

                <Input placeholder="Search docs…" value={docsQ} onChange={(e) => setDocsQ(e.target.value)} />

                <div className="h-[520px] overflow-auto rounded-md border">
                  {docsIndexFiltered.length === 0 ? (
                    <div className="p-3 text-sm text-muted-foreground">
                      {docsIndex.length === 0 ? "No docs index yet. Click “Generate index”." : "No matches."}
                    </div>
                  ) : (
                    docsIndexFiltered.map((it) => (
                      <button
                        key={it.path}
                        onClick={() => openDoc(it.path)}
                        className={`w-full text-left text-sm px-3 py-2 border-b hover:bg-muted/30 ${
                          docSelected === it.path ? "bg-muted/40" : ""
                        }`}
                      >
                        <div className="font-medium truncate">{it.title || it.path}</div>
                        <div className="text-xs text-muted-foreground truncate">{it.path}</div>
                        <div className="text-xs text-muted-foreground truncate">{it.purpose}</div>
                      </button>
                    ))
                  )}
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm text-muted-foreground truncate">
                    {docSelected ? docSelected : "Select a doc item"}
                  </div>

                  <div className="flex gap-2">
                    <Button
                      variant="secondary"
                      disabled={!docSelected}
                      onClick={() => {
                        if (!docSelected) return;
                        jumpToLocation(docSelected, 1, 1, "Opened file ✅");
                      }}
                    >
                      Open file
                    </Button>
                  </div>
                </div>

                {docsErr && (
                  <pre className="whitespace-pre-wrap text-sm p-4 rounded-md border border-red-500/40">{docsErr}</pre>
                )}

                {docsBusy && <div className="text-sm text-muted-foreground">Generating docs…</div>}

                {!docsBusy && doc && (
                  <div className="rounded-md border p-4 space-y-3">
                    <div>
                      <div className="text-lg font-semibold">{doc.title}</div>
                      <div className="text-xs text-muted-foreground">{doc.updatedAt}</div>
                    </div>

                    <div className="text-sm">
                      <span className="font-medium">Purpose: </span>
                      <span className="text-muted-foreground">{doc.purpose}</span>
                    </div>

                    <DocList label="Inputs" items={doc.inputs} />
                    <DocList label="Outputs" items={doc.outputs} />
                    <DocList label="Side effects" items={doc.sideEffects} />
                    <DocList label="Uses" items={doc.uses} />
                    <DocList label="Used by" items={doc.usedBy} />
                    <DocList label="Risks" items={doc.risks} />
                    <DocList label="Examples" items={doc.examples} />
                    <DocList label="Notes" items={doc.notes} />
                  </div>
                )}

                {!docsBusy && !doc && !docsErr && (
                  <div className="text-sm text-muted-foreground">Pick an item from the index.</div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Patch preview modal */}
      {patchOpen && patch && (
        <div className="fixed inset-0 z-50">
          <div className="absolute inset-0 bg-black/50" onClick={closePatchModal} />
          <div className="absolute inset-0 flex items-center justify-center p-4">
            <div className="w-full max-w-5xl rounded-xl border bg-background shadow-xl">
              <div className="p-4 border-b flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-semibold truncate">
                    Patch preview — <span className="text-muted-foreground">{patch.file}</span>
                  </div>
                  {patch.note && <div className="text-xs text-muted-foreground mt-1">{patch.note}</div>}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant={copiedOk ? "default" : "secondary"}
                    onClick={async () => {
                      await copyToClipboard(patch.updated);
                      flashCopy();
                      flashMsg("Copied updated file ✅");
                    }}
                  >
                    {copiedOk ? "Copied ✓" : "Copy"}
                  </Button>

                  <Button
                    variant={downloadOk ? "default" : "secondary"}
                    onClick={() => {
                      const name = `cipher-ai-patched-${patch.file.replace(/[\/\\]/g, "_")}`;
                      downloadText(name, patch.updated);
                      flashDownload();
                      flashMsg("Downloaded updated file ✅");
                    }}
                  >
                    {downloadOk ? "Downloaded ✓" : "Download"}
                  </Button>

                  <Button onClick={applyPatchPreview}>Apply preview</Button>

                  <Button variant="secondary" onClick={openPatchedInEditorOneOff}>
                    Open patched
                  </Button>

                  <Button variant="secondary" onClick={openOriginalFileInEditor}>
                    Open file
                  </Button>

                  <Button onClick={closePatchModal}>Close</Button>
                </div>
              </div>

              <div className="p-4 space-y-3">
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant={patchView === "compare" ? "default" : "secondary"}
                    onClick={() => setPatchView("compare")}
                  >
                    Compare
                  </Button>
                  <Button
                    variant={patchView === "updated" ? "default" : "secondary"}
                    onClick={() => setPatchView("updated")}
                  >
                    Updated file
                  </Button>
                  <Button variant={patchView === "diff" ? "default" : "secondary"} onClick={() => setPatchView("diff")}>
                    Unified diff
                  </Button>
                </div>

                {patchView === "compare" && (
                  <div className="rounded-md border overflow-hidden">
                    <DiffEditor
                      height="560px"
                      language={guessLanguage(patch.file)}
                      original={patch.original}
                      modified={patch.updated}
                      options={{
                        readOnly: true,
                        renderSideBySide: false,
                        minimap: { enabled: false },
                        scrollBeyondLastLine: false,
                        wordWrap: "on",
                      }}
                    />
                  </div>
                )}

                {patchView === "updated" && (
                  <div className="rounded-md border overflow-hidden">
                    <Editor
                      height="560px"
                      language={guessLanguage(patch.file)}
                      value={patch.updated}
                      options={{
                        readOnly: true,
                        minimap: { enabled: false },
                        scrollBeyondLastLine: false,
                        wordWrap: "on",
                      }}
                    />
                  </div>
                )}

                {patchView === "diff" && (
                  <div className="rounded-md border overflow-hidden">
                    <div className="p-2 border-b flex items-center justify-between gap-2">
                      <div className="text-sm text-muted-foreground">Smart unified diff (hunks)</div>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={async () => {
                            await copyToClipboard(patch.diff);
                            flashCopy();
                            flashMsg("Copied unified diff ✅");
                          }}
                        >
                          Copy diff
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => {
                            const name = `cipher-ai-diff-${patch.file.replace(/[\/\\]/g, "_")}.diff`;
                            downloadText(name, patch.diff);
                            flashMsg("Downloaded diff ✅");
                          }}
                        >
                          Download diff
                        </Button>
                      </div>
                    </div>
                    <pre className="text-xs whitespace-pre-wrap p-3 bg-muted/10 overflow-auto max-h-[560px]">{patch.diff}</pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Global styles */}
      <style jsx global>{`
        .cipher-revealLine {
          background: rgba(255, 200, 0, 0.18);
          outline: 1px solid rgba(255, 200, 0, 0.35);
        }
        .cipher-revealLineGutter {
          border-left: 3px solid rgba(255, 200, 0, 0.9);
        }
        .cipher-link {
          cursor: pointer;
          text-decoration: underline;
          text-underline-offset: 3px;
          opacity: 0.95;
        }
        .cipher-link:hover {
          opacity: 1;
        }

        /* inline chevron (no libs) + rotate */
        .cipher-chevron {
          display: inline-block;
          width: 9px;
          height: 9px;
          border-right: 2px solid currentColor;
          border-bottom: 2px solid currentColor;
          transform: rotate(-45deg);
          transition: transform 140ms ease, opacity 140ms ease;
          opacity: 0.7;
          translate: 0 -1px;
        }
        .cipher-chevron.open {
          transform: rotate(45deg);
          opacity: 0.95;
        }
      `}</style>
    </main>
  );
}

function DocList({ label, items }: { label: string; items?: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="space-y-1">
      <div className="text-sm font-medium">{label}</div>
      <ul className="list-disc pl-5 text-sm text-muted-foreground space-y-1">
        {items.slice(0, 12).map((x, i) => (
          <li key={i}>{x}</li>
        ))}
      </ul>
    </div>
  );
}

function SeverityPill({ s, n }: { s: Severity; n: number }) {
  const variant =
    s === "CRITICAL" ? "destructive" : s === "HIGH" ? "default" : s === "MEDIUM" ? "secondary" : "outline";
  return (
    <Badge variant={variant as any} title={`${s} findings`}>
      {s}: {n}
    </Badge>
  );
}

function SeverityBadge({ s }: { s: Severity }) {
  const variant =
    s === "CRITICAL" ? "destructive" : s === "HIGH" ? "default" : s === "MEDIUM" ? "secondary" : "outline";
  return <Badge variant={variant as any}>{s}</Badge>;
}

function SeverityFilter({
  value,
  onChange,
  counts,
  total,
}: {
  value: "ALL" | Severity;
  onChange: (v: "ALL" | Severity) => void;
  counts: Record<Severity, number>;
  total: number;
}) {
  const items: Array<{ key: "ALL" | Severity; label: string; count: number }> = [
    { key: "ALL", label: "All", count: total },
    { key: "CRITICAL", label: "Critical", count: counts.CRITICAL },
    { key: "HIGH", label: "High", count: counts.HIGH },
    { key: "MEDIUM", label: "Medium", count: counts.MEDIUM },
    { key: "LOW", label: "Low", count: counts.LOW },
  ];

  return (
    <div className="flex flex-wrap items-center gap-2">
      {items.map((it) => (
        <Button
          key={it.key}
          size="sm"
          variant={value === it.key ? "default" : "secondary"}
          onClick={() => onChange(it.key)}
          className="h-8"
        >
          {it.label} <span className="ml-2 text-xs opacity-80">{it.count}</span>
        </Button>
      ))}
    </div>
  );
}

function countBySeverity<T extends { severity: Severity }>(arr: T[]) {
  return arr.reduce(
    (acc, x) => {
      acc[x.severity] += 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<Severity, number>
  );
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

function pickBestFixedVersion(ecosystem: "npm" | "PyPI", a?: string, b?: string) {
  if (!a) return b;
  if (!b) return a;
  if (ecosystem === "npm") {
    return semverGt(b, a) ? b : a;
  }
  // PyPI: best-effort numeric compare
  return pep440Gt(b, a) ? b : a;
}

function semverGt(a: string, b: string) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return a.localeCompare(b) > 0;
  if (pa[0] !== pb[0]) return pa[0] > pb[0];
  if (pa[1] !== pb[1]) return pa[1] > pb[1];
  return pa[2] > pb[2];
}
function parseSemver(v: string): [number, number, number] | null {
  const m = String(v).trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}
function pep440Gt(a: string, b: string) {
  const na = pepNums(a);
  const nb = pepNums(b);
  const L = Math.max(na.length, nb.length);
  for (let i = 0; i < L; i++) {
    const ai = na[i] ?? 0;
    const bi = nb[i] ?? 0;
    if (ai !== bi) return ai > bi;
  }
  return false;
}
function pepNums(v: string) {
  const parts = String(v).split(/[^0-9]+/).filter(Boolean).map((x) => Number(x));
  return parts.length ? parts : [0];
}

/**
 * Smart unified diff without external deps.
 * Myers diff on lines + context hunks.
 */
function unifiedDiffFromTexts(file: string, oldText: string, newText: string, context = 3) {
  const oldLines = splitLines(oldText);
  const newLines = splitLines(newText);

  const maxLines = 2400;
  if (oldLines.length > maxLines || newLines.length > maxLines) {
    return (
      `--- a/${file}\n+++ b/${file}\n@@ -1,${oldLines.length} +1,${newLines.length} @@\n` +
      `# Diff is large (${oldLines.length}→${newLines.length} lines). Use Compare view.\n`
    );
  }

  const edits = myersDiffLines(oldLines, newLines);
  const records = editsToRecords(edits);
  const hunks = buildHunks(records, context);
  const header = `--- a/${file}\n+++ b/${file}\n`;

  if (hunks.length === 0) return header + `@@ -0,0 +0,0 @@\n# No changes.\n`;

  let out = header;
  for (const h of hunks) {
    out += `@@ -${h.oldStart},${h.oldCount} +${h.newStart},${h.newCount} @@\n`;
    for (const r of h.lines) out += r + "\n";
  }
  return out.trimEnd() + "\n";
}

function splitLines(text: string) {
  const t = text.replace(/\r\n/g, "\n");
  const endsWithNewline = t.endsWith("\n");
  const parts = t.split("\n");
  if (endsWithNewline) parts.pop();
  return parts;
}

type Edit = { type: "equal" | "insert" | "delete"; line: string };

function myersDiffLines(a: string[], b: string[]): Edit[] {
  const N = a.length;
  const M = b.length;
  const max = N + M;
  const offset = max;

  let v = new Int32Array(2 * max + 1);
  const trace: Int32Array[] = [];

  for (let d = 0; d <= max; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      const idx = k + offset;

      let x: number;
      if (k === -d || (k !== d && v[idx - 1] < v[idx + 1])) x = v[idx + 1];
      else x = v[idx - 1] + 1;

      let y = x - k;

      while (x < N && y < M && a[x] === b[y]) {
        x++;
        y++;
      }

      v[idx] = x;
      if (x >= N && y >= M) return backtrack(trace, a, b, offset);
    }
  }
  return backtrack(trace, a, b, offset);
}

function backtrack(trace: Int32Array[], a: string[], b: string[], offset: number): Edit[] {
  let x = a.length;
  let y = b.length;
  const edits: Edit[] = [];

  for (let d = trace.length - 1; d >= 0; d--) {
    const v = trace[d];
    const k = x - y;
    const idx = k + offset;

    let prevK: number;
    if (k === -d || (k !== d && v[idx - 1] < v[idx + 1])) prevK = k + 1;
    else prevK = k - 1;

    const prevX = v[prevK + offset];
    const prevY = prevX - prevK;

    while (x > prevX && y > prevY) {
      edits.push({ type: "equal", line: a[x - 1] });
      x--;
      y--;
    }
    if (d === 0) break;

    if (x === prevX) edits.push({ type: "insert", line: b[prevY] });
    else edits.push({ type: "delete", line: a[prevX] });

    x = prevX;
    y = prevY;
  }

  edits.reverse();
  return edits;
}

type RecordLine = {
  type: "equal" | "insert" | "delete";
  line: string;
  oldLine: number;
  newLine: number;
};

function editsToRecords(edits: Edit[]): RecordLine[] {
  let oldLine = 1;
  let newLine = 1;
  const out: RecordLine[] = [];

  for (const e of edits) {
    if (e.type === "equal") {
      out.push({ type: "equal", line: e.line, oldLine, newLine });
      oldLine++;
      newLine++;
    } else if (e.type === "delete") {
      out.push({ type: "delete", line: e.line, oldLine, newLine });
      oldLine++;
    } else {
      out.push({ type: "insert", line: e.line, oldLine, newLine });
      newLine++;
    }
  }
  return out;
}

function buildHunks(records: RecordLine[], context: number) {
  const hunks: Array<{ oldStart: number; newStart: number; oldCount: number; newCount: number; lines: string[] }> = [];
  let i = 0;

  while (i < records.length) {
    if (records[i].type === "equal") {
      i++;
      continue;
    }

    const start = Math.max(0, i - context);

    let lastChange = i;
    let j = i;
    while (j < records.length) {
      if (records[j].type !== "equal") lastChange = j;
      if (j - lastChange > context) break;
      j++;
    }
    const end = Math.min(records.length, j);

    const oldStart = records[start].oldLine;
    const newStart = records[start].newLine;

    let oldCount = 0;
    let newCount = 0;
    const lines: string[] = [];

    for (let k = start; k < end; k++) {
      const r = records[k];
      if (r.type !== "insert") oldCount++;
      if (r.type !== "delete") newCount++;

      if (r.type === "equal") lines.push(" " + r.line);
      if (r.type === "delete") lines.push("-" + r.line);
      if (r.type === "insert") lines.push("+" + r.line);
    }

    hunks.push({ oldStart, newStart, oldCount, newCount, lines });
    i = end;
  }

  return hunks;
}
