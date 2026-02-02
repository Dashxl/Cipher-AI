"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  PanelLeft,
  LayoutDashboard,
  Search,
  ShieldAlert,
  Package,
  Wrench,
  BookOpen,
  Download,
  Copy,
  Check,
  X,
  ChevronDown,
} from "lucide-react";

export type NavKey = "overview" | "explore" | "vuln" | "deps" | "debt" | "docs";

type Counts = {
  vulns: number;
  deps: number; // groups o findings, tú decides (ahorita úsalo como groups)
  debt: number;
  patched: number; // patched previews count (server best-effort)
};

type Props = {
  analysisId: string;
  repoName?: string | null;

  stage?: string | null;
  message?: string | null;
  progress?: number | null;
  lastUpdatedAt?: number | null;

  activeNav: NavKey;
  onNavigate: (k: NavKey) => void;

  counts: Counts;

  highPlusOnly?: boolean;
  highPlusTotal?: number;
  onToggleHighPlus?: () => void;

  onExportMd: () => void;
  onExportPdf: () => void;
  onExportZip?: () => void;
  canExportZip?: boolean;

  actionMsg?: string; // mensaje corto (copied/applied/etc)
  children: React.ReactNode;
};

const LS_SIDEBAR = "cipher:sidebar:collapsed:v1";

function shortId(id: string) {
  if (!id) return "";
  if (id.length <= 10) return id;
  return `${id.slice(0, 6)}…${id.slice(-4)}`;
}

function formatAgo(ts?: number | null) {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

export function AnalysisShell({
  analysisId,
  repoName,
  stage,
  message,
  progress,
  lastUpdatedAt,
  activeNav,
  onNavigate,
  counts,
  highPlusOnly,
  highPlusTotal,
  onToggleHighPlus,
  onExportMd,
  onExportPdf,
  onExportZip,
  canExportZip,
  actionMsg,
  children,
}: Props) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const [idCopied, setIdCopied] = useState(false);
  const idTimer = useRef<number | null>(null);

  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(LS_SIDEBAR);
      setCollapsed(raw === "1");
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(LS_SIDEBAR, collapsed ? "1" : "0");
    } catch {
      // ignore
    }
  }, [collapsed]);

  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (!exportOpen) return;
      const el = exportRef.current;
      if (!el) return;
      if (e.target instanceof Node && el.contains(e.target)) return;
      setExportOpen(false);
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [exportOpen]);

  async function copyAnalysisId() {
    try {
      await navigator.clipboard.writeText(analysisId);
      setIdCopied(true);
      if (idTimer.current) window.clearTimeout(idTimer.current);
      idTimer.current = window.setTimeout(() => setIdCopied(false), 1200);
    } catch {
      // ignore
    }
  }

  const updatedLabel = useMemo(() => formatAgo(lastUpdatedAt), [lastUpdatedAt]);

  function NavItem({
    k,
    label,
    icon,
    count,
  }: {
    k: NavKey;
    label: string;
    icon: React.ReactNode;
    count?: number;
  }) {
    const active = activeNav === k;
    return (
      <Button
        type="button"
        variant="ghost"
        onClick={() => {
          onNavigate(k);
          setMobileOpen(false);
        }}
        className={[
          "w-full justify-start gap-2 rounded-xl px-3 py-2 h-10",
          "text-muted-foreground hover:text-foreground hover:bg-accent/40",
          active ? "bg-primary/10 text-foreground font-semibold" : "",
          collapsed ? "px-2 justify-center" : "",
        ].join(" ")}
        title={label}
      >
        <span className={["shrink-0", active ? "text-[var(--primary)]" : ""].join(" ")}>{icon}</span>

        {!collapsed && (
          <span className="flex-1 min-w-0 truncate text-sm">{label}</span>
        )}

        {!collapsed && typeof count === "number" && (
          <Badge variant="secondary" className="ml-auto">
            {count}
          </Badge>
        )}

        {collapsed && typeof count === "number" && count > 0 && (
          <span
            className="absolute right-2 top-2 inline-flex h-5 min-w-[20px] items-center justify-center rounded-full bg-primary/15 px-1 text-[11px] text-foreground"
            aria-label={`${count}`}
          >
            {count}
          </span>
        )}
      </Button>
    );
  }

  function GroupLabel({ children }: { children: React.ReactNode }) {
    if (collapsed) return null;
    return (
      <div className="px-3 pt-4 pb-2 text-[11px] font-semibold tracking-wider text-muted-foreground/90">
        {children}
      </div>
    );
  }

  const SidebarInner = (
    <div className="h-full flex flex-col">
      {/* Brand */}
      <div className={["px-3 pt-3", collapsed ? "px-2" : ""].join(" ")}>
        <div className="flex items-center gap-2">
          <div
            className="h-9 w-9 rounded-2xl bg-primary/12 ring-1 ring-border/60 flex items-center justify-center"
            title="Cipher AI"
          >
            <span className="text-[13px] font-bold tracking-tight">C</span>
          </div>

          {!collapsed && (
            <div className="min-w-0">
              <div className="font-semibold leading-tight">Cipher AI</div>
              <div className="text-xs text-muted-foreground leading-tight">code archaeology</div>
            </div>
          )}

          <div className="flex-1" />

          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="hidden md:inline-flex"
            onClick={() => setCollapsed((v) => !v)}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <PanelLeft className="h-4 w-4" />
          </Button>

          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="md:hidden"
            onClick={() => setMobileOpen(false)}
            title="Close"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Nav */}
      <div className={["mt-3 px-2", collapsed ? "px-1" : ""].join(" ")}>
        <GroupLabel>ANALYSIS</GroupLabel>
        <NavItem k="overview" label="Overview" icon={<LayoutDashboard className="h-4 w-4" />} />

        <GroupLabel>EXPLORE</GroupLabel>
        <NavItem k="explore" label="Explore" icon={<Search className="h-4 w-4" />} count={counts.patched} />

        <GroupLabel>SCANS</GroupLabel>
        <NavItem k="vuln" label="Vulnerabilities" icon={<ShieldAlert className="h-4 w-4" />} count={counts.vulns} />
        <NavItem k="deps" label="Dependency CVEs" icon={<Package className="h-4 w-4" />} count={counts.deps} />
        <NavItem k="debt" label="Tech Debt" icon={<Wrench className="h-4 w-4" />} count={counts.debt} />

        <GroupLabel>DOCS</GroupLabel>
        <NavItem k="docs" label="Docs" icon={<BookOpen className="h-4 w-4" />} />
      </div>

      {/* Sidebar footer actions */}
      <div className={["mt-auto p-3", collapsed ? "px-2" : ""].join(" ")}>
        {!collapsed && (
          <div className="rounded-2xl border bg-card p-3 space-y-2">
            <div className="flex items-center gap-2">
              <Download className="h-4 w-4 text-muted-foreground" />
              <div className="text-sm font-medium">Export</div>
              <div className="flex-1" />
            </div>

            <div className="grid grid-cols-1 gap-2">
              <Button variant="secondary" onClick={onExportMd} className="justify-start">
                Export Markdown
              </Button>
              <Button onClick={onExportPdf} className="justify-start">
                Export PDF
              </Button>
              <Button
                variant="secondary"
                onClick={onExportZip}
                disabled={!canExportZip || !onExportZip}
                className="justify-start"
                title={canExportZip ? "Export patched ZIP" : "No patch previews yet"}
              >
                Export patched ZIP
              </Button>
            </div>
          </div>
        )}

        {collapsed && (
          <div className="flex flex-col gap-2">
            <Button variant="ghost" size="icon" onClick={onExportPdf} title="Export PDF">
              <Download className="h-4 w-4" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="flex min-h-screen">
        {/* Desktop sidebar */}
        <aside
          className={[
            "hidden md:flex sticky top-0 h-screen border-r bg-sidebar text-sidebar-foreground",
            collapsed ? "w-[76px]" : "w-[272px]",
          ].join(" ")}
        >
          {SidebarInner}
        </aside>

        {/* Mobile drawer */}
        {mobileOpen && (
          <div className="md:hidden fixed inset-0 z-50">
            <div
              className="absolute inset-0 bg-black/45"
              onClick={() => setMobileOpen(false)}
              aria-hidden="true"
            />
            <div className="absolute inset-y-0 left-0 w-[86%] max-w-[320px] border-r bg-sidebar text-sidebar-foreground shadow-xl">
              {SidebarInner}
            </div>
          </div>
        )}

        {/* Main */}
        <div className="flex-1 min-w-0">
          {/* Topbar */}
          <header className="cipher-glass sticky top-0 z-40">
            <div className="mx-auto max-w-[1280px] px-4 sm:px-6 h-14 flex items-center gap-3">
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="md:hidden"
                onClick={() => setMobileOpen(true)}
                title="Open menu"
              >
                <PanelLeft className="h-4 w-4" />
              </Button>

              <div className="min-w-0 flex items-center gap-2">
                <div className="font-semibold truncate max-w-[42vw] sm:max-w-[420px]">
                  {repoName || "Repository"}
                </div>

                <button
                  type="button"
                  className="inline-flex items-center gap-1 rounded-full border bg-card px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
                  onClick={copyAnalysisId}
                  title="Copy analysisId"
                >
                  <span className="font-mono">{shortId(analysisId)}</span>
                  {idCopied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>

              <div className="hidden lg:flex items-center gap-3 ml-2 min-w-0">
                {stage && <Badge variant="secondary">{stage}</Badge>}
                {message && <div className="text-xs text-muted-foreground truncate max-w-[420px]">{message}</div>}
                <div className="text-xs text-muted-foreground">Updated {updatedLabel}</div>
              </div>

              <div className="flex-1" />

              {/* High+ quick toggle (optional) */}
              {onToggleHighPlus && (
                <Button
                  variant={highPlusOnly ? "default" : "secondary"}
                  size="sm"
                  onClick={onToggleHighPlus}
                  className="hidden sm:inline-flex h-8"
                  title="Toggle High+ filter"
                >
                  {highPlusOnly ? "High+ ✓" : "High+"}
                  {typeof highPlusTotal === "number" && (
                    <span className="ml-2 text-xs opacity-80">{highPlusTotal}</span>
                  )}
                </Button>
              )}

              {/* Exports desktop */}
              <div className="hidden sm:flex items-center gap-2">
                <Button size="sm" variant="secondary" onClick={onExportMd} className="h-8">
                  MD
                </Button>
                <Button size="sm" onClick={onExportPdf} className="h-8">
                  PDF
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={onExportZip}
                  disabled={!canExportZip || !onExportZip}
                  className="h-8"
                  title={canExportZip ? "Export patched ZIP" : "No patch previews yet"}
                >
                  ZIP
                </Button>
              </div>

              {/* Exports mobile menu */}
              <div className="sm:hidden relative" ref={exportRef}>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  className="h-8"
                  onClick={() => setExportOpen((v) => !v)}
                >
                  Export <ChevronDown className="ml-1 h-4 w-4" />
                </Button>

                {exportOpen && (
                  <div
                    role="menu"
                    className="absolute right-0 mt-2 w-44 rounded-xl border bg-card shadow-lg overflow-hidden"
                  >
                    <button
                      className="w-full text-left px-3 py-2 text-sm hover:bg-accent/40"
                      onClick={() => {
                        setExportOpen(false);
                        onExportMd();
                      }}
                    >
                      Export Markdown
                    </button>
                    <button
                      className="w-full text-left px-3 py-2 text-sm hover:bg-accent/40"
                      onClick={() => {
                        setExportOpen(false);
                        onExportPdf();
                      }}
                    >
                      Export PDF
                    </button>
                    <button
                      className="w-full text-left px-3 py-2 text-sm hover:bg-accent/40 disabled:opacity-40"
                      disabled={!canExportZip || !onExportZip}
                      onClick={() => {
                        setExportOpen(false);
                        onExportZip?.();
                      }}
                    >
                      Export patched ZIP
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Progress row (mobile + tablet) */}
            <div className="lg:hidden mx-auto max-w-[1280px] px-4 sm:px-6 pb-3">
              <div className="flex items-center gap-2">
                {stage && <Badge variant="secondary">{stage}</Badge>}
                <div className="text-xs text-muted-foreground truncate flex-1">
                  {message || "—"}
                </div>
                <div className="text-xs text-muted-foreground">Updated {updatedLabel}</div>
              </div>

              <div className="mt-2">
                <Progress value={Number(progress ?? 0)} className="h-2" />
              </div>

              {actionMsg ? (
                <div className="mt-2 text-xs text-muted-foreground" aria-live="polite">
                  {actionMsg}
                </div>
              ) : null}
            </div>
          </header>

          {/* Content */}
          <main className="mx-auto max-w-[1280px] px-4 sm:px-6 py-6">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
