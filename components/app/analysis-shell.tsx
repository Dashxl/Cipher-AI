//src/components/app/analysis-shell.tsx
"use client";
import { KeyRound } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Archive,
  BookOpen,
  Bug,
  ClipboardCopy,
  Download,
  FileCode2,
  FileDown,
  FileText,
  LayoutDashboard,
  Menu,
  Moon,
  Package,
  Sun,
  ShieldAlert,
  Wrench,
  X,
} from "lucide-react";

export const ShellIcons = {
  Overview: LayoutDashboard,
  Explore: FileCode2,
  Vuln: ShieldAlert,
  Deps: Package,
  Debt: Wrench,
  Docs: BookOpen,
  Export: Download,
  Md: FileText,
  Pdf: FileDown,
  Zip: Archive,
  Theme: Moon,
} as const;

export type NavItem = {
  id: string;
  label: string;
  icon?: any;
  badge?: number | string;
  active?: boolean;
  onClick?: () => void;
  /** visually indented, used for “Dependency CVEs” pseudo-item */
  pseudo?: boolean;
  /** rendered lower emphasis (e.g., Export actions) */
  secondary?: boolean;
};

export type NavGroup = { title: string; items: NavItem[] };

type Props = {
  repoName: string;
  analysisId: string;
  stage: string;
  message?: string;
  progress?: number;

  highPlusOnly: boolean;
  highPlusTotal: number;
  onToggleHighPlus: () => void;

  actionMsg?: string;

  nav: NavGroup[];

  onExportMd?: () => void;
  onExportPdf?: () => void;
  onExportZip?: () => void;
  exportZipEnabled?: boolean;

  children: React.ReactNode;
};

function shortId(id: string) {
  const s = String(id || "");
  if (s.length <= 10) return s;
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

export function AnalysisShell({
  repoName,
  analysisId,
  stage,
  message,
  progress = 0,
  highPlusOnly,
  highPlusTotal,
  onToggleHighPlus,
  actionMsg,
  nav,
  onExportMd,
  onExportPdf,
  onExportZip,
  exportZipEnabled,
  children,
}: Props) {
  // Drawer nav for ALL screen sizes
const [navOpen, setNavOpen] = useState(false);
const [copied, setCopied] = useState(false);

// Theme (light/dark) — persisted
const [theme, setTheme] = useState<"light" | "dark">("light");

function applyTheme(next: "light" | "dark") {
  setTheme(next);
  try {
    localStorage.setItem("cipher.theme", next);
  } catch {
    // ignore
  }
  const root = document.documentElement;
  root.classList.toggle("dark", next === "dark");
  // Better native form rendering
  root.style.colorScheme = next;
}

useEffect(() => {
  // Initial theme
  try {
    const saved = localStorage.getItem("cipher.theme");
    if (saved === "light" || saved === "dark") {
      applyTheme(saved);
      return;
    }
  } catch {
    // ignore
  }

  const prefersDark =
    typeof window !== "undefined" &&
    window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;

  applyTheme(prefersDark ? "dark" : "light");
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, []);

function toggleTheme() {
  applyTheme(theme === "dark" ? "light" : "dark");
}

  async function copyId() {
    try {
      await navigator.clipboard.writeText(String(analysisId || ""));
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch {
      // ignore
    }
  }

  const exportButtons = useMemo(() => {
    const items: Array<{
      id: string;
      label: string;
      icon: any;
      onClick?: () => void;
      enabled: boolean;
    }> = [
      { id: "md", label: "Markdown", icon: FileText, onClick: onExportMd, enabled: typeof onExportMd === "function" },
      { id: "pdf", label: "PDF", icon: FileDown, onClick: onExportPdf, enabled: typeof onExportPdf === "function" },
      {
        id: "zip",
        label: "Patched ZIP",
        icon: Archive,
        onClick: onExportZip,
        enabled: !!exportZipEnabled && typeof onExportZip === "function",
      },
    ];
    return items.filter((x) => x.enabled);
  }, [onExportMd, onExportPdf, onExportZip, exportZipEnabled]);

  // UX: ESC closes drawer + lock body scroll while open
  useEffect(() => {
    if (!navOpen) return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNavOpen(false);
    };

    window.addEventListener("keydown", onKeyDown);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = prevOverflow;
    };
  }, [navOpen]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="flex min-h-screen">
        {/* Content column (full width; nav is a drawer) */}
        <div className="flex-1 min-w-0">
          {/* Topbar */}
          <header className="sticky top-0 z-40 border-b bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/65">
            <div className="mx-auto w-full max-w-[1300px] px-4 md:px-6 h-14 flex items-center gap-2">
              {/* Menu button visible on ALL sizes */}
              <Button
                variant="ghost"
                size="icon"
                className="h-9 w-9"
                onClick={() => setNavOpen(true)}
                title="Open navigation"
              >
                <Menu className="h-4 w-4" />
              </Button>

              <div className="min-w-0">
                <div className="flex items-center gap-2 min-w-0">
                  <div className="text-sm font-semibold truncate">{repoName}</div>
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <span className="font-mono">{shortId(analysisId)}</span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={copyId}
                      title="Copy analysisId"
                    >
                      <ClipboardCopy className="h-3.5 w-3.5" />
                    </Button>
                    {copied ? <span className="text-[11px] text-muted-foreground">copied</span> : null}
                  </div>
                </div>

                <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                  <Badge variant="secondary" className="h-5 px-2">
                    {stage}
                  </Badge>
                  <span className="truncate">{message || ""}</span>
                </div>
              </div>

              <div className="flex-1" />


<Button
  variant="ghost"
  size="icon"
  className="h-9 w-9"
  onClick={toggleTheme}
  title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
>
  {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
</Button>

              <Button
                size="sm"
                className="h-8"
                variant={highPlusOnly ? "default" : "secondary"}
                onClick={onToggleHighPlus}
                title="Toggle High+ filter (CRITICAL + HIGH)"
              >
                High+
                <span className="ml-2 text-xs opacity-80 tabular-nums">{highPlusTotal}</span>
              </Button>

              <div className="hidden sm:flex items-center gap-2">
                {exportButtons.map((b) => {
                  const Icon = b.icon ?? Download;
                  return (
                    <Button
                      key={b.id}
                      size="sm"
                      variant="secondary"
                      className="h-8"
                      onClick={b.onClick}
                      title={`Export ${b.label}`}
                    >
                      <Icon className="h-4 w-4" />
                      <span className="ml-2">Export {b.label}</span>
                    </Button>
                  );
                })}
              </div>

              <div className="sm:hidden flex items-center gap-2">
                {exportButtons.map((b) => {
                  const Icon = b.icon ?? Download;
                  return (
                    <Button
                      key={b.id}
                      size="icon"
                      variant="secondary"
                      className="h-8 w-8"
                      onClick={b.onClick}
                      title={`Export ${b.label}`}
                    >
                      <Icon className="h-4 w-4" />
                    </Button>
                  );
                })}
              </div>
            </div>

            <div className="mx-auto w-full max-w-[1300px] px-4 md:px-6 pb-2">
              <div className="flex items-center gap-3">
                <div className="flex-1">
                  <Progress value={progress} className="h-2" />
                </div>
                {actionMsg ? (
                  <div
                    className="hidden md:block text-[11px] text-muted-foreground whitespace-nowrap"
                    aria-live="polite"
                  >
                    {actionMsg}
                  </div>
                ) : null}
              </div>
            </div>
          </header>

          {children}
        </div>

        {/* Drawer navigation (ALL sizes) */}
        {navOpen ? (
          <div className="fixed inset-0 z-50">
            <div className="absolute inset-0 bg-black/45 motion-safe:animate-in motion-safe:fade-in motion-safe:duration-150 motion-reduce:animate-none" onClick={() => setNavOpen(false)} />
            <div className="absolute inset-y-0 left-0 w-[86%] max-w-[360px] bg-background border-r shadow-2xl motion-safe:animate-in motion-safe:slide-in-from-left-6 motion-safe:duration-200 motion-reduce:animate-none">
              <div className="h-14 px-4 flex items-center gap-3 border-b">
                <div className="h-9 w-9 rounded-xl border bg-gradient-to-br from-violet-500/20 to-cyan-400/10 flex items-center justify-center">
                  <KeyRound className="h-4 w-4 text-violet-600/90 dark:text-violet-300/90" aria-hidden="true" />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold leading-none">Cipher AI</div>
                  <div className="text-[11px] text-muted-foreground leading-none mt-1 truncate">{repoName}</div>
                </div>
                <div className="flex-1" />
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-9 w-9"
                  onClick={() => setNavOpen(false)}
                  title="Close"
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>

              <nav className="h-[calc(100vh-3.5rem)] overflow-auto py-3 px-3">
                {nav.map((group) => (
                  <div key={group.title}>
                    <div className="px-2 py-2 text-[11px] uppercase tracking-wide text-muted-foreground">
                      {group.title}
                    </div>
                    <div className="space-y-1">
                      {group.items.map((it) => (
                        <NavButton
                          key={it.id}
                          item={it}
                          onSelect={() => {
                            it.onClick?.();
                            setNavOpen(false);
                          }}
                        />
                      ))}
                    </div>
                    <div className="my-3 h-px bg-border/60" />
                  </div>
                ))}
              </nav>
            </div>
          </div>
        ) : null}

        {actionMsg ? (
          <div className="pointer-events-none fixed bottom-4 right-4 z-[60]">
            <div className="pointer-events-auto rounded-2xl border bg-background/90 backdrop-blur px-3 py-2 shadow-lg text-xs flex items-center gap-2 motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-bottom-2 motion-safe:duration-200 motion-reduce:animate-none">
              <span className="h-2 w-2 rounded-full bg-primary/70" />
              <span className="text-foreground">{actionMsg}</span>
            </div>
          </div>
        ) : null}

      </div>
    </div>
  );
}

function NavButton({ item, onSelect }: { item: NavItem; onSelect: () => void }) {
  const Icon = item.icon ?? Bug;
  const isActive = !!item.active;

  return (
    <button
      onClick={onSelect}
      className={[
        "w-full rounded-xl px-3 py-2 text-left flex items-center gap-2 motion-safe:transition-colors motion-safe:transition-transform duration-150 active:scale-[0.99]",
        "focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        isActive ? "bg-muted/50" : "hover:bg-muted/30",
        item.secondary ? "opacity-85" : "",
        item.pseudo ? "pl-9" : "",
      ].join(" ")}
    >
      <Icon className={["h-4 w-4 shrink-0", item.pseudo ? "opacity-70" : ""].join(" ")} />
      <span className={["text-sm truncate", item.pseudo ? "text-[13px]" : ""].join(" ")}>
        {item.label}
      </span>
      <span className="flex-1" />
      {item.badge !== undefined ? (
        <Badge variant={isActive ? "default" : "secondary"} className="h-5 px-2 text-[11px] tabular-nums">
          {item.badge}
        </Badge>
      ) : null}
    </button>
  );
}
