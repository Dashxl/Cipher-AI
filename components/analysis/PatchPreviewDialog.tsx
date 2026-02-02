"use client";

import { useMemo, useRef, useState } from "react";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Copy, Check, Download, FileCode2, Sparkles, X } from "lucide-react";

export type PatchPreviewState = {
  open: boolean;
  file: string;
  diff: string;
  note?: string;
  line?: number;
  updatedContent?: string; // ✅
};

type Props = {
  value: PatchPreviewState;
  onChange: (next: PatchPreviewState) => void;
  onOpenFile: (file: string, line?: number) => void;
  onPreviewPatch: (file: string, updatedContent: string, line?: number) => void; // ✅
};

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

export function PatchPreviewDialog({ value, onChange, onOpenFile, onPreviewPatch }: Props) {
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<number | null>(null);

  const filename = useMemo(() => {
    const safe = (value.file || "patch").replace(/[\/\\]/g, "_");
    return `cipher-ai-${safe}.diff`;
  }, [value.file]);

  function close() {
    onChange({ ...value, open: false });
  }

  async function copyDiff() {
    await copyToClipboard(value.diff || "");
    setCopied(true);
    if (copyTimer.current) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopied(false), 1200);
  }

  function downloadDiff() {
    const blob = new Blob([value.diff || ""], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function openFile() {
    onOpenFile(value.file, value.line);
    close();
  }

  function applyPreview() {
    const content = (value.updatedContent ?? "").trim();
    if (!content) return;
    onPreviewPatch(value.file, content, value.line);
    close();
  }

  const canPreview = Boolean((value.updatedContent ?? "").trim().length);

  return (
    <Dialog open={value.open} onOpenChange={(open) => onChange({ ...value, open })}>
      <DialogContent className="p-0 w-[95vw] max-w-5xl h-[88vh] overflow-hidden">
        {/* Header */}
        <div className="px-4 py-3 border-b bg-background/80 backdrop-blur">
          <div className="flex items-start gap-3">
            <div className="min-w-0">
              <div className="font-semibold leading-tight">
                Patch preview{" "}
                <span className="text-muted-foreground font-mono">
                  {value.file}
                  {typeof value.line === "number" ? `:${value.line}` : ""}
                </span>
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                Unified diff preview (smart hunks). Apply preview to persist it in Explore.
              </div>
            </div>

            <div className="flex-1" />

            <Button size="icon" variant="ghost" className="h-8 w-8" onClick={close} title="Close">
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Actions */}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Badge variant="secondary" className="h-6">
              Diff
            </Badge>

            {value.note ? (
              <div className="text-xs text-muted-foreground truncate max-w-[68ch]">
                {value.note}
              </div>
            ) : null}

            <div className="flex-1" />

            <Button size="sm" variant={copied ? "default" : "secondary"} onClick={copyDiff} className="h-8">
              {copied ? <Check className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
              {copied ? "Copied ✓" : "Copy diff"}
            </Button>

            <Button size="sm" variant="secondary" onClick={downloadDiff} className="h-8">
              <Download className="h-4 w-4 mr-2" />
              Download
            </Button>

            <Button size="sm" onClick={applyPreview} disabled={!canPreview} className="h-8">
              <Sparkles className="h-4 w-4 mr-2" />
              Apply preview
            </Button>

            <Button size="sm" variant="secondary" onClick={openFile} className="h-8">
              <FileCode2 className="h-4 w-4 mr-2" />
              Open file
            </Button>
          </div>
        </div>

        {/* Body */}
        <div className="p-4 h-[calc(88vh-112px)] overflow-auto">
          <pre className="rounded-2xl border bg-muted/10 p-3 text-xs leading-relaxed whitespace-pre font-mono">
{value.diff || "(empty diff)"}
          </pre>

          {!canPreview ? (
            <div className="mt-3 text-xs text-muted-foreground">
              Note: <span className="font-medium">updatedContent</span> no viene en este diálogo, así que “Apply preview” estará deshabilitado.
              (Esto es normal si este componente solo se usa para ver diffs.)
            </div>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
