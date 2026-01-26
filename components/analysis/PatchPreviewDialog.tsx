"use client";

import { useMemo, useState } from "react";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

export type PatchPreviewState = {
  open: boolean;
  file: string;
  diff: string;
  note?: string;
  line?: number;
  updatedContent?: string; // ✅ NEW
};

type Props = {
  value: PatchPreviewState;
  onChange: (next: PatchPreviewState) => void;
  onOpenFile: (file: string, line?: number) => void;
  onPreviewPatch: (file: string, updatedContent: string, line?: number) => void; // ✅ NEW
};

export function PatchPreviewDialog({ value, onChange, onOpenFile, onPreviewPatch }: Props) {
  const [copyState, setCopyState] = useState<"idle" | "ok" | "err">("idle");

  const filename = useMemo(() => {
    const safe = (value.file || "patch").replace(/[\/\\]/g, "_");
    return `cipher-ai-${safe}.diff`;
  }, [value.file]);

  function close() {
    onChange({ ...value, open: false });
    setCopyState("idle");
  }

  async function copyDiff() {
    try {
      await navigator.clipboard.writeText(value.diff || "");
      setCopyState("ok");
      setTimeout(() => setCopyState("idle"), 1200);
    } catch {
      setCopyState("err");
      setTimeout(() => setCopyState("idle"), 1600);
    }
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

  function previewPatch() {
    const content = (value.updatedContent ?? "").trim();
    if (!content) return;
    onPreviewPatch(value.file, content, value.line);
    close();
  }

  const canPreview = Boolean((value.updatedContent ?? "").trim().length);

  return (
    <Dialog open={value.open} onOpenChange={(open) => onChange({ ...value, open })}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Diff preview</DialogTitle>
        </DialogHeader>

        <div className="space-y-2">
          <div className="text-sm text-muted-foreground">
            <span className="font-mono">{value.file}</span>
            {typeof value.line === "number" ? <span>:{value.line}</span> : null}
          </div>

          {value.note ? (
            <div className="text-xs rounded-md border p-2 text-muted-foreground">
              {value.note}
            </div>
          ) : null}

          <pre className="max-h-[55vh] overflow-auto rounded-md border p-3 text-xs leading-relaxed whitespace-pre font-mono">
{value.diff || "(empty diff)"}
          </pre>
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <div className="flex w-full flex-col-reverse gap-2 sm:flex-row sm:justify-between">
            <Button variant="outline" onClick={close}>Close</Button>

            <div className="flex flex-wrap gap-2 justify-end">
              <Button variant="secondary" onClick={copyDiff}>
                {copyState === "ok" ? "Copied" : copyState === "err" ? "Copy failed" : "Copy diff"}
              </Button>
              <Button variant="secondary" onClick={downloadDiff}>Download diff</Button>
              <Button variant="secondary" disabled={!canPreview} onClick={previewPatch}>
                Preview patch
              </Button>
              <Button onClick={openFile}>Open file</Button>
            </div>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
