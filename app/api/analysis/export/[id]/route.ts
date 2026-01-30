import { NextResponse } from "next/server";
import { kvGet } from "@/lib/cache/store";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import type { AnalysisStatus } from "@/types/analysis";
import type { DebtIssue, VulnFinding, Severity, DepCveFinding } from "@/types/scan";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type VulnCache = { findings: VulnFinding[]; note?: string };
type DebtCache = { issues: DebtIssue[]; note?: string };

type DepsCache = {
  findings: DepCveFinding[];
  note?: string;
  scannedDeps?: number;
  totalParsedDeps?: number;
  manifestsUsed?: string[];
  uniqueVulnIds?: number;
  totalVulnHits?: number;
  truncated?: boolean;
};

type PatchCache = {
  analysisId: string;
  patchedCount: number;
  patchedFiles: string[];
  updatedAt?: string | null;
  exportedAt?: string | null;
  source?: string | null;
};

function sevRank(s: Severity) {
  return s === "CRITICAL" ? 0 : s === "HIGH" ? 1 : s === "MEDIUM" ? 2 : 3;
}

function mdEscape(s: string) {
  return (s ?? "").replace(/\r/g, "");
}

function safeName(s: string) {
  return (s || "cipher-ai").replace(/[^\w\-\.]+/g, "_").slice(0, 60);
}

function toWinAnsiSafe(s: string) {
  return (s ?? "")
    .replace(/\u2192/g, "->")
    .replace(/\u2190/g, "<-")
    .replace(/\u2191/g, "^")
    .replace(/\u2193/g, "v")
    .replace(/\u2013|\u2014/g, "-")
    .replace(/\u2018|\u2019/g, "'")
    .replace(/\u201C|\u201D/g, '"')
    .replace(/\u2022/g, "*")
    .replace(/\u00A0/g, " ");
}

function safeTextForPdf(s: string) {
  const t = toWinAnsiSafe(s);
  let out = "";
  for (let i = 0; i < t.length; i++) {
    const code = t.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13) {
      out += t[i];
      continue;
    }
    if (code >= 32 && code <= 255) out += t[i];
    else out += "?";
  }
  return out;
}

async function kvGetFirst<T>(keys: string[]): Promise<T | null> {
  for (const k of keys) {
    const v = await kvGet<T>(k);
    if (v) return v;
  }
  return null;
}

// ✅ FIX: Mermaid a multiline para que no se vea como “línea infinita” en PDF
function formatMermaidForReport(m: string) {
  const t = mdEscape(m ?? "").replace(/\r\n/g, "\n").trim();
  if (!t) return t;

  // si ya viene multilinea, no lo tocamos
  if (t.includes("\n")) return t;

  // si viene "graph TD; A-->B; ..." lo partimos en líneas
  if (t.includes(";")) {
    const parts = t
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean);

    if (parts.length <= 1) return t;

    const first = parts.shift()!;
    return [first, ...parts].join("\n");
  }

  return t;
}

// ---- version helpers (best-effort) ----
function parseSemver(v: string): [number, number, number] | null {
  const m = String(v).trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function semverGt(a: string, b: string) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return a.localeCompare(b) > 0;
  if (pa[0] !== pb[0]) return pa[0] > pb[0];
  if (pa[1] !== pb[1]) return pa[1] > pb[1];
  return pa[2] > pb[2];
}

function pepNums(v: string) {
  const parts = String(v)
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map((x) => Number(x));
  return parts.length ? parts : [0];
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

function pickBestFixedVersion(ecosystem: "npm" | "PyPI", a?: string, b?: string) {
  if (!a) return b;
  if (!b) return a;
  if (ecosystem === "npm") return semverGt(b, a) ? b : a;
  return pep440Gt(b, a) ? b : a;
}

function buildSuggestedCommands(deps: DepsCache | null) {
  if (!deps?.findings?.length) return [];

  const bestByPkg = new Map<string, { ecosystem: "npm" | "PyPI"; name: string; fixed: string }>();

  for (const f of deps.findings) {
    const eco = (f.ecosystem as any) === "npm" ? "npm" : "PyPI";
    if (!f.fixedVersion) continue;

    const key = `${eco}:${f.name}`;
    const existing = bestByPkg.get(key);
    if (!existing) {
      bestByPkg.set(key, { ecosystem: eco, name: f.name, fixed: f.fixedVersion });
    } else {
      existing.fixed = pickBestFixedVersion(eco, existing.fixed, f.fixedVersion) || existing.fixed;
      bestByPkg.set(key, existing);
    }
  }

  const cmds: string[] = [];
  for (const x of bestByPkg.values()) {
    if (x.ecosystem === "npm") cmds.push(`npm i ${x.name}@${x.fixed}`);
    else cmds.push(`pip install ${x.name}==${x.fixed}`);
  }

  return cmds.sort((a, b) => a.localeCompare(b)).slice(0, 120);
}

function makeMarkdownReport(params: {
  id: string;
  status: AnalysisStatus | null;
  vuln: VulnCache | null;
  debt: DebtCache | null;
  deps: DepsCache | null;
  patches: PatchCache | null;
}) {
  const { id, status, vuln, debt, deps, patches } = params;

  const repoName = status?.result?.repoName ?? "(unknown repo)";
  const generatedAt = new Date().toISOString();

  const lines: string[] = [];
  lines.push(`# Cipher AI Report`);
  lines.push(``);
  lines.push(`- **Analysis ID:** ${id}`);
  lines.push(`- **Repository:** ${mdEscape(repoName)}`);
  lines.push(`- **Generated at:** ${generatedAt}`);
  lines.push(``);

  lines.push(`## Architecture`);
  lines.push(``);
  if (status?.result?.mermaid) {
    lines.push(`### Diagram (Mermaid)`);
    lines.push("```mermaid");
    // ✅ FIX: format mermaid multiline
    lines.push(formatMermaidForReport(status.result.mermaid));
    lines.push("```");
    lines.push(``);
  } else {
    lines.push(`Architecture diagram not available.`);
    lines.push(``);
  }

  lines.push(`## Summary`);
  lines.push(``);
  const summary = status?.result?.summary ?? [];
  if (summary.length) summary.forEach((s) => lines.push(`- ${mdEscape(s)}`));
  else lines.push(`No summary available.`);
  lines.push(``);

  lines.push(`## Risks`);
  lines.push(``);
  const risks = status?.result?.risks ?? [];
  if (risks.length) {
    risks.forEach((r) => lines.push(`- **${r.severity}** — ${mdEscape(r.title)}: ${mdEscape(r.details)}`));
  } else {
    lines.push(`No risks available.`);
  }
  lines.push(``);

  lines.push(`## Quick Wins`);
  lines.push(``);
  const wins = status?.result?.quickWins ?? [];
  if (wins.length) wins.forEach((w) => lines.push(`- ${mdEscape(w)}`));
  else lines.push(`No quick wins available.`);
  lines.push(``);

  lines.push(`## Next Steps`);
  lines.push(``);
  const nextSteps = status?.result?.nextSteps ?? [];
  if (nextSteps.length) nextSteps.forEach((n) => lines.push(`- ${mdEscape(n)}`));
  else lines.push(`No next steps available.`);
  lines.push(``);

  // ✅ Applied patches list (server KV)
  lines.push(`## Patch previews applied`);
  lines.push(``);
  if (!patches || !patches.patchedCount) {
    lines.push(
      `No patch previews recorded. (Tip: click "Apply preview" in UI, then wait ~1s, or export patched ZIP once.)`
    );
    lines.push(``);
  } else {
    const ts = patches.updatedAt || patches.exportedAt || "";
    const src = patches.source ? ` • source=${patches.source}` : "";
    lines.push(`Patched previews: **${patches.patchedCount}**${ts ? ` • updatedAt=${ts}` : ""}${src}`);
    lines.push(``);
    (patches.patchedFiles ?? []).slice(0, 200).forEach((p) => lines.push(`- ${mdEscape(p)}`));
    if ((patches.patchedFiles ?? []).length > 200) {
      lines.push(``);
      lines.push(`> Showing first 200 patched files.`);
    }
    lines.push(``);
  }

  // Dependency CVEs (OSV)
  lines.push(`## Dependency CVEs (OSV)`);
  lines.push(``);
  if (!deps) {
    lines.push(`Dependency scan not found in cache. Run “Scan dependencies” from the UI first.`);
    lines.push(``);
  } else {
    if (deps.note) {
      lines.push(`> Note: ${mdEscape(deps.note)}`);
      lines.push(``);
    }

    const metaBits: string[] = [];
    if (typeof deps.totalParsedDeps === "number") metaBits.push(`parsed=${deps.totalParsedDeps}`);
    if (typeof deps.scannedDeps === "number") metaBits.push(`scanned=${deps.scannedDeps}`);
    if (typeof deps.totalVulnHits === "number") metaBits.push(`hits=${deps.totalVulnHits}`);
    if (typeof deps.uniqueVulnIds === "number") metaBits.push(`unique=${deps.uniqueVulnIds}`);
    if (deps.truncated) metaBits.push(`truncated=true`);
    if (metaBits.length) {
      lines.push(`**Scan stats:** ${metaBits.join(", ")}`);
      lines.push(``);
    }

    const findings = (deps.findings ?? []).slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

    if (!findings.length) {
      lines.push(`No dependency CVEs found ✅`);
      lines.push(``);
    } else {
      for (const f of findings.slice(0, 120)) {
        lines.push(
          `- **${mdEscape(f.severity)}** ${mdEscape(f.name)}@${mdEscape(f.version)} (${mdEscape(
            f.ecosystem
          )}) — ${mdEscape(f.vulnId)}`
        );
        if (f.fixedVersion) lines.push(`  - Fixed version: ${mdEscape(f.fixedVersion)}`);
        lines.push(`  - Summary: ${mdEscape(f.summary)}`);
        if (f.references?.length) {
          lines.push(`  - References: ${f.references.map((u) => `<${u}>`).join(" ")}`);
        }
        lines.push(``);
      }
      lines.push(`> Showing first ${Math.min(120, findings.length)} dependency CVEs.`);
      lines.push(``);
    }
  }

  // ✅ Suggested commands (deps)
  lines.push(`## Suggested commands`);
  lines.push(``);
  const cmds = buildSuggestedCommands(deps);
  if (!cmds.length) {
    lines.push(`No suggested upgrade commands available.`);
    lines.push(``);
  } else {
    lines.push(`If you want a quick remediation pass, try:`);
    lines.push(``);
    cmds.slice(0, 120).forEach((c) => lines.push(`- \`${mdEscape(c)}\``));
    lines.push(``);
    if (cmds.length > 120) lines.push(`> Showing first 120 commands.`);
    lines.push(``);
  }

  // Vulnerabilities
  lines.push(`## Vulnerabilities (Heuristic)`);
  lines.push(``);
  if (!vuln) {
    lines.push(`Vulnerability scan not found in cache. Run it first from the UI.`);
    lines.push(``);
  } else {
    if (vuln.note) {
      lines.push(`> Note: ${mdEscape(vuln.note)}`);
      lines.push(``);
    }
    const findings = (vuln.findings ?? []).slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

    if (!findings.length) {
      lines.push(`No findings.`);
      lines.push(``);
    } else {
      for (const f of findings.slice(0, 60)) {
        lines.push(`- **${mdEscape(f.severity)}** ${mdEscape(f.title)} (${f.file}:${f.line})`);
        lines.push(`  - Type: \`${f.type}\``);
        lines.push(`  - Recommendation: ${mdEscape(f.recommendation)}`);
        if (f.fix) lines.push(`  - Suggested fix: ${mdEscape(f.fix)}`);
        lines.push(``);
      }
      lines.push(`> Showing first ${Math.min(60, findings.length)} findings.`);
      lines.push(``);
    }
  }

  // Tech Debt
  lines.push(`## Tech Debt`);
  lines.push(``);
  if (!debt) {
    lines.push(`Tech debt scan not found in cache. Run it first from the UI.`);
    lines.push(``);
  } else {
    if (debt.note) {
      lines.push(`> Note: ${mdEscape(debt.note)}`);
      lines.push(``);
    }
    const issues = (debt.issues ?? []).slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

    if (!issues.length) {
      lines.push(`No issues.`);
      lines.push(``);
    } else {
      for (const it of issues.slice(0, 80)) {
        lines.push(`- **${mdEscape(it.severity)}** ${mdEscape(it.title)} (${it.file}:${it.line})`);
        lines.push(`  - Type: \`${it.type}\``);
        lines.push(`  - Details: ${mdEscape(it.details)}`);
        lines.push(`  - Suggestion: ${mdEscape(it.suggestion)}`);
        if (it.fix) lines.push(`  - Suggested refactor: ${mdEscape(it.fix)}`);
        lines.push(``);
      }
      lines.push(`> Showing first ${Math.min(80, issues.length)} issues.`);
      lines.push(``);
    }
  }

  const out = lines.join("\n");
  return out.length > 900_000 ? out.slice(0, 900_000) + "\n\n(Report truncated)\n" : out;
}

/**
 * PDF renderer (pretty)
 * - Cover page
 * - Header/footer with page X of Y
 * - Headings, lists, blockquotes, code blocks
 * - Width-based wrapping (font.widthOfTextAtSize)
 * - WinAnsi-safe text
 */
async function markdownToPdfBytes(
  md: string,
  meta: { title: string; repoName: string; analysisId: string; createdAt: string }
) {
  const doc = await PDFDocument.create();
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);
  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontMono = await doc.embedFont(StandardFonts.Courier);

  // A4
  const PAGE_W = 595.28;
  const PAGE_H = 841.89;

  // layout
  const marginX = 56;
  const marginTop = 72; // below header bar
  const marginBottom = 54;

  // theme
  const accent = rgb(0.12, 0.43, 0.85);
  const accentSoft = rgb(0.90, 0.95, 1.0);
  const ink = rgb(0.08, 0.10, 0.14);
  const muted = rgb(0.42, 0.46, 0.55);
  const rule = rgb(0.88, 0.90, 0.94);
  const codeBg = rgb(0.95, 0.96, 0.98);
  const quoteBg = rgb(0.96, 0.98, 0.96);

  const title = safeTextForPdf(meta.title || "Cipher AI Report");
  const repoName = safeTextForPdf(meta.repoName || "");
  const analysisId = safeTextForPdf(meta.analysisId || "");
  const createdAt = safeTextForPdf(meta.createdAt || "");

  function splitLinesPreserve(text: string) {
    return safeTextForPdf(text).replace(/\r\n/g, "\n").split("\n");
  }

  function wrapTextWidth(font: any, text: string, size: number, maxWidth: number) {
    const words = safeTextForPdf(text).split(/\s+/).filter(Boolean);
    const lines: string[] = [];
    let cur = "";

    for (const w of words) {
      const test = cur ? `${cur} ${w}` : w;
      const width = font.widthOfTextAtSize(test, size);
      if (width <= maxWidth) cur = test;
      else {
        if (cur) lines.push(cur);
        cur = w;
      }
    }
    if (cur) lines.push(cur);
    return lines;
  }

  // ✅ FIX: wrap real por ancho para monospace (sin "…")
  function wrapMonoByWidth(font: any, text: string, size: number, maxWidth: number) {
    const t = safeTextForPdf(text ?? "");
    if (!t) return [""];
    if (font.widthOfTextAtSize(t, size) <= maxWidth) return [t];

    const out: string[] = [];
    let cur = t;

    while (cur.length) {
      let lo = 1;
      let hi = cur.length;
      let best = 1;

      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const chunk = cur.slice(0, mid);
        const w = font.widthOfTextAtSize(chunk, size);
        if (w <= maxWidth) {
          best = mid;
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }

      if (best <= 0) best = Math.min(1, cur.length);
      out.push(cur.slice(0, best));
      cur = cur.slice(best);
    }

    return out;
  }

  function isHeading(line: string) {
    const m = line.match(/^(#{1,6})\s+(.*)$/);
    if (!m) return null;
    return { level: m[1].length, text: m[2].trim() };
  }
  function isHr(line: string) {
    const t = line.trim();
    return t === "---" || t === "___" || t === "***";
  }
  function isListItem(line: string) {
    const m = line.match(/^(\s*)([-*+]|\d+\.)\s+(.*)$/);
    if (!m) return null;
    return { indent: m[1].length, text: m[3] };
  }
  function isBlockquote(line: string) {
    const m = line.match(/^\s*>\s?(.*)$/);
    if (!m) return null;
    return m[1] ?? "";
  }

  // ---- Cover page ----
  const cover = doc.addPage([PAGE_W, PAGE_H]);

  cover.drawRectangle({ x: 0, y: 0, width: PAGE_W, height: PAGE_H, color: rgb(1, 1, 1) });
  cover.drawRectangle({ x: 0, y: 0, width: 14, height: PAGE_H, color: accent });
  cover.drawRectangle({ x: 14, y: 0, width: 28, height: PAGE_H, color: accentSoft });

  cover.drawText("CIPHER AI", {
    x: marginX,
    y: PAGE_H - 140,
    size: 22,
    font: fontBold,
    color: accent,
  });

  cover.drawText(title, {
    x: marginX,
    y: PAGE_H - 190,
    size: 34,
    font: fontBold,
    color: ink,
  });

  const metaLines = [
    repoName ? `Repo: ${repoName}` : "",
    analysisId ? `Analysis ID: ${analysisId}` : "",
    createdAt ? `Generated: ${createdAt}` : "",
  ].filter(Boolean);

  let metaY = PAGE_H - 275;
  for (const ln of metaLines) {
    cover.drawText(ln, { x: marginX, y: metaY, size: 11, font: fontRegular, color: muted });
    metaY -= 16;
  }

  cover.drawRectangle({ x: marginX, y: PAGE_H - 235, width: 260, height: 3, color: accent });

  // ---- Content pages (no header/footer yet, we'll add after for "of Y") ----
  const contentPages: any[] = [];
  const headerH = 42;

  let page = doc.addPage([PAGE_W, PAGE_H]);
  contentPages.push(page);

  let y = PAGE_H - marginTop;

  function ensureSpace(heightNeeded: number) {
    if (y - heightNeeded < marginBottom) {
      page = doc.addPage([PAGE_W, PAGE_H]);
      contentPages.push(page);
      y = PAGE_H - marginTop;
    }
  }

  function drawRule() {
    ensureSpace(16);
    page.drawRectangle({ x: marginX, y: y, width: PAGE_W - marginX * 2, height: 1, color: rule });
    y -= 16;
  }

  function drawHeading(level: number, text: string) {
    const t = safeTextForPdf(text);
    const sizeMap: Record<number, number> = { 1: 20, 2: 16, 3: 13, 4: 12, 5: 11, 6: 11 };
    const size = sizeMap[Math.min(6, Math.max(1, level))] ?? 12;

    ensureSpace(size + 24);

    // accent bar
    page.drawRectangle({ x: marginX, y: y - 6, width: 6, height: size + 10, color: accent });
    page.drawText(t, { x: marginX + 14, y, size, font: fontBold, color: ink });
    y -= size + 12;

    drawRule();
  }

  function drawParagraph(text: string, indent = 0, size = 11, lineGap = 4, color = ink, font = fontRegular) {
    const maxWidth = PAGE_W - marginX * 2 - indent;
    const lines = wrapTextWidth(font, text, size, maxWidth);
    for (const ln of lines) {
      ensureSpace(size + lineGap);
      page.drawText(safeTextForPdf(ln), { x: marginX + indent, y, size, font, color });
      y -= size + lineGap;
    }
    y -= 4;
  }

  // ✅ FIX: code block ahora wrappea por ancho y detecta lang (mermaid incluido)
  function drawCodeBlock(lines: string[], lang?: string) {
    const isMermaid = (lang ?? "").toLowerCase() === "mermaid";
    const size = isMermaid ? 9 : 9.5;
    const lineH = isMermaid ? 11.5 : 12;
    const padding = 10;

    const maxTextWidth = PAGE_W - marginX * 2 - padding * 2;

    const renderLines: string[] = [];
    for (const l of lines) {
      const safe = safeTextForPdf(l ?? "");
      const wrapped = wrapMonoByWidth(fontMono, safe, size, maxTextWidth);
      renderLines.push(...wrapped);
    }

    const blockH = padding * 2 + renderLines.length * lineH;

    ensureSpace(blockH + 10);

    page.drawRectangle({
      x: marginX,
      y: y - blockH + 6,
      width: PAGE_W - marginX * 2,
      height: blockH,
      color: codeBg,
      borderColor: rule,
      borderWidth: 1,
    });

    let cy = y - padding;
    for (const ln of renderLines) {
      ensureSpace(lineH + 1);
      page.drawText(ln, {
        x: marginX + padding,
        y: cy,
        size,
        font: fontMono,
        color: ink,
      });
      cy -= lineH;
    }

    y -= blockH + 12;
  }

  function drawQuote(text: string) {
    const size = 10.5;
    const padding = 10;
    const maxWidth = PAGE_W - marginX * 2 - padding * 2 - 10;

    const lines = wrapTextWidth(fontRegular, text, size, maxWidth);
    const blockH = padding * 2 + lines.length * (size + 4);

    ensureSpace(blockH + 10);

    page.drawRectangle({
      x: marginX,
      y: y - blockH + 6,
      width: PAGE_W - marginX * 2,
      height: blockH,
      color: quoteBg,
      borderColor: rgb(0.82, 0.88, 0.82),
      borderWidth: 1,
    });

    page.drawRectangle({
      x: marginX,
      y: y - blockH + 6,
      width: 5,
      height: blockH,
      color: rgb(0.25, 0.60, 0.30),
    });

    let qy = y - padding;
    for (const ln of lines) {
      page.drawText(safeTextForPdf(ln), {
        x: marginX + padding + 10,
        y: qy,
        size,
        font: fontRegular,
        color: ink,
      });
      qy -= size + 4;
    }

    y -= blockH + 12;
  }

  const lines = splitLinesPreserve(md);

  let inCode = false;
  let codeLines: string[] = [];
  let codeLang = "";

  for (const raw of lines) {
    const line = raw ?? "";
    const trimmed = line.trim();

    // ✅ code fence with language
    if (trimmed.startsWith("```")) {
      if (!inCode) {
        inCode = true;
        codeLang = trimmed.slice(3).trim().toLowerCase(); // "mermaid", "js", etc
        codeLines = [];
      } else {
        inCode = false;
        drawCodeBlock(codeLines, codeLang);
        codeLines = [];
        codeLang = "";
      }
      continue;
    }

    if (inCode) {
      codeLines.push(line);
      continue;
    }

    if (!line.trim()) {
      y -= 6;
      continue;
    }

    const h = isHeading(line);
    if (h) {
      drawHeading(h.level, h.text);
      continue;
    }

    if (isHr(line)) {
      drawRule();
      continue;
    }

    const bq = isBlockquote(line);
    if (bq !== null) {
      drawQuote(bq);
      continue;
    }

    const li = isListItem(line);
    if (li) {
      const indent = Math.min(40, li.indent * 2);
      drawParagraph(`• ${li.text}`, indent, 11, 4, ink, fontRegular);
      continue;
    }

    // normal paragraph
    drawParagraph(line);
  }

  // unclosed code block
  if (inCode && codeLines.length) drawCodeBlock(codeLines, codeLang);

  // ---- Add header/footer (page X of Y) to content pages ----
  const total = contentPages.length;
  const headerLeft = safeTextForPdf(`${title}${repoName ? ` — ${repoName}` : ""}`);

  for (let i = 0; i < contentPages.length; i++) {
    const p = contentPages[i];
    // header bar
    p.drawRectangle({ x: 0, y: PAGE_H - headerH, width: PAGE_W, height: headerH, color: accentSoft });
    p.drawRectangle({ x: 0, y: PAGE_H - headerH, width: 6, height: headerH, color: accent });

    const headerText = headerLeft.length > 92 ? headerLeft.slice(0, 92) + "…" : headerLeft;
    p.drawText(headerText, {
      x: marginX,
      y: PAGE_H - 28,
      size: 10,
      font: fontBold,
      color: ink,
    });

    const right = createdAt || "";
    if (right) {
      const w = fontRegular.widthOfTextAtSize(right, 9);
      p.drawText(right, {
        x: PAGE_W - marginX - w,
        y: PAGE_H - 28,
        size: 9,
        font: fontRegular,
        color: muted,
      });
    }

    // footer
    const pn = `Page ${i + 1} of ${total}`;
    const pw = fontRegular.widthOfTextAtSize(pn, 9);
    p.drawRectangle({ x: marginX, y: 38, width: PAGE_W - marginX * 2, height: 1, color: rule });
    p.drawText(pn, {
      x: PAGE_W - marginX - pw,
      y: 24,
      size: 9,
      font: fontRegular,
      color: muted,
    });
  }

  return await doc.save();
}

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const url = new URL(req.url);
    const format = (url.searchParams.get("format") ?? "md").toLowerCase();

    const status = await kvGet<AnalysisStatus>(`analysis:${id}`);

    const vuln = await kvGet<VulnCache>(`scan:vuln:${id}:160:80`);
    const debt = await kvGet<DebtCache>(`scan:debt:${id}:220:90`);

    const deps = await kvGetFirst<DepsCache>([
      `scan:deps:${id}:300:300`,
      `scan:deps:${id}:200:200`,
      `scan:deps:${id}:200`,
    ]);

    const patches = await kvGet<PatchCache>(`patches:${id}`);

    const md = makeMarkdownReport({ id, status, vuln, debt, deps, patches });
    const name = safeName(status?.result?.repoName ?? "cipher-ai");

    if (format === "pdf") {
      const repoName = status?.result?.repoName ?? "(unknown repo)";
      const createdAt = new Date().toLocaleString("es-MX", {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });

      const pdfBytes = await markdownToPdfBytes(md, {
        title: "Cipher AI Report",
        repoName,
        analysisId: id,
        createdAt,
      });

      return new NextResponse(Buffer.from(pdfBytes), {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="CipherAI_Report_${name}.pdf"`,
        },
      });
    }

    return new NextResponse(md, {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="CipherAI_Report_${name}.md"`,
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: `Export failed: ${msg}` }, { status: 500 });
  }
}
