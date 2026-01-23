import { NextResponse } from "next/server";
import { kvGet } from "@/lib/cache/store";
import { PDFDocument, StandardFonts } from "pdf-lib";
import type { AnalysisStatus } from "@/types/analysis";
import type { DebtIssue, VulnFinding, Severity } from "@/types/scan";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type VulnCache = { findings: VulnFinding[]; note?: string };
type DebtCache = { issues: DebtIssue[]; note?: string };

function sevRank(s: Severity) {
  return s === "CRITICAL" ? 0 : s === "HIGH" ? 1 : s === "MEDIUM" ? 2 : 3;
}

function mdEscape(s: string) {
  return (s ?? "").replace(/\r/g, "");
}

function safeName(s: string) {
  return (s || "cipher-ai").replace(/[^\w\-\.]+/g, "_").slice(0, 60);
}

/**
 * pdf-lib standard fonts use WinAnsi encoding and can't draw many unicode chars.
 * We convert common unicode symbols to ASCII and replace the rest with '?'.
 */
function toWinAnsiSafe(s: string) {
  return (s ?? "")
    .replace(/\u2192/g, "->") // →
    .replace(/\u2190/g, "<-") // ←
    .replace(/\u2191/g, "^") // ↑
    .replace(/\u2193/g, "v") // ↓
    .replace(/\u2013|\u2014/g, "-") // – —
    .replace(/\u2018|\u2019/g, "'") // ‘ ’
    .replace(/\u201C|\u201D/g, '"') // “ ”
    .replace(/\u2022/g, "*") // •
    .replace(/\u00A0/g, " "); // non-breaking space
}

function safeTextForPdf(s: string) {
  const t = toWinAnsiSafe(s);
  let out = "";
  for (let i = 0; i < t.length; i++) {
    const code = t.charCodeAt(i);
    // Keep tabs/newlines/carriage returns
    if (code === 9 || code === 10 || code === 13) {
      out += t[i];
      continue;
    }
    // Keep printable ASCII + latin1 range
    if (code >= 32 && code <= 255) out += t[i];
    else out += "?";
  }
  return out;
}

function makeMarkdownReport(params: {
  id: string;
  status: AnalysisStatus | null;
  vuln: VulnCache | null;
  debt: DebtCache | null;
}) {
  const { id, status, vuln, debt } = params;

  const repoName = status?.result?.repoName ?? "(unknown repo)";
  const generatedAt = new Date().toISOString();

  const lines: string[] = [];
  lines.push(`# Cipher AI Report`);
  lines.push(``);
  lines.push(`- **Analysis ID:** ${id}`);
  lines.push(`- **Repository:** ${mdEscape(repoName)}`);
  lines.push(`- **Generated at:** ${generatedAt}`);
  lines.push(``);

  // Architecture
  lines.push(`## Architecture`);
  lines.push(``);
  if (status?.result?.mermaid) {
    lines.push(`### Diagram (Mermaid)`);
    lines.push("```mermaid");
    lines.push(mdEscape(status.result.mermaid));
    lines.push("```");
    lines.push(``);
  } else {
    lines.push(`Architecture diagram not available.`);
    lines.push(``);
  }

  // Summary / Risks / Wins / Next
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

  // Vulnerabilities
  lines.push(`## Vulnerabilities`);
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

  // Cap size to avoid memory spikes
  const out = lines.join("\n");
  return out.length > 900_000 ? out.slice(0, 900_000) + "\n\n(Report truncated)\n" : out;
}

function wrapLine(line: string, maxChars: number) {
  if (line.length <= maxChars) return [line];
  const out: string[] = [];
  let cur = line;
  while (cur.length > maxChars) {
    let cut = cur.lastIndexOf(" ", maxChars);
    if (cut < 20) cut = maxChars;
    out.push(cur.slice(0, cut));
    cur = cur.slice(cut).trimStart();
  }
  if (cur.length) out.push(cur);
  return out;
}

async function markdownToPdfBytes(md: string) {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);

  const pageSize: [number, number] = [595.28, 841.89]; // A4
  const margin = 40;
  const fontSize = 10;
  const lineHeight = 14;

  let page = doc.addPage(pageSize);
  let y = page.getHeight() - margin;

  const lines = md.split("\n");
  const MAX_LINES = 10_000; // avoid runaway pdf generation
  const slice = lines.slice(0, MAX_LINES);

  for (const l of slice) {
    const safeLine = safeTextForPdf(l);
    const wrapped = wrapLine(safeLine, 95);

    for (const wl of wrapped) {
      if (y < margin) {
        page = doc.addPage(pageSize);
        y = page.getHeight() - margin;
      }
      page.drawText(safeTextForPdf(wl), { x: margin, y, size: fontSize, font });
      y -= lineHeight;
    }
  }

  return await doc.save();
}

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const url = new URL(req.url);
    const format = (url.searchParams.get("format") ?? "md").toLowerCase();

    const status = await kvGet<AnalysisStatus>(`analysis:${id}`);

    // These cache keys match the defaults used in our scan endpoints
    const vuln = await kvGet<VulnCache>(`scan:vuln:${id}:160:80`);
    const debt = await kvGet<DebtCache>(`scan:debt:${id}:220:90`);

    const md = makeMarkdownReport({ id, status, vuln, debt });
    const name = safeName(status?.result?.repoName ?? "cipher-ai");

    if (format === "pdf") {
      const pdfBytes = await markdownToPdfBytes(md);
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
