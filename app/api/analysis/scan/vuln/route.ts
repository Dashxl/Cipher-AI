//src/app/api/analysis/scan/debt/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import JSZip from "jszip";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";
import { MODELS } from "@/lib/genai/models";
import { ThinkingLevel } from "@google/genai";
import type { VulnFinding, Severity } from "@/types/scan";
import { withRotatingKey } from "@/lib/genai/keyring";
import { makeGenAI } from "@/lib/genai/rotating-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

const BodySchema = z.object({
  analysisId: z.string().min(1),
  maxFiles: z.number().int().min(10).max(400).default(160),
  maxFindings: z.number().int().min(5).max(200).default(80),
});

function isQuota(msg: string) {
  return (
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.includes("429") ||
    msg.includes("Quota exceeded") ||
    msg.includes("exceeded your current quota")
  );
}

function sevRank(s: Severity) {
  return s === "CRITICAL" ? 0 : s === "HIGH" ? 1 : s === "MEDIUM" ? 2 : 3;
}

function mkId(file: string, line: number, type: string) {
  return `${type}:${file}:${line}`;
}

function getLineNumber(text: string, index: number) {
  // count '\n' up to index
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function snippetAround(lines: string[], line: number, radius = 2) {
  const start = Math.max(0, line - 1 - radius);
  const end = Math.min(lines.length, line - 1 + radius + 1);
  return lines.slice(start, end).join("\n").slice(0, 600);
}

// Heuristic rules (fast + demo-friendly)
const RULES: Array<{
  type: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  recommendation: string;
}> = [
  {
    type: "secret",
    title: "Hardcoded secret / credential",
    severity: "CRITICAL",
    pattern: /(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    recommendation: "Move secrets to environment variables or a secret manager. Rotate exposed credentials.",
  },
  {
    type: "private_key",
    title: "Private key material in code",
    severity: "CRITICAL",
    pattern: /-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----/g,
    recommendation: "Remove keys from repo immediately and rotate. Use a secret manager.",
  },
  {
    type: "xss",
    title: "Potential XSS sink",
    severity: "HIGH",
    pattern: /(dangerouslySetInnerHTML|innerHTML\s*=|document\.write\()/g,
    recommendation: "Avoid HTML sinks or sanitize input. Use safe templating/escaping and a sanitizer where needed.",
  },
  {
    type: "sqli",
    title: "Potential SQL injection",
    severity: "HIGH",
    pattern: /(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,120}(\+|%s|format\(|f["']|\.concat\(|\$\{)/gi,
    recommendation: "Use parameterized queries / prepared statements. Never concatenate untrusted input into SQL.",
  },
  {
    type: "cmd_injection",
    title: "Potential command injection",
    severity: "HIGH",
    pattern: /\b(exec|execSync|spawn|spawnSync)\s*\(/g,
    recommendation: "Avoid passing untrusted input to shell commands. Use argument arrays and strict allow-lists.",
  },
  {
    type: "eval",
    title: "Use of eval / dynamic code execution",
    severity: "HIGH",
    pattern: /\beval\s*\(/g,
    recommendation: "Avoid eval. Replace with safe parsing or explicit logic.",
  },
  {
    type: "insecure_deser",
    title: "Insecure deserialization",
    severity: "HIGH",
    pattern: /\b(pickle\.loads|yaml\.load\s*\(|marshal\.loads)\b/g,
    recommendation: "Use safe loaders (e.g., yaml.safe_load) and avoid deserializing untrusted data.",
  },
  {
    type: "weak_crypto",
    title: "Weak hashing algorithm",
    severity: "MEDIUM",
    pattern: /\b(md5|sha1)\b/gi,
    recommendation: "Use modern algorithms (SHA-256+) and appropriate password hashing (bcrypt/argon2/scrypt).",
  },
];

async function enrichWithGemini(repoName: string, findings: VulnFinding[]) {
  // Enrich top findings only (keep cost down)
  const top = findings.slice(0, 12);

  const prompt = [
    "You are a security code reviewer.",
    `Repository: ${repoName}`,
    "For each finding below, propose a concrete fix (short) and a confidence score 0..1.",
    "Respond ONLY as JSON array with items:",
    `{ "id": string, "fix": string, "confidence": number }`,
    "",
    "Findings:",
    ...top.map((f) =>
      [
        `ID: ${f.id}`,
        `Type: ${f.type}`,
        `Severity: ${f.severity}`,
        `Location: ${f.file}:${f.line}`,
        `Snippet:\n${f.snippet}`,
        "---",
      ].join("\n")
    ),
  ].join("\n");

  const res = await withRotatingKey(async (apiKey) => {
    const genai = makeGenAI(apiKey);
    return await genai.models.generateContent({
    model: MODELS.fast, // Gemini 3 Flash
    contents: prompt,
    config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } },
  })
  });

  const text = res.text ?? "[]";
  const first = text.indexOf("[");
  const last = text.lastIndexOf("]");
  const json = first !== -1 && last !== -1 ? text.slice(first, last + 1) : "[]";

  const arr = JSON.parse(json) as Array<{ id: string; fix: string; confidence: number }>;
  const map = new Map(arr.map((x) => [x.id, x]));

  for (const f of findings) {
    const e = map.get(f.id);
    if (e) {
      f.fix = String(e.fix ?? "").slice(0, 1200);
      const c = Number(e.confidence);
      f.confidence = Number.isFinite(c) ? Math.max(0, Math.min(1, c)) : undefined;
    }
  }
}

export async function POST(req: Request) {
  const body = BodySchema.parse(await req.json());
  const cacheKey = `scan:vuln:${body.analysisId}:${body.maxFiles}:${body.maxFindings}`;

  const cached = await kvGet<{ findings: VulnFinding[]; note?: string }>(cacheKey);
  if (cached) return NextResponse.json(cached);

  const meta = await kvGet<RepoMeta>(`repo:${body.analysisId}`);
  if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

  const zipBuf = await loadZip(body.analysisId);
  const zip = await JSZip.loadAsync(zipBuf);

  const files = (meta.files ?? []).slice(0, body.maxFiles);

  const findings: VulnFinding[] = [];

  for (const file of files) {
    const actualPath = meta.root ? `${meta.root}/${file}` : file;
    const f = zip.file(actualPath);
    if (!f) continue;

    const content = (await f.async("string")).slice(0, 200_000);
    const lines = content.split("\n");

    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.pattern.exec(content))) {
        const idx = m.index ?? 0;
        const line = getLineNumber(content, idx);
        const snip = snippetAround(lines, line);

        findings.push({
          id: mkId(file, line, rule.type),
          severity: rule.severity,
          type: rule.type,
          title: rule.title,
          file,
          line,
          snippet: snip,
          recommendation: rule.recommendation,
        });

        if (findings.length >= body.maxFindings) break;
      }
      if (findings.length >= body.maxFindings) break;
    }

    if (findings.length >= body.maxFindings) break;
  }

  findings.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

  let note: string | undefined;

  // Enrich with Gemini (best effort)
  try {
    await enrichWithGemini(meta.repoName, findings);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    note = isQuota(msg)
      ? "Gemini quota exhausted: returning heuristic-only results."
      : `Gemini enrichment failed: ${msg}`;
  }

  const payload = { findings, note };
  await kvSet(cacheKey, payload, 60 * 30); // 30 min

  return NextResponse.json(payload);
}