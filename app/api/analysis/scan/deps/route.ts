import { NextResponse } from "next/server";
import { z } from "zod";
import JSZip from "jszip";
import { kvGet, kvSet } from "@/lib/cache/store";
import { loadZip } from "@/lib/repo/zip-store";
import type { DepCveFinding, Severity } from "@/types/scan";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RepoMeta = { repoName: string; root: string | null; files: string[] };

const BodySchema = z.object({
  analysisId: z.string().min(1),
  maxDeps: z.number().int().min(20).max(400).default(200),
  maxVulns: z.number().int().min(20).max(400).default(200), // cap unique vuln fetches
});

function toMsg(err: unknown) {
  return err instanceof Error ? err.message : String(err);
}

function isQuota(msg: string) {
  const m = (msg || "").toLowerCase();
  return m.includes("429") || m.includes("rate") || m.includes("quota") || m.includes("too many requests");
}

function sevRank(s: Severity) {
  return s === "CRITICAL" ? 0 : s === "HIGH" ? 1 : s === "MEDIUM" ? 2 : 3;
}

function bestMatchPath(files: string[], fileNameLower: string) {
  const candidates = (files ?? []).filter((p) => {
    const pl = p.toLowerCase();
    return pl.endsWith(`/${fileNameLower}`) || pl === fileNameLower;
  });
  if (!candidates.length) return null;
  // prefer shortest path (root-level first)
  candidates.sort((a, b) => a.length - b.length);
  return candidates[0];
}

function parsePackageLock(raw: string): Array<{ name: string; version: string }> {
  try {
    const obj = JSON.parse(raw);
    const out = new Map<string, string>();

    // npm lock v2/v3: { packages: { "node_modules/<name>": { version } } }
    if (obj && typeof obj === "object" && obj.packages && typeof obj.packages === "object") {
      for (const [k, v] of Object.entries<any>(obj.packages)) {
        if (!k || k === "") continue;
        const kk = String(k);
        if (!kk.includes("node_modules/")) continue;

        const name = kk.split("node_modules/").pop() || "";
        const ver = v?.version ? String(v.version) : "";
        if (name && ver && !out.has(name)) out.set(name, ver);
      }
    }

    // npm lock v1: { dependencies: { dep: { version, dependencies: {...} } } }
    const walk = (deps: any) => {
      if (!deps || typeof deps !== "object") return;
      for (const [name, info] of Object.entries<any>(deps)) {
        const ver = info?.version ? String(info.version) : "";
        if (name && ver && !out.has(name)) out.set(String(name), ver);
        if (info?.dependencies) walk(info.dependencies);
      }
    };

    if (obj?.dependencies) walk(obj.dependencies);

    return [...out.entries()].map(([name, version]) => ({ name, version }));
  } catch {
    return [];
  }
}

function parseRequirements(raw: string): Array<{ name: string; version: string }> {
  const out: Array<{ name: string; version: string }> = [];
  const lines = raw.replace(/\r/g, "").split("\n");

  for (const line of lines) {
    const l = line.trim();
    if (!l || l.startsWith("#")) continue;
    if (l.startsWith("-r") || l.startsWith("--requirement")) continue;
    if (l.startsWith("-e") || l.startsWith("--editable")) continue;
    if (l.startsWith("--")) continue;

    // remove env markers ; python_version < "3.11"
    const noMarker = l.split(";")[0].trim();

    // exact pin only: name==1.2.3 or name===1.2.3
    const m = noMarker.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(===|==)\s*([^\s]+)$/);
    if (!m) continue;

    const name = m[1];
    const version = m[3];
    if (name && version) out.push({ name, version });
  }
  return out;
}

function extractCvssScore(vuln: any): number | null {
  if (Array.isArray(vuln?.severity)) {
    for (const s of vuln.severity) {
      const score = s?.score;
      const n = typeof score === "string" ? parseFloat(score) : typeof score === "number" ? score : NaN;
      if (Number.isFinite(n)) return n;
    }
  }
  const ds = vuln?.database_specific;
  const n2 = typeof ds?.cvss === "number" ? ds.cvss : typeof ds?.cvss === "string" ? parseFloat(ds.cvss) : NaN;
  return Number.isFinite(n2) ? n2 : null;
}

function toSeverity(vuln: any): Severity {
  const ds = vuln?.database_specific?.severity;
  if (ds === "CRITICAL" || ds === "HIGH" || ds === "MEDIUM" || ds === "LOW") return ds;

  const score = extractCvssScore(vuln);
  if (score == null) return "MEDIUM";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

function pickFixedVersion(vuln: any, ecosystem: string, name: string): string | undefined {
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  for (const a of affected) {
    const pkg = a?.package;
    if (!pkg) continue;
    if (String(pkg.name || "") !== name) continue;
    if (String(pkg.ecosystem || "") !== ecosystem) continue;

    const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r?.events) ? r.events : [];
      for (const ev of events) {
        if (ev?.fixed) return String(ev.fixed);
      }
    }

    const fx = a?.database_specific?.fixed;
    if (fx) return String(fx);
  }
  return undefined;
}

async function fetchJson(url: string, init: RequestInit, timeoutMs = 20_000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ac.signal });
    const text = await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { ok: res.ok, status: res.status, json, text };
  } finally {
    clearTimeout(t);
  }
}

async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const out: R[] = [];
  let i = 0;
  const workers = new Array(Math.max(1, limit)).fill(0).map(async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  });
  await Promise.all(workers);
  return out;
}

export async function POST(req: Request) {
  try {
    const body = BodySchema.parse(await req.json());

    // ✅ incluye maxVulns en cache key para que sea correcto
    const cacheKey = `scan:deps:${body.analysisId}:${body.maxDeps}:${body.maxVulns}`;

    const cached = await kvGet<{
      findings: DepCveFinding[];
      note?: string;
      scannedDeps?: number;
      totalParsedDeps?: number;
      manifestsUsed?: string[];
      uniqueVulnIds?: number;
      totalVulnHits?: number;
      depsSample?: Array<{ ecosystem: string; name: string; version: string }>;
      truncated?: boolean;
    }>(cacheKey);

    if (cached) return NextResponse.json(cached);

    const meta = await kvGet<RepoMeta>(`repo:${body.analysisId}`);
    if (!meta) return NextResponse.json({ error: "Repo not found" }, { status: 404 });

    const zipBuf = await loadZip(body.analysisId);
    const zip = await JSZip.loadAsync(zipBuf);

    // Detect manifests (best-effort, MVP)
    const pkgLockPath = bestMatchPath(meta.files, "package-lock.json");
    const reqPath = bestMatchPath(meta.files, "requirements.txt");

    const manifestsUsed: string[] = [];
    if (pkgLockPath) manifestsUsed.push(pkgLockPath);
    if (reqPath) manifestsUsed.push(reqPath);

    const deps: Array<{ ecosystem: "npm" | "PyPI"; name: string; version: string }> = [];

    // Read & parse package-lock
    if (pkgLockPath) {
      const actual = meta.root ? `${meta.root}/${pkgLockPath}` : pkgLockPath;
      const f = zip.file(actual);
      if (f) {
        const raw = await f.async("string");
        const parsed = parsePackageLock(raw);
        parsed.forEach((d) => deps.push({ ecosystem: "npm", name: d.name, version: d.version }));
      }
    }

    // Read & parse requirements.txt (pinned only)
    if (reqPath) {
      const actual = meta.root ? `${meta.root}/${reqPath}` : reqPath;
      const f = zip.file(actual);
      if (f) {
        const raw = await f.async("string");
        const parsed = parseRequirements(raw);
        parsed.forEach((d) => deps.push({ ecosystem: "PyPI", name: d.name, version: d.version }));
      }
    }

    const totalParsedDeps = deps.length;

    // De-dupe + cap
    const seen = new Set<string>();
    const deduped: typeof deps = [];
    let truncated = false;

    for (const d of deps) {
      const key = `${d.ecosystem}:${d.name}@${d.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(d);
      if (deduped.length >= body.maxDeps) {
        truncated = true;
        break;
      }
    }

    // No manifests at all
    if (!pkgLockPath && !reqPath) {
      const payload = {
        findings: [],
        note:
          "No dependency manifests detected. Add package-lock.json (npm) and/or requirements.txt (PyPI pinned with ==).",
        scannedDeps: 0,
        totalParsedDeps,
        manifestsUsed: [],
        uniqueVulnIds: 0,
        totalVulnHits: 0,
        depsSample: [],
        truncated,
      };
      await kvSet(cacheKey, payload, 60 * 30);
      return NextResponse.json(payload);
    }

    // Manifests exist but no pinned deps extracted
    if (!deduped.length) {
      const payload = {
        findings: [],
        note:
          "Manifests detected but no pinned dependencies found to scan. For npm, include package-lock.json. For Python, pin versions in requirements.txt using ==.",
        scannedDeps: 0,
        totalParsedDeps,
        manifestsUsed,
        uniqueVulnIds: 0,
        totalVulnHits: 0,
        depsSample: [],
        truncated,
      };
      await kvSet(cacheKey, payload, 60 * 30);
      return NextResponse.json(payload);
    }

    // Querybatch (IDs only)
    const queryBody = {
      queries: deduped.map((d) => ({
        package: { ecosystem: d.ecosystem, name: d.name },
        version: d.version,
      })),
    };

    const qb = await fetchJson("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(queryBody),
    });

    if (!qb.ok) {
      const msg = `OSV querybatch failed (${qb.status})`;
      const status = qb.status === 429 ? 429 : 502;
      return NextResponse.json(
        { error: msg, details: (qb.text ?? "").slice(0, 500) },
        { status }
      );
    }

    const results = Array.isArray(qb.json?.results) ? qb.json.results : [];

    // results[i].vulns = [{id, modified}] (IDs only)
    const depToVulnIds: Array<{ dep: (typeof deduped)[number]; ids: string[] }> = deduped.map((d, i) => {
      const vulns = Array.isArray(results?.[i]?.vulns) ? results[i].vulns : [];
      const ids = vulns.map((v: any) => String(v?.id || "")).filter(Boolean);
      return { dep: d, ids };
    });

    const uniqueIds = new Set<string>();
    let totalVulnHits = 0;
    for (const x of depToVulnIds) {
      totalVulnHits += x.ids.length;
      for (const vid of x.ids) uniqueIds.add(vid);
    }

    const cappedIds = [...uniqueIds].slice(0, body.maxVulns);

    // Fetch vuln details (limited concurrency)
    const vulnDetailsArr = await mapLimit(cappedIds, 10, async (vid) => {
      const r = await fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(vid)}`, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });
      return { vid, ok: r.ok, status: r.status, json: r.json, text: r.text };
    });

    const vulnMap = new Map<string, any>();
    for (const v of vulnDetailsArr) {
      if (v.ok && v.json) vulnMap.set(v.vid, v.json);
    }

    const findings: DepCveFinding[] = [];
    for (const x of depToVulnIds) {
      for (const vid of x.ids) {
        const detail = vulnMap.get(vid);
        if (!detail) continue;

        const severity = toSeverity(detail);
        const fixedVersion = pickFixedVersion(detail, x.dep.ecosystem, x.dep.name);

        const summary =
          String(detail?.summary || "").trim() ||
          String(detail?.details || "").trim().slice(0, 180) ||
          "Vulnerability reported by OSV";

        const details = String(detail?.details || "").trim().slice(0, 1800);

        const refs = Array.isArray(detail?.references)
          ? detail.references.map((r: any) => String(r?.url || "")).filter(Boolean).slice(0, 4)
          : [];

        findings.push({
          id: `${x.dep.ecosystem}:${x.dep.name}@${x.dep.version}:${vid}`,
          ecosystem: x.dep.ecosystem,
          name: x.dep.name,
          version: x.dep.version,
          vulnId: vid,
          severity,
          summary,
          details: details || undefined,
          fixedVersion: fixedVersion || undefined,
          references: refs.length ? refs : undefined,
        });
      }
    }

    findings.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

    // ✅ nota mucho más clara para demo/UX
    const usedParts: string[] = [];
    if (pkgLockPath) usedParts.push("npm: package-lock.json");
    if (reqPath) usedParts.push("PyPI: requirements.txt");

    let note = `Scanned dependencies via OSV (${usedParts.join(", ")}). `;
    note += `deps(parsed=${totalParsedDeps}, scanned=${deduped.length}${truncated ? ", truncated" : ""}); `;
    note += `vulns(hits=${totalVulnHits}, unique=${uniqueIds.size}${uniqueIds.size > body.maxVulns ? ", capped" : ""}).`;
    if (findings.length === 0) note += " No dependency CVEs found ✅.";

    const payload = {
      findings,
      note,
      // ✅ telemetría extra (no rompe UI)
      scannedDeps: deduped.length,
      totalParsedDeps,
      manifestsUsed,
      uniqueVulnIds: uniqueIds.size,
      totalVulnHits,
      depsSample: deduped.slice(0, 8).map((d) => ({ ecosystem: d.ecosystem, name: d.name, version: d.version })),
      truncated,
    };

    await kvSet(cacheKey, payload, 60 * 30);
    return NextResponse.json(payload);
  } catch (err) {
    const msg = toMsg(err);
    const status = isQuota(msg) ? 429 : 500;
    return NextResponse.json({ error: msg }, { status });
  }
}
