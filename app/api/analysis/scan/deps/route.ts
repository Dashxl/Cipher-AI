// src/app/api/analysis/scan/deps/route.ts
import JSZip from "jszip";
import type { DepCveFinding, Severity } from "@/types/scan";
import { kvGet, kvSet } from "@/lib/cache/store";
import {
  loadZip,
  ZipNotReadyError,
  ZipCorruptError,
  ZipChunkMissingError,
} from "@/lib/repo/zip-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Dep = { ecosystem: "npm" | "PyPI"; name: string; version: string; source: string };

const DEFAULT_MAX_DEPS = 450;
const CACHE_TTL_SECONDS = 60 * 30; // 30 min

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const analysisId = String(body?.analysisId ?? "");
    const maxDeps = clampInt(body?.maxDeps ?? DEFAULT_MAX_DEPS, 50, 1500);

    if (!analysisId) return Response.json({ error: "Missing analysisId" }, { status: 400 });

    const cacheKey = `scan:deps:${analysisId}:${maxDeps}`;
    const cached = await kvGet<any>(cacheKey);
    if (cached) return Response.json(cached);

    let zipBytes: Buffer;
    try {
      zipBytes = await loadZip(analysisId);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);

      if (e instanceof ZipNotReadyError || e instanceof ZipChunkMissingError) {
        console.error("[scan:deps] zip not ready", { id: analysisId, msg });
        return Response.json(
          { error: "Analysis zip not ready or expired. Re-run analysis.", code: (e as any).code },
          { status: 410 }
        );
      }

      if (e instanceof ZipCorruptError) {
        console.error("[scan:deps] zip corrupt", { id: analysisId, msg });
        return Response.json(
          { error: "Analysis zip is corrupt. Re-run analysis.", code: "ZIP_CORRUPT" },
          { status: 500 }
        );
      }

      console.error("[scan:deps] zip load failed", { id: analysisId, msg });
      return Response.json({ error: "Failed to load analysis zip", code: "ZIP_LOAD_FAILED" }, { status: 500 });
    }

    let zip: JSZip;
    try {
      zip = await JSZip.loadAsync(zipBytes as any);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[scan:deps] JSZip.loadAsync failed", { id: analysisId, msg });
      return Response.json(
        { error: "Failed to parse zip (corrupt). Re-run analysis.", code: "ZIP_PARSE_FAILED" },
        { status: 500 }
      );
    }

    const fileNames = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
    const manifests = pickManifests(fileNames);

    if (manifests.length === 0) {
      const payload = {
        findings: [],
        note:
          "No dependency manifests found. Supported: package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, poetry.lock, pyproject.toml",
      };
      await kvSet(cacheKey, payload, CACHE_TTL_SECONDS);
      return Response.json(payload);
    }

    const deps: Dep[] = [];
    const notes: string[] = [];
    let unpinnedPy = 0;

    let readableManifests = 0;
    let emptyManifests = 0;

    for (const m of manifests) {
      const file = zip.file(m);
      if (!file) continue;

      const text = await file.async("string");
      if (text.trim().length === 0) {
        emptyManifests++;
        continue;
      }

      readableManifests++;

      const lower = m.toLowerCase();

      if (lower.endsWith("package-lock.json")) {
        deps.push(...extractFromPackageLock(text, m));
      } else if (lower.endsWith("yarn.lock")) {
        deps.push(...extractFromYarnLock(text, m));
      } else if (lower.endsWith("pnpm-lock.yaml")) {
        deps.push(...extractFromPnpmLock(text, m));
      } else if (lower.endsWith("requirements.txt")) {
        const out = extractFromRequirements(text, m);
        deps.push(...out.deps);
        unpinnedPy += out.unpinned;
        if (out.note) notes.push(out.note);
      } else if (lower.endsWith("poetry.lock")) {
        deps.push(...extractFromPoetryLock(text, m));
      } else if (lower.endsWith("pyproject.toml")) {
        const out = extractFromPyProject(text, m);
        deps.push(...out.deps);
        unpinnedPy += out.unpinned;
        if (out.note) notes.push(out.note);
      }
    }

    // If all manifests were empty, abort loudly (don’t silently claim “no deps”)
    if (readableManifests === 0) {
      return Response.json(
        {
          error: "No readable dependency manifests found (all were empty). The analysis zip may be corrupt/expired.",
          code: "NO_READABLE_MANIFESTS",
          stats: { manifests: manifests.length, emptyManifests },
        },
        { status: 422 }
      );
    }

    const unique = uniqDeps(deps);

    if (unique.length === 0) {
      const payload = {
        findings: [],
        note:
          "Dependency manifests found, but no pinned dependencies could be extracted. If using ranges (^, ~, >=), pin exact versions for best CVE accuracy." +
          (emptyManifests ? ` (Skipped ${emptyManifests} empty manifests.)` : ""),
      };
      await kvSet(cacheKey, payload, CACHE_TTL_SECONDS);
      return Response.json(payload);
    }

    let scanList = unique;
    if (scanList.length > maxDeps) {
      scanList = scanList.slice(0, maxDeps);
      notes.push(`Scanned first ${maxDeps} deps (found ${unique.length}). Increase maxDeps if needed.`);
    }

    if (unpinnedPy > 0) {
      notes.push(`Skipped ${unpinnedPy} Python deps without exact pins (use == for best accuracy).`);
    }

    if (emptyManifests > 0) {
      notes.push(`Skipped ${emptyManifests} empty manifests.`);
    }

    const { findings, osvNote } = await queryOsv(scanList);
    if (osvNote) notes.push(osvNote);

    const payload = {
      findings,
      note:
        `Manifests: ${manifests.join(", ")}.\n` +
        `Deps scanned: ${scanList.length}.\n` +
        `Findings: ${findings.length}.\n` +
        (notes.length ? notes.join("\n") : ""),
    };

    await kvSet(cacheKey, payload, CACHE_TTL_SECONDS);
    return Response.json(payload);
  } catch (err: any) {
    return Response.json({ error: err?.message ?? "Dependency scan failed" }, { status: 500 });
  }
}

/* ---------------- helpers ---------------- */

function clampInt(v: any, min: number, max: number) {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function pickManifests(files: string[]) {
  const wanted = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "pyproject.toml",
  ];

  const found: string[] = [];
  for (const w of wanted) {
    const hit =
      files.find((p) => p.toLowerCase().endsWith(`/${w}`)) ??
      files.find((p) => p.toLowerCase() === w);
    if (hit) found.push(hit);
  }
  return found;
}

function uniqDeps(deps: Dep[]) {
  const map = new Map<string, Dep>();
  for (const d of deps) {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    if (!map.has(key)) map.set(key, d);
  }
  return Array.from(map.values());
}

/* --------- extractors --------- */

function extractFromPackageLock(text: string, source: string): Dep[] {
  try {
    const json = JSON.parse(text);
    const out: Dep[] = [];

    if (json && typeof json === "object" && json.packages && typeof json.packages === "object") {
      for (const k of Object.keys(json.packages)) {
        const node = json.packages[k];
        if (!node || typeof node !== "object") continue;
        const name = (node as any).name;
        const version = (node as any).version;
        if (typeof name === "string" && typeof version === "string") {
          out.push({ ecosystem: "npm", name, version, source });
        }
      }
      return out;
    }

    if (json && typeof json === "object" && (json as any).dependencies && typeof (json as any).dependencies === "object") {
      walkNpmDeps((json as any).dependencies, out, source);
      return out;
    }

    return [];
  } catch {
    return [];
  }
}

function walkNpmDeps(tree: any, out: Dep[], source: string) {
  if (!tree || typeof tree !== "object") return;
  for (const name of Object.keys(tree)) {
    const node = tree[name];
    if (!node || typeof node !== "object") continue;
    const version = node.version;
    if (typeof version === "string") out.push({ ecosystem: "npm", name, version, source });
    if (node.dependencies) walkNpmDeps(node.dependencies, out, source);
  }
}

function extractFromYarnLock(text: string, source: string): Dep[] {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const out: Dep[] = [];
  let currentName: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];

    if (!ln.startsWith(" ") && ln.trim().endsWith(":") && ln.includes("@")) {
      const rawKey = ln.trim().replace(/:$/, "");
      const first = rawKey.split(",")[0]?.trim();
      const spec = first.replace(/^"|"$/g, "");
      const at = spec.lastIndexOf("@");
      if (at > 0) currentName = spec.slice(0, at);
      else currentName = null;
      continue;
    }

    if (!currentName) continue;

    const m1 = ln.match(/^\s*version\s+"([^"]+)"/);
    const m2 = ln.match(/^\s*version:\s*([^\s#]+)/);
    const version = m1?.[1] ?? m2?.[1];

    if (version) {
      out.push({ ecosystem: "npm", name: currentName, version: String(version).trim(), source });
      currentName = null;
    }
  }

  return out;
}

function extractFromPnpmLock(text: string, source: string): Dep[] {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const out: Dep[] = [];
  let inPackages = false;

  for (const ln of lines) {
    const t = ln.trimEnd();

    if (!inPackages) {
      if (t.trim() === "packages:" || t.trim() === "packages: {}") inPackages = true;
      continue;
    }

    const m = t.match(/^ {2}\/(.+?):\s*$/);
    if (!m) continue;

    let key = m[1].trim().replace(/^"|"$/g, "");
    const paren = key.indexOf("(");
    if (paren >= 0) key = key.slice(0, paren);

    const at = key.lastIndexOf("@");
    if (at <= 0) continue;

    const name = key.slice(0, at);
    const version = key.slice(at + 1);
    if (name && version) out.push({ ecosystem: "npm", name, version, source });
  }

  return out;
}

function extractFromRequirements(text: string, source: string): { deps: Dep[]; unpinned: number; note?: string } {
  const out: Dep[] = [];
  let unpinned = 0;

  const lines = text.replace(/\r\n/g, "\n").split("\n");
  for (const ln of lines) {
    const s = ln.trim();
    if (!s || s.startsWith("#")) continue;
    if (s.startsWith("-r ") || s.startsWith("--requirement")) continue;

    const m = s.match(/^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)\s*(?:#.*)?$/);
    if (!m) {
      unpinned++;
      continue;
    }
    out.push({ ecosystem: "PyPI", name: m[1], version: m[2], source });
  }

  return { deps: out, unpinned, note: unpinned ? `requirements.txt had ${unpinned} unpinned entries.` : undefined };
}

function extractFromPoetryLock(text: string, source: string): Dep[] {
  const out: Dep[] = [];
  const lines = text.replace(/\r\n/g, "\n").split("\n");

  let name: string | null = null;
  let version: string | null = null;

  for (const ln of lines) {
    if (ln.trim() === "[[package]]") {
      if (name && version) out.push({ ecosystem: "PyPI", name, version, source });
      name = null;
      version = null;
      continue;
    }

    const mName = ln.match(/^\s*name\s*=\s*"([^"]+)"/);
    if (mName) name = mName[1];

    const mVer = ln.match(/^\s*version\s*=\s*"([^"]+)"/);
    if (mVer) version = mVer[1];
  }

  if (name && version) out.push({ ecosystem: "PyPI", name, version, source });
  return out;
}

function extractFromPyProject(text: string, source: string): { deps: Dep[]; unpinned: number; note?: string } {
  const out: Dep[] = [];
  let unpinned = 0;

  const t = text.replace(/\r\n/g, "\n");

  const depArray = t.match(/^\s*dependencies\s*=\s*\[(.|\n)*?\]/m);
  if (depArray) {
    const chunk = depArray[0];
    const matches = chunk.match(/"([^"]+)"/g) ?? [];
    for (const q of matches) {
      const entry = q.replace(/^"|"$/g, "");
      const m = entry.match(/^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)$/);
      if (m) out.push({ ecosystem: "PyPI", name: m[1], version: m[2], source });
      else unpinned++;
    }
  }

  const section = t.split(/\n\[\s*tool\.poetry\.dependencies\s*\]\n/i);
  if (section.length > 1) {
    const after = section[1];
    const untilNext = after.split(/\n\[/)[0] ?? after;
    const lines = untilNext.split("\n");

    for (const ln of lines) {
      const s = ln.trim();
      if (!s || s.startsWith("#")) continue;
      if (s.toLowerCase().startsWith("python")) continue;

      const m = s.match(/^([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"\s*$/);
      if (!m) continue;

      const name = m[1];
      const spec = m[2].trim();

      if (/^\d+(\.\d+){1,3}$/.test(spec)) out.push({ ecosystem: "PyPI", name, version: spec, source });
      else unpinned++;
    }
  }

  const note = unpinned ? `pyproject.toml had ${unpinned} non-exact dependency specs.` : undefined;
  return { deps: out, unpinned, note };
}

/* --------- OSV query --------- */

async function queryOsv(deps: Dep[]): Promise<{ findings: DepCveFinding[]; osvNote?: string }> {
  const findings: DepCveFinding[] = [];
  const batches = chunk(deps, 350);
  let totalVulns = 0;

  for (const batch of batches) {
    const body = {
      queries: batch.map((d) => ({
        package: { ecosystem: d.ecosystem, name: d.name },
        version: d.version,
      })),
    };

    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      return { findings, osvNote: `OSV querybatch failed (${res.status}).` };
    }

    const data = await res.json();
    const results = Array.isArray(data?.results) ? data.results : [];

    for (let i = 0; i < results.length; i++) {
      const dep = batch[i];
      const vulns = Array.isArray(results[i]?.vulns) ? results[i].vulns : [];
      totalVulns += vulns.length;

      for (const v of vulns) {
        const vulnId = String(v?.id ?? "");
        const summary = String(v?.summary ?? "Vulnerability");
        const details = safeTrim(String(v?.details ?? ""), 1200);

        const sev = severityFromOsv(v);
        const fixedVersion = pickFixedVersionFor(dep, v);

        const refs = Array.isArray(v?.references)
          ? v.references.map((r: any) => String(r?.url ?? "")).filter(Boolean).slice(0, 6)
          : [];

        findings.push({
          id: `${dep.ecosystem}:${dep.name}@${dep.version}:${vulnId}`,
          ecosystem: dep.ecosystem,
          name: dep.name,
          version: dep.version,
          vulnId,
          severity: sev,
          summary,
          details: details || undefined,
          fixedVersion: fixedVersion || undefined,
          references: refs.length ? refs : undefined,
        });
      }
    }
  }

  findings.sort((a, b) => {
    const d = severityRank(b.severity) - severityRank(a.severity);
    if (d) return d;
    return `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`);
  });

  const osvNote = totalVulns === 0 ? "No dependency CVEs found ✅ (good news)." : undefined;
  return { findings, osvNote };
}

function safeTrim(s: string, max: number) {
  const t = s.trim();
  if (t.length <= max) return t;
  return t.slice(0, max) + "\n…";
}

function severityRank(s: Severity) {
  return s === "CRITICAL" ? 4 : s === "HIGH" ? 3 : s === "MEDIUM" ? 2 : 1;
}

function severityFromOsv(v: any): Severity {
  const arr = Array.isArray(v?.severity) ? v.severity : [];
  for (const s of arr) {
    const score = Number(s?.score);
    if (Number.isFinite(score)) {
      if (score >= 9) return "CRITICAL";
      if (score >= 7) return "HIGH";
      if (score >= 4) return "MEDIUM";
      return "LOW";
    }
  }

  const ds = String(v?.database_specific?.severity ?? "").toUpperCase();
  if (ds === "CRITICAL" || ds === "HIGH" || ds === "MEDIUM" || ds === "LOW") return ds as Severity;

  return "MEDIUM";
}

function pickFixedVersionFor(dep: Dep, vuln: any): string | "" {
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  const fixeds: string[] = [];

  for (const a of affected) {
    const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r?.events) ? r.events : [];
      for (const e of events) {
        if (e?.fixed) fixeds.push(String(e.fixed));
      }
    }
  }

  if (!fixeds.length) return "";

  const current = dep.version;

  if (dep.ecosystem === "npm") {
    const sorted = fixeds
      .filter((x) => !!parseSemver(x))
      .sort((a, b) => (semverGt(a, b) ? 1 : -1));
    for (const fx of sorted) {
      if (semverGt(fx, current)) return fx;
    }
    return sorted[0] ?? "";
  }

  const sorted = fixeds.sort((a, b) => (pep440Gt(a, b) ? 1 : -1));
  for (const fx of sorted) {
    if (pep440Gt(fx, current)) return fx;
  }
  return sorted[0] ?? "";
}

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

function chunk<T>(arr: T[], size: number) {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}
