// src/lib/genai/keyring.ts
// Simple in-memory Gemini API key rotation (server-side).
// Configure in .env.local:
//   GEMINI_API_KEYS="key1,key2,key3,key4"

export type KeyState = {
  key: string;
  badUntil: number; // ms timestamp
  dead: boolean;
  failures: number;
};

const DEFAULT_COOLDOWN_MS = 60_000; // 1 min
const MAX_BACKOFF_MULT = 15;

function now() {
  return Date.now();
}

function parseKeys(): string[] {
  const raw = process.env.GEMINI_API_KEYS || process.env.GEMINI_API_KEY || "";
  const keys = raw
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean);
  if (keys.length === 0) throw new Error("No Gemini API keys configured. Set GEMINI_API_KEYS.");
  return keys;
}

function getStatus(err: any): number | null {
  const v = err?.status ?? err?.code ?? err?.response?.status ?? null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function isQuotaError(err: any) {
  const status = getStatus(err);
  const msg = String(err?.message ?? "");
  return status === 429 || /RESOURCE_EXHAUSTED|quota|rate limit|Too Many Requests/i.test(msg);
}

function isInvalidKeyError(err: any) {
  const status = getStatus(err);
  const msg = String(err?.message ?? "");
  return status === 401 || status === 403 || /API key not valid|invalid api key|permission denied/i.test(msg);
}

// Persist across hot reloads in dev
const g = globalThis as any;
const store: { states: KeyState[]; cursor: number } =
  g.__cipherGeminiKeyring ||
  (g.__cipherGeminiKeyring = {
    states: parseKeys().map((key) => ({ key, badUntil: 0, dead: false, failures: 0 })),
    cursor: 0,
  });

export function getNextKey(): KeyState {
  const N = store.states.length;
  const t = now();

  for (let i = 0; i < N; i++) {
    const idx = (store.cursor + i) % N;
    const s = store.states[idx];
    if (!s.dead && s.badUntil <= t) {
      store.cursor = (idx + 1) % N;
      return s;
    }
  }

  const alive = store.states.filter((s) => !s.dead);
  if (alive.length === 0) throw new Error("All Gemini API keys are invalid (dead).");

  alive.sort((a, b) => a.badUntil - b.badUntil);
  return alive[0];
}

export function markQuota(state: KeyState, cooldownMs = DEFAULT_COOLDOWN_MS) {
  state.failures += 1;
  const mult = Math.min(MAX_BACKOFF_MULT, Math.pow(2, Math.min(4, state.failures - 1)));
  state.badUntil = now() + cooldownMs * mult;
}

export function markDead(state: KeyState) {
  state.dead = true;
  state.badUntil = Number.POSITIVE_INFINITY;
}

export async function withRotatingKey<T>(
  runner: (apiKey: string) => Promise<T>,
  opts?: { maxAttempts?: number }
): Promise<T> {
  const maxAttempts = opts?.maxAttempts ?? store.states.length;
  let lastErr: any;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const state = getNextKey();
    try {
      return await runner(state.key);
    } catch (err: any) {
      lastErr = err;

      if (isInvalidKeyError(err)) {
        markDead(state);
        continue;
      }
      if (isQuotaError(err)) {
        markQuota(state);
        continue;
      }
      throw err;
    }
  }

  throw lastErr ?? new Error("Gemini request failed after rotating keys.");
}
