import { Redis } from "@upstash/redis";
import { env } from "@/lib/env";

const hasUpstash = Boolean(env.UPSTASH_REDIS_REST_URL && env.UPSTASH_REDIS_REST_TOKEN);

const redis = hasUpstash
  ? new Redis({ url: env.UPSTASH_REDIS_REST_URL!, token: env.UPSTASH_REDIS_REST_TOKEN! })
  : null;

/**
 * Fallback in-memory cache with TTL.
 * - Stores { value, expiresAt } in ms.
 * - Best-effort sweeping to avoid unbounded growth.
 */
type MemEntry = { value: unknown; expiresAt: number };

const mem = new Map<string, MemEntry>();

const MEM_MAX_ENTRIES = 5000; // hard cap
const SWEEP_EVERY_MS = 30_000; // run sweep at most every 30s
const SWEEP_BATCH = 600; // delete up to N expired per sweep

let lastSweepAt = 0;

function sweepMem(now = Date.now()) {
  if (mem.size === 0) return;
  if (now - lastSweepAt < SWEEP_EVERY_MS) return;

  lastSweepAt = now;

  // 1) remove expired (best effort, bounded)
  let checked = 0;
  for (const [k, v] of mem) {
    if (v.expiresAt <= now) mem.delete(k);
    checked++;
    if (checked >= SWEEP_BATCH) break;
  }

  // 2) hard cap eviction (oldest first)
  if (mem.size > MEM_MAX_ENTRIES) {
    const toDrop = mem.size - MEM_MAX_ENTRIES;
    let dropped = 0;
    for (const k of mem.keys()) {
      mem.delete(k);
      dropped++;
      if (dropped >= toDrop) break;
    }
  }
}

export async function kvSet<T>(key: string, value: T, ttlSeconds = 60 * 60) {
  if (!key) return;

  // TTL <= 0 means "expire immediately"
  if (ttlSeconds <= 0) {
    if (redis) {
      // Upstash supports del; keeping behavior consistent is nice, but optional.
      // If you prefer no-op, you can remove this.
      await redis.del(key);
    } else {
      mem.delete(key);
    }
    return;
  }

  if (redis) {
    await redis.set(key, value, { ex: ttlSeconds });
    return;
  }

  const now = Date.now();
  const expiresAt = now + ttlSeconds * 1000;

  mem.set(key, { value, expiresAt });
  sweepMem(now);
}

export async function kvGet<T>(key: string): Promise<T | null> {
  if (!key) return null;

  if (redis) return (await redis.get<T>(key)) ?? null;

  const now = Date.now();
  const entry = mem.get(key);
  if (!entry) {
    sweepMem(now);
    return null;
  }

  if (entry.expiresAt <= now) {
    mem.delete(key);
    sweepMem(now);
    return null;
  }

  sweepMem(now);
  return (entry.value as T) ?? null;
}
