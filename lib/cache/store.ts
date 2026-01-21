import { Redis } from "@upstash/redis";
import { env } from "@/lib/env";

const hasUpstash = Boolean(env.UPSTASH_REDIS_REST_URL && env.UPSTASH_REDIS_REST_TOKEN);

const redis = hasUpstash
  ? new Redis({ url: env.UPSTASH_REDIS_REST_URL!, token: env.UPSTASH_REDIS_REST_TOKEN! })
  : null;

const mem = new Map<string, unknown>();

export async function kvSet<T>(key: string, value: T, ttlSeconds = 60 * 60) {
  if (redis) {
    await redis.set(key, value, { ex: ttlSeconds });
    return;
  }
  mem.set(key, value);
}

export async function kvGet<T>(key: string): Promise<T | null> {
  if (redis) return (await redis.get<T>(key)) ?? null;
  return (mem.get(key) as T) ?? null;
}
