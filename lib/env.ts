import { z } from "zod";

const EnvSchema = z.object({
  GEMINI_API_KEY: z.string().min(1),
  GEMINI_FAST_MODEL: z.string().default("gemini-3-flash-preview"),
  GEMINI_DEEP_MODEL: z.string().default("gemini-3-pro-preview"),

  UPSTASH_REDIS_REST_URL: z.string().url().optional().or(z.literal("")),
  UPSTASH_REDIS_REST_TOKEN: z.string().optional().or(z.literal("")),

  GITHUB_TOKEN: z.string().optional().or(z.literal("")),
});

export const env = EnvSchema.parse({
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  GEMINI_FAST_MODEL: process.env.GEMINI_FAST_MODEL,
  GEMINI_DEEP_MODEL: process.env.GEMINI_DEEP_MODEL,
  UPSTASH_REDIS_REST_URL: process.env.UPSTASH_REDIS_REST_URL,
  UPSTASH_REDIS_REST_TOKEN: process.env.UPSTASH_REDIS_REST_TOKEN,
  GITHUB_TOKEN: process.env.GITHUB_TOKEN,
});
