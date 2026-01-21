import { env } from "@/lib/env";

export const MODELS = {
  fast: env.GEMINI_FAST_MODEL, // gemini-3-flash-preview
  deep: env.GEMINI_DEEP_MODEL, // gemini-3-pro-preview
} as const;
