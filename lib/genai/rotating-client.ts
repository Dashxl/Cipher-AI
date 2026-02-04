// src/lib/genai/rotating-client.ts
// Creates a Gemini client per API key (server-only).

import * as GenAI from "@google/genai";

export function makeGenAI(apiKey: string) {
  const Ctor = (GenAI as any).GoogleGenAI || (GenAI as any).GoogleGenerativeAI;
  if (!Ctor) {
    throw new Error("Could not find Google GenAI client constructor in @google/genai.");
  }
  return new Ctor({ apiKey });
}
