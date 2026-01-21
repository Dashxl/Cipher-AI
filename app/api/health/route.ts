import { NextResponse } from "next/server";
import { MODELS } from "@/lib/genai/models";

export async function GET() {
  return NextResponse.json({ ok: true, models: MODELS });
}
