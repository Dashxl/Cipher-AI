//src/app/upload/page.tsx
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/app/theme-toggle";

export default function UploadPage() {
  const router = useRouter();
  const [zip, setZip] = useState<File | null>(null);
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);

  async function startFromZip() {
    if (!zip) return;
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("zip", zip);

      const res = await fetch("/api/analysis/start", { method: "POST", body: fd });
      const data = (await res.json()) as { analysisId: string };
      router.push(`/analysis/${data.analysisId}`);
    } finally {
      setLoading(false);
    }
  }

  async function startFromGitHub() {
    const url = githubUrl.trim();
    if (!url) return;

    setLoading(true);
    try {
      const res = await fetch("/api/analysis/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ githubUrl: url }),
      });

      const data = (await res.json()) as { analysisId: string };
      router.push(`/analysis/${data.analysisId}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="relative min-h-screen flex items-center justify-center p-6 bg-background text-foreground">
      {/* Theme toggle */}
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>

      <Card className="w-full max-w-xl">
        <CardHeader>
          <CardTitle>Analyze a repository</CardTitle>
        </CardHeader>

        <CardContent className="space-y-6">
          <div className="space-y-3">
            <h3 className="font-medium">Option A: Upload ZIP</h3>
            <Input type="file" accept=".zip" onChange={(e) => setZip(e.target.files?.[0] ?? null)} />
            <Button onClick={startFromZip} disabled={loading || !zip}>
              {loading ? "Analyzing…" : "Analyze ZIP with Gemini 3"}
            </Button>
          </div>

          <div className="space-y-3">
            <h3 className="font-medium">Option B: GitHub URL</h3>
            <Input
              placeholder="https://github.com/owner/repo"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
            />
            <Button onClick={startFromGitHub} disabled={loading || !githubUrl.trim()}>
              {loading ? "Analyzing…" : "Analyze GitHub repo with Gemini 3"}
            </Button>
            <p className="text-sm text-muted-foreground">
              Only URLs from public repos.
            </p>
          </div>
        </CardContent>
      </Card>
    </main>
  );
}
