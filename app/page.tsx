import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function HomePage() {
  return (
    <main className="min-h-screen flex items-center justify-center p-6">
      <div className="max-w-xl w-full space-y-4">
        <h1 className="text-4xl font-semibold">Cipher AI</h1>
        <p className="text-muted-foreground">
          Crack the code — Decipher your legacy.
        </p>
        <div className="flex gap-3">
          <Button asChild>
            <Link href="/upload">Start analysis</Link>
          </Button>
        </div>
      </div>
    </main>
  );
}
