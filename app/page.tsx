//src/app/page.tsx
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/app/theme-toggle";

export default function HomePage() {
  return (
    <main className="relative min-h-screen flex items-center justify-center p-6 bg-background text-foreground">
      {/* Theme toggle (persists to localStorage: cipher.theme) */}
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>

      <div className="max-w-xl w-full space-y-4">
        <h1 className="text-4xl font-semibold">Cipher AI</h1>
        <p className="text-muted-foreground">Crack the code — Decipher your legacy.</p>
        <div className="flex gap-3">
          <Button asChild>
            <Link href="/upload">Start analysis</Link>
          </Button>
        </div>
      </div>
    </main>
  );
}
