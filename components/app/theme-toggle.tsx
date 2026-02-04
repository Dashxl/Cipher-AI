"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Moon, Sun } from "lucide-react";

export type ThemeMode = "light" | "dark";

function getPreferredTheme(): ThemeMode {
  if (typeof window === "undefined") return "light";
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(next: ThemeMode) {
  const root = document.documentElement;
  root.classList.toggle("dark", next === "dark");
  // Better native form rendering
  root.style.colorScheme = next;
}

/**
 * Small theme toggle that persists to localStorage (key: cipher.theme)
 * and updates the <html> class "dark".
 */
export function ThemeToggle({ className = "" }: { className?: string }) {
  const [theme, setTheme] = useState<ThemeMode>("light");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    let next: ThemeMode = getPreferredTheme();
    try {
      const saved = localStorage.getItem("cipher.theme");
      if (saved === "light" || saved === "dark") next = saved;
    } catch {
      // ignore
    }

    setTheme(next);
    applyTheme(next);
    setMounted(true);
  }, []);

  function toggle() {
    const next: ThemeMode = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
    try {
      localStorage.setItem("cipher.theme", next);
    } catch {
      // ignore
    }
  }

  // Avoid hydration mismatch (icons depend on client state)
  if (!mounted) return null;

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      onClick={toggle}
      className={["h-9 w-9", className].join(" ")}
      title={theme === "dark" ? "Switch to light" : "Switch to dark"}
      aria-label={theme === "dark" ? "Switch to light" : "Switch to dark"}
    >
      {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </Button>
  );
}
