export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type VulnFinding = {
  id: string;
  severity: Severity;
  type: string;
  title: string;
  file: string;
  line: number;
  snippet: string;
  recommendation: string;
  fix?: string;        // Gemini suggested fix (optional)
  confidence?: number; // 0..1 (optional)
};

export type DebtIssue = {
  id: string;
  severity: Severity;
  type: string;
  title: string;
  file: string;
  line: number;
  details: string;
  suggestion: string;
  fix?: string;        // Gemini suggested refactor (optional)
  confidence?: number; // 0..1 (optional)
};

export type DepCveFinding = {
  id: string; // e.g. "npm:react@18.2.0:GHSA-xxxx"
  ecosystem: "npm" | "PyPI";
  name: string;
  version: string;
  vulnId: string;
  severity: Severity;
  summary: string;
  details?: string;
  fixedVersion?: string;
  references?: string[];
};

