export type AnalysisStage =
  | "queued"
  | "exploring_structure"
  | "calling_gemini"
  | "done"
  | "error";

export type AnalysisResult = {
  repoName: string;
  fileCount: number;
  keyFiles: string[];
  mermaid: string; // mermaid diagram source
  summary: string[]; // bullet points
  risks: { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"; title: string; details: string }[];
  quickWins: string[];
  nextSteps: string[];
};

export type AnalysisStatus = {
  id: string;
  stage: AnalysisStage;
  progress: number; // 0..100
  message: string;
  startedAt: string;
  updatedAt: string;
  result?: AnalysisResult;
  error?: string;
};
