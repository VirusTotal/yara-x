import type { ResultSummary } from "./result-summary";

export type ResultMode = "summary" | "raw";
export type SampleMode = "text" | "file";

export type LoadedSampleFile = {
  name: string;
  size: number;
  bytes: Uint8Array;
};

export type ExecutionState = {
  raw: unknown;
  durationMs: number | null;
  summary: ResultSummary;
};
