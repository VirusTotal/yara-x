export type ResultMode = "summary" | "raw" | "console";

export type ResultTone =
  | "idle"
  | "clean"
  | "match"
  | "warning"
  | "issues"
  | "cancelled";

export type PatternSummary = {
  identifier: string;
  hits: number;
  ranges: MatchRange[];
};

export type MatchRange = {
  start: number;
  end: number;
};

export type RuleSummary = {
  identifier: string;
  namespace: string;
  hits: number;
  patterns: PatternSummary[];
};

export type ResultSummary = {
  errors: number;
  warnings: number;
  matches: number;
  nonMatches: number;
  hitCount: number;
  headline: string;
  tone: ResultTone;
  errorsList: string[];
  warningsList: string[];
  matchingRules: RuleSummary[];
  nonMatchingRules: string[];
};

export type ExecutionState = {
  raw: unknown;
  consoleOutput: string[];
  durationMs: number | null;
  summary: ResultSummary;
};
