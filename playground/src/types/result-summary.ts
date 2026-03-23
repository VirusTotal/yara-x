export type ResultTone = "idle" | "clean" | "match" | "issues";

export type PatternSummary = {
  identifier: string;
  hits: number;
  ranges: string[];
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
