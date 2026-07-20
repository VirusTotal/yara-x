import type { MatchRange, ResultSummary, RuleSummary } from "./result-types";
import {
  normalizeScanResult,
  type ScanResultMatch,
  type ScanResultRule,
} from "./scan-result";
import { asRecord } from "../validation/guards";

function formatIssue(value: unknown): string {
  if (typeof value === "string") return value;
  if (value instanceof Error) return value?.message;

  const object = asRecord(value);
  if (typeof object.text === "string") return object?.text;
  if (typeof object.title === "string") return object?.title;

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function summarizeRange(match: ScanResultMatch): MatchRange | null {
  if (match.start === null || match.end === null) {
    return null;
  }

  return {
    start: match.start,
    end: match.end,
  };
}

function isMatchRange(range: MatchRange | null): range is MatchRange {
  return range !== null;
}

function summarizeRule(rule: ScanResultRule): RuleSummary {
  const patterns = rule.patterns.map((pattern) => {
    const ranges = pattern.matches.map(summarizeRange).filter(isMatchRange);

    return {
      identifier: pattern.identifier,
      hits: pattern.matches.length,
      ranges,
    };
  });

  return {
    identifier: rule.identifier,
    namespace: rule.namespace,
    hits: patterns.reduce((sum, pattern) => sum + pattern.hits, 0),
    patterns,
  };
}

export function summarizeResult(
  raw: unknown,
  mode: "validate" | "scan",
): ResultSummary {
  const result = normalizeScanResult(raw);

  if (result.cancelled) {
    return {
      errors: 0,
      warnings: 0,
      matches: 0,
      nonMatches: 0,
      hitCount: 0,
      headline: "Scan cancelled.",
      tone: "cancelled",
      errorsList: [],
      warningsList: [],
      matchingRules: [],
      nonMatchingRules: [],
    };
  }

  const errorsList = result.errors.map(formatIssue);
  const warningsList = result.warnings.map(formatIssue);
  const matchingRules = result.matchingRules.map(summarizeRule);
  const nonMatchingRules = result.nonMatchingRules;
  const hitCount = matchingRules.reduce((sum, rule) => sum + rule.hits, 0);

  let headline = "Ready to run a rule.";
  let tone: ResultSummary["tone"] = "idle";

  if (mode === "validate") {
    if (errorsList.length > 0) {
      headline = `Validation found ${errorsList.length} error(s).`;
      tone = "issues";
    } else if (warningsList.length > 0) {
      headline = `Validation completed with ${warningsList.length} warning(s).`;
      tone = "warning";
    } else {
      headline = "Rule validation passed without issues.";
      tone = "clean";
    }
  } else if (errorsList.length > 0) {
    headline = `Scan finished with ${errorsList.length} error(s).`;
    tone = "issues";
  } else if (warningsList.length > 0 && matchingRules.length > 0) {
    headline = `Matched ${matchingRules.length} rule(s) with ${hitCount} pattern hit(s) and ${warningsList.length} warning(s).`;
    tone = "warning";
  } else if (matchingRules.length > 0) {
    headline = `Matched ${matchingRules.length} rule(s) with ${hitCount} pattern hit(s).`;
    tone = "match";
  } else if (warningsList.length > 0) {
    headline = `Scan completed with ${warningsList.length} warning(s).`;
    tone = "warning";
  } else {
    headline = "Scan completed with no matching rules.";
    tone = "clean";
  }

  return {
    errors: errorsList.length,
    warnings: warningsList.length,
    matches: matchingRules.length,
    nonMatches: nonMatchingRules.length,
    hitCount,
    headline,
    tone,
    errorsList,
    warningsList,
    matchingRules,
    nonMatchingRules,
  };
}
