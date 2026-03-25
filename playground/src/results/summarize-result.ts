import type { ResultSummary, RuleSummary } from "../types/result-summary";

type MaybeObject = Record<string, unknown>;

type PatternMatch = {
  range?: {
    start?: number;
    end?: number;
  };
};

function asObject(value: unknown): MaybeObject {
  return value && typeof value === "object" ? (value as MaybeObject) : {};
}

function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function formatIssue(value: unknown): string {
  if (typeof value === "string") return value;
  if (value instanceof Error) return value?.message;

  const object = asObject(value);
  if (typeof object.text === "string") return object?.text;
  if (typeof object.title === "string") return object?.title;

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function formatRange(match: unknown): string | null {
  const matchObject = asObject(match);
  const range = asObject(matchObject.range);
  const start = range?.start;
  const end = range?.end;

  if (typeof start === "number" && typeof end === "number") {
    return `${start}-${end}`;
  }

  const offset = matchObject.offset;
  const length = matchObject.length;

  if (typeof offset !== "number" || typeof length !== "number") {
    return null;
  }

  return `${offset}-${offset + length}`;
}

function summarizeRule(rule: unknown): RuleSummary {
  const object = asObject(rule);
  const patterns = asArray<unknown>(object.patterns).map((pattern) => {
    const patternObject = asObject(pattern);
    const matches = asArray<PatternMatch>(patternObject.matches);
    const ranges = matches
      .map(formatRange)
      .filter((value): value is string => Boolean(value));

    return {
      identifier:
        typeof patternObject.identifier === "string"
          ? patternObject.identifier
          : "unknown",
      hits: matches.length,
      ranges,
    };
  });

  return {
    identifier:
      typeof object.identifier === "string"
        ? object.identifier
        : "unknown_rule",
    namespace:
      typeof object.namespace === "string" ? object.namespace : "default",
    hits: patterns.reduce((sum, pattern) => sum + pattern.hits, 0),
    patterns,
  };
}

export function summarizeResult(
  raw: unknown,
  mode: "validate" | "scan",
): ResultSummary {
  const object = asObject(raw);
  const errorsList = asArray(object.errors).map(formatIssue);
  const warningsList = asArray(object.warnings).map(formatIssue);
  const matchingRules = asArray(object.matching_rules ?? object.matches).map(
    summarizeRule,
  );
  const nonMatchingRules = asArray<unknown>(object.non_matching_rules).map(
    (rule) => {
      const ruleObject = asObject(rule);
      return typeof ruleObject.identifier === "string"
        ? ruleObject.identifier
        : "unknown_rule";
    },
  );
  const hitCount = matchingRules.reduce((sum, rule) => sum + rule.hits, 0);

  let headline = "Ready to run a rule.";
  let tone: ResultSummary["tone"] = "idle";

  if (mode === "validate") {
    if (errorsList.length > 0) {
      headline = `Validation found ${errorsList.length} error(s).`;
      tone = "issues";
    } else if (warningsList.length > 0) {
      headline = `Validation completed with ${warningsList.length} warning(s).`;
      tone = "issues";
    } else {
      headline = "Rule validation passed without issues.";
      tone = "clean";
    }
  } else if (errorsList.length > 0) {
    headline = `Scan finished with ${errorsList.length} error(s).`;
    tone = "issues";
  } else if (matchingRules.length > 0) {
    headline = `Matched ${matchingRules.length} rule(s) with ${hitCount} pattern hit(s).`;
    tone = "match";
  } else {
    headline = "Scan completed with no matching rules.";
    tone = warningsList.length > 0 ? "issues" : "clean";
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
