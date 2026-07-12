import { asArray, asRecord, asStringArray } from "../validation/guards";

export type ScanResultMatch = {
  start: number | null;
  end: number | null;
};

export type ScanResultPattern = {
  identifier: string;
  matches: ScanResultMatch[];
};

export type ScanResultRule = {
  identifier: string;
  namespace: string;
  patterns: ScanResultPattern[];
};

export type ScanResult = {
  cancelled: boolean;
  errors: string[];
  warnings: string[];
  matchingRules: ScanResultRule[];
  nonMatchingRules: string[];
};

function readMatch(value: unknown): ScanResultMatch {
  const match = asRecord(value);
  const range = asRecord(match.range);

  if (typeof range.start === "number" && typeof range.end === "number") {
    return { start: range.start, end: range.end };
  }

  if (typeof match.offset === "number" && typeof match.length === "number") {
    return {
      start: match.offset,
      end: match.offset + match.length,
    };
  }

  return { start: null, end: null };
}

function readPattern(value: unknown): ScanResultPattern {
  const pattern = asRecord(value);

  return {
    identifier:
      typeof pattern.identifier === "string"
        ? pattern.identifier
        : "unknown_pattern",
    matches: asArray(pattern.matches).map(readMatch),
  };
}

function readRule(value: unknown): ScanResultRule {
  const rule = asRecord(value);

  return {
    identifier:
      typeof rule.identifier === "string" ? rule.identifier : "unknown_rule",
    namespace: typeof rule.namespace === "string" ? rule.namespace : "default",
    patterns: asArray(rule.patterns).map(readPattern),
  };
}

function readNonMatchingRule(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  const rule = asRecord(value);
  return typeof rule.identifier === "string" ? rule.identifier : "unknown_rule";
}

export function normalizeScanResult(raw: unknown): ScanResult {
  const result = asRecord(raw);

  return {
    cancelled: result.cancelled === true,
    errors: asStringArray(result.errors),
    warnings: asStringArray(result.warnings),
    matchingRules: asArray(result.matching_rules ?? result.matches).map(
      readRule,
    ),
    nonMatchingRules: asArray(result.non_matching_rules).map(
      readNonMatchingRule,
    ),
  };
}
