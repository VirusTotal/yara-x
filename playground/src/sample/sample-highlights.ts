import type { EditorHighlight } from "../editor/yara-monaco";
import type { MatchRange } from "../results/result-types";
import { normalizeScanResult } from "../results/scan-result";
import type { InlineSampleMode } from "./sample-modes";

type ByteHighlight = {
  start: number;
  end: number;
  labels: string[];
};

type HighlightOffsets = {
  start: number | null;
  end: number | null;
};

export type SampleEditorRange = {
  start: number;
  end: number;
};

type TextBoundary = {
  byteOffset: number;
  highlightIndex: number;
  edge: keyof HighlightOffsets;
};

type HexBoundary = {
  digitOffset: number;
  highlightIndex: number;
  edge: keyof HighlightOffsets;
};

const whitespacePattern = /\s/;

function pushLabel(
  byRange: Map<string, ByteHighlight>,
  start: number,
  end: number,
  label: string,
) {
  if (start < 0 || end <= start) {
    return;
  }

  const key = `${start}:${end}`;
  const existing = byRange.get(key);

  if (existing) {
    if (!existing.labels.includes(label)) {
      existing.labels.push(label);
    }
    return;
  }

  byRange.set(key, {
    start,
    end,
    labels: [label],
  });
}

function extractByteHighlights(raw: unknown): ByteHighlight[] {
  const { matchingRules } = normalizeScanResult(raw);
  const byRange = new Map<string, ByteHighlight>();

  for (const rule of matchingRules) {
    for (const pattern of rule.patterns) {
      for (const match of pattern.matches) {
        const { start, end } = match;

        if (start == null || end == null) {
          continue;
        }

        pushLabel(
          byRange,
          start,
          end,
          `${rule.identifier} · ${pattern.identifier} · bytes ${start}-${end - 1}`,
        );
      }
    }
  }

  return [...byRange.values()].sort((left, right) => left.start - right.start);
}

function utf8ByteLength(char: string) {
  const codePoint = char.codePointAt(0)!;

  if (codePoint <= 0x7f) return 1;
  if (codePoint <= 0x7ff) return 2;
  if (codePoint <= 0xffff) return 3;
  return 4;
}

function setTextHighlightOffset(
  offsets: HighlightOffsets[],
  boundary: TextBoundary,
  value: number,
) {
  offsets[boundary.highlightIndex]![boundary.edge] = value;
}

function isEndBoundary(boundary: { edge: keyof HighlightOffsets }) {
  return boundary.edge === "end";
}

/**
 * Maps YARA byte ranges to Monaco text positions.
 *
 * YARA returns byte offsets for the UTF-8 input, while Monaco uses UTF-16
 * string offsets. Unicode characters can use different sizes in each, so
 * resolve boundaries while tracking both positions.
 *
 * Highlights are applied on the main thread after a scan. That is normally
 * cheap, but broad rules can produce enough matches that walking the source
 * once per range becomes noticeable. Collect all boundaries, sort them once,
 * then resolve them in one source walk instead.
 *
 * Worst case: O(H log H + n), where H is the number of highlights and n is
 * the source length. Uses O(H) additional memory.
 */
function mapTextHighlightOffsets(
  source: string,
  highlights: ByteHighlight[],
): HighlightOffsets[] {
  if (highlights.length === 0) {
    return [];
  }

  const offsets: HighlightOffsets[] = highlights.map(() => ({
    start: null,
    end: null,
  }));
  const boundaries: TextBoundary[] = [];

  for (const [highlightIndex, highlight] of highlights.entries()) {
    boundaries.push(
      {
        byteOffset: highlight.start,
        highlightIndex,
        edge: "start",
      },
      {
        byteOffset: highlight.end,
        highlightIndex,
        edge: "end",
      },
    );
  }

  boundaries.sort((left, right) => left.byteOffset - right.byteOffset);

  let boundaryIndex = 0;
  let consumedBytes = 0;
  let consumedCodeUnits = 0;

  for (const char of source) {
    if (boundaryIndex >= boundaries.length) {
      break;
    }

    const nextBytes = consumedBytes + utf8ByteLength(char);
    const nextCodeUnits = consumedCodeUnits + char.length;

    while (
      boundaryIndex < boundaries.length &&
      boundaries[boundaryIndex]!.byteOffset < nextBytes
    ) {
      const boundary = boundaries[boundaryIndex]!;
      setTextHighlightOffset(
        offsets,
        boundary,
        isEndBoundary(boundary) ? nextCodeUnits : consumedCodeUnits,
      );
      boundaryIndex += 1;
    }

    consumedBytes = nextBytes;
    consumedCodeUnits = nextCodeUnits;

    while (
      boundaryIndex < boundaries.length &&
      boundaries[boundaryIndex]!.byteOffset === consumedBytes
    ) {
      setTextHighlightOffset(
        offsets,
        boundaries[boundaryIndex]!,
        consumedCodeUnits,
      );
      boundaryIndex += 1;
    }
  }

  return offsets;
}

function isEditorHighlight(
  highlight: EditorHighlight | null,
): highlight is EditorHighlight {
  return highlight !== null;
}

function toEditorHighlights(
  highlights: ByteHighlight[],
  offsets: HighlightOffsets[],
  activeRange: MatchRange | null,
): EditorHighlight[] {
  return highlights
    .map<EditorHighlight | null>((highlight, index) => {
      const offset = offsets[index];

      if (
        offset == null ||
        offset.start == null ||
        offset.end == null ||
        offset.end <= offset.start
      ) {
        return null;
      }

      return {
        start: offset.start,
        end: offset.end,
        hoverMessage: highlight.labels.join("\n"),
        isActive:
          activeRange?.start === highlight.start &&
          activeRange?.end === highlight.end,
      };
    })
    .filter(isEditorHighlight);
}

/**
 * Maps YARA byte ranges to visible positions in a hex sample.
 *
 * Hex input ignores whitespace and rejects other characters, so every byte
 * corresponds to two visible digits. Resolve sorted boundaries in one walk
 * instead of keeping a position for every digit in the input.
 *
 * Adjacent ranges share a digit boundary. Ends must be processed before
 * starts there, otherwise the previous range's end is skipped as the digit
 * offset advances and the highlight is dropped.
 *
 * Worst case: O(H log H + n), where H is the number of highlights and n is
 * the source length. Uses O(H) additional memory.
 */
function mapHexHighlightOffsets(
  source: string,
  highlights: ByteHighlight[],
): HighlightOffsets[] {
  if (highlights.length === 0) {
    return [];
  }

  const offsets: HighlightOffsets[] = highlights.map(() => ({
    start: null,
    end: null,
  }));
  const boundaries: HexBoundary[] = [];

  for (const [highlightIndex, highlight] of highlights.entries()) {
    boundaries.push(
      {
        digitOffset: highlight.start * 2,
        highlightIndex,
        edge: "start",
      },
      {
        digitOffset: highlight.end * 2,
        highlightIndex,
        edge: "end",
      },
    );
  }

  // See the adjacent-range note above: the end must sort before the start
  // when both point at the same digit offset.
  boundaries.sort(
    (left, right) =>
      left.digitOffset - right.digitOffset ||
      Number(isEndBoundary(right)) - Number(isEndBoundary(left)),
  );

  let boundaryIndex = 0;
  let digitOffset = 0;

  for (let index = 0; index < source.length; index += 1) {
    if (boundaryIndex >= boundaries.length) {
      break;
    }

    if (whitespacePattern.test(source[index]!)) {
      continue;
    }

    while (
      boundaryIndex < boundaries.length &&
      boundaries[boundaryIndex]!.digitOffset === digitOffset &&
      !isEndBoundary(boundaries[boundaryIndex]!)
    ) {
      const boundary = boundaries[boundaryIndex]!;
      offsets[boundary.highlightIndex]![boundary.edge] = index;
      boundaryIndex += 1;
    }

    digitOffset += 1;

    while (
      boundaryIndex < boundaries.length &&
      boundaries[boundaryIndex]!.digitOffset === digitOffset &&
      isEndBoundary(boundaries[boundaryIndex]!)
    ) {
      const boundary = boundaries[boundaryIndex]!;
      offsets[boundary.highlightIndex]![boundary.edge] = index + 1;
      boundaryIndex += 1;
    }
  }

  return offsets;
}

function mapHighlightOffsets(
  mode: InlineSampleMode,
  source: string,
  highlights: ByteHighlight[],
): HighlightOffsets[] {
  switch (mode) {
    case "text":
      return mapTextHighlightOffsets(source, highlights);
    case "hex":
      return mapHexHighlightOffsets(source, highlights);
    case "base64":
      return [];
  }
}

export function mapSampleByteRangeToEditorRange(
  mode: InlineSampleMode,
  source: string,
  range: { start: number; end: number },
): SampleEditorRange | null {
  if (range.start < 0 || range.end <= range.start) {
    return null;
  }

  const [offsets] = mapHighlightOffsets(mode, source, [
    { ...range, labels: [] },
  ]);

  if (
    offsets?.start == null ||
    offsets.end == null ||
    offsets.end <= offsets.start
  ) {
    return null;
  }

  return {
    start: offsets.start,
    end: offsets.end,
  };
}

export function createSampleHighlights(
  raw: unknown,
  mode: InlineSampleMode,
  source: string,
  activeRange: MatchRange | null = null,
): EditorHighlight[] {
  if (mode === "base64") {
    return [];
  }

  const highlights = extractByteHighlights(raw);

  return toEditorHighlights(
    highlights,
    mapHighlightOffsets(mode, source, highlights),
    activeRange,
  );
}
