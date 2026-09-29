import type { InlineSampleMode } from "../sample/sample-modes";

export type PlaygroundSession = {
  rule: string;
  sampleMode: InlineSampleMode;
  sampleDrafts: Record<InlineSampleMode, string>;
};

export function createDefaultPlaygroundSession(
  rule: string,
  sampleText: string,
): PlaygroundSession {
  return {
    rule,
    sampleMode: "text",
    sampleDrafts: {
      text: sampleText,
      base64: "",
      hex: "",
    },
  };
}

export function clonePlaygroundSession(
  session: PlaygroundSession,
): PlaygroundSession {
  return {
    rule: session.rule,
    sampleMode: session.sampleMode,
    sampleDrafts: {
      text: session.sampleDrafts.text,
      base64: session.sampleDrafts.base64,
      hex: session.sampleDrafts.hex,
    },
  };
}
