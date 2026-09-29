import { readStoredJson, writeStoredJson } from "./browser-storage";
import {
  clonePlaygroundSession,
  createDefaultPlaygroundSession,
  type PlaygroundSession,
} from "../session/playground-session";
import {
  isInlineSampleMode,
  INLINE_SAMPLE_MODES,
} from "../sample/sample-modes";
import { isRecord } from "../validation/guards";

export const PLAYGROUND_SESSION_STORAGE_KEY = "yara-x-playground.session.v1";

export function loadStoredPlaygroundSession(
  rule: string,
  sampleText: string,
): PlaygroundSession {
  const defaults = createDefaultPlaygroundSession(rule, sampleText);
  const stored = readStoredJson(PLAYGROUND_SESSION_STORAGE_KEY);

  if (!isRecord(stored)) {
    return defaults;
  }

  const nextSession = clonePlaygroundSession(defaults);

  if (typeof stored.rule === "string" && stored.rule.trim().length > 0) {
    nextSession.rule = stored.rule;
  } else {
    nextSession.rule = rule;
  }

  if (
    typeof stored.sampleMode === "string" &&
    isInlineSampleMode(stored.sampleMode)
  ) {
    nextSession.sampleMode = stored.sampleMode;
  }

  if (isRecord(stored.sampleDrafts)) {
    for (const { id } of INLINE_SAMPLE_MODES) {
      const value = stored.sampleDrafts[id];

      if (typeof value === "string") {
        nextSession.sampleDrafts[id] = value;
      }
    }
  }

  if (
    typeof nextSession.sampleDrafts.text !== "string" ||
    nextSession.sampleDrafts.text.trim().length === 0
  ) {
    nextSession.sampleDrafts.text = sampleText;
  }

  return nextSession;
}

export function storePlaygroundSession(session: PlaygroundSession) {
  writeStoredJson(PLAYGROUND_SESSION_STORAGE_KEY, session);
}
