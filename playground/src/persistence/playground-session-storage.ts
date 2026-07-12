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

  if (typeof stored.rule === "string") {
    nextSession.rule = stored.rule;
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

  return nextSession;
}

export function storePlaygroundSession(session: PlaygroundSession) {
  writeStoredJson(PLAYGROUND_SESSION_STORAGE_KEY, session);
}
