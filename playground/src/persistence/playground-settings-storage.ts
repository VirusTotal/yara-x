import { readStoredJson, writeStoredJson } from "./browser-storage";
import {
  clonePlaygroundSettings,
  createDefaultPlaygroundSettings,
  parseScannerMaxMatches,
  type PlaygroundFormattingSettings,
  type PlaygroundSettings,
} from "../settings/playground-settings";
import { isPositiveInteger, isRecord } from "../validation/guards";

export const PLAYGROUND_SETTINGS_STORAGE_KEY = "yara-x-playground.settings.v1";

function isMetadataValidationType(value: unknown) {
  return (
    value === "string" ||
    value === "integer" ||
    value === "float" ||
    value === "bool" ||
    value === "date"
  );
}

export function loadStoredPlaygroundSettings(): PlaygroundSettings {
  const defaults = createDefaultPlaygroundSettings();
  const stored = readStoredJson(PLAYGROUND_SETTINGS_STORAGE_KEY);

  if (!isRecord(stored)) {
    return defaults;
  }

  const nextSettings = clonePlaygroundSettings(defaults);

  if (isRecord(stored.editor)) {
    if (typeof stored.editor.ruleNameValidation === "string") {
      nextSettings.editor.ruleNameValidation = stored.editor.ruleNameValidation;
    }

    if (isRecord(stored.editor.formatting)) {
      for (const key of Object.keys(nextSettings.editor.formatting) as Array<
        keyof PlaygroundFormattingSettings
      >) {
        const value = stored.editor.formatting[key];

        if (typeof value === "boolean") {
          nextSettings.editor.formatting[key] = value;
        }
      }
    }

    if (Array.isArray(stored.editor.metadataValidation)) {
      nextSettings.editor.metadataValidation = stored.editor.metadataValidation
        .filter(isRecord)
        .map((rule) => ({
          identifier:
            typeof rule.identifier === "string" ? rule.identifier : "",
          required: typeof rule.required === "boolean" ? rule.required : false,
          type: isMetadataValidationType(rule.type) ? rule.type : "string",
          format: typeof rule.format === "string" ? rule.format : "",
          regex: typeof rule.regex === "string" ? rule.regex : "",
        }));
    }
  }

  if (isRecord(stored.scanner)) {
    const maxMatchesPerPattern = stored.scanner.maxMatchesPerPattern;

    if (isPositiveInteger(maxMatchesPerPattern)) {
      nextSettings.scanner.maxMatchesPerPattern = maxMatchesPerPattern;
    } else if (typeof maxMatchesPerPattern === "string") {
      nextSettings.scanner.maxMatchesPerPattern =
        parseScannerMaxMatches(maxMatchesPerPattern);
    }
  }

  return nextSettings;
}

export function storePlaygroundSettings(settings: PlaygroundSettings) {
  writeStoredJson(PLAYGROUND_SETTINGS_STORAGE_KEY, settings);
}
