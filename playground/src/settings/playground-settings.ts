export type MetadataValidationType =
  | "string"
  | "integer"
  | "float"
  | "bool"
  | "date";

export type PlaygroundFormattingSettings = {
  alignMetadata: boolean;
  alignPatterns: boolean;
  indentSectionHeaders: boolean;
  indentSectionContents: boolean;
  newlineBeforeCurlyBrace: boolean;
  emptyLineBeforeSectionHeader: boolean;
  emptyLineAfterSectionHeader: boolean;
};

export type PlaygroundMetadataValidationRule = {
  identifier: string;
  required: boolean;
  type: MetadataValidationType;
  format: string;
  regex: string;
};

export type PlaygroundEditorSettings = {
  formatting: PlaygroundFormattingSettings;
  ruleNameValidation: string;
  metadataValidation: PlaygroundMetadataValidationRule[];
};

export type PlaygroundScannerSettings = {
  maxMatchesPerPattern: number | null;
};

export type PlaygroundSettings = {
  editor: PlaygroundEditorSettings;
  scanner: PlaygroundScannerSettings;
};

export type YaraMetadataValidationRuleConfig = {
  identifier: string;
  required?: boolean;
  type?: MetadataValidationType;
  format?: string;
  regex?: string;
};

export type YaraConfig = {
  codeFormatting: PlaygroundFormattingSettings;
  metadataValidation: YaraMetadataValidationRuleConfig[];
  ruleNameValidation: string | null;
  cacheWorkspace: boolean;
};

export function createDefaultYaraConfig(): YaraConfig {
  return {
    codeFormatting: {
      alignMetadata: true,
      alignPatterns: true,
      indentSectionHeaders: true,
      indentSectionContents: true,
      newlineBeforeCurlyBrace: false,
      emptyLineBeforeSectionHeader: false,
      emptyLineAfterSectionHeader: false,
    },
    metadataValidation: [],
    ruleNameValidation: null,
    cacheWorkspace: false,
  };
}

export function createDefaultPlaygroundSettings(): PlaygroundSettings {
  const config = createDefaultYaraConfig();

  return {
    editor: {
      formatting: { ...config.codeFormatting },
      ruleNameValidation: config.ruleNameValidation ?? "",
      metadataValidation: [],
    },
    scanner: {
      maxMatchesPerPattern: null,
    },
  };
}

export function clonePlaygroundSettings(
  settings: PlaygroundSettings,
): PlaygroundSettings {
  return {
    editor: {
      formatting: { ...settings.editor.formatting },
      ruleNameValidation: settings.editor.ruleNameValidation,
      metadataValidation: settings.editor.metadataValidation.map((rule) => ({
        ...rule,
      })),
    },
    scanner: {
      maxMatchesPerPattern: settings.scanner.maxMatchesPerPattern,
    },
  };
}

export function toYaraConfig(settings: PlaygroundSettings): YaraConfig {
  return {
    codeFormatting: { ...settings.editor.formatting },
    metadataValidation: settings.editor.metadataValidation
      .map((rule) => {
        const identifier = rule?.identifier?.trim();

        if (identifier.length === 0) {
          return null;
        }

        const nextRule: YaraMetadataValidationRuleConfig = {
          identifier,
          required: rule.required,
          type: rule.type,
        };

        if (rule.type === "date" && rule.format.trim().length > 0) {
          nextRule.format = rule.format.trim();
        }

        if (rule.type === "string" && rule.regex.trim().length > 0) {
          nextRule.regex = rule.regex.trim();
        }

        return nextRule;
      })
      .filter((rule): rule is YaraMetadataValidationRuleConfig => rule != null),
    ruleNameValidation:
      settings.editor.ruleNameValidation.trim().length > 0
        ? settings.editor.ruleNameValidation.trim()
        : null,
    cacheWorkspace: false,
  };
}

export function createEmptyMetadataValidationRule(): PlaygroundMetadataValidationRule {
  return {
    identifier: "",
    required: false,
    type: "string",
    format: "",
    regex: "",
  };
}

export function parseScannerMaxMatches(rawValue: string): number | null {
  const value = rawValue.trim();

  if (value.length === 0) {
    return null;
  }

  if (!/^[1-9]\d*$/.test(value)) {
    return null;
  }

  const parsed = Number(value);

  return Number.isSafeInteger(parsed) ? parsed : null;
}
