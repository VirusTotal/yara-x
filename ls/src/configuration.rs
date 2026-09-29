use serde::Deserialize;

/// This structure contains all client-side configuration settings,
/// which user can specify in the code editor.
#[derive(Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default)]
    pub code_formatting: FormattingConfiguration,
    #[serde(default)]
    pub metadata_validation: Vec<MetadataValidationRule>,
    #[serde(default)]
    pub rule_name_validation: Option<String>,
    #[serde(default)]
    pub cache_workspace: bool,
}

/// This structure represents settings for the YARA-X formatter.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct FormattingConfiguration {
    pub align_metadata: bool,
    pub align_patterns: bool,
    pub indent_section_headers: bool,
    pub indent_section_contents: bool,
    pub newline_before_curly_brace: bool,
    pub empty_line_before_section_header: bool,
    pub empty_line_after_section_header: bool,
}

impl Default for FormattingConfiguration {
    fn default() -> Self {
        Self {
            align_metadata: true,
            align_patterns: true,
            indent_section_headers: true,
            indent_section_contents: true,
            newline_before_curly_brace: false,
            empty_line_before_section_header: false,
            empty_line_after_section_header: false,
        }
    }
}

/// Rule that describes a how to validate a metadata entry in a rule.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct MetadataValidationRule {
    /// Metadata identifier
    pub identifier: String,
    /// Whether the metadata entry is required or not.
    #[serde(default)]
    pub required: bool,
    /// Type of the metadata entry.
    #[serde(rename = "type")]
    pub ty: Option<String>,
    /// Format of the metadata entry, if type is "date".
    pub format: Option<String>,
    /// Regex pattern to validate the metadata entry, if type is "string".
    #[serde(default)]
    pub regex: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.code_formatting.align_metadata);
        assert!(config.code_formatting.align_patterns);
        assert!(config.code_formatting.indent_section_headers);
        assert!(config.code_formatting.indent_section_contents);
        assert!(!config.code_formatting.newline_before_curly_brace);
        assert!(!config.code_formatting.empty_line_before_section_header);
        assert!(!config.code_formatting.empty_line_after_section_header);
        assert!(config.metadata_validation.is_empty());
        assert!(config.rule_name_validation.is_none());
        assert!(!config.cache_workspace);
    }

    #[test]
    fn test_deserialize_config() {
        let json = r#"{
            "codeFormatting": {
                "alignMetadata": false,
                "newlineBeforeCurlyBrace": true
            },
            "metadataValidation": [
                {
                    "identifier": "author",
                    "required": true,
                    "type": "string",
                    "regex": "^[A-Za-z ]+$"
                }
            ],
            "ruleNameValidation": "^[a-z_]+$",
            "cacheWorkspace": true
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert!(!config.code_formatting.align_metadata);
        assert!(config.code_formatting.align_patterns); // default is true
        assert!(config.code_formatting.newline_before_curly_brace);
        assert_eq!(config.metadata_validation.len(), 1);
        let rule = &config.metadata_validation[0];
        assert_eq!(rule.identifier, "author");
        assert!(rule.required);
        assert_eq!(rule.ty.as_deref(), Some("string"));
        assert_eq!(rule.regex.as_deref(), Some("^[A-Za-z ]+$"));
        assert_eq!(config.rule_name_validation.as_deref(), Some("^[a-z_]+$"));
        assert!(config.cache_workspace);
    }
}
