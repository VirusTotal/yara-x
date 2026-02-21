use serde::Deserialize;

/// This structure containts all client-side configuration settings,
/// which user can specify in the code editor.
#[derive(Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub code_formatting: FormattingConfiguration,
    pub metadata_validation: Vec<MetadataValidationRule>,
    pub rule_name_validation: Option<String>,
}

/// This structure represents settings for the YARA-X formatter.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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
pub struct MetadataValidationRule {
    /// Metadata identifier
    pub identifier: String,
    /// Whether the metadata entry is required or not.
    #[serde(default)]
    pub required: bool,
    /// Type of the metadata entry.
    #[serde(rename = "type")]
    pub ty: Option<String>,
}
