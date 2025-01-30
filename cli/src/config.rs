use std::collections::BTreeMap;
use std::path::Path;

use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

/// Configuration structure for "yr" commands.
#[derive(Deserialize, Serialize, Debug)]
pub struct Config {
    /// Format specific configuration information.
    pub fmt: FormatConfig,

    /// Check specific configuration information.
    pub check: CheckConfig,
}

/// Format specific configuration information.
#[derive(Deserialize, Serialize, Debug)]
pub struct FormatConfig {
    /// Rule specific formatting information.
    pub rule: RuleFormatConfig,
    /// Meta specific formatting information.
    pub meta: MetaFormatConfig,
    /// Pattern specific formatting information.
    pub patterns: PatternsFormatConfig,
}

/// Types allowed in the check.metadata table of the config file. Used to
/// require specific metadata identifiers have specific types by "yr check".
#[derive(Display, Deserialize, Serialize, Debug, Clone, EnumString)]
pub enum MetaValueType {
    /// Represents a String type
    #[serde(rename = "string")]
    #[strum(serialize = "string")]
    String,
    /// Represents an Integer type
    #[serde(rename = "integer")]
    #[strum(serialize = "integer")]
    Integer,
    /// Represents a Float type
    #[serde(rename = "float")]
    #[strum(serialize = "float")]
    Float,
    /// Represents a Boolean type
    #[serde(rename = "bool")]
    #[strum(serialize = "bool")]
    Bool,
    /// Represents a SHA256 (string) type
    #[serde(rename = "sha256")]
    #[strum(serialize = "sha256")]
    Sha256,
    /// Represents a SHA1 (string) type
    #[serde(rename = "sha1")]
    #[strum(serialize = "sha1")]
    Sha1,
    /// Represents a MD5 (string) type
    #[serde(rename = "md5")]
    #[strum(serialize = "md5")]
    MD5,
    /// Represents a generic hash (string) type. Can be MD5/SHA1/SHA256
    #[serde(rename = "hash")]
    #[strum(serialize = "hash")]
    Hash,
}

/// Format specific configuration information.
#[derive(Deserialize, Serialize, Debug)]
pub struct CheckConfig {
    /// Meta specific formatting information.
    // Note: Using a BTreeMap here because we want a consistent ordering when
    // we iterate over it, so that warnings always appear in the same order.
    pub metadata: BTreeMap<String, MetadataConfig>,

    /// Regexp used to validate the rule name.
    pub rule_name_regexp: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct MetadataConfig {
    #[serde(rename = "type")]
    pub ty: MetaValueType,
    #[serde(default)]
    pub required: bool,
}

/// Rule specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
pub struct RuleFormatConfig {
    /// Indent section headers (meta, strings, condition).
    pub indent_section_headers: bool,
    /// Indent section contents one level past section headers.
    pub indent_section_contents: bool,
    /// Number of spaces for indent. Set to 0 to use tabs.
    pub indent_spaces: u8,
    /// Insert a newline after the rule declaration but before the curly brace.
    pub newline_before_curly_brace: bool,
    /// Insert an empty line before section headers.
    pub empty_line_before_section_header: bool,
    /// Insert an empty line after section headers.
    pub empty_line_after_section_header: bool,
}

/// Meta specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
pub struct MetaFormatConfig {
    /// Align values to longest key.
    pub align_values: bool,
}

/// Pattern specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
pub struct PatternsFormatConfig {
    /// Align patterns to the longest name.
    pub align_values: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            fmt: FormatConfig {
                rule: RuleFormatConfig {
                    indent_section_headers: true,
                    indent_section_contents: true,
                    indent_spaces: 2,
                    newline_before_curly_brace: false,
                    empty_line_before_section_header: true,
                    empty_line_after_section_header: false,
                },
                meta: MetaFormatConfig { align_values: true },
                patterns: PatternsFormatConfig { align_values: true },
            },
            check: CheckConfig {
                metadata: BTreeMap::default(),
                rule_name_regexp: None,
            },
        }
    }
}

/// Load config file from a given path. Path must contain a valid TOML file or
/// this function will propagate the error. For structure of the config file
/// see "YARA-X Config Guide.md".
pub fn load_config_from_file(
    config_file: &Path,
) -> Result<Config, figment::Error> {
    let config: Config =
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file_exact(config_file))
            .extract()?;
    Ok(config)
}
