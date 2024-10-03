use std::path::Path;

use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

/// Configuration structure for "yr" commands.
#[derive(Deserialize, Serialize, Debug)]
pub struct Config {
    /// Format specific configuration information.
    pub fmt: FormatConfig,
}

/// Format specific configuration information.
#[derive(Deserialize, Serialize, Debug)]
pub struct FormatConfig {
    /// Rule specific formatting information.
    pub rule: Rule,
    /// Meta specific formatting information.
    pub meta: Meta,
    /// Pattern specific formatting information.
    pub patterns: Patterns,
}

/// Rule specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
pub struct Rule {
    /// Indent section headers (meta, strings, condition).
    pub indent_section_headers: bool,
    /// Indent section contents one level past section headers.
    pub indent_section_contents: bool,
    /// Number of spaces for indent. Set to 0 to use tabs.
    pub indent_spaces: u8,
}

/// Meta specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
pub struct Meta {
    /// Align values to longest key.
    pub align_values: bool,
}

/// Pattern specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
pub struct Patterns {
    /// Align patterns to the longest name.
    pub align_values: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            fmt: FormatConfig {
                rule: Rule {
                    indent_section_headers: true,
                    indent_section_contents: true,
                    indent_spaces: 2,
                },
                meta: Meta { align_values: true },
                patterns: Patterns { align_values: true },
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
