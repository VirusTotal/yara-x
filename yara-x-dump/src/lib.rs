mod serializer;
use protobuf::reflect::MessageRef;
use protobuf_json_mapping::print_to_string;
use serde_json;
use serde_yaml;
use std::io;
use thiserror::Error;
use yansi::Color::Cyan;
use yara_x;

use crate::serializer::{get_human_readable_output, get_serializer};

/// Errors returned by [`Dumper::dump`].
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// Error while reading from input.
    #[error("Read error")]
    ReadError(io::Error),
    /// Error while serializing protobuf messages.
    #[error("Serialization error")]
    SerializationError(#[from] protobuf_json_mapping::PrintError),
    /// Error while parsing JSON strings.
    #[error("Parsing JSON error")]
    ParsingJSONError(#[from] serde_json::Error),
    /// Error while parsing YAML strings.
    #[error("Parsing YAML error")]
    ParsingYAMLError(#[from] serde_yaml::Error),
    /// Error while parsing TOML strings.
    #[error("Parsing TOML error")]
    ParsingTOMLError(#[from] toml::ser::Error),
    /// Error while parsing XML strings.
    #[error("Parsing XML error")]
    ParsingXMLError(#[from] xml2json_rs::X2JError),
    /// Error for unsupported serilization formats.
    #[error("Unsupported serilization format")]
    UnsupportedFormat,
}

/// Dumps information about binary files.
pub struct Dumper {}

impl Default for Dumper {
    fn default() -> Self {
        Self::new()
    }
}

// Dumper public API.
impl Dumper {
    /// Creates a new dumper.
    pub fn new() -> Self {
        Dumper {}
    }

    /// Dumps information about the binary file.
    pub fn dump<R>(
        &self,
        mut input: R,
        modules: Option<&Vec<String>>,
        output_format: Option<&String>,
    ) -> Result<(), Error>
    where
        R: io::Read,
    {
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer).map_err(Error::ReadError)?;

        // Get the list of modules to import.
        let import_modules = if let Some(modules) = modules {
            modules.clone()
        } else {
            yara_x::get_builtin_modules_names()
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        };

        // Create a rule that imports all the built-in modules.
        let import_statements = import_modules
            .iter()
            .map(|module_name| format!("import \"{}\"", module_name))
            .collect::<Vec<_>>()
            .join("\n");

        // Create a dummy rule
        let rule = format!(
            r#"{} rule test {{ condition: false }}"#,
            import_statements
        );

        // Compile the rule.
        let rules = yara_x::compile(rule.as_str()).unwrap();

        let mut scanner = yara_x::Scanner::new(&rules);

        let scan_results =
            scanner.scan(&buffer).expect("scan should not fail");

        // Iterate over the modules' outputs and get serialized results to
        // print.
        for (mod_name, mod_output) in scan_results.module_outputs() {
            let serialized_result;

            match output_format {
                // Output is desired to be human-readable.
                Some(format) if format == "human-readable" => {
                    serialized_result = get_human_readable_output(
                        &MessageRef::from(mod_output),
                    );
                }
                // Serialize output for other given formats.
                Some(format) => {
                    let json_output = print_to_string(mod_output)?;
                    let serializer = get_serializer(format)?;

                    serialized_result = serializer.serialize(json_output)?;
                }
                // Default to human-readable output.
                None => {
                    serialized_result = get_human_readable_output(
                        &MessageRef::from(mod_output),
                    );
                }
            }

            println!(
                ">>>\n{}:\n{}\n<<<",
                Cyan.paint(mod_name).bold(),
                serialized_result
            );
        }
        Ok(())
    }
}
