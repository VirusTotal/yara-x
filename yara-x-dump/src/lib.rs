mod serializer;
use protobuf::{
    reflect::MessageRef, reflect::ReflectValueRef::Bool, MessageDyn,
};
use protobuf_json_mapping::print_to_string;
use serde_json;
use serde_yaml;
use std::io;
use thiserror::Error;
use yansi::Color::Cyan;
use yara_x;
use yara_x_proto::exts::module_options;

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

    // Checks if the module output is valid by checking the validity flag.
    fn module_is_valid(&self, mod_output: &dyn MessageDyn) -> bool {
        if let Some(module_desc) = module_options
            .get(&mod_output.descriptor_dyn().file_descriptor_proto().options)
        {
            if let Some(validity_flag_str) =
                module_desc.validity_flag.as_deref()
            {
                if let Some(field) = mod_output
                    .descriptor_dyn()
                    .field_by_name(validity_flag_str)
                {
                    if let Some(value) = field.get_singular(mod_output) {
                        return value != Bool(false);
                    }
                }
            }
        }

        false
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
            let mut serialized_result = String::new();
            let mut is_first_line = false;

            // Skip empty outputs or invalid outputs that are not requested.
            if mod_output.compute_size_dyn() == 0
                || (!self.module_is_valid(mod_output)
                    && !modules
                        .unwrap_or(&vec![])
                        .contains(&mod_name.to_string()))
            {
                continue;
            }
            match output_format {
                // Output is desired to be human-readable.
                Some(format) if format == "human-readable" => {
                    serialized_result = get_human_readable_output(
                        &MessageRef::from(mod_output),
                        &mut serialized_result,
                        0,
                        &mut is_first_line,
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
                    get_human_readable_output(
                        &MessageRef::from(mod_output),
                        &mut serialized_result,
                        0,
                        &mut is_first_line,
                    );
                }
            }

            // Print the result.
            println!(
                ">>>\n{}:\n{}\n<<<",
                Cyan.paint(mod_name).bold(),
                serialized_result
            );
        }
        Ok(())
    }
}
