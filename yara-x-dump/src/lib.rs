mod serializer;
use protobuf::{
    reflect::MessageRef, reflect::ReflectValueRef::Bool, MessageDyn,
};
use protobuf_json_mapping::print_to_string;
use std::fmt::Write;
use std::io;
use thiserror::Error;
use yansi::Color::Cyan;
use yara_x_proto::exts::module_options;

use crate::serializer::{get_human_readable_output, get_serializer};

#[cfg(test)]
mod tests;

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
    /// Error while formatting output
    #[error("Formatting Error")]
    FormattingError(#[from] std::fmt::Error),
}

/// Dumps information about binary files.
#[derive(Debug, Default, Clone)]
pub struct Dumper {}

// Dumper public API.
impl Dumper {
    // Checks if the module output is valid by checking the validity flag.
    //
    // # Arguments
    //
    // * `mod_output`: The module output to check.
    //
    // # Returns
    //
    // * `true` if the module output is valid, `false` otherwise.
    fn module_is_valid(&self, mod_output: &dyn MessageDyn) -> bool {
        // Get the module options.
        if let Some(module_desc) = module_options
            .get(&mod_output.descriptor_dyn().file_descriptor_proto().options)
        {
            // Get the field name which is considered as the validity flag.
            if let Some(validity_flag_str) =
                module_desc.validity_flag.as_deref()
            {
                // Get the validity flag value.
                if let Some(field) = mod_output
                    .descriptor_dyn()
                    .field_by_name(validity_flag_str)
                {
                    // Check if the validity flag is set.
                    // Validity flag is set if the value present and is not
                    // false.
                    if let Some(value) = field.get_singular(mod_output) {
                        return value != Bool(false);
                    }
                }
            }
        }

        false
    }

    /// Dumps information about the binary file.
    ///
    /// # Arguments
    ///
    /// * `input`: The input to read from.
    /// * `modules`: The list of modules to import.
    /// * `output_format`: The desired output format.
    ///
    /// # Returns
    ///
    /// Returns a `Result<(), Error>` indicating whether the operation was
    /// successful or not.
    pub fn dump<R>(
        &self,
        mut input: R,
        modules: Vec<&str>,
        output_format: Option<&String>,
    ) -> Result<String, Error>
    where
        R: io::Read,
    {
        let mut buffer = Vec::new();
        let mut result = String::new();

        input.read_to_end(&mut buffer).map_err(Error::ReadError)?;

        // Get the list of modules to import.
        let import_modules = if !modules.is_empty() {
            modules.clone()
        } else {
            yara_x::get_builtin_modules_names()
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

        // Scan the buffer and get the results.
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
                    && !modules.contains(&mod_name))
            {
                continue;
            }
            match output_format {
                // Output is desired to be human-readable.
                Some(format) if format == "human-readable" => {
                    get_human_readable_output(
                        &MessageRef::from(mod_output),
                        &mut serialized_result,
                        0,
                        &mut is_first_line,
                    )?;
                }
                // Serialize output for other given formats.
                Some(format) => {
                    let json_output = print_to_string(mod_output)?;
                    let serializer = get_serializer(format)?;

                    serialized_result =
                        serializer.serialize(json_output.as_str())?;
                }
                // Default to human-readable output.
                None => {
                    get_human_readable_output(
                        &MessageRef::from(mod_output),
                        &mut serialized_result,
                        0,
                        &mut is_first_line,
                    )?;
                }
            }

            write!(
                result,
                ">>>\n{}:\n{}\n<<<",
                Cyan.paint(mod_name).bold(),
                serialized_result
            )?;
        }
        Ok(result)
    }
}
