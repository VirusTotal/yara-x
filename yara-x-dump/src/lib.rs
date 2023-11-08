mod serializer;
use protobuf::{reflect::MessageRef, MessageDyn};
use protobuf_json_mapping::print_to_string;

use std::io;
use thiserror::Error;

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
    pub fn dump(
        &self,
        mod_output: &dyn MessageDyn,
        output_format: Option<&String>,
    ) -> Result<String, Error> {
        // Iterate over the modules' outputs and get serialized results to
        // print.

        let mut serialized_result = String::new();
        let mut is_first_line = false;

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

        Ok(serialized_result)
    }
}
