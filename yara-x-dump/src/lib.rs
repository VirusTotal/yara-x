mod serializer;
use protobuf::{reflect::MessageRef, MessageDyn};
use serializer::get_yaml;

use thiserror::Error;

#[cfg(test)]
mod tests;

pub use test::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

/// Errors returned by [`Dumper::dump`].
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
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
    /// * `mod_output` - The module output to be dumped.
    ///
    /// # Returns
    ///
    /// Returns a `Result<(), Error>` indicating whether the operation was
    /// successful or not.
    pub fn dump(&self, mod_output: &dyn MessageDyn) -> Result<String, Error> {
        // Iterate over the modules' outputs and get serialized results to
        // print.

        let mut serialized_result = String::new();
        let mut is_first_line = false;

        get_yaml(
            &MessageRef::from(mod_output),
            &mut serialized_result,
            0,
            &mut is_first_line,
        )?;

        Ok(serialized_result)
    }
}
