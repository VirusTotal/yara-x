use indent::indent_all_by;
use std::io;
use thiserror::Error;
use yara_x;

/// Errors returned by [`Dumper::dump`].
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// Error while reading from input.
    #[error("Read error")]
    ReadError(io::Error),
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

    pub fn dump<R>(&self, mut input: R) -> Result<(), Error>
    where
        R: io::Read,
    {
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer).map_err(Error::ReadError)?;

        // Construct a dummy YARA rule that only imports the module.
        let rule = r#"import "macho" rule test { condition: false } "#;

        // Compile the rule.
        let rules = yara_x::compile(rule).unwrap();

        let mut scanner = yara_x::Scanner::new(&rules);

        let scan_results =
            scanner.scan(&buffer).expect("scan should not fail");

        let output =
            scan_results.module_output("macho").unwrap_or_else(|| {
                panic!("module `macho` should produce some output")
            });

        // Get a text representation of the module's output.
        let output = protobuf::text_format::print_to_string_pretty(output);
        println!("{}", indent_all_by(4, output));
        Ok(())
    }
}
