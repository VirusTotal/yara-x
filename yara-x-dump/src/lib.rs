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

    pub fn dump<R>(
        &self,
        mut input: R,
        modules: Vec<String>,
    ) -> Result<(), Error>
    where
        R: io::Read,
    {
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer).map_err(Error::ReadError)?;

        println!("desired modules: {}", modules.join(", "));
        // Create a rule that imports all the built-in modules.
        let import_statements = yara_x::get_builtin_modules_names()
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

        // Iterate over the modules' outputs.
        for (mod_name, mod_output) in scan_results.module_outputs() {
            // Get a text representation of the module's output.
            println!(
                "{}: {}",
                mod_name,
                indent_all_by(
                    4,
                    protobuf::text_format::print_to_string_pretty(mod_output)
                )
            );
        }
        Ok(())
    }
}
