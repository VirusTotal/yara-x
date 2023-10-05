use std::fs;
use std::io::Write;
use std::path::Path;

use globwalk;
use goldenfile;
use ihex;

pub fn create_binary_from_ihex<P: AsRef<Path>>(
    path: P,
) -> anyhow::Result<Vec<u8>> {
    let contents = fs::read_to_string(path)?;
    let mut reader = ihex::Reader::new(&contents);
    let mut data = Vec::new();
    while let Some(Ok(record)) = reader.next() {
        if let ihex::Record::Data { value, .. } = record {
            data.extend(value);
        }
    }
    Ok(data)
}

#[test]
fn test_modules() {
    // Create goldenfile mint.
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/modules/**/*.in").unwrap().flatten() {
        // Path to the .in file.
        let in_path = entry.into_path();

        // Path to the .out file.
        let out_path = in_path.with_extension("out");

        // The name of module being tested is extracted from the path, which
        // should have the form src/modules/<module name>/....
        let module_name = in_path
            .components()
            .nth(3)
            .map(|s| s.as_os_str().to_str().unwrap())
            .expect("can not extract module name from tests path");

        // Construct a dummy YARA rule that only imports the module.
        let rule = format!(
            r#"import "{}" rule test {{ condition: false }}"#,
            module_name
        );

        // Compile the rule.
        let rules = crate::compile(rule.as_str()).unwrap();
        let mut scanner = crate::scanner::Scanner::new(&rules);

        // Read the .in file and create a binary from it.
        let data = create_binary_from_ihex(&in_path).unwrap_or_else(|err| {
            panic!("error reading ihex file {:?}: {:?}", in_path, err)
        });

        // Scan the data.
        let scan_results = scanner.scan(&data).expect("scan should not fail");

        // Get the module output.
        let output =
            scan_results.module_output(module_name).unwrap_or_else(|| {
                panic!("module `{}` should produce some output", module_name)
            });

        // Create a goldenfile test
        let mut output_file = mint.new_goldenfile(out_path).unwrap();

        write!(output_file, "{:#?}", output).unwrap();
    }
}
