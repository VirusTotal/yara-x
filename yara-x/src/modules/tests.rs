use std::fs;
use std::io::Write;
use std::path::Path;

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

/// This function tests YARA modules by comparing the output produced by the
/// module with a golden file that contains the expected output.
///
/// The function walks the  directory looking for files
/// with extension `*.in`. These files can contain arbitrary binary content,
/// but they must be encoded in the [`Intel HEX format`][1], which is a text
/// representation of the original content. Storing binary files in our
/// source repository is not a good idea, specially if such files are
/// executable files containing malware.
///
/// The `*.in` files are decoded when the tests are run, and passed to the
/// corresponding module, which is determined by looking at the path where
/// the file was found. If the file is found anywhere under a directory named
/// `yara-x/src/modules/foo`, its content is passed as input to the `foo`
/// module. Then, the output produced by the module is compared with the
/// content of a `*.out` file that is expected to have the same name than
/// the `*.in` file.
///
/// There are many tools for converting binary files to Intel HEX format, one
/// of such tools is `objcopy` (`llvm-objcopy` on Mac OS X).
///
/// ```
/// objcopy -I binary -O ihex foo.bin foo.ihex.in
/// ```
///
/// [1]: https://en.wikipedia.org/wiki/Intel_HEX
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

        // Get a text representation of the module's output.
        let output = protobuf::text_format::print_to_string_pretty(output);

        // Create a goldenfile test
        let mut output_file = mint.new_goldenfile(out_path).unwrap();

        write!(output_file, "{}", output).unwrap();
    }
}
