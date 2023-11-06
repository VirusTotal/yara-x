use rstest::rstest;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

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

#[rstest(
    module,
    output_format,
    case(&vec!["macho"], "json"),
    case(&vec!["macho"], "yaml"),
    case(&vec!["macho"], "toml"),
    case(&vec!["macho"], "xml"),
    case(&vec!["macho"], "human-readable"),
    case(&vec!["macho"], "None"),
    case(&vec!["lnk"], "json"),
    case(&vec!["lnk"], "yaml"),
    case(&vec!["lnk"], "toml"),
    case(&vec!["lnk"], "xml"),
    case(&vec!["lnk"], "human-readable"),
    case(&vec!["lnk"], "None"),
    case(&vec!["macho", "lnk"], "json"),
    case(&vec!["macho", "lnk"], "yaml"),
    case(&vec!["macho", "lnk"], "toml"),
    case(&vec!["macho", "lnk"], "xml"),
    case(&vec!["macho", "lnk"], "human-readable"),
    case(&vec!["macho", "lnk"], "None"),
    case(&vec![], "json"),
    case(&vec![], "yaml"),
    case(&vec![], "toml"),
    case(&vec![], "xml"),
    case(&vec![], "human-readable"),
    case(&vec![], "None"),
)]
fn test_dumper(module: &Vec<&str>, output_format: &str) {
    // Create goldenfile mint.
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/tests/testdata/*.in").unwrap().flatten() {
        // Path to the .in file.
        println!("{:?}", entry);
        let in_path = entry.into_path();

        // Change the module to "automatic" if it's an empty vector.
        let module_name = if module.is_empty() {
            "automatic".to_string()
        } else {
            module.join("_")
        };

        // Create a unique test name based on the combination of module and
        // output_format.
        let test_name = format!(
            "{}.{}.{}.out",
            in_path.with_extension("").to_str().unwrap(),
            module_name,
            output_format
        );

        let mut input = NamedTempFile::new().unwrap();
        let input_stream = input.reopen().unwrap();
        let bytes = create_binary_from_ihex(&in_path).unwrap_or_else(|err| {
            panic!("error reading ihex file {:?}: {:?}", in_path, err)
        });
        input.write_all(&bytes).unwrap();

        let dumper = crate::Dumper::default();
        let output = if output_format == "None" {
            dumper.dump(input_stream, module.clone(), None)
        } else {
            dumper.dump(
                input_stream,
                module.clone(),
                Some(&output_format.to_string()),
            )
        }
        .unwrap();

        // Create a goldenfile test
        let mut output_file = mint.new_goldenfile(test_name).unwrap();

        write!(output_file, "{}", output).unwrap();
    }
}
