use protobuf::text_format::parse_from_str;
use rstest::rstest;
use std::fs;
use std::io::Write;

#[rstest(output_format, case("json"))]
fn test_dumper(output_format: &str) {
    // Create goldenfile mint.
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/tests/testdata/*.in").unwrap().flatten() {
        // Path to the .in file.
        println!("{:?}", entry);
        let in_path = entry.into_path();

        // Create a unique test name based on the combination of module and
        // output_format.
        let test_name = format!(
            "{}.{}.out",
            in_path.with_extension("").to_str().unwrap(),
            output_format
        );
        let input = fs::read_to_string(in_path).expect("Unable to read");
        let protobuf_module_output = parse_from_str(&input).unwrap();

        let dumper = crate::Dumper::default();
        let output = dumper.dump(protobuf_module_output, output_format);

        // Create a goldenfile test
        let mut output_file = mint.new_goldenfile(test_name).unwrap();

        write!(output_file, "{}", output).unwrap();
    }
}
