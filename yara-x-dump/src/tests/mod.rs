use protobuf::text_format::parse_from_str;
use protobuf::MessageDyn;
use rstest::rstest;
use std::fs;
use std::io::Write;

use crate::Dumper;

#[rstest(
    output_format,
    case("json"),
    case("yaml"),
    case("toml"),
    case("xml"),
    case("human-readable"),
    case("None")
)]
fn test_dumper(output_format: String) {
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

        let test = parse_from_str::<crate::test::MyMessage>(&input).unwrap();

        let dumper = Dumper::default();
        let output = if output_format == "None" {
            dumper.dump(&test as &dyn MessageDyn, None)
        } else {
            dumper.dump(
                &test as &dyn MessageDyn,
                Some(&output_format.to_string()),
            )
        }
        .unwrap();

        // Create a goldenfile test
        let mut output_file = mint.new_goldenfile(test_name).unwrap();

        write!(output_file, "{}", output).unwrap();
    }
}
