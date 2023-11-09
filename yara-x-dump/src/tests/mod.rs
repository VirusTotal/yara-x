use protobuf::text_format::parse_from_str;
use protobuf::MessageDyn;
use std::fs;
use std::io::Write;
use yansi::Paint;

use crate::Dumper;

#[test]
fn test_dumper() {
    // Disable colors for testing.
    Paint::disable();

    // Create goldenfile mint.
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/tests/testdata/*.in").unwrap().flatten() {
        // Path to the .in file.
        println!("{:?}", entry);
        let in_path = entry.into_path();

        // Path to the .out file.
        let out_path = in_path.with_extension("out");

        let input = fs::read_to_string(in_path).expect("Unable to read");

        let test = parse_from_str::<crate::test::MyMessage>(&input).unwrap();

        let dumper = Dumper::default();
        let output = dumper.dump(&test as &dyn MessageDyn).unwrap();

        // Create a goldenfile test
        let mut output_file = mint.new_goldenfile(out_path).unwrap();

        write!(output_file, "{}", output).unwrap();
    }
}
