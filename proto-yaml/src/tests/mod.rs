use protobuf::text_format::parse_from_str;
use std::fs;

use crate::Serializer;

#[test]
fn yaml_serializer() {
    // Disable colors for testing.
    yansi::disable();

    // Create goldenfile mint.
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/tests/testdata/*.in").unwrap().flatten() {
        // Path to the .in file.
        let in_path = entry.into_path();
        // Path to the .out file.
        let out_path = in_path.with_extension("out");

        let input = fs::read_to_string(in_path).expect("Unable to read");
        let test_pb = parse_from_str::<crate::test::Message>(&input).unwrap();

        let output_file = mint.new_goldenfile(out_path).unwrap();
        let mut serializer = Serializer::new(output_file);

        serializer.serialize(&test_pb).expect("Unable to serialize");
    }
}
