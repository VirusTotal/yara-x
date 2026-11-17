use protobuf::text_format::parse_from_str;
use std::fs;

use crate::yaml::Serializer;

#[test]
fn yaml_serializer() {
    // Disable colors for testing.
    yansi::disable();

    // Create goldenfile mint.
    let mut mint = goldenfile::Mint::new(".");

    for entry in
        globwalk::glob("src/tests/testdata_yaml/*.in").unwrap().flatten()
    {
        // Path to the .in file.
        let in_path = entry.into_path();
        // Path to the .out file.
        let out_path = in_path.with_extension("out");

        let input = fs::read_to_string(in_path).expect("Unable to read");
        let test_pb =
            parse_from_str::<crate::test_yaml::Message>(&input).unwrap();

        let output_file = mint.new_goldenfile(out_path).unwrap();
        let mut serializer = Serializer::new(output_file);

        serializer.serialize(&test_pb).expect("Unable to serialize");
    }
}

#[test]
fn yaml_serializer_out_of_range_timestamp() {
    yansi::disable();

    for ts in [i64::MIN, i64::MAX] {
        let mut msg = crate::test_yaml::Message::new();
        msg.set_timestamp(ts);

        let mut output = Vec::new();
        let mut serializer = Serializer::new(&mut output);
        serializer.serialize(&msg).expect("Unable to serialize");

        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("timestamp: {ts}")
        );
    }
}
