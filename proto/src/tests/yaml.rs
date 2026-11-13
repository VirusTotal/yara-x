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

#[test]
fn yaml_serializer_map() {
    yansi::disable();

    let mut msg1 = crate::test_yaml::Message::new();
    msg1.set_int32_dec(42);
    msg1.set_str("hello".to_string());

    let mut msg2 = crate::test_yaml::Message::new();
    msg2.set_int32_hex(0xff);

    let empty_msg = crate::test_yaml::Message::new();

    let mut output = Vec::new();
    let mut serializer = Serializer::new(&mut output);
    let mut map = serializer.serialize_map().unwrap();
    map.serialize_entry("dir/file1.bin", &msg1).unwrap();
    map.serialize_entry("dir/empty.bin", &empty_msg).unwrap();
    map.serialize_entry("dir/\"quoted\".bin", &msg2).unwrap();
    map.finish().unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "\"dir/file1.bin\":\n",
            "    int32_dec: 42\n",
            "    str: \"hello\"\n",
            "\"dir/empty.bin\": {}\n",
            "\"dir/\\\"quoted\\\".bin\":\n",
            "    int32_hex: 0xff",
        )
    );
}
