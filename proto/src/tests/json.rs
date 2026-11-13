use protobuf::text_format::parse_from_str;
use std::fs;

use crate::json::{Format, Serializer};

#[test]
fn json_serializer() {
    // Create goldenfile mint.
    let mut mint = goldenfile::Mint::new(".");

    for entry in
        globwalk::glob("src/tests/testdata_json/*.in").unwrap().flatten()
    {
        // Path to the .in file.
        let in_path = entry.into_path();

        let input = fs::read_to_string(&in_path).expect("Unable to read");
        let test_pb =
            parse_from_str::<crate::test_json::Message>(&input).unwrap();

        // The .out file has the output in the default format, and the
        // .yr_dump.out file has the output in the format used by `yr dump`.
        for (format, extension) in
            [(Format::Default, "out"), (Format::Legacy, "yr_dump.out")]
        {
            let out_path = in_path.with_extension(extension);
            let output_file = mint.new_goldenfile(out_path).unwrap();
            let mut serializer = Serializer::new(output_file);

            serializer
                .with_format(format)
                .serialize(&test_pb)
                .expect("Unable to serialize");
        }
    }
}

#[test]
fn json_serializer_map() {
    yansi::disable();

    let mut msg1 = crate::test_json::Message::new();
    msg1.set_i32(42);
    msg1.set_str("hello".to_string());

    let mut msg2 = crate::test_json::Message::new();
    msg2.set_bool(true);

    let mut output = Vec::new();
    let mut serializer = Serializer::new(&mut output);
    let mut map = serializer.serialize_map().unwrap();
    map.serialize_entry("dir/file1.bin", &msg1).unwrap();
    map.serialize_entry("dir/\"quoted\".bin", &msg2).unwrap();
    map.finish().unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "{\n",
            "    \"dir/file1.bin\": {\n",
            "        \"i32\": 42,\n",
            "        \"str\": \"hello\"\n",
            "    },\n",
            "    \"dir/\\\"quoted\\\".bin\": {\n",
            "        \"bool\": true\n",
            "    }\n",
            "}",
        )
    );

    let mut empty_output = Vec::new();
    let mut empty_serializer = Serializer::new(&mut empty_output);
    empty_serializer.serialize_map().unwrap().finish().unwrap();
    assert_eq!(String::from_utf8(empty_output).unwrap(), "{}");
}
