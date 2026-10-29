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
            [(Format::Default, "out"), (Format::YrDump, "yr_dump.out")]
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
