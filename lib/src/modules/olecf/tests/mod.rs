use crate::modules::olecf::parser::Olecf;
use crate::modules::tests::create_binary_from_zipped_ihex;
use std::borrow::Cow;

#[test]
fn test_stream_data_extraction() {
    // 1. reg_contiguous (5000 bytes, contiguous in FAT -> Cow::Borrowed)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/reg_contiguous.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let stream = olecf.get_stream_data("ContiguousReg").unwrap();
    assert!(matches!(stream, Cow::Borrowed(_)));
    assert_eq!(stream.len(), 5000);
    assert_eq!(stream[0], 0xAA);
    assert_eq!(stream[9 * 512], 0xBB);

    // 2. reg_fragmented (5000 bytes, fragmented in FAT -> Cow::Owned)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/reg_fragmented.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let stream = olecf.get_stream_data("FragReg").unwrap();
    assert!(matches!(stream, Cow::Owned(_)));
    assert_eq!(stream.len(), 5000);
    assert_eq!(stream[0], 0x11);
    assert_eq!(stream[9 * 512], 0x22);

    // 3. reg_cycle (circular reference in FAT -> error)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/reg_cycle.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let err = olecf.get_stream_data("CycleReg").unwrap_err();
    assert_eq!(err, "Circular reference detected in sector chain");

    // 4. mini_contiguous (120 bytes, contiguous in MiniFAT and Root Storage -> Cow::Borrowed)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/mini_contiguous.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let stream = olecf.get_stream_data("ContiguousMini").unwrap();
    assert!(matches!(stream, Cow::Borrowed(_)));
    assert_eq!(stream.len(), 120);
    assert_eq!(stream[0], 0xAA);
    assert_eq!(stream[64], 0xBB);

    // 5. mini_fragmented (120 bytes, fragmented in MiniFAT -> Cow::Owned)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/mini_fragmented.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let stream = olecf.get_stream_data("FragMini").unwrap();
    assert!(matches!(stream, Cow::Owned(_)));
    assert_eq!(stream.len(), 120);
    assert_eq!(stream[0], 0x11);
    assert_eq!(stream[64], 0x22);

    // 6. mini_in_frag_root (64 bytes, Root Storage itself is fragmented -> Cow::Owned)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/mini_in_frag_root.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let stream = olecf.get_stream_data("MiniInFragRoot").unwrap();
    assert!(matches!(stream, Cow::Owned(_)));
    assert_eq!(stream.len(), 64);
    assert_eq!(stream[0], 0x99);

    // 7. mini_cycle (circular reference in MiniFAT -> error)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/mini_cycle.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let err = olecf.get_stream_data("CycleMini").unwrap_err();
    assert_eq!(err, "Circular reference detected in sector chain");

    // 8. empty_stream (0 bytes -> Cow::Borrowed empty slice)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/empty_stream.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let stream = olecf.get_stream_data("EmptyStream").unwrap();
    assert!(matches!(stream, Cow::Borrowed(_)));
    assert!(stream.is_empty());

    // 9. incomplete_stream (stream truncated before size -> error)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/incomplete_stream.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let err = olecf.get_stream_data("TruncatedStream").unwrap_err();
    assert_eq!(err, "Incomplete stream data");

    // 10. v4_stream (version 4 file with 4096-byte sector size -> Cow::Borrowed)
    let data = create_binary_from_zipped_ihex(
        "src/modules/olecf/tests/testdata/v4_stream.in.zip",
    );
    let olecf = Olecf::parse(&data).unwrap();
    let stream = olecf.get_stream_data("V4DataStream").unwrap();
    assert!(matches!(stream, Cow::Borrowed(_)));
    assert_eq!(stream.len(), 5000);
    assert_eq!(stream[0], 0xDD);
    assert_eq!(stream[4096], 0xEE);
}
