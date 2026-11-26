#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Rules that exercise the structures validated by `Rules::deserialize`:
/// plain and wide patterns, a regexp with a jump, a hex pattern with a jump,
/// an alternation, and string metadata.
const SOURCE: &str = r#"
rule fuzz_me {
  meta:
    author = "fuzz"
    description = "serialized rules for the deserializer"
  strings:
    $a = "foo"
    $b = "bar" wide nocase
    $c = /ba(r|z).{0,4}qux/
    $d = { 01 02 [1-4] 03 04 }
  condition:
    $a and ($b or $c or $d) and filesize > 10
}
"#;

/// A valid serialized rule set, built once.
///
/// Arbitrary bytes cannot reach the deserializer on their own: the first bytes
/// of the stream must be the magic plus the exact serialization version, so a
/// random input is rejected before anything is decoded. The fuzzer is given a
/// well-formed rule set to mutate instead, which is how the structural
/// corruption reported in GHSA-2jx3-ff3v-j7jj was found.
fn baseline() -> &'static [u8] {
    static BASELINE: OnceLock<Vec<u8>> = OnceLock::new();
    BASELINE.get_or_init(|| {
        yara_x::compile(SOURCE)
            .expect("baseline rules should compile")
            .serialize()
            .expect("baseline rules should serialize")
    })
}

fuzz_target!(|data: &[u8]| {
    let baseline = baseline();

    // The first four bytes choose where to write, the rest is what gets
    // written. Taking the offset modulo the length keeps every input useful.
    if data.len() < 5 {
        return;
    }

    let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]])
        as usize
        % baseline.len();

    let patch = &data[4..];
    let end = baseline.len().min(offset + patch.len());

    let mut bytes = baseline.to_vec();
    bytes[offset..end].copy_from_slice(&patch[..end - offset]);

    // Deserializing is only half of it. The identifiers and offsets restored
    // here are used during scanning to index arrays without bounds checks, so
    // the scan is where a corrupted structure shows up.
    if let Ok(rules) = yara_x::Rules::deserialize(&bytes) {
        let mut scanner = yara_x::Scanner::new(&rules);
        let _ = scanner.scan(b"foo b\0a\0r\0 barqux \x01\x02\x00\x00\x03\x04");
    }
});
