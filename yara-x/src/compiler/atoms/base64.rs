use base64;
use base64::Engine;
use bstr::{BString, ByteVec};

/// Given a slice of bytes, returns three strings of which one must be
/// present in the base64-encoded version of any buffer that contains the
/// slice.
///
/// For example, suppose the string "ipsum" can appear somewhere in a file,
/// but it will appear as part of a longer string that has been encoded
/// in base64. Let's say that the file contains the string:
///
/// TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=
///
/// Which is the result of:
///
/// base64("Lorem ipsum dolor sit amet")
///
/// The result of base64("ipsum") is aXBzdW0==, which happens to appear within
/// the longer base64 string (after stripping the == padding):
///
/// TG9yZW0g *aXBzdW0* gZG9sb3Igc2l0IGFtZXQ
///
/// However, due the nature of base64 this is not always the case. The substring
/// "ipsum" can adopt multiple forms in the base64-encoded text, depending on
/// the characters that surround it, and its position within the text. The good
/// news is that there are only 3 string that we need to look for: "aXBzdW",
/// "lwc3Vt" or "pcHN1b". If some string S contains "ipsum", the result of
/// base64(S) must contain one of those three patterns.
///
/// See: https://www.leeholmes.com/searching-for-content-in-base-64-strings/
///
/// This function returns the three patterns that can be used for locating the
/// string `s` withing some data encoded as base64.
pub(super) fn base64_patterns(
    s: &[u8],
    alphabet: Option<&str>,
) -> Vec<BString> {
    // The input string must be at least 2 bytes long.
    assert_eq!(s.len() > 1);

    let alphabet = if let Some(alphabet) = alphabet {
        // TODO: what if alphabet is incorrect? Validate it when generating
        // the AST.
        base64::alphabet::Alphabet::new(alphabet).unwrap()
    } else {
        base64::alphabet::STANDARD
    };

    let base64_engine = base64::engine::GeneralPurpose::new(
        &alphabet,
        base64::engine::general_purpose::NO_PAD,
    );

    // Prepend "XX" to the original string. These two characters are irrelevant,
    // the portion of the base64 result affected by them will be removed from
    // the final results. They are prepended only for being able to compute the
    // base64 with 1 and 2 extra bytes at the left of the pattern.
    let mut pattern: Vec<u8> = Vec::with_capacity(3 + s.len());

    pattern.push_str("XX");
    pattern.push_str(s);

    let mut base64_patterns = Vec::new();

    // Create a buffer with enough capacity for holding the pattern after
    // being encoded as base64.
    let mut buf = vec![0; base64::encoded_len(pattern.len(), false).unwrap()];

    // Compute base64("XX" + s), base64("X" + s) and base64(s), in that
    // order. The resulting base64 strings are trimmed from the left and
    // right ends, in order to remove the parts that are influenced by the
    // bytes around the pattern.
    for i in 0..=2 {
        let base64_len =
            base64_engine.encode_slice(&pattern[i..], &mut buf).unwrap();

        // Now `buf` contains the base64 string, but we must adjust the length
        // to match the actual size of the string, as returned by
        // `encode_slice`.
        buf.truncate(base64_len);

        let right_trim = if (pattern.len() - i) % 3 == 0 { 0 } else { 1 };

        let range = match i {
            // "XX" + s
            0 => 3..base64_len - right_trim,
            // "X" + s
            1 => 2..base64_len - right_trim,
            // s
            2 => 0..base64_len - right_trim,
            _ => unreachable!(),
        };

        base64_patterns.push(BString::from(&buf[range]));
    }

    base64_patterns
}

#[cfg(test)]
mod test {
    use crate::compiler::atoms::base64::base64_patterns;
    use bstr::BString;
    use pretty_assertions::assert_eq;

    #[test]
    fn base64() {
        // TODO: test cases with a different alphabet

        assert_eq!(
            base64_patterns(b"fo", None),
            vec![
                BString::from("mb"),
                BString::from("Zv"),
                BString::from("Zm")
            ]
        );

        assert_eq!(
            base64_patterns(b"foo", None),
            vec![
                BString::from("mb2"),
                BString::from("Zvb"),
                BString::from("Zm9v")
            ]
        );

        assert_eq!(
            base64_patterns(b"foob", None),
            vec![
                BString::from("mb29i"),
                BString::from("Zvb2"),
                BString::from("Zm9vY")
            ]
        );

        assert_eq!(
            base64_patterns(b"fooba", None),
            vec![
                BString::from("mb29iY"),
                BString::from("Zvb2Jh"),
                BString::from("Zm9vYm")
            ]
        );

        assert_eq!(
            base64_patterns(b"foobar", None),
            vec![
                BString::from("mb29iYX"),
                BString::from("Zvb2Jhc"),
                BString::from("Zm9vYmFy")
            ]
        );
    }
}
