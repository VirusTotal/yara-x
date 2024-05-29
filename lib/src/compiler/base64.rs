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
/// `TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=`
///
/// Which is the result of:
///
/// `base64("Lorem ipsum dolor sit amet")`
///
/// The result of `base64("ipsum")` is `aXBzdW0==`, which happens to appear
/// within the longer base64 string (the == padding is stripped):
///
/// ```text
/// TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ
///         ------- here is aXBzdW0
/// ```
/// However, due the nature of base64 this is not always the case. The substring
/// "ipsum" can adopt multiple forms in the base64-encoded text, depending on
/// the characters that surround it and its position within the text. For
/// example `base64("-Lorem ipsum dolor sit amet")` produces a different
/// result, which doesn't contain `aXBzdW0`:
///
/// `LUxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0`
///
/// The good news is that there are only 3 strings that we need to look for:
/// `aXBzdW`, `lwc3Vt` and `pcHN1b`. If some string `S` contains "ipsum", the
/// result of `base64(S)` must contain one of these three patterns.
///
/// These three patterns are the result of `base64(S)`, `base64("X" + S)`
/// and `base64("XX" + S)`, after removing the characters that are affected
/// by the "X" at the beginning of the pattern, or that could be affected
/// if more bytes are added after "ipsum".
///
/// padding + S        base64(padding + S)      final pattern
/// "ipsum"         -> "aXBzdW0"            ->  "aXBzdW"
/// "Xipsum"        -> "WGlwc3Vt"           ->  "lwc3Vt"
/// "XXipsum"       -> "WFhpcHN1bQ"         ->  "pcHN1b"
///
/// See: https://www.leeholmes.com/searching-for-content-in-base-64-strings/
///
/// This function returns the three patterns that can be used for locating the
/// string `s` within some data encoded as base64.
///
/// Each pattern is returned together with the amount of padding applied, that
/// can be either 0, 1 or 2.
///
/// # Panics
///
/// If the provided alphabet is not valid. The alphabet must be exactly 64
/// characters long and can't have repeated characters.
///
/// Also panics if the length of s is 1 or less.
pub(crate) fn base64_patterns(
    s: &[u8],
    alphabet: Option<&str>,
) -> Vec<(u8, BString)> {
    // The input string must be at least 2 bytes long.
    assert!(s.len() > 1);

    // If some alphabet is provided the caller must guarantee that it is a
    // valid alphabet.
    let alphabet = alphabet.map_or(base64::alphabet::STANDARD, |a| {
        base64::alphabet::Alphabet::new(a).unwrap()
    });

    let base64_engine = base64::engine::GeneralPurpose::new(
        &alphabet,
        base64::engine::general_purpose::NO_PAD,
    );

    // Prepend "XX" to the original string. These two characters are irrelevant,
    // the portion of the base64 result affected by them will be stripped from
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
    for i in 0..=2_u8 {
        // Trim the pattern i bytes from the left in order to ignore 0, 1 or 2
        // "X" characters.
        let pattern = &pattern[i as usize..];

        // Encode the pattern as base64.
        let base64_len =
            base64_engine.encode_slice(pattern, &mut buf).unwrap();

        // Now `buf` contains the base64 string, but we must adjust the length
        // to match the actual size of the string, as returned by
        // `encode_slice`.
        buf.truncate(base64_len);

        // If the pattern's length is not multiple of 3 remove the right-most
        // character from the produced base64.
        let right_trim = usize::from(pattern.len() % 3 != 0);

        // Depending on the amount of padding applied we must discard a certain
        // number of characters from the left of the produced base64 strings.
        let range = match i {
            // "XX" + s, 3 characters discarded from the left of the base64
            // string, as they are affected by "XX".
            0 => 3..base64_len - right_trim,
            // "X" + s, 2 characters discarded from the left of the base64
            // string, as they are affected by "X".
            1 => 2..base64_len - right_trim,
            // s, no bytes discarded from the left.
            2 => 0..base64_len - right_trim,
            _ => unreachable!(),
        };

        base64_patterns.push((2 - i, BString::from(&buf[range])));
    }

    base64_patterns
}

#[cfg(test)]
mod test {
    use super::base64_patterns;
    use bstr::BString;
    use pretty_assertions::assert_eq;

    #[test]
    fn base64() {
        assert_eq!(
            base64_patterns(b"fo", None),
            vec![
                (2, BString::from("mb")),
                (1, BString::from("Zv")),
                (0, BString::from("Zm"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foo", None),
            vec![
                (2, BString::from("mb2")),
                (1, BString::from("Zvb")),
                (0, BString::from("Zm9v")),
            ]
        );

        assert_eq!(
            base64_patterns(b"foob", None),
            vec![
                (2, BString::from("mb29i")),
                (1, BString::from("Zvb2")),
                (0, BString::from("Zm9vY"))
            ]
        );

        assert_eq!(
            base64_patterns(b"fooba", None),
            vec![
                (2, BString::from("mb29iY")),
                (1, BString::from("Zvb2Jh")),
                (0, BString::from("Zm9vYm"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foobar", None),
            vec![
                (2, BString::from("mb29iYX")),
                (1, BString::from("Zvb2Jhc")),
                (0, BString::from("Zm9vYmFy"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foobar", Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")),
            vec![
                (2, BString::from("mb29iYX")),
                (1, BString::from("Zvb2Jhc")),                      
                (0, BString::from("Zm9vYmFy"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foobar", Some("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
            vec![
                (2, BString::from("kZ07gWV")),
                (1, BString::from("XtZ0Hfa")),
                (0, BString::from("Xk7tWkDw"))
            ]
        );
    }
}
