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
///
/// Each pattern has an associated offset, that can be either 0, 2 or 3. The
/// offset indicates how many bytes we must go back in order to find a place
/// where it is safe to start decoding the string. This rely on the fact that
/// you can start decoding a base64 string at the middle of it, as long as the
/// offset is a multiple of 4. The string TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ
/// can be decoded starting at:
///
/// ZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ
/// aXBzdW0gZG9sb3Igc2l0IGFtZXQ
/// dW0gZG9sb3Igc2l0IGFtZXQ
///
/// ..etc
///
/// When this function returns something like (2, "lwc3Vt") it means that
/// "lwc3Vt" can appear as part of a longer base64 string containing the
/// plain-text string "ipsum", and it's safe to decode that base64 string
/// starting 2 bytes before the offset where "lwc3Vt" was found.
///
/// # Panics
///
/// If the provided alphabet is not valid. The alphabet must be exactly 64
/// characters long and can't have repeated characters.
///
/// Also panics if the length of s is 1 or less.
pub(super) fn base64_patterns(
    s: &[u8],
    alphabet: Option<&str>,
) -> Vec<(usize, BString)> {
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

        base64_patterns.push((range.start, BString::from(&buf[range])));
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
        assert_eq!(
            base64_patterns(b"fo", None),
            vec![
                (3, BString::from("mb")),
                (2, BString::from("Zv")),
                (0, BString::from("Zm"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foo", None),
            vec![
                (3, BString::from("mb2")),
                (2, BString::from("Zvb")),
                (0, BString::from("Zm9v")),
            ]
        );

        assert_eq!(
            base64_patterns(b"foob", None),
            vec![
                (3, BString::from("mb29i")),
                (2, BString::from("Zvb2")),
                (0, BString::from("Zm9vY"))
            ]
        );

        assert_eq!(
            base64_patterns(b"fooba", None),
            vec![
                (3, BString::from("mb29iY")),
                (2, BString::from("Zvb2Jh")),
                (0, BString::from("Zm9vYm"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foobar", None),
            vec![
                (3, BString::from("mb29iYX")),
                (2, BString::from("Zvb2Jhc")),
                (0, BString::from("Zm9vYmFy"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foobar", Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")),
            vec![
                (3, BString::from("mb29iYX")),
                (2, BString::from("Zvb2Jhc")),                      
                (0, BString::from("Zm9vYmFy"))
            ]
        );

        assert_eq!(
            base64_patterns(b"foobar", Some("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
            vec![
                (3, BString::from("kZ07gWV")),
                (2, BString::from("XtZ0Hfa")),
                (0, BString::from("Xk7tWkDw"))
            ]
        );
    }
}
