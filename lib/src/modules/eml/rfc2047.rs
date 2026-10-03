use base64::prelude::*;
use bstr::ByteSlice;
use encoding_rs::Encoding;

/// Decodes RFC 2047 encoded words (`=?charset?B|Q?text?=`) found in `input`
/// and returns the result as UTF-8.
///
/// The decoder is lenient: anything that isn't a well-formed encoded word, or
/// that uses an unknown charset, is left untouched.
pub(super) fn decode_encoded_words(input: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len());
    // Consecutive encoded words with the same charset are decoded together,
    // as a multibyte character can be split across two of them.
    let mut pending: Option<(&'static Encoding, Vec<u8>)> = None;
    let mut literal_start = 0;
    let mut i = 0;

    while i + 1 < input.len() {
        if input[i] == b'='
            && input[i + 1] == b'?'
            && let Some((end, encoding, bytes)) = parse_word(input, i)
        {
            let literal = &input[literal_start..i];
            // Whitespace between two encoded words is not significant.
            if pending.is_none() || !literal.iter().all(u8::is_ascii_whitespace)
            {
                flush(&mut pending, &mut result);
                result.extend_from_slice(literal);
            }
            match &mut pending {
                Some((e, b)) if *e == encoding => b.extend_from_slice(&bytes),
                _ => {
                    flush(&mut pending, &mut result);
                    pending = Some((encoding, bytes));
                }
            }
            i = end;
            literal_start = end;
            continue;
        }
        i += 1;
    }

    flush(&mut pending, &mut result);
    result.extend_from_slice(&input[literal_start..]);
    result
}

fn flush(pending: &mut Option<(&'static Encoding, Vec<u8>)>, out: &mut Vec<u8>) {
    if let Some((encoding, bytes)) = pending.take() {
        let (text, _) = encoding.decode_without_bom_handling(&bytes);
        out.extend_from_slice(text.as_bytes());
    }
}

/// Tries to parse an encoded word starting at `start`, which must point to
/// `=?`. Returns the end offset, the charset and the decoded bytes.
fn parse_word(
    input: &[u8],
    start: usize,
) -> Option<(usize, &'static Encoding, Vec<u8>)> {
    let rest = &input[start + 2..];

    let charset_len = rest.iter().position(|&b| b == b'?')?;
    let charset = &rest[..charset_len];
    if charset.iter().any(u8::is_ascii_whitespace) {
        return None;
    }
    // Drop the optional RFC 2231 language suffix (`UTF-8*en`).
    let label = charset.split_once_str("*").map_or(charset, |(l, _)| l);
    let encoding = Encoding::for_label(label)?;

    let kind = *rest.get(charset_len + 1)?;
    if *rest.get(charset_len + 2)? != b'?' {
        return None;
    }

    let text_start = charset_len + 3;
    let text_len = rest[text_start..].iter().position(|&b| b == b'?')?;
    let text = &rest[text_start..text_start + text_len];
    if text.iter().any(u8::is_ascii_whitespace) {
        return None;
    }
    if *rest.get(text_start + text_len + 1)? != b'=' {
        return None;
    }

    let bytes = match kind {
        // Padding is optional in the wild.
        b'B' | b'b' => BASE64_STANDARD_NO_PAD
            .decode(text.trim_end_with(|c| c == '='))
            .ok()?,
        // "Q" is quoted-printable where `_` means space.
        b'Q' | b'q' => quoted_printable::decode(
            text.replace("_", " "),
            quoted_printable::ParseMode::Robust,
        )
        .ok()?,
        _ => return None,
    };

    Some((start + 2 + text_start + text_len + 2, encoding, bytes))
}

#[cfg(test)]
mod tests {
    use super::decode_encoded_words;

    fn decode(input: &str) -> String {
        String::from_utf8(decode_encoded_words(input.as_bytes())).unwrap()
    }

    #[test]
    fn plain_text_is_untouched() {
        assert_eq!(decode("Hello world"), "Hello world");
        assert_eq!(decode(""), "");
    }

    #[test]
    fn base64_word() {
        assert_eq!(decode("=?UTF-8?B?w6k=?="), "é");
        // Missing padding is tolerated.
        assert_eq!(decode("=?UTF-8?B?w6k?="), "é");
    }

    #[test]
    fn q_word() {
        assert_eq!(decode("=?ISO-8859-1?Q?caf=E9?="), "café");
        assert_eq!(decode("=?utf-8?q?a_b?="), "a b");
    }

    #[test]
    fn mixed_with_plain_text() {
        assert_eq!(decode("Hello =?UTF-8?Q?w=C3=B6rld?= !"), "Hello wörld !");
    }

    #[test]
    fn whitespace_between_words_is_dropped() {
        assert_eq!(decode("=?UTF-8?Q?a?= =?UTF-8?Q?b?="), "ab");
        assert_eq!(decode("=?UTF-8?Q?a?=\r\n =?UTF-8?Q?b?="), "ab");
    }

    #[test]
    fn whitespace_around_a_single_word_is_kept() {
        assert_eq!(decode("a =?UTF-8?Q?b?= c"), "a b c");
        assert_eq!(decode("=?UTF-8?Q?a?= "), "a ");
    }

    #[test]
    fn multibyte_character_split_across_words() {
        assert_eq!(decode("=?UTF-8?B?ww==?= =?UTF-8?B?qQ==?="), "é");
    }

    #[test]
    fn different_charsets() {
        assert_eq!(
            decode("=?ISO-8859-1?Q?caf=E9?= =?UTF-8?Q?=C3=A9?="),
            "caféé"
        );
    }

    #[test]
    fn language_suffix() {
        assert_eq!(decode("=?UTF-8*en?Q?a?="), "a");
    }

    #[test]
    fn malformed_is_left_untouched() {
        for input in [
            "=?UTF-8?B?!!!?=",
            "=?x-bogus?Q?a?=",
            "=?UTF-8?Q?abc",
            "=?UTF-8?X?abc?=",
            "=?UTF-8?Q?a b?=",
            "=??Q?a?=",
            "=?",
        ] {
            assert_eq!(decode(input), input, "input: {input}");
        }
    }
}
