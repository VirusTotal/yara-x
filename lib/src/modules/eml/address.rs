use super::rfc2047::decode_encoded_words;
use crate::modules::protos::eml::Address;
use bstr::ByteSlice;

/// A mailbox being accumulated by [`parse_address_list`].
#[derive(Default)]
struct Mailbox {
    /// Text outside angle brackets and comments, with quotes removed.
    outside: Vec<u8>,
    /// Text inside angle brackets.
    inner: Vec<u8>,
    /// Text of the last top-level comment.
    comment: Vec<u8>,
    saw_angle: bool,
}

impl Mailbox {
    fn push(&mut self, b: u8, in_comment: bool, in_angle: bool) {
        if in_comment {
            self.comment.push(b);
        } else if in_angle {
            self.inner.push(b);
        } else {
            self.outside.push(b);
        }
    }

    /// `Name <addr>`, `<addr>`, `addr` or `addr (Name)`.
    fn into_address(self) -> Option<Address> {
        let (name, address) = if self.saw_angle {
            (self.outside, self.inner)
        } else {
            (self.comment, self.outside)
        };

        let name = decode_encoded_words(name.trim());
        let address = address.trim().to_vec();

        if name.is_empty() && address.is_empty() {
            return None;
        }

        Some(Address {
            name: (!name.is_empty()).then_some(name),
            address: (!address.is_empty()).then_some(address),
            ..Default::default()
        })
    }
}

/// Parses the value of an address-list header (`From`, `To`, `Cc`,
/// `Reply-To`...) into a list of [`Address`].
///
/// This is a lenient parser for the subset of RFC 5322 that appears in real
/// mail: quoted display names, `Name <addr>` and bare `addr` forms,
/// `addr (Name)` comments, and groups (`Group: a@x, b@y;`).
pub(super) fn parse_address_list(input: &[u8]) -> Vec<Address> {
    let mut result = Vec::new();
    let mut mailbox = Mailbox::default();
    let mut in_quote = false;
    let mut escape = false;
    let mut in_angle = false;
    let mut comment_depth = 0usize;

    for &b in input {
        if escape {
            escape = false;
            mailbox.push(b, comment_depth > 0, in_angle);
        } else if comment_depth > 0 {
            match b {
                b'\\' => escape = true,
                b'(' => {
                    comment_depth += 1;
                    mailbox.comment.push(b);
                }
                b')' => {
                    comment_depth -= 1;
                    if comment_depth > 0 {
                        mailbox.comment.push(b);
                    }
                }
                _ => mailbox.comment.push(b),
            }
        } else if in_quote {
            match b {
                b'\\' => escape = true,
                b'"' => in_quote = false,
                _ => mailbox.push(b, false, in_angle),
            }
        } else {
            match b {
                b'"' => in_quote = true,
                b'(' => {
                    comment_depth = 1;
                    mailbox.comment.clear();
                }
                b'<' if !in_angle && !mailbox.saw_angle => {
                    in_angle = true;
                    mailbox.saw_angle = true;
                }
                b'>' if in_angle => in_angle = false,
                // Start of a group: discard the group name.
                b':' if !in_angle => mailbox = Mailbox::default(),
                b',' | b';' if !in_angle => {
                    result.extend(std::mem::take(&mut mailbox).into_address());
                }
                _ => mailbox.push(b, false, in_angle),
            }
        }
    }
    result.extend(mailbox.into_address());
    result
}

#[cfg(test)]
mod tests {
    use super::parse_address_list;

    fn parse(input: &str) -> Vec<(Option<String>, Option<String>)> {
        parse_address_list(input.as_bytes())
            .into_iter()
            .map(|a| {
                (
                    a.name.map(|n| String::from_utf8(n).unwrap()),
                    a.address.map(|n| String::from_utf8(n).unwrap()),
                )
            })
            .collect()
    }

    fn pair(name: Option<&str>, addr: &str) -> (Option<String>, Option<String>) {
        (name.map(String::from), Some(addr.to_string()))
    }

    #[test]
    fn bare_address() {
        assert_eq!(parse("user@example.com"), vec![pair(None, "user@example.com")]);
    }

    #[test]
    fn name_and_angle() {
        assert_eq!(
            parse("John Doe <john@example.com>"),
            vec![pair(Some("John Doe"), "john@example.com")]
        );
        assert_eq!(parse("<a@b.com>"), vec![pair(None, "a@b.com")]);
    }

    #[test]
    fn quoted_name_with_comma_and_angle() {
        assert_eq!(
            parse(r#""Doe, John <x>" <john@example.com>, b@c.com"#),
            vec![
                pair(Some("Doe, John <x>"), "john@example.com"),
                pair(None, "b@c.com")
            ]
        );
    }

    #[test]
    fn escaped_quote_in_name() {
        assert_eq!(
            parse(r#""Jo \"J\" Doe" <j@x.com>"#),
            vec![pair(Some(r#"Jo "J" Doe"#), "j@x.com")]
        );
    }

    #[test]
    fn comment_name() {
        assert_eq!(
            parse("john@example.com (John Doe)"),
            vec![pair(Some("John Doe"), "john@example.com")]
        );
    }

    #[test]
    fn encoded_display_name() {
        assert_eq!(
            parse("=?UTF-8?B?w6k=?= <e@x.com>, \"=?UTF-8?Q?a_b?=\" <f@x.com>"),
            vec![pair(Some("é"), "e@x.com"), pair(Some("a b"), "f@x.com")]
        );
    }

    #[test]
    fn group() {
        assert_eq!(
            parse("Team: a@x.com, B <b@x.com>;"),
            vec![pair(None, "a@x.com"), pair(Some("B"), "b@x.com")]
        );
    }

    #[test]
    fn empty_and_null_path() {
        assert!(parse("").is_empty());
        assert!(parse("<>").is_empty());
    }
}
