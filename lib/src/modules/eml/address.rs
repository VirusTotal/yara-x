use crate::modules::protos::eml::Address;
use bstr::ByteSlice;

/// Parses the value of an address-list header (`From`, `To`, `Cc`,
/// `Reply-To`...) into a list of [`Address`].
///
/// This is a lenient parser for the subset of RFC 5322 that appears in real
/// mail: quoted display names, `Name <addr>` and bare `addr` forms,
/// `addr (Name)` comments, and groups (`Group: a@x, b@y;`). Encoded words
/// (RFC 2047) are not decoded.
pub(super) fn parse_address_list(input: &[u8]) -> Vec<Address> {
    split_mailboxes(input).iter().filter_map(|s| parse_mailbox(s)).collect()
}

/// Splits an address list into individual mailbox strings, honoring quoted
/// strings, angle brackets, comments and groups.
fn split_mailboxes(input: &[u8]) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    let mut in_quote = false;
    let mut escape = false;
    let mut in_angle = false;
    let mut comment_depth = 0usize;

    for &b in input {
        if escape {
            escape = false;
            current.push(b);
            continue;
        }
        if in_quote {
            match b {
                b'\\' => escape = true,
                b'"' => in_quote = false,
                _ => {}
            }
            current.push(b);
            continue;
        }
        if comment_depth > 0 {
            match b {
                b'\\' => escape = true,
                b'(' => comment_depth += 1,
                b')' => comment_depth -= 1,
                _ => {}
            }
            current.push(b);
            continue;
        }
        match b {
            b'"' => {
                in_quote = true;
                current.push(b);
            }
            b'(' => {
                comment_depth = 1;
                current.push(b);
            }
            b'<' => {
                in_angle = true;
                current.push(b);
            }
            b'>' => {
                in_angle = false;
                current.push(b);
            }
            // Start of a group: discard the group name.
            b':' if !in_angle => current.clear(),
            b',' | b';' if !in_angle => {
                result.push(std::mem::take(&mut current));
            }
            _ => current.push(b),
        }
    }
    result.push(current);
    result
}

/// Parses a single mailbox: `Name <addr>`, `<addr>`, `addr` or `addr (Name)`.
fn parse_mailbox(input: &[u8]) -> Option<Address> {
    // Text outside angle brackets and comments, with quotes removed.
    let mut outside = Vec::new();
    // Text inside angle brackets.
    let mut inner = Vec::new();
    // Text of the first top-level comment.
    let mut comment = Vec::new();

    let mut saw_angle = false;
    let mut in_angle = false;
    let mut in_quote = false;
    let mut escape = false;
    let mut comment_depth = 0usize;

    for &b in input {
        if escape {
            escape = false;
            if comment_depth > 0 {
                comment.push(b);
            } else if in_angle {
                inner.push(b);
            } else {
                outside.push(b);
            }
            continue;
        }
        if comment_depth > 0 {
            match b {
                b'\\' => escape = true,
                b'(' => {
                    comment_depth += 1;
                    comment.push(b);
                }
                b')' => {
                    comment_depth -= 1;
                    if comment_depth > 0 {
                        comment.push(b);
                    }
                }
                _ => comment.push(b),
            }
            continue;
        }
        if in_quote {
            match b {
                b'\\' => escape = true,
                b'"' => in_quote = false,
                _ if in_angle => inner.push(b),
                _ => outside.push(b),
            }
            continue;
        }
        match b {
            b'"' => in_quote = true,
            b'(' => {
                // Only keep the first comment.
                comment_depth = 1;
                if !comment.is_empty() {
                    comment.clear();
                }
            }
            b'<' if !in_angle && !saw_angle => {
                in_angle = true;
                saw_angle = true;
            }
            b'>' if in_angle => in_angle = false,
            _ if in_angle => inner.push(b),
            _ => outside.push(b),
        }
    }

    let (name, address) = if saw_angle {
        (outside, inner)
    } else {
        (comment, outside)
    };

    let name = name.trim().to_vec();
    let address = address.trim().to_vec();

    if name.is_empty() && address.is_empty() {
        return None;
    }

    Some(Address {
        name: if name.is_empty() { None } else { Some(name) },
        address: if address.is_empty() { None } else { Some(address) },
        ..Default::default()
    })
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
