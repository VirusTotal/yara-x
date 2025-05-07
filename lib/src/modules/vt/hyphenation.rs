/// Returns true if `b` is equal to `a` with one or more hyphens (`-`)
/// inserted between two of its characters. For example, the following
/// are true:
///
/// * `hyphenation("abc", "ab-c")`
/// * `hyphenation("abc", "a-b-c")`
///
/// The hyphen must not appear at the beginning or end of `b`, so the
/// following are false:
/// 
/// * `hyphenation("abc", "-abc")` 
/// * `hyphenation("abc", "abc-")` 
pub fn hyphenation(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();
    let mut first_char = true;
    let mut hyphen = false;

    loop {
        let a = a_chars.next();
        let b = b_chars.next();

        match (a, b) {
            (Some(a), Some(b)) => {
                if a != b {
                    if first_char || b != '-' || b_chars.next() != Some(a) {
                        return false;
                    }
                    hyphen = true;
                }
                first_char = false;
            }
            (None, None) => return hyphen,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::modules::vt::hyphenation::hyphenation;

    #[test]
    fn test_hyphenation() {
        assert!(hyphenation("abc", "a-bc"));
        assert!(hyphenation("abc", "ab-c"));
        assert!(hyphenation("abc", "a-b-c"));
        assert!(!hyphenation("", "-"));
        assert!(!hyphenation("abc", "-abc"));
        assert!(!hyphenation("abc", "abc-"));
        assert!(!hyphenation("abc", "a-bc-"));
        assert!(!hyphenation("abc", "-a-b-c"));
    }
}
