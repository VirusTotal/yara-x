/// Returns true if `b` is equal to `a` with one or more of the character
/// `c` inserted between two of its characters. For example, the following
/// are true:
///
/// * `interleaved("abc", "ab-c", '-')`
/// * `interleaved("abc", "a-b-c", '-')`
///
/// `c` must not appear at the beginning or end of `b`, so the
/// following are false:
///
/// * `interleaved("abc", "-abc", `-`)`
/// * `interleaved("abc", "abc-", `-`)`
pub fn interleaved(a: &str, b: &str, c: char) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();
    let mut first_char = true;
    let mut found = false;

    loop {
        let a = a_chars.next();
        let b = b_chars.next();

        match (a, b) {
            (Some(a), Some(b)) => {
                if a != b {
                    if first_char || b != c || b_chars.next() != Some(a) {
                        return false;
                    }
                    found = true;
                }
                first_char = false;
            }
            (None, None) => return found,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::modules::vt::interleaved::interleaved;

    #[test]
    fn test_interleaved() {
        assert!(interleaved("abc", "a-bc", '-'));
        assert!(interleaved("abc", "a.bc", '.'));
        assert!(interleaved("abc", "ab-c", '-'));
        assert!(interleaved("abc", "a-b-c", '-'));
        assert!(!interleaved("", "-", '-'));
        assert!(!interleaved("abc", "-abc", '-'));
        assert!(!interleaved("abc", "abc-", '-'));
        assert!(!interleaved("abc", "a-bc-", '-'));
        assert!(!interleaved("abc", "-a-b-c", '-'));
    }
}
