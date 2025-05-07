/// Returns true if `a` and `b` differs only in a single bit, while the changed
/// character keeps being alphanumeric.
pub fn bitsquatting(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();

    loop {
        let next_a = a_chars.next();
        let next_b = b_chars.next();

        match (next_a, next_b) {
            (Some(next_a), Some(next_b)) => {
                if next_a != next_b {
                    if !next_a.is_ascii() || !next_a.is_ascii() {
                        return false;
                    }
                    let xor = next_a as u8 ^ next_b as u8;
                    return xor.count_ones() == 1 && a_chars.eq(b_chars);
                }
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::modules::vt::bitsquatting::bitsquatting;

    #[test]
    fn test_bitsquatting() {
        assert!(!bitsquatting("a", "o"));
        assert!(bitsquatting("a", "q"));
        assert!(bitsquatting("q", "a"));
        assert!(!bitsquatting("a", "a"));
        assert!(bitsquatting("aa", "aq"));
        assert!(bitsquatting("aa", "qa"));
        assert!(bitsquatting("aaa", "aqa"));
        assert!(!bitsquatting("aaa", "aqq"));
    }
}
