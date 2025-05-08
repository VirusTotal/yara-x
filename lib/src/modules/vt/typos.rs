/// Returns true if `b` is equal to `a`, except for a single character inserted
/// in `b` that is close in the QWERTY keyboard to its surrounding characters.
///
/// For instance, `insertion("ab", "azb")` is true because `"azb"` is the result
/// of inserting a single character in `"ab"`, and the inserted character is `a`,
/// which is close to the preceding `a`. Similarly, `insertion("ab", "avb")` is
/// true because the inserted `v` is close to `b`.
///
/// In the other hand `insertion("ab", "aby")` is false because the `y` is not
/// close to the `b`.
pub fn insertion(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();

    let mut prev = None;

    loop {
        let next_a = a_chars.next();
        let next_b = b_chars.next();

        match (prev, next_a, next_b) {
            (_, Some(next_a), Some(next_b)) if next_a == next_b => {
                prev = Some(next_a);
            }
            (_, Some(next_a), Some(next_b))
                if qwerty_neighbours(next_a, next_b) =>
            {
                b_chars.next();
                return a_chars.eq(b_chars);
            }
            (Some(prev), _, Some(next_b))
                if qwerty_neighbours(prev, next_b) =>
            {
                b_chars.next();
                return a_chars.eq(b_chars);
            }
            _ => return false,
        }
    }
}

/// Returns true if `b` is equal to `a`, except for a single character that
/// was present in `a` but omitted from `b`.
///
/// For instance, `omission("ab", "a")` is true because `"a"` is the result
/// of omitting the `b`.
pub fn omission(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();

    loop {
        let next_a = a_chars.next();
        let next_b = b_chars.next();

        match (next_a, next_b) {
            (Some(next_a), Some(next_b)) => {
                if next_a != next_b {
                    return a_chars.next() == Some(next_b)
                        && a_chars.eq(b_chars);
                }
            }
            (Some(_), None) => return a_chars.next().is_none(),
            _ => return false,
        }
    }
}

/// Returns true if `b` is equal to `a`, except for a single character in `b`
/// that was replaced by another one that is close to the original character
/// in a QWERTY keyboard.
///
/// For instance, `replacement("ab", "av")` is true because `b` was replaced
/// by `v`. In the other hand, `replacement("abc", "av")` is false, because
/// `"av"` is not the result of replacing a single character in `a`.
pub fn replacement(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();

    loop {
        let next_a = a_chars.next();
        let next_b = b_chars.next();

        match (next_a, next_b) {
            (Some(next_a), Some(next_b)) => {
                if next_a != next_b {
                    return qwerty_neighbours(next_a, next_b)
                        && a_chars.eq(b_chars);
                }
            }
            _ => return false,
        }
    }
}

/// Returns true if `b` is equal to `a`, except for a single vowel that was
/// replaced with another vowel.
///
/// For instance, `vowel_swap("ab", "eb")` is true because `a` was replaced
/// with `e`. In the other hand, `vowel_swap("aa", "ee")` is false, because
/// two vowels were replaced.
pub fn vowel_swap(a: &str, b: &str) -> bool {
    let is_vowel = |c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u');

    let mut a_chars = a.chars();
    let mut b_chars = b.chars();

    loop {
        let a = a_chars.next();
        let b = b_chars.next();

        match (a, b) {
            (Some(a), Some(b)) => {
                if a != b {
                    return is_vowel(a) && is_vowel(b) && a_chars.eq(b_chars);
                }
            }
            _ => return false,
        }
    }
}

/// Returns true if `b` is equal to `a`, except for a single character in `b`
/// that was doubled.
///
/// For instance, `doubling("abc", "abbc")` is true because `b` was doubled.
pub fn doubling(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();
    let mut prev = None;

    loop {
        let next_a = a_chars.next();
        let next_b = b_chars.next();

        match (prev, next_a, next_b) {
            (_, Some(next_a), Some(next_b)) if next_a == next_b => {
                prev = Some(next_a)
            }
            (Some(prev), Some(_), Some(next_b)) => {
                return if prev == next_b {
                    b_chars.next();
                    a_chars.eq(b_chars)
                } else {
                    false
                }
            }
            (Some(prev), None, Some(next_b)) => {
                return prev == next_b && a_chars.eq(b_chars)
            }
            _ => return false,
        }
    }
}

/// Returns true if `b` is equal to `a`, except for two adjacent characters
/// that were swapped.
///
/// For instance, `swap("abc", "bac")` is true because `a` and `b` were swapped,
/// but `swap("abc", "cba")` is false because the `a` and `b` are not adjacent,
/// and `swap("abcd", "badc")` is false because there are two pairs of
/// characters that were swapped.
pub fn swap(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();

    let mut prev_a = None;
    let mut prev_b = None;
    let mut swaps = 0;

    loop {
        let next_a = a_chars.next();
        let next_b = b_chars.next();

        match (prev_a, prev_b, next_a, next_b) {
            (_, _, Some(next_a), Some(next_b)) if next_a == next_b => {
                prev_a = Some(next_a);
                prev_b = Some(next_b);
            }
            (None, None, Some(next_a), Some(next_b)) => {
                prev_a = Some(next_a);
                prev_b = Some(next_b);
            }
            (Some(pa), Some(pb), Some(next_a), Some(next_b))
                if next_a == pb && next_b == pa =>
            {
                swaps += 1;
                prev_a = None;
                prev_b = None;
            }
            (pa, pb, None, None) => return swaps == 1 && pa == pb,
            _ => return false,
        }
    }
}

/// Returns true if `a` and `b` are alphanumeric and close to each other in a
/// QWERTY keyboard.
///
/// For non-alphanumeric characters the result is always false. This function
/// is symmetrical, if `a` is close to `b`, then `b` is close `a`.
#[rustfmt::skip]
fn qwerty_neighbours(a: char, b: char) -> bool {
    match a {
        '1' => matches!(b, '2' | 'q'),
        '2' => matches!(b, '1' | '3' | 'q' | 'w'),
        '3' => matches!(b, '2' | '4' | 'w' | 'e'),
        '4' => matches!(b, '3' | '5' | 'e' | 'r'),
        '5' => matches!(b, '4' | '6' | 'r' | 't'),
        '6' => matches!(b, '5' | '7' | 't' | 'y'),
        '7' => matches!(b, '6' | '8' | 'y' | 'u'),
        '8' => matches!(b, '7' | '9' | 'u' | 'i'),
        '9' => matches!(b, '8' | '0' | 'i' | 'o'),
        '0' => matches!(b, '9' | 'o' | 'p'),

        'q' => matches!(b, '1' | '2' | 'w' | 'a'),
        'w' => matches!(b, 'q' | 'e' | 'a' | 's' | '2' | '3'),
        'e' => matches!(b, 'w' | 'r' | 's' | 'd' | '3' | '4'),
        'r' => matches!(b, 'e' | 't' | 'd' | 'f' | '4' | '5'),
        't' => matches!(b, 'r' | 'y' | 'f' | 'g' | '5' | '6'),
        'y' => matches!(b, 't' | 'u' | 'g' | 'h' | '6' | '7'),
        'u' => matches!(b, 'y' | 'i' | 'h' | 'j' | '7' | '8'),
        'i' => matches!(b, 'u' | 'o' | 'j' | 'k' | '8' | '9'),
        'o' => matches!(b, 'i' | 'p' | 'k' | 'l' | '9' | '0'),
        'p' => matches!(b, 'o' | 'l' | '0'),

        'a' => matches!(b, 'q' | 'w' | 's' | 'z'),
        's' => matches!(b, 'a' | 'w' | 'e' | 'd' | 'z' | 'x'),
        'd' => matches!(b, 's' | 'e' | 'r' | 'f' | 'x' | 'c'),
        'f' => matches!(b, 'd' | 'r' | 't' | 'g' | 'c' | 'v'),
        'g' => matches!(b, 'f' | 't' | 'y' | 'h' | 'v' | 'b'),
        'h' => matches!(b, 'g' | 'y' | 'u' | 'j' | 'b' | 'n'),
        'j' => matches!(b, 'h' | 'u' | 'i' | 'k' | 'n' | 'm'),
        'k' => matches!(b, 'j' | 'i' | 'o' | 'l' | 'm'),
        'l' => matches!(b, 'k' | 'o' | 'p'),

        'z' => matches!(b, 'a' | 's' | 'x'),
        'x' => matches!(b, 'z' | 's' | 'd' | 'c'),
        'c' => matches!(b, 'x' | 'd' | 'f' | 'v'),
        'v' => matches!(b, 'c' | 'f' | 'g' | 'b'),
        'b' => matches!(b, 'v' | 'g' | 'h' | 'n'),
        'n' => matches!(b, 'b' | 'h' | 'j' | 'm'),
        'm' => matches!(b, 'n' | 'j' | 'k'),

        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::modules::vt::typos::{
        doubling, insertion, omission, qwerty_neighbours, replacement, swap,
        vowel_swap,
    };

    #[test]
    fn test_qwerty_neighbour() {
        assert!(qwerty_neighbours('a', 'q'));
        assert!(qwerty_neighbours('a', 'w'));
        assert!(qwerty_neighbours('s', 'w'));
        assert!(qwerty_neighbours('d', 'e'));
        assert!(qwerty_neighbours('f', 'g'));
        assert!(qwerty_neighbours('j', 'k'));
        assert!(qwerty_neighbours('m', 'n'));
        assert!(qwerty_neighbours('1', '2'));
        assert!(qwerty_neighbours('2', 'q'));

        // Non-neighbours
        assert!(!qwerty_neighbours('a', 'k'));
        assert!(!qwerty_neighbours('s', 'l'));
        assert!(!qwerty_neighbours('d', 'm'));
        assert!(!qwerty_neighbours('f', 'z'));
        assert!(!qwerty_neighbours('1', '9'));

        // Same character.
        assert!(!qwerty_neighbours('a', 'a'));
        assert!(!qwerty_neighbours('z', 'z'));
        assert!(!qwerty_neighbours('1', '1'));

        // Make sure that qwerty_neighbour is not reflexive.
        for a in 0u8..=127 {
            let ch = a as char;
            if qwerty_neighbours(ch, ch) {
                assert!(
                    qwerty_neighbours(ch, ch),
                    "'{}' can't be a neighbour of itself.",
                    ch,
                );
            }
        }

        // Make sure that qwerty_neighbour is symmetrical in all cases.
        for a in 0u8..=127 {
            for b in 0u8..=127 {
                let ch1 = a as char;
                let ch2 = b as char;
                if qwerty_neighbours(ch1, ch2) {
                    assert!(
                        qwerty_neighbours(ch2, ch1),
                        "Function is not symmetrical: '{}' -> '{}' is true, but '{}' -> '{}' is false",
                        ch1, ch2, ch2, ch1
                    );
                }
            }
        }
    }

    #[test]
    fn test_insertion() {
        assert!(!insertion("", ""));
        assert!(!insertion("", "a"));
        assert!(!insertion("a", "aa"));
        assert!(insertion("a", "az"));
        assert!(insertion("a", "za"));
        assert!(insertion("ab", "azb"));
        assert!(insertion("ab", "avb"));
        assert!(insertion("aa", "asa"));
        assert!(!insertion("aa", "zz"));
        assert!(!insertion("aa", "axa"));
    }

    #[test]
    fn test_omission() {
        assert!(omission("a", ""));
        assert!(!omission("", "a"));
        assert!(!omission("", ""));
        assert!(omission("abc", "bc"));
        assert!(omission("abc", "ac"));
        assert!(omission("abc", "ab"));
        assert!(!omission("abc", "abc"));
        assert!(!omission("abcfe", "abde"));
    }

    #[test]
    fn test_replacement() {
        assert!(replacement("d", "f"));
        assert!(replacement("ab", "av"));
        assert!(!replacement("ab", "sv"));
        assert!(!replacement("ab", "az"));
        assert!(!replacement("ab", "ab"));
        assert!(!replacement("abc", "ab"));
        assert!(!replacement("ab", "abc"));
    }

    #[test]
    fn test_doubling() {
        assert!(!doubling("", ""));
        assert!(!doubling("a", "a"));
        assert!(doubling("a", "aa"));
        assert!(!doubling("a", "aaa"));
        assert!(!doubling("a", "aab"));
        assert!(doubling("ab", "aab"));
        assert!(doubling("ab", "abb"));
        assert!(doubling("abc", "aabc"));
        assert!(doubling("abc", "abbc"));
        assert!(doubling("abc", "abcc"));
        assert!(doubling("abc", "aabc"));
        assert!(!doubling("abc", "abbbc"));
    }

    #[test]
    fn test_vowel_swap() {
        assert!(!vowel_swap("", ""));
        assert!(!vowel_swap("a", "a"));
        assert!(vowel_swap("a", "e"));
        assert!(vowel_swap("a", "i"));
        assert!(vowel_swap("a", "o"));
        assert!(vowel_swap("a", "u"));
        assert!(vowel_swap("e", "i"));
        assert!(vowel_swap("e", "o"));
        assert!(vowel_swap("e", "u"));
        assert!(vowel_swap("i", "o"));
        assert!(vowel_swap("i", "u"));
        assert!(vowel_swap("o", "u"));
        assert!(vowel_swap("abc", "ebc"));
        assert!(vowel_swap("abba", "abbi"));
        assert!(!vowel_swap("abba", "ibbi"));
    }

    #[test]
    fn test_swap() {
        assert!(!swap("", ""));
        assert!(swap("ab", "ba"));
        assert!(!swap("a", "b"));
        assert!(!swap("a", "ba"));
        assert!(!swap("abc", "ba"));
        assert!(!swap("abcd", "badc"));
        assert!(swap("abcd", "bacd"));
        assert!(!swap("ing", "nih"));
    }
}
