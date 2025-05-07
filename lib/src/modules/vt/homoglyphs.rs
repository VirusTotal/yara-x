/// Returns true if `a` and `b` are homoglyphs.
///
/// Two strings are homoglyphs if `a` and `b` are equal, except for one or more
/// characters in `b` that are similarly looking to the corresponding character
/// in `a`.
///
/// This relationship is symmetrical (if `a` is homoglyph of `b`, `b` is 
/// homoglyph of `a`), but not reflexive (a string is never a homoglyph of
/// itself).
pub fn is_homoglyph(a: &str, b: &str) -> bool {
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();
    let mut homoglyph = false;

    loop {
        match (a_chars.next(), b_chars.next()) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) if a != b => {
                if !is_homoglyph_char(a, b) && !is_homoglyph_char(b, a) {
                    return false;
                }
                homoglyph = true;
            }
            // The end of both strings has been reached. They are homoglyphs
            // if some character in `b` was a homoglyph of the corresponding
            // character in `a`.
            (None, None) => return homoglyph,
            // Strings have different lengths, they are not homoglyphs.
            _ => return false,
        }
    }
}

/// Returns true if `b` is a homoglyph of `a`.
///
/// This means that `b` will be visually similar `a`, but not equal. Notice
/// this function is not symmetrical, if `b` is homoglyph of `a` it doesn't
/// mean that `a` is homoglyph of `b`.
#[rustfmt::skip]
fn is_homoglyph_char(a: char, b: char) -> bool {
    match a {
        'a' => matches!(b, 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ɑ' | 'ạ' | 'ǎ' | 'ă' | 'ȧ' | 'ą'),
        'b' => matches!(b, 'd' | 'ʙ' | 'ɓ' | 'ḃ' | 'ḅ' | 'ḇ' | 'ƅ'),
        'c' => matches!(b, 'e' | 'ƈ' | 'ċ' | 'ć' | 'ç' | 'č' | 'ĉ' | 'o'),
        'd' => matches!(b, 'b' | 'ɗ' | 'đ' | 'ď' | 'ɖ' | 'ḑ' | 'ḋ' | 'ḍ' | 'ḏ' | 'ḓ'),
        'e' => matches!(b, 'c' | 'é' | 'è' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ě' | 'ė' | 'ẹ' | 'ę' | 'ȩ' | 'ɇ' | 'ḛ'),
        'f' => matches!(b, 'ƒ' | 'ḟ'),
        'g' => matches!(b, 'q' | 'ɢ' | 'ɡ' | 'ġ' | 'ğ' | 'ǵ' | 'ģ' | 'ĝ' | 'ǧ' | 'ǥ'),
        'h' => matches!(b, 'ĥ' | 'ȟ' | 'ħ' | 'ɦ' | 'ḧ' | 'ḩ' | 'ⱨ' | 'ḣ' | 'ḥ' | 'ḫ' | 'ẖ'),
        'i' => matches!(b, '1' | 'l' | 'í' | 'ì' | 'ï' | 'ı' | 'ɩ' | 'ǐ' | 'ĭ' | 'ỉ' | 'ị' | 'ɨ' | 'ȋ' | 'ī'),
        'j' => matches!(b, 'ʝ' | 'ɉ'),
        'k' => matches!(b, 'ḳ' | 'ḵ' | 'ⱪ' | 'ķ'),
        'l' => matches!(b, '1' | 'i' | 'ɫ' | 'ł'),
        'm' => matches!(b, 'n' | 'ṁ' | 'ṃ' | 'ᴍ' | 'ɱ' | 'ḿ'),
        'n' => matches!(b, 'm' | 'r' | 'ń' | 'ṅ' | 'ṇ' | 'ṉ' | 'ñ' | 'ņ' | 'ǹ' | 'ň' | 'ꞑ'),
        'o' => matches!(b, '0' | 'ȯ' | 'ọ' | 'ỏ' | 'ơ' | 'ó' | 'ö' | 'ő'),
        'p' => matches!(b, 'ƿ' | 'ƥ' | 'ṕ' | 'ṗ'),
        'q' => matches!(b, 'g' | 'ʠ'),
        'r' => matches!(b, 'ʀ' | 'ɼ' | 'ɽ' | 'ŕ' | 'ŗ' | 'ř' | 'ɍ' | 'ɾ' | 'ȓ' | 'ȑ' | 'ṙ' | 'ṛ' | 'ṟ'),
        's' => matches!(b, 'ʂ' | 'ś' | 'ṣ' | 'ṡ' | 'ș' | 'ŝ' | 'š'),
        't' => matches!(b, 'ţ' | 'ŧ' | 'ṫ' | 'ṭ' | 'ț' | 'ƫ'),
        'u' => matches!(b, 'ᴜ' | 'ǔ' | 'ŭ' | 'ü' | 'ʉ' | 'ù' | 'ú' | 'û' | 'ũ' | 'ū' | 'ų' | 'ư' | 'ů' | 'ű' | 'ȕ' | 'ȗ' | 'ụ'),
        'v' => matches!(b, 'ṿ' | 'ⱱ' | 'ᶌ' | 'ṽ' | 'ⱴ'),
        'w' => matches!(b, 'ŵ' | 'ẁ' | 'ẃ' | 'ẅ' | 'ⱳ' | 'ẇ' | 'ẉ' | 'ẘ'),
        'y' => matches!(b, 'ʏ' | 'ý' | 'ÿ' | 'ŷ' | 'ƴ' | 'ȳ' | 'ɏ' | 'ỿ' | 'ẏ' | 'ỵ'),
        'z' => matches!(b, 'ʐ' | 'ż' | 'ź' | 'ᴢ' | 'ƶ' | 'ẓ' | 'ẕ' | 'ⱬ'),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::modules::vt::homoglyphs::is_homoglyph;

    #[test]
    fn homoglyph_a_to_z() {
        assert!(is_homoglyph("a", "à"));
        assert!(is_homoglyph("b", "ḃ"));
        assert!(is_homoglyph("c", "ç"));
        assert!(is_homoglyph("d", "đ"));
        assert!(is_homoglyph("e", "é"));
        assert!(is_homoglyph("f", "ƒ"));
        assert!(is_homoglyph("g", "ɢ"));
        assert!(is_homoglyph("h", "ĥ"));
        assert!(is_homoglyph("i", "í"));
        assert!(is_homoglyph("j", "ʝ"));
        assert!(is_homoglyph("k", "ḳ"));
        assert!(is_homoglyph("l", "ł"));
        assert!(is_homoglyph("m", "ṃ"));
        assert!(is_homoglyph("n", "ń"));
        assert!(is_homoglyph("o", "ơ"));
        assert!(is_homoglyph("p", "ƥ"));
        assert!(is_homoglyph("q", "ʠ"));
        assert!(is_homoglyph("r", "ŕ"));
        assert!(is_homoglyph("s", "š"));
        assert!(is_homoglyph("t", "ţ"));
        assert!(is_homoglyph("u", "ü"));
        assert!(is_homoglyph("v", "ṿ"));
        assert!(is_homoglyph("w", "ŵ"));
        assert!(is_homoglyph("y", "ý"));
        assert!(is_homoglyph("z", "ź"));
    }

    #[test]
    fn homoglyphs() {
        assert!(is_homoglyph("ba", "ƅɑ"));
        assert!(is_homoglyph("ƅɑ", "ba"));
        assert!(is_homoglyph("hello", "hȩłłő"));
        assert!(is_homoglyph("test", "ţëśţ"));
        assert!(is_homoglyph("apple", "àƥƥłè"));
        assert!(is_homoglyph("computer", "çơṃƥůţëɍ"));
        assert!(!is_homoglyph("apple", "appl3")); // '3' is not a homoglyph for 'e'
        assert!(!is_homoglyph("hello", "h3llo")); // '3' is not a homoglyph for 'e'
        assert!(!is_homoglyph("rust", "rusty")); // Different lengths
        assert!(!is_homoglyph("", "")); // Empty strings should be considered equal
        assert!(!is_homoglyph("foo", "foo"));
        assert!(!is_homoglyph("a", "b"));
    }
}
