use bstr::ByteSlice;
use std::hash::{Hash, Hasher};
use std::mem;
use std::ops::RangeInclusive;

use regex_syntax::hir::Class;
use regex_syntax::hir::ClassBytes;
use regex_syntax::hir::ClassBytesRange;
use regex_syntax::hir::ClassUnicode;
use regex_syntax::hir::ClassUnicodeRange;
use regex_syntax::hir::Dot;
use regex_syntax::hir::HirKind;
use regex_syntax::hir::Repetition;

use yara_x_parser::ast;

use crate::utils::cast;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct HexByte {
    pub value: u8,
    pub mask: u8,
}

impl From<ast::HexByte> for HexByte {
    fn from(hex_byte: ast::HexByte) -> Self {
        Self { value: hex_byte.value, mask: hex_byte.mask }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct ChainedPattern {
    pub gap: RangeInclusive<u32>,
    pub hir: Hir,
}

/// High level intermediate representation (HIR) for a regular expression.
///
/// This is a thin wrapper around [`regex_syntax::hir::Hir`] that implements
/// some YARA-specific functionality.
#[derive(Clone, Eq, Debug)]
pub(crate) struct Hir {
    pub(super) inner: regex_syntax::hir::Hir,
    /// Indicates whether the regexp is all greedy (`Some(true)`), all
    /// non-greedy (`Some(false)`), or has a mixture of greedy and non-greedy
    /// quantifiers (`None`).
    pub(super) greedy: Option<bool>,
}

impl Hash for Hir {
    fn hash<H: Hasher>(&self, state: &mut H) {
        regex_syntax::hir::visit(&self.inner, HirHasher { state }).unwrap();
    }
}

impl PartialEq for Hir {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl From<regex_syntax::hir::Hir> for Hir {
    fn from(value: regex_syntax::hir::Hir) -> Self {
        Self { inner: value, greedy: None }
    }
}

impl Hir {
    /// Pattern chaining is the process of splitting a pattern that contains very
    /// large gaps (a.k.a. jumps) into multiple pieces that are chained together.
    ///
    /// For example, when matching the pattern `{ 01 02 03 [0-2000] 04 05 06 }` is
    /// more efficient if we split it into two patterns `{ 01 02 03}` and
    /// `{ 04 05 06 }`, while the latter is chained to the former in order to make
    /// sure that `{ 01 02 03}` won't match if `{ 04 05 06 }` doesn't appear at the
    /// correct distance after `{ 01 02 03}`.
    ///
    /// Both `{ 01 02 03}` and `{ 04 05 06 }` are handled as if they were separate
    /// patterns, except that they are chained together.
    ///
    /// [`PATTERN_CHAINING_THRESHOLD`] controls how large the gap (or jump)
    /// must be in order split the pattern at that point. Gaps shorter than this
    /// value don't cause the splitting of the pattern.
    const PATTERN_CHAINING_THRESHOLD: u32 = 200;

    /// Controls the minimum allowed length for chained patterns. When splitting
    /// a pattern into a chain of smaller patterns, every piece in the chain
    /// must be larger than [`MIN_PATTERN_LENGTH_IN_CHAIN`]. For instance,
    /// pattern `{ 01 02 [0-2000] 03 }` won't be split at `[0-2000]` into
    /// `{01 02}` and `{ 03 }`, because `{ 03 }` is too short for being an
    /// independent pattern.
    const MIN_PATTERN_LENGTH_IN_CHAIN: usize = 2;

    /// Splits a pattern into multiple pieces if it contains gaps that are larger
    /// than [`PATTERN_CHAINING_THRESHOLD`]. Notice that this only applies to
    /// gaps that can contain any arbitrary character, therefore a regexp like
    /// `/abc.*xyz/` can not be split into `abc` and `xyz` because the `.*`
    /// matches any character except newlines. However, if the `/s` suffix (i.e:
    /// `dot_matches_new_line` is true) is added to the regexp, then `.*` will
    /// match anything, and the regexp will be split.
    ///
    /// Receives the HIR for the original pattern and returns a tuple where the
    /// first item corresponds to the leading piece of the original pattern, and
    /// the second item is a vector with zero o more items, corresponding to each
    /// remaining piece.
    ///
    /// For example, for pattern `{ 01 02 03 [-] 04 05 06 [-] 07 08 09 }` the
    /// first item in the tuple is the HIR for `{ 01 02 03 }`, while the second
    /// item is a vector containing two entries, one for `{ 04 05 06 }` and the
    /// other for `{ 07 08 09 }`.
    ///
    /// If the pattern doesn't contain any gap that is long enough, the pattern
    /// won't be split, and the leading piece will contain the whole pattern
    /// while the vector will be empty.
    ///
    /// Each pattern in the final chain is guaranteed to match at least
    /// [`MIN_PATTERN_LENGTH_IN_CHAIN`] bytes. The original pattern won't be
    /// split at points where the resulting sub-patterns are very short. For
    /// instance, `{ 01 02 [0-2000] 03 }` is not split because `{ 03 }` would
    /// be too short.
    pub fn split_at_large_gaps(self) -> (Self, Vec<ChainedPattern>) {
        if !matches!(self.kind(), HirKind::Concat(_)) {
            return (self, vec![]);
        }

        let greedy = self.greedy;
        let mut gap_min = 0;
        let mut gap_max = None;
        let mut gap_greedy = false;
        let mut chunks = Vec::new();
        let mut chain = Vec::new();

        for item in cast!(self.into_kind(), HirKind::Concat) {
            if let HirKind::Repetition(rep) = item.kind() {
                let num_repetitions =
                    rep.max.unwrap_or(u32::MAX).saturating_sub(rep.min);

                if !chunks.is_empty()
                    && num_repetitions > Self::PATTERN_CHAINING_THRESHOLD
                    && any_byte(rep.sub.as_ref().kind())
                {
                    let hir: Hir = Hir::concat(chunks).set_greedy(greedy);
                    if hir.minimum_len().unwrap_or(0)
                        >= Self::MIN_PATTERN_LENGTH_IN_CHAIN
                    {
                        chain.push(ChainedPattern {
                            gap: gap_min..=gap_max.unwrap_or(u32::MAX),
                            hir,
                        });
                        gap_min = rep.min;
                        gap_max = rep.max;
                        gap_greedy = rep.greedy;
                        chunks = Vec::new();
                    } else {
                        chunks = vec![hir, item.into()];
                    }
                } else {
                    chunks.push(item.into());
                }
            } else {
                chunks.push(item.into())
            }
        }

        if chunks.is_empty() {
            return (chain.remove(0).hir, chain);
        }

        let hir = Hir::concat(chunks).set_greedy(greedy);

        if chain.is_empty()
            || hir.minimum_len().unwrap_or(0)
                >= Self::MIN_PATTERN_LENGTH_IN_CHAIN
        {
            chain.push(ChainedPattern {
                gap: gap_min..=gap_max.unwrap_or(u32::MAX),
                hir,
            });
        } else {
            let mut last = chain.pop().unwrap();

            last.hir = Hir::concat(vec![
                last.hir,
                Hir::any_byte_repetition(gap_min, gap_max, gap_greedy),
                hir,
            ])
            .set_greedy(greedy);

            chain.push(last);
        }

        (chain.remove(0).hir, chain)
    }

    pub fn set_greedy(mut self, greediness: Option<bool>) -> Self {
        self.greedy = greediness;
        self
    }

    #[inline]
    pub fn is_greedy(&self) -> Option<bool> {
        self.greedy
    }

    #[inline]
    pub fn kind(&self) -> &HirKind {
        self.inner.kind()
    }

    #[inline]
    pub fn into_kind(self) -> HirKind {
        self.inner.into_kind()
    }

    #[inline]
    pub fn into_inner(self) -> regex_syntax::hir::Hir {
        self.inner
    }

    /// Returns the length (in bytes) of the smallest string matched by this HIR.
    ///
    /// A return value of `0` is possible and occurs when the HIR can match an
    /// empty string.
    ///
    /// `None` is returned when there is no minimum length. This occurs in
    /// precisely the cases where the HIR matches nothing. i.e., The language
    /// the regex matches is empty. An example of such a regex is `\P{any}`.
    #[inline]
    pub fn minimum_len(&self) -> Option<usize> {
        self.inner.properties().minimum_len()
    }

    /// Returns true if this HIR is either a simple literal or an alternation
    /// of simple literals.
    ///
    /// For example, `f`, `foo`, `(a|b|c)` and `(foo|bar|baz)` are alternation
    /// literals. This also includes capture groups that contain a literal or
    /// alternation of literals, like for example `(f)`, `(foo)`, `(a|b|c)`,
    /// and `(foo|bar|baz)`.
    #[inline]
    pub fn is_alternation_literal(&self) -> bool {
        // self.inner.properties().is_alternation_literal() can return true
        // when the HIR is a concat of literals or alternation of literals,
        // but that's not what we want and return false in those cases.
        if self.inner.properties().is_alternation_literal()
            && !matches!(self.inner.kind(), HirKind::Concat(_))
        {
            return true;
        }
        match self.inner.kind() {
            HirKind::Capture(cap) => {
                cap.sub.properties().is_alternation_literal()
                    && !matches!(cap.sub.kind(), HirKind::Concat(_))
            }
            _ => false,
        }
    }

    /// If the HIR represents a regular expression that can be reduced
    /// to a literal sequence of bytes, returns the bytes.
    pub fn as_literal_bytes(&self) -> Option<&[u8]> {
        match self.inner.kind() {
            HirKind::Literal(literal) => Some(literal.0.as_bytes()),
            _ => None,
        }
    }
}

impl Hir {
    #[cfg(test)]
    pub fn literal<B: Into<Box<[u8]>>>(lit: B) -> Hir {
        regex_syntax::hir::Hir::literal(lit).into()
    }

    /// Returns the concatenation of the given expressions.
    pub fn concat(subs: Vec<Hir>) -> Hir {
        regex_syntax::hir::Hir::concat(
            subs.into_iter().map(|s| s.inner).collect(),
        )
        .into()
    }

    /// Returns an expression that is a repetition of any byte
    /// that repeats at least `min` times and at most `max` time, w
    pub fn any_byte_repetition(
        min: u32,
        max: Option<u32>,
        greedy: bool,
    ) -> Hir {
        regex_syntax::hir::Hir::repetition(Repetition {
            min,
            max,
            greedy,
            sub: Box::new(regex_syntax::hir::Hir::dot(Dot::AnyByte)),
        })
        .into()
    }
}

struct HirHasher<'a, H: Hasher> {
    state: &'a mut H,
}

impl<'a, H: Hasher> regex_syntax::hir::Visitor for HirHasher<'a, H> {
    type Output = ();
    type Err = ();

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(())
    }

    fn visit_pre(
        &mut self,
        hir: &regex_syntax::hir::Hir,
    ) -> Result<(), Self::Err> {
        mem::discriminant(hir.kind()).hash(self.state);
        match hir.kind() {
            HirKind::Literal(lit) => {
                lit.0.hash(self.state);
            }
            HirKind::Class(class) => {
                mem::discriminant(class).hash(self.state);
                match class {
                    Class::Unicode(class) => {
                        for range in class.ranges() {
                            range.start().hash(self.state);
                            range.end().hash(self.state);
                        }
                    }
                    Class::Bytes(class) => {
                        for range in class.ranges() {
                            range.start().hash(self.state);
                            range.end().hash(self.state);
                        }
                    }
                }
            }
            HirKind::Repetition(rep) => {
                rep.min.hash(self.state);
                rep.max.hash(self.state);
                rep.greedy.hash(self.state);
            }
            HirKind::Empty => {}
            HirKind::Look(_) => {}
            HirKind::Capture(_) => {}
            HirKind::Concat(_) => {}
            HirKind::Alternation(_) => {}
        }

        Ok(())
    }
}

/// Returns true if `hir_kind` is a byte class containing all possible bytes.
///
/// For example `??` in an hex pattern, or `.` in a regexp that uses the `/s`
/// modifier (i.e: `dot_matches_new_line` is true).
pub fn any_byte(hir_kind: &HirKind) -> bool {
    match hir_kind {
        HirKind::Class(Class::Bytes(class)) => {
            if let Some(range) = class.ranges().first() {
                range.start() == 0 && range.end() == u8::MAX
            } else {
                false
            }
        }
        HirKind::Class(Class::Unicode(class)) => {
            if let Some(range) = class.ranges().first() {
                range.start() == 0 as char && range.end() == char::MAX
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Returns true if `hir_kind` is a byte class containing all possible bytes
/// except newline.
///
/// For example `.` in a regexp that doesn't use the `/s` modifier
/// (i.e: `dot_matches_new_line` is false).
pub fn any_byte_except_newline(hir_kind: &HirKind) -> bool {
    match hir_kind {
        HirKind::Class(Class::Bytes(class)) => {
            // The class must contain two ranges, one that contains all bytes
            // in the range 0x00-0x09, and the other that contains all bytes
            // in the range 0x0B-0xFF. Only 0x0A (ASCII code for line-feed) is
            // excluded.
            let all_bytes_except_newline = ClassBytes::new([
                ClassBytesRange::new(0x00, 0x09),
                ClassBytesRange::new(0x0B, 0xFF),
            ]);
            all_bytes_except_newline.eq(class)
        }
        HirKind::Class(Class::Unicode(class)) => {
            let all_bytes_except_newline = ClassUnicode::new([
                ClassUnicodeRange::new(0x00 as char, 0x09 as char),
                ClassUnicodeRange::new(0x0B as char, char::MAX),
            ]);
            all_bytes_except_newline.eq(class)
        }
        _ => false,
    }
}

/// Returns [`Some(HexByte)`] if the given [`ClassBytes`] represents a
/// masked byte.
///
/// This function basically does the opposite than [`hex_byte_to_class`].
/// However, not all the classes represent a masked byte, in such cases
/// this function returns [`None`].
pub fn class_to_masked_byte(c: &ClassBytes) -> Option<HexByte> {
    if c.ranges().is_empty() {
        return None;
    }

    // Get the smallest and largest bytes in the class. The ranges are
    // guaranteed to be sorted, so the smallest byte is the one that
    // starts the first range and the largest byte is the one that ends
    // the last range.
    let smallest_byte = c.ranges().first().unwrap().start();
    let largest_byte = c.ranges().last().unwrap().end();

    // In a class that represents a masked hex byte, we can compute the mask
    // by XORing the largest byte and the smallest one. The smallest byte
    // corresponds to the byte with all the masked bits set to 0, and the
    // largest byte is the byte with all the masked bits set to 1. For
    // example, in `3?`, the smallest byte is `30` and the largest one is
    // `3F`, by xoring the two we get `0x0F`.
    let neg_mask = largest_byte ^ smallest_byte;

    // This will hold the number of bytes in the class.
    let mut num_bytes: u32 = 0;

    for range in c.ranges().iter() {
        // Make sure that a bitwise AND between all bytes in the class and
        // the smallest byte is equal to the smallest one.
        for b in range.start()..=range.end() {
            if b & smallest_byte != smallest_byte {
                return None;
            }
        }
        num_bytes += range.len() as u32;
    }

    // The class must have 2^N bytes, where N is the number of 1s in the
    // negated mask, if not, this is not a masked byte. For instance, if the
    // negated mask is `0000 1111`, it means that the bits that are set to 1
    // can have an arbitrary value in the byte, so possible bytes are
    // `0000 0001`, `0000 0010`, `0000 0011`, up to `0000 1111`. Therefore,
    // the number of possible bytes is 2^4 (16).
    if 1 << neg_mask.count_ones() != num_bytes {
        return None;
    }

    Some(HexByte { value: smallest_byte, mask: !neg_mask })
}

pub fn class_to_masked_bytes_alternation(
    c: &ClassBytes,
) -> Option<Vec<HexByte>> {
    if c.ranges().is_empty() {
        return None;
    }
    let mut result = Vec::new();
    for range in c.ranges() {
        if range.start() & range.end() != range.start() {
            return None;
        }
        let neg_mask = range.start() ^ range.end();
        let num_bytes = (range.end() - range.start()) + 1;
        if 1 << neg_mask.count_ones() != num_bytes {
            return None;
        }
        result.push(HexByte { value: range.start(), mask: !neg_mask });
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::Hir;
    use crate::re::hir::ChainedPattern;

    #[test]
    fn split() {
        assert_eq!(
            Hir::literal([0x01, 0x02, 0x03]).split_at_large_gaps(),
            (Hir::literal([0x01, 0x02, 0x03]), vec![])
        );

        assert_eq!(
            // Input
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::literal([0x06, 0x07]),
            ])
            // Output
            .split_at_large_gaps(),
            (
                Hir::concat(vec![
                    Hir::literal([0x01, 0x02, 0x03]),
                    Hir::literal([0x06, 0x07])
                ]),
                vec![]
            )
        );

        // Check that the pattern is not split when the jump is small.
        assert_eq!(
            // Input
            Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::any_byte_repetition(
                    0,
                    Some(Hir::PATTERN_CHAINING_THRESHOLD),
                    false
                ),
                Hir::literal([0x02, 0x03]),
            ])
            // Output
            .split_at_large_gaps(),
            (
                Hir::concat(vec![
                    // Input
                    Hir::literal([0x01]),
                    Hir::any_byte_repetition(
                        0,
                        Some(Hir::PATTERN_CHAINING_THRESHOLD),
                        false
                    ),
                    Hir::literal([0x02, 0x03]),
                ]),
                vec![]
            )
        );

        // Check that the pattern is split when the jump is large.
        assert_eq!(
            // Input
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::any_byte_repetition(0, None, false),
                Hir::literal([0x05]),
                Hir::any_byte_repetition(
                    10,
                    Some(11 + Hir::PATTERN_CHAINING_THRESHOLD),
                    false
                ),
                Hir::literal([0x06, 0x07]),
            ])
            .split_at_large_gaps(),
            // Output
            (
                Hir::literal([0x01, 0x02, 0x03]),
                vec![ChainedPattern {
                    gap: 0..=u32::MAX,
                    hir: Hir::concat(vec![
                        Hir::literal([0x05]),
                        Hir::any_byte_repetition(
                            10,
                            Some(11 + Hir::PATTERN_CHAINING_THRESHOLD),
                            false
                        ),
                        Hir::literal([0x06, 0x07])
                    ])
                }]
            )
        );

        // Do not split because the trailing fragment ([0x05]) is too short.
        assert_eq!(
            // Input
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::any_byte_repetition(0, None, false),
                Hir::literal([0x05]),
            ])
            .split_at_large_gaps(),
            // Output
            (
                Hir::concat(vec![
                    Hir::literal([0x01, 0x02, 0x03]),
                    Hir::any_byte_repetition(0, None, false),
                    Hir::literal([0x05]),
                ]),
                vec![]
            )
        );

        // Check that the pattern is split when the jump is greedy.
        assert_eq!(
            // Input
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::any_byte_repetition(0, None, true),
                Hir::literal([0x04, 0x05]),
            ])
            .split_at_large_gaps(),
            // Output
            (
                Hir::literal([0x01, 0x02, 0x03]),
                vec![ChainedPattern {
                    gap: 0..=u32::MAX,
                    hir: Hir::literal([0x04, 0x05])
                },]
            )
        );

        // If the pattern starts with a jump, it is not split
        assert_eq!(
            // Input
            Hir::concat(vec![
                Hir::any_byte_repetition(0, None, true),
                Hir::literal([0x04, 0x05]),
            ])
            .split_at_large_gaps(),
            // Output
            (
                Hir::concat(vec![
                    Hir::any_byte_repetition(0, None, true),
                    Hir::literal([0x04, 0x05]),
                ]),
                vec![]
            )
        );
    }
}
