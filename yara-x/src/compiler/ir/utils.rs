use regex_syntax::hir::HirKind::Concat;
use regex_syntax::hir::{Class, Hir, HirKind};
use std::ops::RangeInclusive;

#[derive(Debug, PartialEq)]
pub struct TrailingPattern {
    pub gap: RangeInclusive<u32>,
    pub hir: Hir,
}

/// Pattern chaining is the process of splitting a pattern that contains very
/// large gaps (a.k.a jumps) into multiple pieces that are chained together.
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
/// [`PATTERN_CHAINING_THRESHOLD`] controls the how large the gap (or jump)
/// must be in order split the pattern at that point. Gaps shorter than this
/// value don't cause the splitting of the pattern.
const PATTERN_CHAINING_THRESHOLD: u32 = 200;

/// Splits a pattern into multiple pieces if it contains gaps that are larger
/// than [`PATTERN_CHAINING_THRESHOLD`]. Notice that these gaps must be
/// non-greedy, so it doesn't apply to regexps like `/abc.*xyz/s` because `.*`
/// is greedy, but it applies to the non-greedy `/abc.*?xyz/s`. Also notice
/// that only regexps with the `/s` modifier (i.e: `dot_matches_new_line` is
/// true) will be split. In regexps without this modifier `.*?` can not contain
/// newlines, and therefore is not a real gap that contain anything.
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
pub(in crate::compiler) fn split_at_large_gaps(
    hir: Hir,
) -> (Hir, Vec<TrailingPattern>) {
    if !matches!(hir.kind(), Concat(_)) {
        return (hir, vec![]);
    }

    let mut heading = None;
    let mut trailing = Vec::new();

    let mut push = |gap: Option<RangeInclusive<u32>>, fragment| {
        if let Some(gap) = gap {
            trailing.push(TrailingPattern { gap, hir: Hir::concat(fragment) });
        } else {
            heading = Some(Hir::concat(fragment));
        }
    };

    let items = if let Concat(items) = hir.into_kind() {
        items
    } else {
        unreachable!()
    };

    let mut prev_gap = None;
    let mut pattern_chunk = Vec::new();

    for item in items {
        if let HirKind::Repetition(repetition) = item.kind() {
            let max_gap = repetition.max.unwrap_or(u32::MAX) - repetition.min;
            if max_gap > PATTERN_CHAINING_THRESHOLD
                && !repetition.greedy
                && any_byte(repetition.sub.as_ref())
            {
                push(prev_gap, pattern_chunk);
                prev_gap =
                    Some(repetition.min..=repetition.max.unwrap_or(u32::MAX));

                pattern_chunk = Vec::new();
            } else {
                pattern_chunk.push(item);
            }
        } else {
            pattern_chunk.push(item)
        }
    }

    push(prev_gap, pattern_chunk);

    (heading.unwrap(), trailing)
}

/// Returns true if `hir` is a byte class containing all possible bytes.
///
/// For example `??` in an hex pattern, or `.` in a regexp that uses the `/s`
/// modifier (i.e: `dot_matches_new_line` is true).
fn any_byte(hir: &Hir) -> bool {
    match hir.kind() {
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

#[cfg(test)]
mod tests {
    use crate::compiler::ir::utils::{
        TrailingPattern, PATTERN_CHAINING_THRESHOLD,
    };
    use pretty_assertions::assert_eq;
    use regex_syntax::hir::{Dot, Hir, Repetition};

    #[test]
    fn split() {
        assert_eq!(
            super::split_at_large_gaps(Hir::literal([0x01, 0x02, 0x03])),
            (Hir::literal([0x01, 0x02, 0x03]), vec![])
        );

        assert_eq!(
            super::split_at_large_gaps(Hir::concat(vec![
                // Input
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::literal([0x06, 0x07]),
            ])),
            (
                // Output
                Hir::concat(vec![
                    Hir::literal([0x01, 0x02, 0x03]),
                    Hir::literal([0x06, 0x07])
                ]),
                vec![]
            )
        );

        // Check that the pattern is not split when the jump is small.
        assert_eq!(
            super::split_at_large_gaps(Hir::concat(vec![
                // Input
                Hir::literal([0x01]),
                Hir::repetition(Repetition {
                    min: 0,
                    max: Some(PATTERN_CHAINING_THRESHOLD),
                    greedy: false,
                    sub: Box::new(Hir::dot(Dot::AnyByte)),
                }),
                Hir::literal([0x02, 0x03]),
            ])),
            (
                // Output
                Hir::concat(vec![
                    // Input
                    Hir::literal([0x01]),
                    Hir::repetition(Repetition {
                        min: 0,
                        max: Some(PATTERN_CHAINING_THRESHOLD),
                        greedy: false,
                        sub: Box::new(Hir::dot(Dot::AnyByte)),
                    }),
                    Hir::literal([0x02, 0x03]),
                ]),
                vec![]
            )
        );

        // Check that the pattern is not split when the jump is greedy.
        assert_eq!(
            super::split_at_large_gaps(Hir::concat(vec![
                // Input
                Hir::literal([0x01]),
                Hir::repetition(Repetition {
                    min: 0,
                    max: Some(2 * PATTERN_CHAINING_THRESHOLD),
                    greedy: true,
                    sub: Box::new(Hir::dot(Dot::AnyByte)),
                }),
                Hir::literal([0x02, 0x03]),
            ])),
            (
                // Output
                Hir::concat(vec![
                    // Input
                    Hir::literal([0x01]),
                    Hir::repetition(Repetition {
                        min: 0,
                        max: Some(2 * PATTERN_CHAINING_THRESHOLD),
                        greedy: true,
                        sub: Box::new(Hir::dot(Dot::AnyByte)),
                    }),
                    Hir::literal([0x02, 0x03]),
                ]),
                vec![]
            )
        );

        // Check that the pattern is split when the jump is large.
        assert_eq!(
            super::split_at_large_gaps(Hir::concat(vec![
                // Input
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::repetition(Repetition {
                    min: 0,
                    max: None,
                    greedy: false,
                    sub: Box::new(Hir::dot(Dot::AnyByte)),
                }),
                Hir::literal([0x05]),
                Hir::repetition(Repetition {
                    min: 10,
                    max: Some(11 + PATTERN_CHAINING_THRESHOLD),
                    greedy: false,
                    sub: Box::new(Hir::dot(Dot::AnyByte)),
                }),
                Hir::literal([0x06, 0x07]),
            ])),
            (
                // Output
                Hir::literal([0x01, 0x02, 0x03]),
                vec![
                    TrailingPattern {
                        gap: 0..=u32::MAX,
                        hir: Hir::literal([0x05])
                    },
                    TrailingPattern {
                        gap: 10..=11 + PATTERN_CHAINING_THRESHOLD,
                        hir: Hir::literal([0x06, 0x07])
                    }
                ]
            )
        );
    }
}
