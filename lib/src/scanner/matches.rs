use std::collections::hash_map::Entry;
use std::ops::{Range, RangeInclusive};

use core::slice::{Iter, IterMut};
use rustc_hash::FxHashMap;

use crate::compiler::PatternId;
use crate::re::hir::ChainedPatternGap;

/// Represents the match of a pattern.
#[derive(Debug, Clone)]
pub(crate) struct Match {
    /// Range within the scanned data where the match occurred. Notice that
    /// this is an absolute range, in other words: in block scanning this
    /// range is not relative to the block where the match occurred, it is
    /// relative to the start of the data.
    pub range: Range<usize>,
    /// For patterns that have the `xor` modifier this is always `Some(k)`
    /// where `k` is the XOR key (it may be 0). For any other type of
    /// pattern this is `None`.
    pub xor_key: Option<u8>,
}

impl Match {
    #[inline]
    pub fn new(range: Range<usize>) -> Self {
        Self { range, xor_key: None }
    }

    /// Creates a [`Match`] from a block-relative `range` and the block's
    /// starting `base` offset.
    #[inline]
    pub fn with_base(base: usize, range: Range<usize>) -> Self {
        Self { range: (range.start + base)..(range.end + base), xor_key: None }
    }

    /// Sets the xor key for the match.
    #[inline]
    pub fn xor_key(mut self, key: u8) -> Self {
        self.xor_key = Some(key);
        self
    }
}

/// Represents the list of matches for a pattern.
///
/// The matches are kept sorted by starting offset in ascending order. Two
/// different matches can't have the same starting offset.
#[derive(Debug, Default)]
pub(crate) struct MatchList {
    matches: Vec<Match>,
}

impl MatchList {
    /// Creates a new [`MatchList`] that can hold at least `capacity` items
    /// without relocating. The capacity will increase if [`MatchList::add`]
    /// is called and there's no capacity to store the new item.
    pub fn with_capacity(capacity: usize) -> Self {
        Self { matches: Vec::with_capacity(capacity) }
    }

    /// Adds a new match to the list while keeping the matches sorted by
    /// start offset in ascending order. If a match at the same offset already
    /// exits, and the length of the new match is longer than the existing one,
    /// the old match will be replaced if `replace_if_longer` is true. If it
    /// is false, the existing match will remain untouched and the new one will
    /// be ignored.
    ///
    /// Returns `true` if a new match was added to the list, or `false` if an
    /// existing match was updated or ignored.
    ///
    /// This operation is O(1) in the most common case, which is inserting
    /// the new match at an offset that is higher than those from previous
    /// matches.
    pub fn add(&mut self, new_match: Match, replace_if_longer: bool) -> bool {
        matches!(
            self.add_with_limit(new_match, usize::MAX, replace_if_longer),
            AddResult::Inserted(_)
        )
    }

    /// Adds a new match to the list while enforcing an upper bound on the
    /// total number of matches.
    ///
    /// If a match at the same start offset already exists, it is updated in
    /// place (when `replace_if_longer` is `true` and `new_match` is longer) or
    /// ignored without increasing the list length, even when `self.len()` has
    /// already reached `max_matches`.
    pub fn add_with_limit(
        &mut self,
        new_match: Match,
        max_matches: usize,
        replace_if_longer: bool,
    ) -> AddResult {
        match self.matches.last_mut() {
            // The new match starts at some offset greater than the offset of
            // the last match, we can simply push the new match at the end.
            Some(last) if new_match.range.start > last.range.start => {
                if self.matches.len() >= max_matches {
                    return AddResult::MaxMatchesReached;
                }
                self.matches.push(new_match);
                AddResult::Inserted(self.matches.len())
            }
            // The new match starts has the same offset as the last match. We
            // only need to update its end position when replace_if_longer is
            // true and the new match is actually longer than the existing one.
            Some(last) if new_match.range.start == last.range.start => {
                if replace_if_longer && last.range.end < new_match.range.end {
                    last.range.end = new_match.range.end;
                    AddResult::Updated { extended: true }
                } else {
                    AddResult::Updated { extended: false }
                }
            }
            // No matches so far, the match is first one.
            None => {
                if max_matches == 0 {
                    return AddResult::MaxMatchesReached;
                }
                self.matches.push(new_match);
                AddResult::Inserted(1)
            }
            _ => {
                // If not at the end, use binary search to find the insertion point.
                match self
                    .matches
                    .binary_search_by_key(&new_match.range.start, |m| {
                        m.range.start
                    }) {
                    // Found, and replace_if_longer is true.
                    Ok(index) if replace_if_longer => {
                        let existing_match = &mut self.matches[index];
                        if existing_match.range.end < new_match.range.end {
                            existing_match.range.end = new_match.range.end;
                            AddResult::Updated { extended: true }
                        } else {
                            AddResult::Updated { extended: false }
                        }
                    }
                    // Found, but replace_if_longer is false, do nothing and keep the
                    // existing match.
                    Ok(_) => AddResult::Updated { extended: false },
                    // Not found, insert at the corresponding position.
                    Err(index) => {
                        if self.matches.len() >= max_matches {
                            return AddResult::MaxMatchesReached;
                        }
                        self.matches.insert(index, new_match);
                        AddResult::Inserted(self.matches.len())
                    }
                }
            }
        }
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<&Match> {
        self.matches.get(i)
    }

    /// Returns the number of matches that start within the given range.
    pub fn matches_in_range(&self, range: RangeInclusive<i64>) -> i64 {
        let start = *range.start();
        let end = *range.end();

        // If the end of the range is negative there can't be any matches in
        // that range.
        if end.is_negative() {
            return 0;
        }

        // If start is negative, make it 0. No match can exist in the range
        // (-X,0).
        let start = start.max(0);

        // Convert to usize, saturating to `usize::MAX` if the value is
        // larger.
        let start: usize = start.try_into().unwrap_or(usize::MAX);
        let end: usize = end.try_into().unwrap_or(usize::MAX);

        // Find the index of the match that starts at `start`, or the index
        // where it should be. Any match starting at some offset >= `start`,
        // must be located at `index` or higher in the matches array.
        // Notice that the fact that two matches can't have the same starting
        // offset is very helpful in this case. Because of this, we don't need
        // to take into account matches at `index-1`, `index-2`, etc. Otherwise,
        // we would like to take into account matches at those indexes because
        // the `search` function does not guarantee that it returns the *first*
        // match with a given offset, but *any* match with that offset.
        match self.search(start) {
            Ok(index) | Err(index) => {
                let mut count = 0;
                for m in &self.matches.as_slice()[index..] {
                    if (start..=end).contains(&m.range.start) {
                        count += 1;
                    } else {
                        break;
                    }
                }
                count
            }
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.matches.capacity()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.matches.clear()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_, Match> {
        self.matches.iter()
    }

    /// Searches for a match that starts at the given offset.
    ///
    /// If a match starting at `offset` is found, then [`Ok`] is returned
    /// containing the index of the match. If no match is found, then [`Err`]
    /// is returned, containing the index where the match would be located.
    ///
    /// This operation is O(log(N)) because it takes advantage of the fact
    /// that matches are sorted by starting offset and uses a binary search
    /// internally.
    ///
    /// The list can't contain two matches with the same starting offset,
    /// but if that would be the case this function doesn't guarantee that
    /// it returns the *first* match with given offset, but *any* match
    /// with that offset.
    #[inline]
    pub fn search(&self, offset: usize) -> Result<usize, usize> {
        self.matches.binary_search_by(|m| m.range.start.cmp(&offset))
    }
}

impl<'a> IntoIterator for &'a MatchList {
    type Item = &'a Match;
    type IntoIter = Iter<'a, Match>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Clone)]
pub struct UnconfirmedMatch {
    pub range: Range<usize>,
    pub chain_length: usize,
}

/// Collection of unconfirmed matches for a chained sub-pattern, along with
/// the minimum and maximum `range.end` offsets across all stored matches for
/// O(1) distance pre-filtering.
pub(crate) struct UnconfirmedMatches {
    matches: Vec<UnconfirmedMatch>,
    min_end: usize,
    max_end: usize,
}

impl Default for UnconfirmedMatches {
    #[inline]
    fn default() -> Self {
        Self { matches: Vec::new(), min_end: usize::MAX, max_end: 0 }
    }
}

impl UnconfirmedMatches {
    #[inline]
    pub fn push(&mut self, m: UnconfirmedMatch) {
        self.min_end = self.min_end.min(m.range.end);
        self.max_end = self.max_end.max(m.range.end);
        self.matches.push(m);
    }

    #[cfg(feature = "logging")]
    #[inline]
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, UnconfirmedMatch> {
        self.matches.iter_mut()
    }

    /// Returns true if any stored match ends within `gap` bytes before some
    /// offset in `start_range`.
    ///
    /// Let `start_range` be `min_start..=max_start`. For a stored match `m`
    /// ending at `end = m.range.end`, the valid start offsets for the next
    /// sub-pattern in the chain form the interval `[end + gap_min, +inf)`
    /// ([`ChainedPatternGap::Unbounded`]) or `[end + gap_min, end + gap_max]`
    /// ([`ChainedPatternGap::Bounded`]). `start_range` contains a valid offset
    /// for `m` iff the two intervals intersect:
    ///
    /// ```text
    ///   valid starts for m:   [end + gap_min ..= end + gap_max]
    ///   candidate starts:                [min_start ..= max_start]
    ///                                    ^^^^^^^^^^ intersection
    /// ```
    ///
    /// Two closed intervals `[a, b]` and `[c, d]` intersect iff `b >= c` and
    /// `a <= d`, evaluated without risking `end + gap_*` overflow as:
    ///
    /// 1. `max_start >= end + gap_min`, checked via
    ///    `max_start.checked_sub(end).is_some_and(|d| d >= gap_min)`.
    /// 2. `min_start <= end + gap_max`, checked via
    ///    `min_start.saturating_sub(end) <= gap_max` (when `min_start <= end`,
    ///    `saturating_sub` yields `0 <= gap_max`, which always holds).
    ///
    /// # Complexity
    ///
    /// * [`ChainedPatternGap::Unbounded`]: always **O(1)** via `self.min_end`.
    /// * [`ChainedPatternGap::Bounded`]: **O(1)** whenever `start_range` falls
    ///   outside the aggregate envelope `[self.min_end + gap_min,
    ///   self.max_end + gap_max]` or when `self.min_end == self.max_end`
    ///   (including the common single-match case). Only when multiple matches
    ///   have distinct `end` offsets and `start_range` falls inside their
    ///   combined envelope—where it might still land in an uncovered "hole"
    ///   between two widely separated matches—does this scan `self.matches`
    ///   (in reverse order, since recent matches are closest during a
    ///   left-to-right scan).
    #[inline]
    pub fn has_match_within_gap(
        &self,
        start_range: RangeInclusive<usize>,
        gap: &ChainedPatternGap,
    ) -> bool {
        if self.matches.is_empty() {
            return false;
        }

        let min_start = *start_range.start();
        let max_start = *start_range.end();
        debug_assert!(min_start <= max_start);

        match gap {
            ChainedPatternGap::Unbounded(range) => {
                let gap_min = range.start as usize;
                // Because `self.min_end` is the exact `range.end` of at least
                // one stored match, a start offset in `min_start..=max_start`
                // can satisfy `start >= m.range.end + gap_min` if and only if
                // `max_start` satisfies it for `self.min_end`.
                max_start
                    .checked_sub(self.min_end)
                    .is_some_and(|max_gap| max_gap >= gap_min)
            }
            ChainedPatternGap::Bounded(range) => {
                let gap_min = *range.start() as usize;
                let gap_max = *range.end() as usize;

                if gap_min > gap_max {
                    return false;
                }

                // O(1) rejection if even the earliest match end is not far
                // enough before `max_start` to satisfy `gap_min`.
                if max_start
                    .checked_sub(self.min_end)
                    .is_none_or(|max_gap| max_gap < gap_min)
                {
                    return false;
                }

                // O(1) rejection if even the latest match end is too far
                // behind `min_start` to satisfy `gap_max`.
                if min_start.saturating_sub(self.max_end) > gap_max {
                    return false;
                }

                // Fast path when all stored matches end at the same offset
                // (including the common single-match case): the two envelope
                // checks above already establish a valid gap in `start_range`.
                if self.min_end == self.max_end {
                    return true;
                }

                // Check recent matches first, as nearby head matches during a
                // left-to-right scan sit at the end of `self.matches`.
                self.matches.iter().rev().any(|m| {
                    max_start.checked_sub(m.range.end).is_some_and(
                        |max_actual_gap| {
                            max_actual_gap >= gap_min
                                && min_start.saturating_sub(m.range.end)
                                    <= gap_max
                        },
                    )
                })
            }
        }
    }
}

impl<'a> IntoIterator for &'a mut UnconfirmedMatches {
    type Item = &'a mut UnconfirmedMatch;
    type IntoIter = IterMut<'a, UnconfirmedMatch>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.matches.iter_mut()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddResult {
    /// A new match was inserted into the list, growing it to the given length.
    Inserted(usize),
    /// An existing match at the same start offset was either extended in place
    /// (`extended == true`) or left unchanged (`extended == false`).
    Updated { extended: bool },
    /// Pattern has reached `max_matches_per_pattern` limit and the match was rejected.
    MaxMatchesReached,
}

/// A hash map that tracks matches for each pattern.
///
/// Each key in this map is a [`PatternId`], and its associated value is a
/// [`MatchList`] that contains the matches found for the pattern.
///
/// Each pattern is limited to a maximum number of matches that may be
/// configured.
pub(crate) struct PatternMatches {
    matches: FxHashMap<PatternId, MatchList>,
    max_matches_per_pattern: usize,
    capacity: usize,
}

impl PatternMatches {
    /// The maximum number of matches accepted for each pattern by default.
    const DEFAULT_MAX_MATCHES_PER_PATTERN: usize = 1_000_000;

    pub fn new() -> Self {
        Self {
            matches: FxHashMap::default(),
            max_matches_per_pattern: Self::DEFAULT_MAX_MATCHES_PER_PATTERN,
            capacity: 0,
        }
    }

    /// Sets the maximum number of matches per pattern.
    ///
    /// The default value is [`Self::DEFAULT_MAX_MATCHES_PER_PATTERN`].
    pub fn max_matches_per_pattern(&mut self, n: usize) -> &mut Self {
        self.max_matches_per_pattern = n;
        self
    }

    /// Returns the list of matches for a given pattern.
    pub fn get(&self, pattern_id: PatternId) -> Option<&MatchList> {
        self.matches.get(&pattern_id)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Clears the matches for all patterns.
    ///
    /// To optimize performance, the memory allocated for storing matches
    /// is not released every time this function is invoked. Instead, the
    /// allocated memory is retained and reused in subsequent scans. However,
    /// due to the potential volume of patterns and matches, persistently
    /// holding onto this memory can result in a significant memory footprint.
    /// When the total capacity of stored data exceeds a defined threshold,
    /// memory is deallocated to manage resource usage efficiently.
    pub fn clear(&mut self) {
        // If the capacity goes above a certain threshold, completely
        // clear the matches, which frees the memory associated to the
        // list of matches. If not, clear the list of matches, but maintain
        // the memory allocated for them.
        if self.capacity > 10000 {
            self.matches.clear();
            self.capacity = 0;
        } else {
            for matches in self.matches.values_mut() {
                matches.clear();
            }
        }
    }

    /// Adds a new match to the pattern identified by the given [`PatternId`]
    ///
    /// If a match at the same offset already exists, the `replace_if_longer`
    /// argument indicates what to do. If this argument is `true` and the new
    /// match is longer than the existing one, the existing match will be
    /// replaced. If the argument is `false` the new match will be ignored and
    /// the existing one will remain.
    ///
    /// Returns [`AddResult`] indicating whether a new match was inserted, an
    /// existing match was updated, or the maximum match limit was reached.
    pub fn add(
        &mut self,
        pattern_id: PatternId,
        m: Match,
        replace_if_longer: bool,
    ) -> AddResult {
        if self.max_matches_per_pattern == 0 {
            return AddResult::MaxMatchesReached;
        }

        match self.matches.entry(pattern_id) {
            Entry::Occupied(mut entry) => {
                let matches = entry.get_mut();
                self.capacity -= matches.capacity();
                let res = matches.add_with_limit(
                    m,
                    self.max_matches_per_pattern,
                    replace_if_longer,
                );
                self.capacity += matches.capacity();
                res
            }
            Entry::Vacant(entry) => {
                let mut matches = MatchList::with_capacity(8);
                self.capacity += matches.capacity();
                matches.add(m, replace_if_longer);
                let len = matches.len();
                entry.insert(matches);
                AddResult::Inserted(len)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::scanner::matches::{
        AddResult, Match, MatchList, PatternMatches,
    };
    use std::ops::Range;

    #[test]
    fn match_list() {
        let mut ml = MatchList::with_capacity(5);

        ml.add(Match::new(2..10), false);
        ml.add(Match::new(1..10), false);
        ml.add(Match::new(1..15), true);
        ml.add(Match::new(4..10), false);
        ml.add(Match::new(3..10), false);
        ml.add(Match::new(5..10), false);

        assert_eq!(
            ml.iter().map(|m| m.range.clone()).collect::<Vec<Range<usize>>>(),
            vec![(1..15), (2..10), (3..10), (4..10), (5..10)]
        )
    }

    #[test]
    fn match_list_growth() {
        let mut ml = MatchList::with_capacity(10_000);
        for i in 0..10_000 {
            ml.add(Match::new(i..i + 1), false);
        }
        assert_eq!(ml.len(), 10_000);
    }

    #[test]
    fn pattern_matches_growth() {
        use crate::compiler::PatternId;
        let mut pm = PatternMatches::new();
        let pid = PatternId::from(0);
        for i in 0..10_000 {
            pm.add(pid, Match::new(i..i + 1), false);
        }
        assert_eq!(pm.get(pid).unwrap().len(), 10_000);

        let mut pm = PatternMatches::new();
        pm.max_matches_per_pattern(2);
        assert_eq!(
            pm.add(pid, Match::new(2..5), true),
            AddResult::Inserted(1)
        );
        assert_eq!(
            pm.add(pid, Match::new(10..12), true),
            AddResult::Inserted(2)
        );
        // Extending the last match in place at capacity must succeed.
        assert_eq!(
            pm.add(pid, Match::new(10..18), true),
            AddResult::Updated { extended: true }
        );
        // Extending an earlier match via binary search at capacity must succeed.
        assert_eq!(
            pm.add(pid, Match::new(2..9), true),
            AddResult::Updated { extended: true }
        );
        // Shorter match at an existing offset is ignored without error.
        assert_eq!(
            pm.add(pid, Match::new(2..4), true),
            AddResult::Updated { extended: false }
        );
        // New start offsets (both after the end and in the middle) are rejected.
        assert_eq!(
            pm.add(pid, Match::new(20..22), true),
            AddResult::MaxMatchesReached
        );
        assert_eq!(
            pm.add(pid, Match::new(6..8), true),
            AddResult::MaxMatchesReached
        );
        assert_eq!(
            pm.get(pid)
                .unwrap()
                .iter()
                .map(|m| m.range.clone())
                .collect::<Vec<_>>(),
            vec![2..9, 10..18]
        );

        let mut pm = PatternMatches::new();
        pm.max_matches_per_pattern(0);
        assert_eq!(
            pm.add(pid, Match::new(0..4), true),
            AddResult::MaxMatchesReached
        );
        assert!(pm.get(pid).is_none());
    }

    #[test]
    fn unconfirmed_matches_gap_lookup() {
        use crate::re::hir::ChainedPatternGap;
        use crate::scanner::matches::{UnconfirmedMatch, UnconfirmedMatches};

        let bounded = ChainedPatternGap::Bounded(5..=10);
        let unbounded = ChainedPatternGap::Unbounded(5..);

        // Empty set never matches, even at usize::MAX.
        let mut um = UnconfirmedMatches::default();
        assert!(!um.has_match_within_gap(0..=100, &bounded));
        assert!(!um.has_match_within_gap(usize::MAX..=usize::MAX, &unbounded));

        // Single match ending at 20 (`min_end == max_end` fast path).
        um.push(UnconfirmedMatch { range: 10..20, chain_length: 0 });
        assert!(!um.has_match_within_gap(15..=24, &bounded));
        assert!(um.has_match_within_gap(15..=25, &bounded));
        assert!(um.has_match_within_gap(30..=30, &bounded));
        assert!(um.has_match_within_gap(30..=40, &bounded));
        assert!(!um.has_match_within_gap(31..=40, &bounded));
        assert!(!um.has_match_within_gap(24..=24, &unbounded));
        assert!(um.has_match_within_gap(25..=25, &unbounded));
        assert!(um.has_match_within_gap(1_000_000..=1_000_000, &unbounded));

        // Non-monotonic `range.end`: push a long match `22..100` followed by a
        // shorter match `25..30`. A tail at `105` must still match `22..100`
        // (`105 - 100 == 5` in `5..=10`), while a gap hole `40..=90` must fail.
        um.push(UnconfirmedMatch { range: 22..100, chain_length: 0 });
        um.push(UnconfirmedMatch { range: 25..30, chain_length: 0 });
        assert!(!um.has_match_within_gap(41..=94, &bounded));
        assert!(um.has_match_within_gap(105..=105, &bounded));
        assert!(um.has_match_within_gap(90..=105, &bounded));
        assert!(!um.has_match_within_gap(111..=120, &bounded));

        // Large u32::MAX gap bounds do not overflow `usize`.
        let max_gap = ChainedPatternGap::Bounded(u32::MAX..=u32::MAX);
        assert!(!um.has_match_within_gap(100..=1000, &max_gap));
    }
}
