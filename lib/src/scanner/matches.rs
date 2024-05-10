use crate::compiler::PatternId;
use core::slice::Iter;
use rustc_hash::FxHashMap;
use std::collections::hash_map::Entry;
use std::ops::{Range, RangeInclusive};

/// Represents the match of a pattern.
#[derive(Debug, Clone)]
pub struct Match {
    /// Range within the scanned data where the match was found.
    pub range: Range<usize>,
    /// For patterns that have the `xor` modifier this is always `Some(k)`
    /// where `k` is the XOR key (it may be 0). For any other type of
    /// pattern this is `None`.
    pub xor_key: Option<u8>,
}

/// Represents the list of matches for a pattern.
///
/// The matches are kept sorted by starting offset in ascending order. Two
/// different matches can't have the same starting offset.
#[derive(Debug, Default)]
pub struct MatchList {
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
    /// This operation is O(n), where the worst case is adding a new match
    /// with a start offset that is lower than all the other matches in the
    /// list. This would require moving all the elements one position to the
    /// right, making space for the new match at offset 0.
    ///
    /// However, in most cases new matches will be added in roughly ascending
    /// order, which means that the operation will be the best possible case,
    /// when the new match has a start offset larger or equal than the last
    /// match in the list.
    pub fn add(&mut self, m: Match, replace_if_longer: bool) {
        let mut insertion_index = self.matches.len();

        while insertion_index > 0 {
            let existing_match = &mut self.matches[insertion_index - 1];
            if m.range.start == existing_match.range.start {
                // We have found another match that start at same offset, than
                // the new match. Replace the existing match if the new one is
                // longer and `replace_if_longer` is true.
                if replace_if_longer && existing_match.range.end < m.range.end
                {
                    existing_match.range.end = m.range.end;
                }
                return;
            }
            // The match just before `insertion_index` starts at some offset
            // that is lower than the match being inserted, so this is the
            // final insertion index.
            if m.range.start > existing_match.range.start {
                break;
            }
            insertion_index -= 1;
        }

        if insertion_index == self.matches.len() {
            self.matches.push(m);
        } else {
            self.matches.insert(insertion_index, m);
        }
    }

    #[inline]
    pub fn remove(&mut self, i: usize) -> Match {
        self.matches.remove(i)
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<&Match> {
        self.matches.get(i)
    }

    /// Returns the number of matches that start within the given range.
    pub fn matches_in_range(&self, range: RangeInclusive<isize>) -> i64 {
        // If the end of the range is negative there can't be any matches in
        // that range.
        if range.end().is_negative() {
            return 0;
        }

        let start: usize = (*range.start()).try_into().unwrap_or(0);
        let end: usize = (*range.end()).try_into().unwrap();

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
    pub fn first(&self) -> Option<&Match> {
        self.matches.first()
    }

    #[inline]
    pub fn as_slice(&self) -> &[Match] {
        self.matches.as_slice()
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
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    #[inline]
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.matches.shrink_to(min_capacity)
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
        self.matches.binary_search_by(|x| x.range.start.cmp(&offset))
    }
}

impl<'a> IntoIterator for &'a MatchList {
    type Item = &'a Match;
    type IntoIter = Iter<'a, Match>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct UnconfirmedMatch {
    pub range: Range<usize>,
    pub chain_length: usize,
}

/// A hash map that tracks matches for each pattern.
///
/// Each key in this map is a [`PatternId`], and its associated value is a
/// [`MatchList`] that contains the matches found for the pattern.
///
/// Each pattern is limited to a maximum number of matches that may be
/// configured.
pub struct PatternMatches {
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
            for (_, matches) in self.matches.iter_mut() {
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
    /// This function returns `true` if the new match was added, or `false`
    /// if the pattern already reached the maximum number of matches and
    /// therefore the new match was not added.
    pub fn add(
        &mut self,
        pattern_id: PatternId,
        m: Match,
        replace_if_longer: bool,
    ) -> bool {
        match self.matches.entry(pattern_id) {
            Entry::Occupied(mut entry) => {
                let matches = entry.get_mut();
                if matches.len() < self.max_matches_per_pattern {
                    self.capacity -= matches.capacity();
                    matches.add(m, replace_if_longer);
                    self.capacity += matches.capacity();
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(entry) => {
                let mut matches = MatchList::with_capacity(8);
                self.capacity += matches.capacity();
                matches.add(m, replace_if_longer);
                entry.insert(matches);
                true
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::scanner::matches::{Match, MatchList};
    use std::ops::Range;

    #[test]
    fn match_list() {
        let mut ml = MatchList::with_capacity(5);

        ml.add(Match { range: (2..10), xor_key: None }, false);
        ml.add(Match { range: (1..10), xor_key: None }, false);
        ml.add(Match { range: (4..10), xor_key: None }, false);
        ml.add(Match { range: (3..10), xor_key: None }, false);
        ml.add(Match { range: (5..10), xor_key: None }, false);

        assert_eq!(
            ml.iter().map(|m| m.range.clone()).collect::<Vec<Range<usize>>>(),
            vec![(1..10), (2..10), (3..10), (4..10), (5..10)]
        )
    }
}
