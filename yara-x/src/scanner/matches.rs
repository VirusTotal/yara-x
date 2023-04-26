use core::slice::Iter;
use std::ops::Range;

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
/// The matches are kept sorted by starting offset in ascending order.
#[derive(Debug, Default)]
pub struct MatchList {
    matches: Vec<Match>,
}

impl MatchList {
    pub fn new() -> Self {
        Self { matches: Vec::new() }
    }

    /// Adds a new match to the list while keeping the matches sorted by
    /// start offset in ascending order.
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
    pub fn add(&mut self, m: Match) {
        let mut insertion_index = self.matches.len();

        while insertion_index > 0 {
            if m.range.start >= self.matches[insertion_index - 1].range.start {
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
    pub fn iter(&self) -> Iter<'_, Match> {
        self.matches.iter()
    }
}

#[cfg(test)]
mod test {
    use crate::scanner::matches::{Match, MatchList};
    use std::ops::Range;

    #[test]
    fn match_list() {
        let mut ml = MatchList::new();

        ml.add(Match { range: (2..10), xor_key: None });
        ml.add(Match { range: (1..10), xor_key: None });
        ml.add(Match { range: (4..10), xor_key: None });
        ml.add(Match { range: (3..10), xor_key: None });
        ml.add(Match { range: (5..10), xor_key: None });
        ml.add(Match { range: (5..9), xor_key: None });

        assert_eq!(
            ml.iter().map(|m| m.range.clone()).collect::<Vec<Range<usize>>>(),
            vec![(1..10), (2..10), (3..10), (4..10), (5..10), (5..9)]
        )
    }
}
