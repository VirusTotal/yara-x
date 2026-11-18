use bitvec::vec::BitVec;

use crate::re::DEFAULT_SCAN_LIMIT;

/// An insertion-ordered set of `usize` byte positions backed by a flat bitmap.
///
/// Used by [`crate::re::fast::FastVM`] to track active candidate byte offsets
/// without hashing or heap-allocating auxiliary sets on duplicate insertions.
#[derive(Debug, Default)]
pub(crate) struct PositionSet {
    items: Vec<usize>,
    bitmap: BitVec<usize>,
}

impl PositionSet {
    /// Creates an empty [`PositionSet`] pre-sized for `0..=DEFAULT_SCAN_LIMIT`.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            bitmap: BitVec::repeat(false, DEFAULT_SCAN_LIMIT as usize + 1),
        }
    }

    /// Inserts `pos` into the set if it is not already present.
    ///
    /// Returns `true` if `pos` was newly inserted, or `false` if it was
    /// already in the set.
    #[inline]
    pub fn insert(&mut self, pos: usize) -> bool {
        if pos >= self.bitmap.len() {
            self.grow(pos);
        }
        // SAFETY: `pos < self.bitmap.len()` is guaranteed by the check above.
        unsafe {
            if *self.bitmap.get_unchecked(pos) {
                return false;
            }
            self.bitmap.set_unchecked(pos, true);
        }
        self.items.push(pos);
        true
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, pos: usize) {
        let new_len = (pos + 1).checked_next_power_of_two().unwrap_or(pos + 1);
        self.bitmap.resize(new_len, false);
    }

    /// Removes all positions from the set while retaining allocated capacity.
    #[inline]
    pub fn clear(&mut self) {
        for pos in self.items.drain(..) {
            // SAFETY: every `pos` stored in `self.items` grew `self.bitmap`
            // to at least `pos + 1` upon insertion.
            unsafe {
                self.bitmap.set_unchecked(pos, false);
            }
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterates over the positions in insertion order.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, usize> {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::PositionSet;

    #[test]
    fn preserves_insertion_order_and_deduplicates() {
        let mut s = PositionSet::new();
        assert!(s.is_empty());

        assert!(s.insert(10));
        assert!(s.insert(3));
        assert!(s.insert(5000));
        assert!(s.insert(0));

        // Duplicate insertions return false and do not alter order.
        assert!(!s.insert(10));
        assert!(!s.insert(3));
        assert!(!s.insert(5000));
        assert!(!s.insert(0));

        let collected: Vec<usize> = s.iter().copied().collect();
        assert_eq!(collected, vec![10, 3, 5000, 0]);

        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.iter().count(), 0);

        // Reuse after clear, including offsets beyond the legacy 512 KiB cap.
        assert!(s.insert(600_000));
        assert!(s.insert(10));
        assert!(!s.insert(600_000));
        let collected: Vec<usize> = s.iter().copied().collect();
        assert_eq!(collected, vec![600_000, 10]);
    }
}
