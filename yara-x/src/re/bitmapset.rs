use bitvec::vec::BitVec;

/// A high-performance set of `usize` values.
///
/// As in any set, the values are guaranteed to be unique, the `insert`
/// operation is a no-op if the new value already exists in the set.
/// Additionally, this type supports iterating the values in insertion order.
///
/// The distinguishing feature of this set lies in its utilization of bitmaps
/// for efficient membership checks. However, practical limitations prevent
/// having a bitmap with one bit per possible `usize` value, spanning from 0 to
/// `usize::MAX`. Instead, positions in the bitmap are determined relative to
/// the initial value inserted in the set. For instance, if the first value is
/// `1234`, the first bitmap bit corresponds to `1234`, the second to `1235`,
/// the third to `1236`, and so on. A separate bitmap is maintained for values
/// lower than the initial one, with `1233` represented as the first bit in
/// this other bitmap. Both bitmaps dynamically expand to accommodate newly
/// inserted values.
///
/// `BitmapSet` works well with values that are close to each other. Outliers
/// can make the memory required for storing the bitmaps to grow very quickly.
/// Another property of this type is that values inserted in the set can be
/// iterated in insertion order.
#[derive(Debug, PartialEq, Default)]
pub(crate) struct BitmapSet {
    // Vector that contains the values in the set, in insertion order.
    values: Vec<usize>,
    // First value inserted in the set.
    initial_value: usize,
    // Bitmap for values that are > initial_value.
    p_bitmap: BitVec<usize>,
    // Bitmap for values that are < initial_value.
    n_bitmap: BitVec<usize>,
}

impl BitmapSet {
    pub const MAX_OFFSET: usize = 524288;

    pub fn new() -> Self {
        Self {
            values: Vec::new(),
            initial_value: 0,
            p_bitmap: BitVec::repeat(false, 1024),
            n_bitmap: BitVec::repeat(false, 1024),
        }
    }

    /// Adds a value to the set.
    ///
    /// Returns `true` if the value didn't exist in the set and was added, and
    /// `false` if the value already existed.
    ///
    /// # Panics
    ///
    /// If `value` is too far from the first value added to the set.
    /// Specifically, it panics when `abs(value - initial_value) >= MAX_OFFSET`
    ///
    #[inline]
    pub fn insert(&mut self, value: usize) -> bool {
        // Special case when the set is totally empty.
        if self.values.is_empty() {
            self.initial_value = value;
            self.values.push(value);
            return true;
        }
        // Special case where the new value is equal to the first value
        // added to the set. We don't need to spare a bit on this value.
        if self.initial_value == value {
            return false;
        }

        let offset = value as isize - self.initial_value as isize;

        match offset {
            offset if offset < 0 => {
                let offset = -offset as usize;
                unsafe {
                    if self.n_bitmap.len() <= offset {
                        assert!(offset < Self::MAX_OFFSET);
                        self.n_bitmap.resize(offset + 1, false);
                        self.n_bitmap.set_unchecked(offset, true);
                        self.values.push(value);
                        true
                    } else if !*self.n_bitmap.get_unchecked(offset) {
                        self.n_bitmap.set_unchecked(offset, true);
                        self.values.push(value);
                        true
                    } else {
                        false
                    }
                }
            }
            offset => {
                // At this point `offset` cannot be zero, it's safe to subtract
                // 1 so that the first bit in the `p_bitmap` is used.
                let offset = offset as usize - 1;
                unsafe {
                    if self.p_bitmap.len() <= offset {
                        assert!(offset < Self::MAX_OFFSET);
                        self.p_bitmap.resize(offset + 1, false);
                        self.p_bitmap.set_unchecked(offset, true);
                        self.values.push(value);
                        true
                    } else if !*self.p_bitmap.get_unchecked(offset) {
                        self.p_bitmap.set_unchecked(offset, true);
                        self.values.push(value);
                        true
                    } else {
                        false
                    }
                }
            }
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Removes all values in the set.
    #[inline]
    pub fn clear(&mut self) {
        for thread in self.values.drain(0..) {
            let offset = thread as isize - self.initial_value as isize;
            match offset {
                offset if offset > 0 => {
                    self.p_bitmap.set((offset - 1) as usize, false);
                }
                offset if offset < 0 => {
                    self.n_bitmap.set((-offset) as usize, false);
                }
                _ => {
                    // when `offset` is 0 there's no bit to clear, the initial
                    // value doesn't have a bit in neither of the bitmaps.
                }
            }
        }
    }

    /// Returns an iterator for the items in the set.
    ///
    /// Items are returned in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &usize> {
        self.values.iter()
    }

    #[cfg(test)]
    pub fn into_vec(self) -> Vec<usize> {
        self.values
    }
}

#[cfg(test)]
mod tests {
    use super::BitmapSet;

    #[test]
    fn thread_set() {
        let mut s = BitmapSet::new();

        assert!(s.insert(4));
        assert!(s.insert(2));
        assert!(s.insert(10));
        assert!(s.insert(0));
        assert!(s.insert(2000));

        assert!(!s.insert(4));
        assert!(!s.insert(2));
        assert!(!s.insert(10));
        assert!(!s.insert(0));
        assert!(!s.insert(2000));

        assert_eq!(s.values, vec![4, 2, 10, 0, 2000]);

        s.clear();

        assert!(s.insert(200));
        assert!(s.insert(2));
        assert!(s.insert(10));
        assert!(s.insert(300));
        assert!(s.insert(250));

        assert_eq!(s.values, vec![200, 2, 10, 300, 250]);
    }
}
