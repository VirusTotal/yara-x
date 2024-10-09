use bitvec::vec::BitVec;
use rustc_hash::FxHashSet;
use std::hash::Hash;

/// A high-performance set of (`usize`, T) pairs.
///
/// As in any set, the pairs are guaranteed to be unique, the `insert`
/// operation is a no-op if the new pair already exists in the set.
/// Additionally, this type supports iterating the pairs in insertion order.
///
/// The distinguishing feature of this set lies in its utilization of bitmaps
/// for checking if the `usize` key in a pair already exists in the set.
/// However, practical limitations prevent having a bitmap with one bit per
/// possible `usize` value, spanning from 0 to `usize::MAX`. Instead, positions
/// in the bitmap are determined relative to the initial key inserted in the
/// set. For instance, if the first value is (`1234`, T), the first bitmap bit
/// corresponds to key `1234`, the second to key `1235`, the third to key
/// `1236`, and so on. A separate bitmap is maintained for keys lower than
/// the initial one, with `1233` represented as the first bit in this other
/// bitmap. Both bitmaps dynamically expand to accommodate newly inserted
/// values.
///
/// `BitmapSet` works well with keys that are close to each other. Outliers
/// can make the memory required for storing the bitmaps to grow very quickly.
/// Another property of this type is that values inserted in the set can be
/// iterated in insertion order.
#[derive(Debug, Default)]
pub(crate) struct BitmapSet<T>
where
    T: Default + Copy + PartialEq + Eq + Hash,
{
    // Vector that contains the (key,value) pairs in the set, in insertion
    // order.
    items: Vec<(usize, T)>,
    // Set that contains the (key,value) pairs.
    set: FxHashSet<(usize, T)>,
    // Bitmap for keys that are > initial_key.
    p_bitmap: BitVec<usize>,
    // Bitmap for keys that are < initial_key.
    n_bitmap: BitVec<usize>,
}

impl<T> BitmapSet<T>
where
    T: Default + Copy + PartialEq + Eq + Hash,
{
    pub const MAX_OFFSET: usize = 524288;

    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            set: FxHashSet::default(),
            p_bitmap: BitVec::repeat(false, 1024),
            n_bitmap: BitVec::repeat(false, 1024),
        }
    }

    /// Adds a (key,value) pair to the set.
    ///
    /// Returns `true` if the (key,value) pair didn't exist in the map and was
    /// added, and `false` if the pair already existed.
    ///
    /// # Panics
    ///
    /// If `key` is too far from the first key added to the set.
    /// Specifically, it panics when `abs(key - initial_key) >= MAX_OFFSET`
    ///
    #[inline]
    pub fn insert(&mut self, key: usize, value: T) -> bool {
        let first = match self.items.first() {
            Some(first) => first,
            None => {
                // The set is empty, store the first item and return.
                self.items.push((key, value));
                return true;
            }
        };

        // Special case when the new (key,value) pair is equal to the
        // first one added to the set.
        if first.0 == key && first.1 == value {
            return false;
        }

        let offset = key as isize - first.0 as isize;

        match offset {
            offset if offset < 0 => {
                let offset = (-offset as usize) - 1;
                unsafe {
                    if self.n_bitmap.len() <= offset {
                        assert!(offset < Self::MAX_OFFSET);
                        self.n_bitmap.resize(offset + 1, false);
                        self.n_bitmap.set_unchecked(offset, true);
                        self.items.push((key, value));
                        self.set.insert((key, value))
                    } else if !*self.n_bitmap.get_unchecked(offset) {
                        self.n_bitmap.set_unchecked(offset, true);
                        self.items.push((key, value));
                        self.set.insert((key, value))
                    } else if self.set.insert((key, value)) {
                        self.items.push((key, value));
                        true
                    } else {
                        false
                    }
                }
            }
            offset => {
                let offset = offset as usize;
                unsafe {
                    if self.p_bitmap.len() <= offset {
                        assert!(offset < Self::MAX_OFFSET);
                        self.p_bitmap.resize(offset + 1, false);
                        self.p_bitmap.set_unchecked(offset, true);
                        self.items.push((key, value));
                        self.set.insert((key, value))
                    } else if !*self.p_bitmap.get_unchecked(offset) {
                        self.p_bitmap.set_unchecked(offset, true);
                        self.items.push((key, value));
                        self.set.insert((key, value))
                    } else if self.set.insert((key, value)) {
                        self.items.push((key, value));
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
        self.items.is_empty()
    }

    /// Removes all values in the set.
    #[inline]
    pub fn clear(&mut self) {
        let first_key = match self.items.first() {
            Some(first) => first.0,
            None => return,
        };
        for (key, _) in self.items.drain(0..) {
            let offset = key as isize - first_key as isize;
            match offset {
                offset if offset < 0 => {
                    self.n_bitmap.set(((-offset) as usize) - 1, false);
                }
                offset => {
                    self.p_bitmap.set(offset as usize, false);
                }
            }
        }
        self.set.clear();
    }

    /// Returns an iterator for the items in the set.
    ///
    /// Items are returned in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &(usize, T)> {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::BitmapSet;

    #[test]
    fn thread_set() {
        let mut s = BitmapSet::new();

        assert!(s.insert(4, 0));
        assert!(s.insert(2, 0));
        assert!(s.insert(3, 0));
        assert!(s.insert(10, 0));
        assert!(s.insert(0, 0));
        assert!(s.insert(2000, 0));

        assert!(!s.insert(4, 0));
        assert!(!s.insert(2, 0));
        assert!(!s.insert(3, 0));
        assert!(!s.insert(10, 0));
        assert!(!s.insert(0, 0));
        assert!(!s.insert(2000, 0));
        assert!(s.insert(4, 1));
        assert!(!s.insert(4, 1));

        assert_eq!(
            s.items,
            vec![(4, 0), (2, 0), (3, 0), (10, 0), (0, 0), (2000, 0), (4, 1)]
        );

        s.clear();

        assert_eq!(s.p_bitmap.count_ones(), 0);
        assert_eq!(s.n_bitmap.count_ones(), 0);

        assert!(s.insert(200, 0));
        assert!(s.insert(3, 0));
        assert!(s.insert(10, 0));
        assert!(s.insert(300, 0));
        assert!(s.insert(250, 0));

        assert_eq!(
            s.items,
            vec![(200, 0), (3, 0), (10, 0), (300, 0), (250, 0)]
        );
    }
}
