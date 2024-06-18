use std::cmp::{min, Ordering};
use std::collections::VecDeque;
use std::iter;
use std::iter::zip;
use std::ops::{Range, Sub};

use bitvec::array::BitArray;
use regex_syntax::hir::literal::Seq;

use crate::compiler::{Atom, DESIRED_ATOM_SIZE};

/// Given an iterator of pairs (byte, mask) finds the best possible atom
/// that can be extracted from that iterator.
struct BestAtomFinder<'a, I>
where
    I: Iterator<Item = (&'a u8, &'a u8)>,
{
    index: usize,
    base_quality: i32,
    best_quality: i32,
    best_range: Option<Range<usize>>,
    queue: VecDeque<(usize, u8, u8, i32)>,
    bytes_present: BitArray<[u64; 4]>,
    byte_mask_iter: I,
}

impl<'a, I> BestAtomFinder<'a, I>
where
    I: Iterator<Item = (&'a u8, &'a u8)>,
{
    pub fn new(byte_mask_iter: I) -> Self {
        Self {
            byte_mask_iter,
            index: 0,
            base_quality: 0,
            best_quality: i32::MIN,
            best_range: None,
            queue: VecDeque::with_capacity(DESIRED_ATOM_SIZE),
            bytes_present: Default::default(),
        }
    }

    pub fn find(mut self) -> (Option<Range<usize>>, i32) {
        while let Some((byte, mask)) = self.byte_mask_iter.next() {
            if self.queue.len() == self.queue.capacity() {
                self.pop();
            }
            self.push(*byte, *mask);
        }
        while !self.queue.is_empty() {
            self.pop();
        }
        (self.best_range, self.best_quality)
    }

    #[inline]
    fn pop(&mut self) {
        let (_, _, _, q) = self.queue.pop_front().unwrap();
        self.base_quality -= q;

        let quality = self.quality();

        if quality > self.best_quality {
            self.best_quality = quality;
            self.best_range = Some(
                self.queue.front().unwrap().0
                    ..self.queue.back().unwrap().0 + 1,
            );
        }
    }

    #[inline]
    fn push(&mut self, byte: u8, mask: u8) {
        // The quality of the new byte is initially 0.
        let mut q = 0;
        // If there's any masked bit, the quality is incremented by N * 2 - M,
        // where N is the number of non-masked bits and M is the number of
        // masked bits. For ?? the increment is -8, while ?X and X? results in
        // a +4 increment.
        if mask.count_zeros() > 0 {
            q += 2 * mask.count_ones() as i32 - mask.count_zeros() as i32;
        }
        // For non-masked bytes the increment depends on the byte value.
        // Common values like 0x00, 0xff, 0xcc (opcode using of function
        // padding in PE files), 0x20 (whitespace) the increment is a bit
        // lower than for other bytes.
        else {
            match byte {
                // Common values contribute less to the quality than the
                // rest of values.
                0x20 | 0x90 | 0xcc | 0xff => {
                    q += 12;
                }
                // Zeroes are specially bad and contribute less.
                0x00 => {
                    q += 6;
                }
                // Bytes in the ASCII ranges a-z and A-Z have a slightly
                // lower quality than the rest. We want to favor atoms that
                // don't contain too many letters, as they generate less
                // additional atoms when the `nocase` modifier is used in
                // the pattern.
                b'a'..=b'z' | b'A'..=b'Z' => {
                    q += 18;
                }
                // General case.
                _ => {
                    q += 20;
                }
            }
        }

        self.queue.push_back((self.index, byte, mask, q));
        self.base_quality += q;
        self.index += 1;

        let quality = self.quality();
        if quality > self.best_quality {
            self.best_quality = quality;
            self.best_range = Some(
                self.queue.front().unwrap().0
                    ..self.queue.back().unwrap().0 + 1,
            );
        }
    }

    fn quality(&mut self) -> i32 {
        if self.queue.is_empty() {
            return i32::MIN;
        }

        self.bytes_present.fill(false);

        let mut unique_bytes = 0;

        for (_, byte, mask, _) in &self.queue {
            if *mask == 0xff
                && matches!(
                    self.bytes_present.get(*byte as usize).as_deref(),
                    Some(false)
                )
            {
                self.bytes_present.set(*byte as usize, true);
                unique_bytes += 1;
            }
        }

        // The base quality is used as the starting point, but it's boosted
        // or penalized according to the uniqueness of the bytes
        let mut q = self.base_quality;

        // If all the bytes in the atom are equal and very common, let's
        // penalize it heavily.
        if unique_bytes == 1 {
            // As the number of unique bytes is 1, the first one in
            // the queue corresponds to that unique byte.
            match self.queue.front().unwrap().1 {
                0x00 | 0x20 | 0x90 | 0xcc | 0xff => {
                    q -= 5;
                }
                _ => {
                    q += 2;
                }
            }
        }
        // In general, atoms with more unique bytes have better quality,
        // let's boost the quality proportionally to the number of unique
        // bytes.
        else {
            q += 2 * unique_bytes;
        }

        q
    }
}

/// Represents the quality of a set of atoms.
///
/// Instances of [`AtomsQuality`] are compared for determining which set of
/// atoms is better.
pub(crate) struct AtomsQuality {
    num_exact_atoms: usize,
    num_inexact_atoms: usize,
    min_atom_len: usize,
    min_atom_quality: i32,
    sum_atom_quality: i64,
}

impl AtomsQuality {
    fn new<I, T, F>(atoms: I, mut is_exact: F) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
        F: FnMut(&T) -> bool,
    {
        let mut num_inexact_atoms = 0;
        let mut num_exact_atoms = 0;
        let mut sum_quality = 0_i64;
        let mut min_quality = i32::MAX;
        let mut min_len = usize::MAX;

        for atom in atoms.into_iter() {
            if is_exact(&atom) {
                num_exact_atoms += 1;
            } else {
                num_inexact_atoms += 1;
            }
            let atom = atom.as_ref();
            let quality = atom_quality(atom);
            sum_quality = sum_quality.saturating_add(quality as i64);
            min_quality = min(min_quality, quality);
            min_len = min(min_len, atom.len());
        }

        Self {
            num_inexact_atoms,
            num_exact_atoms,
            min_atom_len: min_len,
            sum_atom_quality: sum_quality,
            min_atom_quality: min_quality,
        }
    }

    #[inline]
    pub fn from_seq(seq: &Seq) -> Self {
        AtomsQuality::new(seq.literals().unwrap_or(&[]), |lit| lit.is_exact())
    }

    #[inline]
    pub fn from_atoms<T: AsRef<[Atom]>>(atoms: T) -> Self {
        AtomsQuality::new(atoms.as_ref().iter(), |atom| atom.is_exact())
    }

    #[inline]
    pub fn num_atoms(&self) -> usize {
        self.num_exact_atoms + self.num_inexact_atoms
    }

    #[inline]
    pub fn avg_atom_quality(&self) -> f64 {
        self.sum_atom_quality as f64
            / (self.num_inexact_atoms + self.num_exact_atoms) as f64
    }

    pub fn merge(&mut self, other: Self) -> &mut Self {
        self.num_exact_atoms =
            self.num_exact_atoms.saturating_add(other.num_exact_atoms);

        self.num_inexact_atoms =
            self.num_inexact_atoms.saturating_add(other.num_inexact_atoms);

        self.sum_atom_quality =
            self.sum_atom_quality.saturating_add(other.sum_atom_quality);

        self.min_atom_len = min(self.min_atom_len, other.min_atom_len);

        self.min_atom_quality =
            min(self.min_atom_quality, other.min_atom_quality);

        self
    }

    #[inline]
    pub fn min() -> Self {
        Self {
            num_inexact_atoms: 0,
            num_exact_atoms: 0,
            min_atom_len: 0,
            min_atom_quality: i32::MIN,
            sum_atom_quality: i64::MIN,
        }
    }
}

impl PartialEq for AtomsQuality {
    fn eq(&self, other: &Self) -> bool {
        self.num_inexact_atoms == other.num_inexact_atoms
            && self.min_atom_len == other.min_atom_len
            && self.min_atom_quality == other.min_atom_quality
            && self.sum_atom_quality == other.sum_atom_quality
    }
}

impl Eq for AtomsQuality {}

impl PartialOrd<Self> for AtomsQuality {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AtomsQuality {
    fn cmp(&self, other: &Self) -> Ordering {
        // If the minimum atom length of set A is exactly 1 byte shorter than
        // the minimum atom length of set B, but set B has 256 times the number
        // of atoms of A, then A is better than B even if it has shorter atoms.
        // It's better to have a set with a single 3-bytes atom than a set with
        // 256 4-bytes atoms.
        if self.min_atom_len.abs_diff(other.min_atom_len) == 1 {
            // If `other` has 256 times the atoms of `self`, `self` is better,
            // except if the minimum atom quality of `self` is less than half
            // the quality of `other`.
            if self.num_atoms() > 0
                && self.num_atoms().saturating_mul(256) == other.num_atoms()
                && self.avg_atom_quality() * 2.0 >= other.avg_atom_quality()
            {
                return Ordering::Greater;
            }
            // If `self` has 256 times the atoms of `other`, `other` is better,
            // except if the minimum atom quality of `other` is less than half
            // the quality of `self`.
            if other.num_atoms() > 0
                && other.num_atoms().saturating_mul(256) == self.num_atoms()
                && other.avg_atom_quality() * 2.0 >= self.avg_atom_quality()
            {
                return Ordering::Less;
            }
        }

        // The most important criteria for determining if a set of atoms is
        // better than another one is the minimum atom quality. The minimum
        // atom quality is the quality of the worst atom in the set, and the
        // set with the highest minimum is the best.
        if self.min_atom_quality != other.min_atom_quality {
            return self.min_atom_quality.cmp(&other.min_atom_quality);
        }

        // If the minimum atom quality is the same, use the minimum atom length
        // as the criteria for determining which set is better. The set with
        // the longest atom is the best.
        if self.min_atom_len != other.min_atom_len {
            return self.min_atom_len.cmp(&other.min_atom_len);
        }

        // When the minimum atom quality and the minimum atom length are equal,
        // use the average atom quality for determining which set of atoms is
        // better.
        let quality_self = self.avg_atom_quality();
        let quality_other = other.avg_atom_quality();

        let quality_diff = quality_self.sub(quality_other).abs();

        // If the difference between the average atom quality of one set and
        // the other is large enough, the one with the highest average quality
        // is the better one.
        if quality_diff > 15.0 {
            return quality_self.total_cmp(&quality_other);
        }

        // If the difference between the average atom qualities is not large
        // enough use the number of atoms as the criteria for determining which
        // is the best set of atoms. The set with the lowest number of atoms
        // is better.
        if self.num_inexact_atoms != other.num_inexact_atoms {
            return other.num_inexact_atoms.cmp(&self.num_inexact_atoms);
        }

        other.num_exact_atoms.cmp(&self.num_exact_atoms)
    }
}

/// Returns the range for the best possible atom that can be extracted from
/// the slice and its quality.
pub(crate) fn best_range_in_bytes(
    bytes: &[u8],
) -> (Option<Range<usize>>, i32) {
    let mut best_quality = i32::MIN;
    let mut best_range = None;

    for i in 0..=bytes.len().saturating_sub(DESIRED_ATOM_SIZE) {
        let range = i..min(bytes.len(), i + DESIRED_ATOM_SIZE);
        let quality = atom_quality(&bytes[range.clone()]);
        if quality > best_quality {
            best_quality = quality;
            best_range = Some(range);
        }
    }

    (best_range, best_quality)
}

/// Returns the range for the best possible atom that can be extracted from the
/// masked slice.
#[allow(dead_code)]
pub(crate) fn best_range_in_masked_bytes(
    bytes: &[u8],
    mask: &[u8],
) -> (Option<Range<usize>>, i32) {
    BestAtomFinder::new(zip(bytes, mask)).find()
}

/// Returns the best possible atom from a slice of bytes.
///
/// The returned atom will have [`DESIRED_ATOM_SIZE`] bytes if possible, but it
/// can be shorter if the slice is shorter.
///
/// The atom's backtrack value will be equal to the position of the atom within
/// the slice. This means that once the atom is found, the reported offset will
/// correspond to the start of the slice in the data.
pub(crate) fn best_atom_in_bytes(bytes: &[u8]) -> Atom {
    let (range, _) = best_range_in_bytes(bytes);
    Atom::from_slice_range(bytes, range.unwrap())
}

/// Computes the quality of a masked atom.
#[cfg(test)]
pub fn masked_atom_quality<'a, B, M>(bytes: B, masks: M) -> i32
where
    B: IntoIterator<Item = &'a u8>,
    M: IntoIterator<Item = &'a u8>,
{
    BestAtomFinder::new(zip(bytes, masks)).find().1
}

/// Compute the quality of an atom.
#[inline]
pub fn atom_quality<'a, B>(bytes: B) -> i32
where
    B: IntoIterator<Item = &'a u8>,
{
    BestAtomFinder::new(zip(bytes, iter::repeat(&0xff))).find().1
}

#[cfg(test)]
mod test {
    use super::atom_quality;
    use crate::compiler::atoms::quality::masked_atom_quality;
    use crate::compiler::{atoms, AtomsQuality};
    use itertools::Itertools;
    use regex_syntax::hir::literal::Literal;
    use regex_syntax::hir::literal::Seq;

    #[rustfmt::skip]
    #[allow(non_snake_case)]
    #[test]
    fn test_atom_quality() {
        let q_01 = atom_quality(&[0x01]);
        let q_0001 = atom_quality(&[0x00, 0x01]);
        let q_000001 = atom_quality(&[0x00, 0x00, 0x01]);
        let q_0102 = atom_quality(&[0x01, 0x02]);
        let q_000102 = atom_quality(&[0x00, 0x01, 0x02]);
        let q_010203 = atom_quality(&[0x01, 0x02, 0x03]);
        let q_00000000 = atom_quality(&[0x00, 0x00, 0x00, 0x00]);
        let q_00000001 = atom_quality(&[0x00, 0x00, 0x00, 0x01]);
        let q_00000102 = atom_quality(&[0x00, 0x00, 0x01, 0x02]);
        let q_00010203 = atom_quality(&[0x00, 0x01, 0x02, 0x03]);
        let q_01020304 = atom_quality(&[0x01, 0x02, 0x03, 0x04]);
        let q_01010101 = atom_quality(&[0x01, 0x01, 0x01, 0x01]);
        let q_01020102 = atom_quality(&[0x01, 0x02, 0x01, 0x02]);
        let q_01020000 = atom_quality(&[0x01, 0x02, 0x00, 0x00]);
        let q_ffffffff = atom_quality(&[0xff, 0xff, 0xff, 0xff]);
        let q_cccccccc = atom_quality(&[0xcc, 0xcc, 0xcc, 0xcc]);
        let q_909090 = atom_quality(&[0x90, 0x90, 0x90]);
        let q_90909090 = atom_quality(&[0x90, 0x90, 0x90, 0x90]);
        let q_20202020 = atom_quality(&[0x20, 0x20, 0x20, 0x20]);
        let q_aa = atom_quality(b"aa");
        let q_ab = atom_quality(b"ab");
        let q_abcd = atom_quality(b"abcd");
        let q_ABCD = atom_quality(b"ABCD");
        let q_abc_dot = atom_quality(b"abc.");

        let q_01x203 = masked_atom_quality(
            [0x01, 0x02, 0x03].iter(),
            [0xff, 0x0f, 0xff].iter()
        );

        let q_010x03 = masked_atom_quality(
            [0x01, 0x02, 0x03].iter(),
            [0xff, 0xf0, 0xff].iter()
        );

        let q_01xx03 = masked_atom_quality(
            [0x01, 0x02, 0x03].iter(),
            [0xff, 0x00, 0xff].iter()
        );

        let q_010x0x = masked_atom_quality(
            [0x01, 0x02, 0x03].iter(),
            [0xff, 0xf0, 0xf0].iter()
        );

        let q_0102xx04 = masked_atom_quality(
            [0x01, 0x02, 0x03, 0x04].iter(),
            [0xff, 0xff, 0x00, 0xff].iter(),
        );
        
        assert!(q_00000001 > q_00000000);
        assert!(q_00000001 > q_000001);
        assert!(q_000001 > q_0001);
        assert!(q_00000102 > q_00000001);
        assert!(q_00010203 > q_00000102);
        assert!(q_01020304 > q_00010203);
        assert!(q_000102 > q_000001);
        assert!(q_00010203 > q_010203);
        assert!(q_010203 > q_0102);
        assert!(q_010203 > q_00000000);
        assert!(q_010203 > q_90909090);
        assert!(q_0102 > q_90909090);
        assert!(q_909090 > q_01);
        assert!(q_0102 > q_01);
        assert!(q_01x203 > q_0102);
        assert!(q_01x203 > q_0001);
        assert!(q_01x203 < q_010203);
        assert_eq!(q_01x203, q_010x03);
        assert_eq!(q_cccccccc, q_ffffffff);
        assert_eq!(q_cccccccc, q_90909090);
        assert_eq!(q_cccccccc, q_20202020);
        assert!(q_01xx03 <= q_0102);
        assert!(q_01xx03 < q_010x03);
        assert!(q_01xx03 < q_010203);
        assert!(q_010x0x > q_01);
        assert!(q_010x0x < q_010203);
        assert_eq!(q_01020000, q_0102xx04);
        assert!(q_01020102 > q_01020000);
        assert!(q_01020102 > q_01010101);
        assert!(q_01020304 > q_01020102);
        assert!(q_01020102 > q_010203);
        assert!(q_01020304 > q_abcd);
        assert!(q_010203 < q_abcd);
        assert_eq!(q_abcd, q_ABCD);
        assert!(q_abc_dot > q_abcd);
        assert!(q_ab > q_01);
        assert!(q_aa > q_01);
        assert!(q_ab > q_aa);
        assert!(q_ab > q_000001);
    }

    #[test]
    fn test_seq_quality() {
        let s1 = &Seq::new(vec![Literal::exact("abcd")]);
        let s2 = &Seq::new(vec![Literal::exact("abc")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("abc")]);
        let s2 = &Seq::new(vec![Literal::exact("abc"), Literal::exact("ab")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("ab"), Literal::exact("cd")]);
        let s2 = &Seq::new(vec![Literal::exact("abc"), Literal::exact("a")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("abc"), Literal::exact("cde")]);
        let s2 = &Seq::new(vec![
            Literal::exact("abc"),
            Literal::exact("cde"),
            Literal::exact("fgh"),
        ]);

        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("abcd")]);
        let s2 = &Seq::new(vec![Literal::exact("\x00\x00\x00\x00")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("abc")]);
        let s2 = &Seq::new(vec![Literal::exact("\x00\x00\x00\x00")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("abc")]);
        let s2 = &Seq::new(vec![Literal::exact("\x00\x00\x00\x01")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("\x01\0x02\0x03")]);
        let s2 = &Seq::new(vec![Literal::exact("\x00\x00\x00\x01")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(vec![Literal::exact("ab")]);
        let s2 = &Seq::new(vec![Literal::exact("\x00\x00\x00\x00")]);
        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);

        let s1 = &Seq::new(
            [0x01..=0x01, 0x00..=0xff, 0x00..=0x00]
                .into_iter()
                .multi_cartesian_product()
                .map(Literal::exact)
                .collect::<Vec<Literal>>(),
        );
        let s2 = &Seq::new(vec![Literal::exact("\x00\x00\x00\x00")]);

        let q1 = AtomsQuality::from_seq(s1);
        let q2 = AtomsQuality::from_seq(s2);

        assert!(q1 > q2);
        assert!(q2 < q1);
    }

    #[test]
    fn best_range_in_masked_bytes() {
        assert_eq!(
            atoms::best_range_in_masked_bytes(
                &[0x01, 0x02, 0x03, 0x04, 0x05],
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            ),
            (Some(0..4), 88),
        );

        assert_eq!(
            atoms::best_range_in_masked_bytes(
                &[0x01, 0x02, 0x00, 0x00],
                &[0xFF, 0xFF, 0x00, 0x00],
            ),
            (Some(0..2), 44),
        );

        assert_eq!(
            atoms::best_range_in_masked_bytes(
                &[0x01, 0x02, 0x03, 0x04],
                &[0xFF, 0xFF, 0x0F, 0xFF],
            ),
            (Some(0..4), 70),
        );

        assert_eq!(
            atoms::best_range_in_masked_bytes(
                &[0x01, 0x02, 0x00, 0x04],
                &[0xFF, 0xFF, 0x00, 0xFF]
            ),
            (Some(0..4), 58),
        );

        assert_eq!(
            atoms::best_range_in_masked_bytes(
                &[0x01, 0x02, 0x00, 0x04, 0x05, 0x06, 0x07],
                &[0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
            ),
            (Some(3..7), 88),
        );

        assert_eq!(
            atoms::best_range_in_masked_bytes(
                &[0x68, 0x00, 0x00, 0x00, 0x00, 0xFF],
                &[0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF],
            ),
            (Some(3..6), 28),
        );

        assert_eq!(
            atoms::best_range_in_masked_bytes(&[], &[],),
            (None, i32::MIN),
        );
    }
}
