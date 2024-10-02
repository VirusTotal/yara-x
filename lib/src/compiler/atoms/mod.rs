/*! This module contains the logic for extracting atoms from patterns,
computing atom quality, choosing the best atoms from a pattern, etc.

Atoms are undivided substrings found in patterns, for example, let's consider
this hex string:

```text
{ 01 02 03 04 05 ?? 06 07 08 [1-2] 09 0A }
```

In this string, byte sequences `01 02 03 04 05`, `06 07 08` and `09 0A` are
atoms. Similarly, in the regexp below the strings `"abc"`, `"ed"` and `"fgh"`
are also atoms.

```text
/abc.*ed[0-9]+fgh/
```

When searching for patterns, YARA uses these atoms to find locations within
the scanned data where the pattern could match. If the atom `"abc"` is found
somewhere in the data, there is a chance for the regexp `/abc.*ed[0-9]+fgh/`
to match. In the other hand, if `"abc"` doesn't appear in the data there's no
chance for the regexp to match. When the atom is found in the data YARA
proceeds to fully evaluate the regexp to determine if it's actually a match.

For each regexp/hex pattern YARA extracts one or more atoms. Sometimes a
single atom is enough (in the previous example `"abc"` is enough for finding
`/abc.*ed[0-9]+fgh/`), but sometimes a single atom isn't enough like in
`/(abc|efg)/`. In this case YARA must search for both `"abc"` AND `"efg"` and
fully evaluate the regexp whenever any of the two is found.

In the regexp `/Look(at|into)this/` YARA can search for `"Look"`, or search for
`"this"`, or search for both `"at"` and `"into"`. This is what we call an atoms
tree, because it can be represented by the following tree structure:

```text
-OR
  |- "Look"
  |
  |- AND
  |   |
  |   |- "at"
  |    - "into"
  |
   - "this"
```

From an atom tree YARA chooses the best combination, trying to minimize the
number of required atoms, but also using high quality atoms (long atoms with
not too many zeroes and a bit of byte diversity). In the previous example YARA
will end up using the `"Look"` atom alone, but in `/a(bcd|efg)h/` atoms `"bcd"`
and `"efg"` will be used because `"a"` and `"h"` are too short.
 */

mod mask;
mod quality;

use std::collections::Bound;
use std::iter;
use std::iter::zip;
use std::ops::{RangeBounds, RangeInclusive};
use std::slice::SliceIndex;

use itertools::{Itertools, MultiProduct};
use regex_syntax::hir::literal::Literal;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec, ToSmallVec};

pub(crate) use crate::compiler::atoms::mask::ByteMaskCombinator;
pub(crate) use crate::compiler::atoms::quality::best_atom_in_bytes;
pub(crate) use crate::compiler::atoms::quality::best_range_in_bytes;
pub(crate) use crate::compiler::atoms::quality::best_range_in_masked_bytes;
pub(crate) use crate::compiler::atoms::quality::AtomsQuality;

use crate::compiler::{SubPatternFlagSet, SubPatternFlags};

/// The number of bytes that every atom *should* have. Some atoms may be
/// shorter than DESIRED_ATOM_SIZE when it's impossible to extract a longer,
/// good-quality atom from a string.
pub(crate) const DESIRED_ATOM_SIZE: usize = 4;

/// Maximum number of atoms that will be extracted from a regexp. This number
/// must be at least 4096, which is the number of different combinations of a
/// pattern like { 11 ?? 1? 11 }.
///
/// By increasing this number a higher number of longer atoms can be extracted
/// from a regexp, instead of lower number of shorter atoms. Longer atoms are
/// preferred, but too many of them increase the size of the Aho-Corasick
/// automaton and its build time.
pub(crate) const MAX_ATOMS_PER_REGEXP: usize = 8192;

/// A substring extracted from a rule pattern. See the module documentation for
/// a general explanation of what is an atom.
///
/// Each atom consists in a sequence of bytes of variable length and a
/// backtrack amount. When the atom is found in the scanned data, this amount
/// is subtracted from the offset at which the atom was found. This means
/// that atom matches are reported `backtrack` bytes before the offset where
/// they actually occurred. This is useful while searching for fixed length
/// patterns, where the atom position within the pattern is known beforehand.
/// In such cases, once the atom is found we can go back to the offset where
/// the pattern should match and verify the match from there.
///
/// `exact` is true if finding the atom means that the whole pattern matches
/// For instance, in the regexp `/ab(cd|ef)/` we can extract two atoms: `abcd`
/// and `abef`. If any of the atoms is found the regexp matches. Both of these
/// atoms are exact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Atom {
    bytes: SmallVec<[u8; DESIRED_ATOM_SIZE]>,
    exact: bool,
    backtrack: u16,
}

impl AsRef<[u8]> for Atom {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl From<&[u8]> for Atom {
    #[inline]
    fn from(value: &[u8]) -> Self {
        Self {
            bytes: value.to_smallvec(),
            backtrack: 0,
            exact: !value.is_empty(),
        }
    }
}

impl From<Vec<u8>> for Atom {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self {
            bytes: value.to_smallvec(),
            backtrack: 0,
            exact: !value.is_empty(),
        }
    }
}

impl From<SmallVec<[u8; DESIRED_ATOM_SIZE]>> for Atom {
    #[inline]
    fn from(value: SmallVec<[u8; DESIRED_ATOM_SIZE]>) -> Self {
        let exact = !value.is_empty();
        Self { bytes: value, backtrack: 0, exact }
    }
}

impl From<&Literal> for Atom {
    #[inline]
    fn from(value: &Literal) -> Self {
        Self {
            bytes: value.as_bytes().to_smallvec(),
            backtrack: 0,
            exact: value.is_exact(),
        }
    }
}

impl Atom {
    /// Creates an atom representing a range of offsets within a byte slice.
    ///
    /// The atom's backtrack value will be equal to the atom's start offset
    /// within the byte slice.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let atom = Atom::from_slice_range(&[0x00, 0x01, 0x02, 0x03], 1..=2);
    /// assert_eq!(atom.as_ref(), &[0x01, 0x02]);
    /// assert_eq!(atom.backtrack, 1)
    /// assert(!atom.is_exact);
    /// ```
    ///
    pub fn from_slice_range<R>(s: &[u8], range: R) -> Self
    where
        R: RangeBounds<usize> + SliceIndex<[u8], Output = [u8]>,
    {
        let backtrack = match range.start_bound() {
            Bound::Included(b) => *b as u16,
            Bound::Excluded(b) => (*b + 1) as u16,
            Bound::Unbounded => 0,
        };

        let atom: &[u8] = &s[range];

        Self {
            bytes: atom.to_smallvec(),
            backtrack,
            exact: atom.len() == s.len(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn backtrack(&self) -> u16 {
        self.backtrack
    }

    #[inline]
    pub fn set_backtrack(&mut self, b: u16) {
        self.backtrack = b;
    }

    #[inline]
    pub fn is_exact(&self) -> bool {
        self.exact
    }

    #[inline]
    pub fn set_exact(&mut self, exact: bool) {
        self.exact = exact;
    }

    #[inline]
    pub fn make_inexact(&mut self) -> &mut Self {
        self.exact = false;
        self
    }

    pub fn make_wide(mut self) -> Self {
        let atom_len = self.bytes.len();
        self.backtrack *= 2;
        self.bytes = self
            .bytes
            .into_iter()
            .interleave(itertools::repeat_n(0x00, atom_len))
            .collect();
        self
    }

    #[allow(dead_code)]
    pub fn exact<T: AsRef<[u8]>>(v: T) -> Self {
        let mut atom = Self::from(v.as_ref().to_vec());
        atom.exact = true;
        atom
    }

    #[allow(dead_code)]
    pub fn inexact<T: AsRef<[u8]>>(v: T) -> Self {
        let mut atom = Self::from(v.as_ref().to_vec());
        atom.exact = false;
        atom
    }

    /// Returns a [`XorCombinations`] iterator that produces the atoms that
    /// result from XORing this atom with every byte in a range.
    ///
    /// The iterator produces as many atoms as bytes are in the range.
    pub fn xor_combinations(
        self,
        range: RangeInclusive<u8>,
    ) -> XorCombinations {
        XorCombinations::new(self, range)
    }

    /// Returns a [`CaseCombinations`] iterator that produces all possible case
    /// combinations of this atom.
    pub fn case_combinations(self) -> CaseCombinations {
        CaseCombinations::new(self)
    }

    /// Returns a [`MaskCombinations`] iterator which produces all possible
    /// combinations that result from applying a given mask to the atom.
    ///
    /// The mask's length must be identical to the atom's length. In scenarios
    /// where the mask is shorter than the atom, the iterator will yield atoms
    /// matching the mask's length. If the mask is longer than the atom, it
    /// gets truncated to the atom's length.
    ///
    /// The mask's binary 1 bits are constant, adopting the corresponding bits
    /// from the atom. Conversely, binary 0 bits within the mask are variable;
    /// consequently, the resultant atoms encompass all feasible permutations
    /// for these variable bits.
    #[allow(dead_code)]
    pub fn mask_combinations(self, mask: &[u8]) -> MaskCombinations {
        MaskCombinations::new(self, mask)
    }
}

/// Extract the best possible atom from a literal pattern and generates all
/// case combinations for that atom if the `Nocase` flag is set.
pub(crate) fn extract_atoms(
    literal_bytes: &[u8],
    flags: SubPatternFlagSet,
) -> Box<dyn Iterator<Item = Atom>> {
    let mut best_atom = best_atom_in_bytes(literal_bytes);

    // TODO: this is making all atoms in the chain inexact, even
    // those that are in the middle of a chain and therefore don't
    // have FullwordRight nor FullwordLeft. This logic could be
    // improved.
    if flags.intersects(
        SubPatternFlags::FullwordLeft | SubPatternFlags::FullwordRight,
    ) {
        best_atom.make_inexact();
    }

    if flags.contains(SubPatternFlags::Nocase) {
        Box::new(CaseCombinations::new(best_atom))
    } else {
        Box::new(iter::once(best_atom))
    }
}

/// Given a slice of bytes, returns a vector where each byte is followed by
/// a zero.
///
/// # Example
///
/// ```text
/// assert_eq!(
///    make_wide(&[0x01, 0x02, 0x03]),
///    &[0x01, 0x00, 0x02, 0x00, 0x03, 0x00]
/// )
/// ```
pub(super) fn make_wide(s: &[u8]) -> Vec<u8> {
    itertools::interleave(
        s.iter().cloned(),
        itertools::repeat_n(0_u8, s.len()),
    )
    .collect()
}

/// Iterator that returns all the atoms resulting from masking an atom with
/// with a mask.
pub(crate) struct MaskCombinations {
    cartesian_product: MultiProduct<ByteMaskCombinator>,
    backtrack: u16,
    exact: bool,
}

impl MaskCombinations {
    fn new(atom: Atom, mask: &[u8]) -> Self {
        Self {
            exact: atom.exact,
            backtrack: atom.backtrack,
            cartesian_product: zip(atom.bytes, mask)
                .map(|(byte, mask)| ByteMaskCombinator::new(byte, *mask))
                .multi_cartesian_product(),
        }
    }
}

impl Iterator for MaskCombinations {
    type Item = Atom;

    fn next(&mut self) -> Option<Self::Item> {
        let mut atom = Atom::from(self.cartesian_product.next()?);
        atom.backtrack = self.backtrack;
        atom.exact = self.exact;
        Some(atom)
    }
}

/// Iterator that returns a sequence of atoms that covers all the possible case
/// combinations for the ASCII characters in the original atom. The original
/// atom is always included in the sequence, and non-alphabetic characters are
/// left untouched. For example, for the atom "1aBc2" the result is the sequence:
///
///  "1abc2", "1abC2", "1aBc2", "1aBC2", "1Abc2", "1AbC2", "1ABc2", "1ABC2"
///
pub(crate) struct CaseCombinations {
    cartesian_product:
        MultiProduct<smallvec::IntoIter<[u8; DESIRED_ATOM_SIZE]>>,
    backtrack: u16,
    exact: bool,
}

impl CaseCombinations {
    fn new(atom: Atom) -> Self {
        Self {
            exact: atom.exact,
            backtrack: atom.backtrack,
            cartesian_product: atom
                .bytes
                .to_ascii_lowercase()
                .into_iter()
                .map(|byte| {
                    // For alphabetic characters return both the lowercase
                    // and uppercase variants. For non-alphabetic characters
                    // return the original one.
                    if byte.is_ascii_alphabetic() {
                        smallvec![byte, byte.to_ascii_uppercase()]
                    } else {
                        smallvec![byte]
                    }
                })
                .multi_cartesian_product(),
        }
    }
}

impl Iterator for CaseCombinations {
    type Item = Atom;

    fn next(&mut self) -> Option<Self::Item> {
        let mut atom = Atom::from(self.cartesian_product.next()?);
        atom.backtrack = self.backtrack;
        atom.exact = self.exact;
        Some(atom)
    }
}

/// Iterator that returns the atoms resulting from XORing an atom with all
/// byte values in a given inclusive range (e.g. 0..=255, 10..=20). Each
/// returned atom is the result of XORing the original one with one of the
/// values in the range.
///
/// The resulting atoms are all inexact, regardless of whether the original
/// was exact or not.
pub(crate) struct XorCombinations {
    atom: Atom,
    range: RangeInclusive<u8>,
}

impl XorCombinations {
    fn new(atom: Atom, range: RangeInclusive<u8>) -> Self {
        Self { atom, range }
    }
}

impl Iterator for XorCombinations {
    type Item = Atom;

    fn next(&mut self) -> Option<Self::Item> {
        let i = self.range.next()?;
        // XOR all bytes in the atom with the current value i.
        let mut atom = Atom::from(
            self.atom.bytes.iter().map(|b| b ^ i).collect::<Vec<u8>>(),
        );
        atom.backtrack = self.atom.backtrack;
        atom.exact = false;
        Some(atom)
    }
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use crate::compiler::atoms::Atom;

    #[test]
    fn mask_combinations() {
        let atom = Atom::exact([0x11, 0x22, 0x33, 0x44]);
        let mut c = atom.mask_combinations(&[0xff, 0xf0, 0xff, 0xff]);

        assert_eq!(c.next(), Some(Atom::exact([0x11, 0x20, 0x33, 0x44])));
        assert_eq!(c.next(), Some(Atom::exact([0x11, 0x21, 0x33, 0x44])));
        assert_eq!(c.next(), Some(Atom::exact([0x11, 0x22, 0x33, 0x44])));

        let mut c = c.skip(10);

        assert_eq!(c.next(), Some(Atom::exact([0x11, 0x2d, 0x33, 0x44])));
        assert_eq!(c.next(), Some(Atom::exact([0x11, 0x2e, 0x33, 0x44])));
        assert_eq!(c.next(), Some(Atom::exact([0x11, 0x2f, 0x33, 0x44])));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn case_combinations() {
        let atom = Atom::exact(b"a1B2c");
        let mut c = atom.case_combinations();

        assert_eq!(c.next(), Some(Atom::exact(b"a1b2c")));
        assert_eq!(c.next(), Some(Atom::exact(b"a1b2C")));
        assert_eq!(c.next(), Some(Atom::exact(b"a1B2c")));
        assert_eq!(c.next(), Some(Atom::exact(b"a1B2C")));
        assert_eq!(c.next(), Some(Atom::exact(b"A1b2c")));
        assert_eq!(c.next(), Some(Atom::exact(b"A1b2C")));
        assert_eq!(c.next(), Some(Atom::exact(b"A1B2c")));
        assert_eq!(c.next(), Some(Atom::exact(b"A1B2C")));
        assert_eq!(c.next(), None);

        let mut atom = Atom::exact([0x00_u8, 0x01, 0x02]);
        atom.set_backtrack(2);

        let mut c = atom.clone().case_combinations();

        assert_eq!(c.next(), Some(atom));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn xor_combinations() {
        let atom = Atom::exact([0x00_u8, 0x01, 0x02]);
        let mut c = atom.xor_combinations(0..=1);

        assert_eq!(c.next(), Some(Atom::inexact([0x00, 0x01, 0x02])));
        assert_eq!(c.next(), Some(Atom::inexact([0x01, 0x00, 0x03])));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn make_wide() {
        let mut atom = Atom::exact([0x01_u8, 0x02, 0x03]);
        atom.set_backtrack(2);

        let atom = atom.make_wide();

        assert_eq!(
            atom.bytes.as_slice(),
            &[0x01, 0x00, 0x02, 0x00, 0x03, 0x00]
        );

        assert_eq!(atom.backtrack, 4);
    }
}
