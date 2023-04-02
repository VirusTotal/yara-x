/*! This modules contains the logic for extracting atoms from patterns,
computing an atom's quality, choosing the best atoms from a pattern, etc.

Atoms are undivided substrings found in patterns, for example, let's consider
this hex string:

```text
{ 01 02 03 04 05 ?? 06 07 08 [1-2] 09 0A }
```

In the above string, byte sequences `01 02 03 04 05`, `06 07 08` and `09 0A`
are atoms. Similarly, in the regexp below the strings `"abc"`, `"ed"` and
`"fgh"` are also atoms.

```text
/abc.*ed[0-9]+fgh/
```

When searching for rule patterns, YARA uses these atoms to find locations
inside the file where the pattern could match. If the atom `"abc"` is found
somewhere inside the file, there is a chance for the regexp
`/abc.*ed[0-9]+fgh/` to match the file, if `"abc"` doesn't appear in the file
there's no chance for the regexp to match. When the atom is found in the file
YARA proceeds to fully evaluate the regexp to determine if it's actually a
match.

For each regexp/hex string YARA extracts one or more atoms. Sometimes a
single atom is enough (in the previous example `"abc"` is enough for finding
`/abc.*ed[0-9]+fgh/`), but sometimes a single atom isn't enough like in the
regexp `/(abc|efg)/`. In this case YARA must search for both `"abc"` AND
`"efg"` and fully evaluate the regexp whenever one of these atoms is found.

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

use bstr::ByteSlice;
use itertools::{Itertools, MultiProduct};
use std::cmp;
use std::collections::Bound;
use std::ops::RangeBounds;
use std::slice::SliceIndex;

use yara_x_parser::ast;
use yara_x_parser::ast::Pattern;

use crate::compiler::atoms::mask::ByteMaskCombinator;
use crate::compiler::atoms::quality::{atom_quality, masked_atom_quality};

/// The number of bytes that every atom *should* have. Some atoms may be
/// shorter than DESIRED_ATOM_SIZE when it's impossible to extract a longer,
/// good-quality atom from a string. Similarly, some atoms may be larger.
const DESIRED_ATOM_SIZE: usize = 4;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Atom {
    // TODO: use tinyvec or smallvec?
    bytes: Vec<u8>,
    pub backtrack: u16,
}

impl AsRef<[u8]> for Atom {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl From<&[u8]> for Atom {
    /// Creates an atom from a byte slice.
    ///
    /// The atom's backtrack will be 0.
    fn from(value: &[u8]) -> Self {
        Self { bytes: value.to_vec(), backtrack: 0 }
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
    /// assert_eq!(atom.as_ref(), &[0x01, 0x02])
    /// assert_eq!(atom.backtrack, 1)
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
        let s: &[u8] = &s[range];

        Self { bytes: s.to_vec(), backtrack }
    }

    /// Compute the atom's quality
    pub fn quality(&self) -> i32 {
        atom_quality(self.bytes.clone())
    }
}

/// An atom where some of bits are masked. The masked bits can adopt any value,
/// which means that these atoms can't be fed into the Aho-Corasick automaton.
/// Masked atoms must be expanded into multiple non-masked atoms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MaskedAtom {
    // Each item in this vector is composed of a byte value and its associated
    // mask. The mask indicates which bits in the value are actually relevant.
    // For example, the pattern 1A is expressed as (0x1A, 0xFF), where 0x1A is
    // the value and 0xFF is the mask. The pattern 1? is expressed as
    // (0x10, 0xF0). The non-relevant bits are set to zero both in the value
    // and the mask.
    // TODO: use tinyvec or smallvec?
    bytes: Vec<(u8, u8)>,
    // See the documentation for Atom.
    pub backtrack: u16,
}

impl MaskedAtom {
    pub fn new() -> Self {
        Self { bytes: Vec::new(), backtrack: 0 }
    }

    #[inline]
    pub fn push(&mut self, byte_and_mask: (u8, u8)) -> &mut Self {
        self.bytes.push(byte_and_mask);
        self
    }

    /// Compute the atom's quality
    pub fn quality(&self) -> i32 {
        let (bytes, masks): (Vec<_>, Vec<_>) =
            self.bytes.iter().cloned().unzip();

        masked_atom_quality(bytes, masks)
    }

    pub fn expand(&self) -> MaskedAtomExpander {
        MaskedAtomExpander::new(&self)
    }
}

pub(super) trait Atoms {
    fn atoms(&self) -> Vec<Atom>;
}

impl Atoms for ast::Pattern<'_> {
    fn atoms(&self) -> Vec<Atom> {
        match self {
            Pattern::Text(p) => p.atoms(),
            Pattern::Hex(p) => p.atoms(),
            Pattern::Regexp(p) => p.atoms(),
        }
    }
}

impl Atoms for ast::TextPattern<'_> {
    fn atoms(&self) -> Vec<Atom> {
        let pattern_bytes = self.value.as_ref().as_bytes();
        let pattern_len = pattern_bytes.len();

        let mut max_quality = 0;
        let mut best_atom = None;
        let mut atoms = Vec::new();

        for i in 0..=pattern_len.checked_sub(DESIRED_ATOM_SIZE).unwrap_or(0) {
            let atom = Atom::from_slice_range(
                pattern_bytes,
                i..cmp::min(pattern_len, i + DESIRED_ATOM_SIZE),
            );
            let quality = atom.quality();
            if quality > max_quality {
                max_quality = quality;
                best_atom = Some(atom);
            }
        }

        if let Some(best_atom) = best_atom {
            atoms.push(best_atom);
        }

        // TODO: add new atoms according to the used modifiers.

        atoms
    }
}

impl Atoms for ast::RegexpPattern<'_> {
    fn atoms(&self) -> Vec<Atom> {
        // TODO
        Vec::new()
    }
}

impl Atoms for ast::HexPattern<'_> {
    fn atoms(&self) -> Vec<Atom> {
        // TODO
        Vec::new()
    }
}

/// Expands a [`MaskedAtom`] into multiple [`Atom`] by trying all the possible
/// combinations for the masked bits. The backtrack value for all the produced
/// atoms are the same than the one in the masked atom.
pub(super) struct MaskedAtomExpander {
    cartesian_product: MultiProduct<ByteMaskCombinator>,
    backtrack: u16,
}

impl MaskedAtomExpander {
    pub fn new(atom: &MaskedAtom) -> Self {
        Self {
            backtrack: atom.backtrack,
            cartesian_product: atom
                .bytes
                .iter()
                .map(|(atom, mask)| ByteMaskCombinator::new(*atom, *mask))
                .multi_cartesian_product(),
        }
    }
}

impl Iterator for MaskedAtomExpander {
    type Item = Atom;

    fn next(&mut self) -> Option<Self::Item> {
        let mut atom = Atom::from(self.cartesian_product.next()?.as_slice());
        atom.backtrack = self.backtrack;
        Some(atom)
    }
}

pub(super) struct CaseCombinator {}

impl CaseCombinator {
    pub fn new(atom: &Atom) -> Self {
        Self {}
    }
}

impl Iterator for CaseCombinator {
    type Item = Atom;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use crate::compiler::atoms::{Atom, Atoms, MaskedAtom};
    use bstr::BString;
    use pretty_assertions::assert_eq;
    use std::borrow::Cow;
    use yara_x_parser::ast;
    use yara_x_parser::ast::{Ident, PatternModifiers, Span};
    use yara_x_parser::types::TypeValue;

    #[test]
    fn atom_expander() {
        let mut atoms = MaskedAtom::new().push((0x10, 0xF0)).expand();

        for i in 0x10..=0x1F_u8 {
            assert_eq!(atoms.next(), Some(Atom::from([i].as_slice())));
        }

        assert_eq!(atoms.next(), None);

        let mut atoms =
            MaskedAtom::new().push((0x10, 0xF0)).push((0x02, 0x0F)).expand();

        for i in 0x10..=0x1F_u8 {
            for j in (0x02..=0xF2_u8).step_by(0x10) {
                assert_eq!(atoms.next(), Some(Atom::from([i, j].as_slice())));
            }
        }

        assert_eq!(atoms.next(), None);
    }

    #[test]
    fn text_pattern_atoms() {
        let text_pattern = ast::TextPattern {
            span: Span::default(),
            identifier: Ident {
                span: Span::default(),
                type_value: TypeValue::Unknown,
                name: "",
            },
            value: Cow::Owned(BString::from("abcdef")),
            modifiers: PatternModifiers::default(),
        };

        let expected_atom = Atom::from_slice_range("abcdef".as_bytes(), 0..4);

        assert_eq!(expected_atom.as_ref(), "abcd".as_bytes());
        assert_eq!(expected_atom.backtrack, 0);
        assert_eq!(text_pattern.atoms(), vec![expected_atom]);

        let text_pattern = ast::TextPattern {
            span: Span::default(),
            identifier: Ident {
                span: Span::default(),
                type_value: TypeValue::Unknown,
                name: "",
            },
            value: Cow::Owned(BString::from("ab")),
            modifiers: PatternModifiers::default(),
        };

        let expected_atom = Atom::from_slice_range("ab".as_bytes(), 0..2);

        assert_eq!(expected_atom.as_ref(), "ab".as_bytes());
        assert_eq!(expected_atom.backtrack, 0);
        assert_eq!(text_pattern.atoms(), vec![expected_atom]);

        let text_pattern = ast::TextPattern {
            span: Span::default(),
            identifier: Ident {
                span: Span::default(),
                type_value: TypeValue::Unknown,
                name: "",
            },
            value: Cow::Owned(BString::from("abcd0")),
            modifiers: PatternModifiers::default(),
        };

        let expected_atom = Atom::from_slice_range("abcd0".as_bytes(), 1..=4);

        assert_eq!(expected_atom.as_ref(), "bcd0".as_bytes());
        assert_eq!(expected_atom.backtrack, 1);
        assert_eq!(text_pattern.atoms(), vec![expected_atom]);
    }
}
