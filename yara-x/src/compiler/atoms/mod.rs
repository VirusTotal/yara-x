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

use itertools::{Itertools, MultiProduct};
use std::cmp;

use yara_x_parser::ast;
use yara_x_parser::ast::Pattern;

use crate::compiler::atoms::mask::ByteMaskCombinator;
use crate::compiler::atoms::quality::{atom_quality, masked_atom_quality};

/// Maximum number of bytes in an atom.
const MAX_ATOM_SIZE: usize = 4;

/// A substring extracted from rule patterns. See the module documentation for
/// details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Atom {
    // TODO: use tinyvec or smallvec?
    bytes: Vec<u8>,
}

impl<T> From<T> for Atom
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self { bytes: value.as_ref().to_vec() }
    }
}

impl Atom {
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
}

impl MaskedAtom {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
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
        let s = self.value.as_ref();
        let len = s.len();

        let mut max_quality = 0;
        let mut best_atom = None;
        let mut atoms = Vec::new();

        for i in 0..=len.checked_sub(MAX_ATOM_SIZE).unwrap_or(0) {
            let atom = Atom::from(&s[i..cmp::min(len, i + MAX_ATOM_SIZE)]);
            let quality = atom.quality();
            if quality > max_quality {
                max_quality = quality;
                best_atom = Some(atom);
            }
        }

        if let Some(best_atom) = best_atom {
            atoms.push(best_atom);
        }

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
/// combinations for the masked bits.
pub(super) struct MaskedAtomExpander {
    cartesian_product: MultiProduct<ByteMaskCombinator>,
}

impl MaskedAtomExpander {
    pub fn new(atom: &MaskedAtom) -> Self {
        Self {
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
        Some(Atom::from(self.cartesian_product.next()?))
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

        for i in 0x10..=0x1F {
            assert_eq!(atoms.next(), Some(Atom::from([i])));
        }

        assert_eq!(atoms.next(), None);

        let mut atoms =
            MaskedAtom::new().push((0x10, 0xF0)).push((0x02, 0x0F)).expand();

        for i in 0x10..=0x1F {
            for j in (0x02..=0xF2).step_by(0x10) {
                assert_eq!(atoms.next(), Some(Atom::from([i, j])));
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

        assert_eq!(text_pattern.atoms(), vec![Atom::from("abcd")]);

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

        assert_eq!(text_pattern.atoms(), vec![Atom::from("ab")]);

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

        assert_eq!(text_pattern.atoms(), vec![Atom::from("bcd0")]);
    }
}
