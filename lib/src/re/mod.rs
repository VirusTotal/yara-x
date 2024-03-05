/*! This module parses, compiles, and executes regular expressions.

The parsing of regular expressions is actually done by the [`regex-syntax`][1]
crate, which produces a high-level intermediate representation (HIR) for a
given regular expression in text form. This crates provides its own [`hir::Hir`]
type, but is just a thin wrapper around the [`regex_syntax::hir::Hir`] type.

Both regexp patterns and hex patterns are converted into a [`hir::Hir`], as
every YARA hex pattern can be boiled down to a regular expression. Both kinds
of patterns are treated in the same way once they are converted into their HIR.
Then, given a [`hir::Hir`], a compiler produces code for a VM. This code is
later executed for determining if some string matches the regular expression.

This module provides two different implementations for the compiler and VM. One
is based in the [Thompson's construction][2] algorithm and the Pike's VM
described in [Regular Expression Matching: the Virtual Machine Approach][2].
The other is a custom matching algorithm that can be used only with a subset
of the regular expressions that comply with certain constraints, but is much
faster at runtime.

[1]: https://docs.rs/regex-syntax
[2]: https://en.wikipedia.org/wiki/Thompson%27s_construction
[3]: https://swtch.com/~rsc/regexp/regexp2.html
*/

use std::cell::Cell;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::compiler::Atom;

//#[cfg(feature = "fast-regexp")]
pub mod fast;

pub mod bitmapset;
pub mod hir;
pub mod parser;
pub mod thompson;

/// When it comes to matching a regular expression, the initial step involves
/// locating an "atom" within the data under examination. Once this atom is
/// pinpointed, the regex engine proceeds to read bytes from the data, starting
/// at the offset where the atom was discovered. This reading operation occurs
/// in both forward and backward directions.
///
/// The maximum number of bytes read in each direction is capped. In essence,
/// for every atom match, the regex engine will read, at most, 2 times the
/// scan limit bytes while confirming the match. This is the default value for
/// the scan limit.
pub const DEFAULT_SCAN_LIMIT: u16 = 4096;

/// Maximum number of alternatives in a regexp alternation
/// (e.g: `(foo|bar|baz..)`)
pub const MAX_ALTERNATIVES: u8 = 255;

#[derive(Error, Debug)]
pub enum Error {
    /// The regular expression is too large.
    #[error("regexp too large")]
    TooLarge,

    #[error("too many alternatives in alternation (max: 255)")]
    TooManyAlternatives,

    /// The regular expression doesn't meet the requirements for being
    /// executed by [`fast::fastvm::FastVM`].
    #[error("regexp is incompatible with FastVM")]
    FastIncompatible,
}

/// Represents an atom extracted from a regular expression.
#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct RegexpAtom {
    pub atom: Atom,
    pub fwd_code: Option<FwdCodeLoc>,
    pub bck_code: Option<BckCodeLoc>,
}

impl RegexpAtom {
    #[inline]
    pub fn make_wide(mut self) -> Self {
        self.atom = self.atom.make_wide();
        self
    }

    #[inline]
    pub fn set_exact(&mut self, yes: bool) -> &mut Self {
        self.atom.set_exact(yes);
        self
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.atom.len()
    }
}

/// Trait implementing by both [`FwdCodeLoc`] and [`BckCodeLoc`].
pub(crate) trait CodeLoc: From<usize> {
    fn location(&self) -> usize;
    fn backwards(&self) -> bool;
}

/// Represents a location within the forward code for a regexp.
#[derive(Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) struct FwdCodeLoc(NonZeroU32);

impl From<usize> for FwdCodeLoc {
    fn from(value: usize) -> Self {
        let value: u32 = value.try_into().unwrap();
        Self(NonZeroU32::new(value + 1).unwrap())
    }
}

impl CodeLoc for FwdCodeLoc {
    #[inline]
    fn location(&self) -> usize {
        self.0.get() as usize - 1
    }

    #[inline]
    fn backwards(&self) -> bool {
        false
    }
}

/// Represents a location within the backward code for a regexp.
#[derive(Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) struct BckCodeLoc(NonZeroU32);

impl From<usize> for BckCodeLoc {
    fn from(value: usize) -> Self {
        let value: u32 = value.try_into().unwrap();
        Self(NonZeroU32::new(value + 1).unwrap())
    }
}

impl CodeLoc for BckCodeLoc {
    #[inline]
    fn location(&self) -> usize {
        self.0.get() as usize - 1
    }

    #[inline]
    fn backwards(&self) -> bool {
        true
    }
}

/// Value returned by the callback functions passed to [`PikeVM::try_match`]
/// and [`FastVM::try_match`] for indicating if VM should continue trying to
/// find more matches or stop without trying to find more matches.
pub(crate) enum Action {
    Continue,
    Stop,
}

/// WideIter is an iterator that takes a byte iterator and consumes it two
/// bytes at a time, returning one of the bytes and making sure that other
/// is zero. Which of the two bytes is returned and which is zero depends
/// on the kind of iterator you create. With [`WideIter::non_zero_first`]
/// the iterator expects the first byte of each pair to be non-zero, and
/// the second one to be zero.
///
/// In the other hand, with [`WideIter::zero_first`] the iterator expects
/// the first byte of each pair to be zero, and the second one to be the
/// non-zero byte.
///
/// When the iterator finds a byte that is expected to be zero, but it's
/// not, it saves the number of valid pairs that were consumed before
/// finding this invalid pair.
///
/// ```ignore
/// let error_pos = Cell::new(None);
/// let v = vec![1,0,2,0,3,0];
/// // The non-zero values are expected to be the first of each pair.
/// let i = WideIter::non_zero_first(v.iter(), &error_pos);
/// assert_eq!(i.collect(), vec![1,2,3]);
/// // No error.
/// assert_eq!(error_pos.get(), None);
/// ```
///
/// ```ignore
/// let error_pos = Cell::new(None);
/// let v = vec![1,100,2,0,3,0];
/// let i = WideIter::non_zero_first(v.iter(), &error_pos);
/// assert_eq!(i.collect(), vec![1,2,3]);
/// // Error! the 1 is followed by 100 instead of 0. The
/// // error position is 0 because no valid pairs were found
/// // before this error.
/// assert!(error_pos.get(), Some(0));
/// ```
///
/// ```ignore
/// let error_pos = Cell::new(None);
/// let v = vec![0,1,0,2,0,3];
/// // The zero values are expected to be the first of each pair.
/// let i = WideIter::zero_first(v.iter(), &error_pos);
/// assert_eq!(i.collect(), vec![1,2,3]);
/// // No error
/// assert!(error_pos.get(), None);
/// ```
struct WideIter<'a, I>
where
    I: Iterator<Item = &'a u8>,
{
    iter: I,
    error_pos: &'a Cell<Option<usize>>,
    valid_pairs: usize,
    zero_first: bool,
}

impl<'a, I> WideIter<'a, I>
where
    I: Iterator<Item = &'a u8>,
{
    pub fn non_zero_first(iter: I, error_pos: &'a Cell<Option<usize>>) -> Self
    where
        I: Iterator<Item = &'a u8>,
    {
        WideIter { iter, error_pos, valid_pairs: 0, zero_first: false }
    }

    pub fn zero_first(iter: I, error_pos: &'a Cell<Option<usize>>) -> Self
    where
        I: Iterator<Item = &'a u8>,
    {
        WideIter { iter, error_pos, valid_pairs: 0, zero_first: true }
    }
}

impl<'a, I> Iterator for WideIter<'a, I>
where
    I: Iterator<Item = &'a u8>,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let first_byte = self.iter.next()?;
        let second_byte = self.iter.next()?;

        if self.zero_first {
            if *first_byte != 0_u8 && self.error_pos.get().is_none() {
                self.error_pos.set(Some(self.valid_pairs));
            }
            self.valid_pairs += 1;
            Some(second_byte)
        } else {
            if *second_byte != 0_u8 && self.error_pos.get().is_none() {
                self.error_pos.set(Some(self.valid_pairs));
            }
            self.valid_pairs += 1;
            Some(first_byte)
        }
    }
}
