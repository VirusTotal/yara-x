/*! This module parses, compiles, and executes regular expressions.

The parsing of regular expressions is actually done by the [`regex-syntax`][1]
crate, which produces a high-level intermediate representation (HIR) for a
given regular expression in text form. This crates provides its own [`hir::Hir`]
type, but is is just a thin wrapper around the [`regex_syntax::hir::Hir`] type.

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

pub mod hir;
pub mod parser;
pub mod thompson;
