/*!
This module implements a regexp compiler and matching engine.

The compiler takes a high-level intermediate representation (HIR) of the
regular expression, as outputted by the [`regex-syntax`][1] crate, and produces
VM code for the matching engine, and a list of atoms extracted from the regular
expression. These atoms are simply literal sub-patterns contained in the regexp
that are used for speeding up searches using the Aho-Corasick algorithm. See
`compiler::atoms` for details.

The matching engine is based on a Virtual Machine described in Russ Cox's
article [Regular Expression Matching: the Virtual Machine Approach][1].

[1]: https://docs.rs/regex-syntax
[2]: https://swtch.com/~rsc/regexp/regexp2.html
*/

pub mod compiler;
pub mod hir;
pub mod instr;
pub mod parser;
pub mod pikevm;

#[cfg(test)]
mod tests;
