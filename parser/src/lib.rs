/*! Parses YARA source code and produces a Concrete Syntax Tree (CST) or an
Abstract Syntax Tree (AST).

A CST is a structured representation of the source code that retains all its
details, including punctuation, spacing, comments, etc. Each node in the CST
corresponds to a [`GrammarRule`] (a rule in YARA's grammar).

The CST is appropriate for traversing the structure of the code as it appears
in its original form. Typical uses of CSTs are code formatters, documentation
generators, source code analysis, etc. One of the limitations of the CST is
that it doesn't know about operator's associativity or precedence rules.
Expressions appear in the CST as they are in the source code, without any
attempt from the parser to group them according to operator precedence
rules.

In the other hand, an AST is a simplified, more abstract representation
of the code. The AST drops comments, spacing and syntactic details and focus
on the code semantics. When building an AST, operator precedence rules are
applied, providing a more accurate representation of expressions.

Deciding whether to use a CST or AST depends on the kind of problem you want
to solve.
 */

#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate core;

mod parser;

pub mod ast;
pub mod cst;

pub use parser::*;

#[doc(hidden)]
pub mod report;
