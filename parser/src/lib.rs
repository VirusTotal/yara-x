/*! Parses YARA source code and produces either a Concrete Syntax Tree (CST)
or an Abstract Syntax Tree (AST).

A CST (also known as a lossless syntax tree) is a structured representation of
the source code that retains all its details, including punctuation, spacing,
comments, etc. The CST is appropriate for traversing the source code as it
appears in its original form.

Typical uses of CSTs are code formatters, documentation generators, source
code analysis tools, etc. One of the limitations of the CST is that it doesn’t
know about operator’s associativity or precedence rules. Expressions appear in
the CST as they are in the source code, without any attempt from the parser to
group them according to operator precedence rules.

In the other hand, an AST is a simplified, more abstract representation of the
code. The AST drops comments, spacing and syntactic details and focus on the
code semantics. When building an AST, operator precedence rules are applied,
providing a more accurate representation of expressions.

Deciding whether to use a CST or AST depends on the kind of problem you want to
solve.
 */

use std::fmt::{Display, Formatter};
use std::ops::Range;

pub use parser::Parser;

#[cfg(feature = "serde")]
use serde::Serialize;

pub mod ast;
pub mod cst;

mod parser;
mod tokenizer;

/// Starting and ending positions of some token inside the source code.
#[derive(Default, Clone, Debug, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Span(pub Range<u32>);

impl From<logos::Span> for Span {
    fn from(value: logos::Span) -> Self {
        Self(value.start as u32..value.end as u32)
    }
}

impl Display for Span {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}..{}]", self.start(), self.end())
    }
}

impl Span {
    const MAX: usize = u32::MAX as usize;

    /// Offset within the source code (in bytes) were the span starts.
    #[inline]
    pub fn start(&self) -> usize {
        self.0.start as usize
    }

    /// Offset within the source code (in bytes) where the span ends.
    #[inline]
    pub fn end(&self) -> usize {
        self.0.end as usize
    }

    /// Returns the span as a range of byte offsets.
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.0.start as usize..self.0.end as usize
    }

    /// Returns a new [`Span`] that combines this span with `other`.
    ///
    /// The resulting span goes from `self.start()` to `other.end()`.
    pub fn combine(&self, other: &Self) -> Self {
        Self(self.0.start..other.0.end)
    }

    /// Returns a new [`Span`] that is a subspan of the original one.
    ///
    /// `start` and `end` are the starting and ending offset of the subspan,
    /// relative to the start of the original span.
    pub fn subspan(&self, start: usize, end: usize) -> Span {
        assert!(start <= self.end() - self.start());
        assert!(end <= self.end() - self.start());
        Self(self.0.start + start as u32..self.0.start + end as u32)
    }

    /// Displace the span to the left, incrementing both the starting and
    /// ending positions by the given offset
    ///
    /// ```
    /// # use yara_x_parser::Span;
    /// assert_eq!(Span(0..1).offset(1), Span(1..2))
    /// ```
    pub fn offset(mut self, offset: usize) -> Self {
        self.0.start = self.0.start.saturating_add(offset as u32);
        self.0.end = self.0.end.saturating_add(offset as u32);
        self
    }
}
