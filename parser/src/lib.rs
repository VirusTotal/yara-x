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
use std::ops::{Add, Range, Sub};

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

    /// Returns true if this span completely contains `other`.
    ///
    /// Both the start and end of the `other` span must be within the limits of
    /// this span.
    ///
    /// ```
    /// # use yara_x_parser::Span;
    /// assert!(Span(0..3).contains(&Span(0..2)));
    /// assert!(Span(0..3).contains(&Span(1..3)));
    /// assert!(Span(0..3).contains(&Span(0..3)));
    /// assert!(!Span(0..3).contains(&Span(0..4)));
    /// assert!(!Span(0..3).contains(&Span(3..4)));
    /// ```
    pub fn contains(&self, other: &Self) -> bool {
        self.0.contains(&other.0.start)
            && self.0.contains(&other.0.end.saturating_sub(1))
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

    /// Displace the span by adding `offset` to both the starting and
    /// ending positions.
    ///
    /// ```
    /// # use yara_x_parser::Span;
    /// assert_eq!(Span(0..1).offset(1), Span(1..2));
    /// assert_eq!(Span(1..2).offset(-1), Span(0..1));
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the new span has a start or end positions that are
    /// negative or larger than `Span::MAX`.
    ///
    /// ```should_panic
    /// # use yara_x_parser::Span;
    /// Span(0..1).offset(-1);
    /// ```
    pub fn offset(mut self, offset: isize) -> Self {
        if offset.is_negative() {
            self.0.start = self.0.start.sub(offset.unsigned_abs() as u32);
            self.0.end = self.0.end.sub(offset.unsigned_abs() as u32);
        } else {
            self.0.start = self.0.start.add(offset as u32);
            self.0.end = self.0.end.add(offset as u32);
        }
        self
    }
}
