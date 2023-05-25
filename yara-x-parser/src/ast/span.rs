use crate::ast::{BinaryExpr, Expr};
use crate::parser::SourceId;

pub trait HasSpan {
    /// Returns the starting and ending position within the source code for
    /// some node in the AST.
    fn span(&self) -> Span;
}

/// Span indicates the starting and ending position for some node in the AST.
///
/// Positions are absolute byte offsets within the original source code.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub struct Span {
    /// The [`SourceId`] associated to the source file that contains this span.
    pub(crate) source_id: SourceId,
    /// Starting byte offset.
    pub(crate) start: usize,
    /// Ending byte offset.
    pub(crate) end: usize,
}

impl Span {
    pub(crate) fn new(source_id: SourceId, span: pest::Span<'_>) -> Self {
        Self { source_id, start: span.start(), end: span.end() }
    }

    /// Byte offset where the span starts.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Byte offset where the span ends.
    pub fn end(&self) -> usize {
        self.end
    }

    pub fn combine(&self, span: &Span) -> Span {
        assert_eq!(self.source_id, span.source_id);
        Span { source_id: self.source_id, start: self.start, end: span.end }
    }

    /// Returns a new [`Span`] that is a subspan of the original one.
    ///
    /// `start` and `end` are the starting and ending offset of the subspan,
    /// relative to the start of the original span.
    pub fn subspan(&self, start: usize, end: usize) -> Span {
        assert!(start <= self.end - self.start);
        assert!(end <= self.end - self.start);
        Span {
            source_id: self.source_id,
            start: self.start + start,
            end: self.start + end,
        }
    }
}

impl<'src> HasSpan for BinaryExpr<'src> {
    fn span(&self) -> Span {
        self.lhs.span().combine(&self.rhs.span())
    }
}

impl<'src> HasSpan for &Vec<Expr<'src>> {
    fn span(&self) -> Span {
        let span =
            self.first().expect("calling span() on an empty Vec<Expr>").span();

        span.combine(&self.last().unwrap().span())
    }
}
