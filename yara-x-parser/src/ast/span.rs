use crate::ast::{BinaryExpr, Expr};

pub trait HasSpan {
    /// Returns the starting and ending position of some AST node within the source code.
    fn span(&self) -> Span;
}

/// Contains the starting and ending position for a piece of source code.
#[derive(Debug, Default, Hash, Eq, PartialEq, Copy, Clone)]
pub struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl Span {
    pub fn start(&self) -> usize {
        self.start
    }

    pub fn end(&self) -> usize {
        self.end
    }

    pub fn combine(&self, span: &Span) -> Span {
        Span { start: self.start, end: span.end }
    }
}

#[doc(hidden)]
impl From<pest::Span<'_>> for Span {
    fn from(span: pest::Span) -> Self {
        Self { start: span.start(), end: span.end() }
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
