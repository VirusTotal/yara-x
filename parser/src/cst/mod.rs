/*! Concrete Syntax Tree (CST) for YARA rules.

A CST (also known as a lossless syntax tree) is a structured representation of
the source code that retains all its details, including punctuation, spacing,
comments, etc. The CST is appropriate for traversing the source code as it
appears in its original form.

Typical uses of CSTs are code formatters, documentation generators, source
code analysis tools, etc. One of the limitations of the CST is that it doesn’t
know about operator’s associativity or precedence rules. Expressions appear in
the CST as they are in the source code, without any attempt from the parser to
group them according to operator precedence rules.
 */
use crate::{Parser, Span};
use rowan::GreenNodeBuilder;
use std::fmt::{Debug, Formatter};
use std::str::from_utf8;

pub(crate) mod syntax_kind;
pub(crate) mod syntax_stream;

use crate::cst::SyntaxKind::{COMMENT, NEWLINE, WHITESPACE};
pub use syntax_kind::SyntaxKind;

/// Each of the events in a [`CSTStream`].
///
/// See the documentation of [`CSTStream`] for more details.
#[derive(Debug, PartialEq)]
pub enum Event {
    /// Indicates the beginning of a non-terminal production in the grammar.
    Begin(SyntaxKind),
    /// Indicates the end of a non-terminal production in the grammar.
    End(SyntaxKind),
    /// A terminal symbol in the grammar.
    Token { kind: SyntaxKind, span: Span },
    /// An error found during the parsing of the source.
    Error { message: String, span: Span },
}

/// A Concrete Syntax Tree (CST) represented as a stream of events.
///
/// Each event in the stream has one of the following types:
///
/// - [`Event::Token`]
/// - [`Event::Begin`]
/// - [`Event::End`]
/// - [`Event::Error`]
///
/// [`Event::Token`] represents terminal symbols in the grammar, such as
/// keywords, punctuation, identifiers, comments and even whitespace. Each
/// [`Event::Token`] has an associated [`Span`] that indicates its position
/// in the source code.
///
/// [`Event::Begin`] and [`Event::End`] relate to non-terminal symbols, such as
/// expressions and statements. These events appear in pairs, with each `Begin`
/// followed by a corresponding `End` of the same kind. A `Begin`/`End` pair
/// represents a non-terminal node in the syntax tree, with everything in
/// between being a child of this node.
///
/// [`Event::Error`] events are not technically part of the syntax tree. They
/// contain error messages generated during parsing. Although these errors could
/// be in a separate stream, they are integrated into the syntax tree for
/// simplicity. Each error message is placed under the tree node that was being
/// parsed when the error occurred.
///
/// Notice that [`Event::Error`] and `Event::Begin(ERROR)` are not the same,
/// and both of them can appear in the stream. The former is an error message
/// issued by the parser, while the latter indicates the start of a CST
/// subtree that contains portions of the syntax tree that were not correctly
/// parsed. Of course, `Event::Begin(ERROR)` must be accompanied by a matching
/// `Event::End(ERROR)`.
pub struct CSTStream<'src> {
    parser: Parser<'src>,
    whitespaces: bool,
    newlines: bool,
    comments: bool,
}

impl<'src> CSTStream<'src> {
    /// Returns the source code associated to this CSTStream.
    #[inline]
    pub fn source(&self) -> &'src [u8] {
        self.parser.source()
    }

    /// Enables or disables whitespaces in the returned CST.
    ///
    /// If false, the resulting CST won't contain whitespaces.
    ///
    /// Default value is `true`.
    pub fn whitespaces(mut self, yes: bool) -> Self {
        self.whitespaces = yes;
        self
    }

    /// Enables or disables newlines in the returned CST.
    ///
    /// If false, the resulting CST won't contain newlines.
    ///
    /// Default value is `true`.
    pub fn newlines(mut self, yes: bool) -> Self {
        self.newlines = yes;
        self
    }

    /// Enables or disables comments in the returned CST.
    ///
    /// If false, the resulting CST won't contain comments.
    ///
    /// Default value is `true`.
    pub fn comments(mut self, yes: bool) -> Self {
        self.comments = yes;
        self
    }
}

impl<'src> From<Parser<'src>> for CSTStream<'src> {
    /// Creates a [`CSTStream`] from the given parser.
    fn from(parser: Parser<'src>) -> Self {
        Self { parser, whitespaces: true, newlines: true, comments: true }
    }
}

impl<'src> Iterator for CSTStream<'src> {
    type Item = Event;

    /// Returns the next event in the stream.
    fn next(&mut self) -> Option<Self::Item> {
        if self.whitespaces && self.newlines {
            self.parser.parser.next()
        } else {
            loop {
                match self.parser.parser.next()? {
                    token @ Event::Token { kind: WHITESPACE, .. } => {
                        if self.whitespaces {
                            break Some(token);
                        }
                    }
                    token @ Event::Token { kind: NEWLINE, .. } => {
                        if self.newlines {
                            break Some(token);
                        }
                    }
                    token @ Event::Token { kind: COMMENT, .. } => {
                        if self.comments {
                            break Some(token);
                        }
                    }
                    token => break Some(token),
                }
            }
        }
    }
}

/// A Concrete Syntax Tree (CST) representing the structure of some YARA
/// source code.
pub struct CST {
    tree: rowan::SyntaxNode<YARA>,
    errors: Vec<(Span, String)>,
}

impl Debug for CST {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self.tree)?;
        if !self.errors.is_empty() {
            writeln!(f, "\nERRORS:")?;
            for (span, err) in &self.errors {
                writeln!(f, "- {}: {}", span, err)?;
            }
        }
        Ok(())
    }
}

impl From<Parser<'_>> for CST {
    /// Crates a [`CST`] from the given parser.
    fn from(parser: Parser) -> Self {
        let source = parser.source();
        let mut builder = GreenNodeBuilder::new();
        let mut prev_token_span: Option<Span> = None;
        let mut errors = Vec::new();

        for node in parser.into_cst_stream() {
            match node {
                Event::Begin(kind) => builder.start_node(kind.into()),
                Event::End(_) => builder.finish_node(),
                Event::Token { kind, span } => {
                    // Make sure that the CST covers the whole source code,
                    // each must start where the previous one ended.
                    if let Some(prev_token_span) = prev_token_span {
                        assert_eq!(
                            prev_token_span.end(),
                            span.start(),
                            "gap in the CST, one token ends at {} and the next one starts at {}",
                            prev_token_span.end(),
                            span.start(),
                        );
                    }
                    // The span must within the source code, this unwrap
                    // can't fail.
                    let token = source.get(span.range()).unwrap();
                    // Tokens are always valid UTF-8, this unwrap can't
                    // fail.
                    // TODO: use from_utf8_unchecked?
                    let token = from_utf8(token).unwrap();
                    builder.token(kind.into(), token);
                    prev_token_span = Some(span);
                }
                Event::Error { message, span } => errors.push((span, message)),
            }
        }

        Self { tree: rowan::SyntaxNode::new_root(builder.finish()), errors }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct YARA();

impl rowan::Language for YARA {
    type Kind = SyntaxKind;

    /// Convert from [`rowan::SyntaxKind`] kind to [`SyntaxKind`].
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        unsafe { std::mem::transmute::<u16, SyntaxKind>(raw.0) }
    }

    /// Convert from [`SyntaxKind`] to [`rowan::SyntaxKind`].
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.into()
    }
}
