/*! A Concrete Syntax Tree (CST) for YARA source code.

A CST (also known as lossless syntax tree) is a structured representation of
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
use std::fmt::{Debug, Display, Formatter};
use std::str::from_utf8;

pub(crate) mod syntax_kind;
pub(crate) mod syntax_stream;

pub use syntax_kind::SyntaxKind;
pub use syntax_stream::Event;
pub use syntax_stream::SyntaxStream;

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
                writeln!(f, "- {:?}: {}", span, err)?;
            }
        }
        Ok(())
    }
}

impl From<Parser<'_>> for CST {
    /// Crates a [`CST`] from the given parser.
    fn from(parser: Parser) -> Self {
        let source = parser.tokens.source();
        let mut builder = GreenNodeBuilder::new();

        let mut errors = Vec::new();
        builder.start_node(SyntaxKind::SOURCE_FILE.into());

        for node in parser {
            match node {
                Event::Begin(kind) => builder.start_node(kind.into()),
                Event::End(_) => builder.finish_node(),
                Event::Token { kind, span } => {
                    // The span must within the source code, this unwrap
                    // can't fail.
                    let token = source.get(span.range()).unwrap();
                    // Tokens are always valid UTF-8, this unwrap can't
                    // fail.
                    // TODO: use from_utf8_unchecked?
                    let token = from_utf8(token).unwrap();
                    builder.token(kind.into(), token);
                }
                Event::Error { message, span } => errors.push((span, message)),
            }
        }

        builder.finish_node();

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
