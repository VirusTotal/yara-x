/*! Concrete Syntax Tree (CST) for YARA rules.

A Concrete Syntax Tree (CST), also known as a lossless syntax tree, is a
detailed representation of the source code that retains all aspects, including
punctuation, spacing, and comments. This makes the CST ideal for traversing
the source code exactly as it appears in its original form.

CSTs are typically used in code formatters, documentation generators, source
code analysis tools, and similar applications. However, a key limitation is
that the CST does not account for operator associativity or precedence rules.
Expressions are represented in the CST exactly as they appear in the source
code, without any grouping based on operator precedence.

# Tokens and nodes

In a CST, there is a clear distinction between tokens and nodes. All leaves in
a CST are tokens, each representing a keyword, identifier, comment, punctuation
symbol, delimiter, etc. Conversely, nodes are the inner (non-leaf) components
of the CST, corresponding to non-terminal symbols in the grammar, such as rule
declarations, expressions, import statements, and more.
 */
use rowan::GreenNodeBuilder;
use std::fmt::{Debug, Display, Formatter};
use std::iter;
use std::str::from_utf8;

use crate::{Parser, Span};

pub(crate) mod syntax_kind;
pub(crate) mod syntax_stream;

#[cfg(test)]
mod tests;

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

/// A CST represented as a stream of events.
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

/// A Concrete Syntax Tree (CST).
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

impl CST {
    /// Returns the root node of the CST.
    pub fn root(&self) -> Node {
        Node(self.tree.clone())
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

/// Sibling traversal direction.
pub enum Direction {
    Next,
    Prev,
}

/// Represents the source code covered by a portion of the CST.
///
/// In a CST, each [`Token`] owns a text string containing the source
/// code for that token. As a result, there isn't a single contiguous
/// block of memory that contains all the source code, which means it
/// cannot be represented as a single [`String`].
///
/// Instead, we use the [`Text`] type to represent a logically
/// contiguous portion of the code, even though it is physically
/// composed of non-contiguous chunks, each owned by a [`Token`].
#[derive(PartialEq, Eq)]
pub struct Text(rowan::SyntaxText);

impl Text {
    /// Returns the length of the text.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len().into()
    }

    /// Returns true if the text is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Folds every chunk in text into an accumulator by applying an operation
    /// returning the final result.
    #[inline]
    pub fn try_fold_chunks<T, F, E>(&self, init: T, f: F) -> Result<T, E>
    where
        F: FnMut(T, &str) -> Result<T, E>,
    {
        self.0.try_fold_chunks(init, f)
    }

    /// Applies a fallible function `f` to each chunk in the text, stopping at
    /// the first error and returning that error.
    pub fn try_for_each_chunks<F, E>(&self, f: F) -> Result<(), E>
    where
        F: FnMut(&str) -> Result<(), E>,
    {
        self.0.try_for_each_chunk(f)
    }

    /// Applies a function `f` to each chunk in the text.
    pub fn for_each_chunks<F>(&self, f: F)
    where
        F: FnMut(&str),
    {
        self.0.for_each_chunk(f)
    }
}

impl Display for Text {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl Debug for Text {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl PartialEq<Text> for str {
    fn eq(&self, other: &Text) -> bool {
        other.0 == self
    }
}

impl PartialEq<Text> for &str {
    fn eq(&self, other: &Text) -> bool {
        other == self
    }
}

impl PartialEq<&'_ str> for Text {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A token in the CST.
///
/// Tokens are the leaves of the tree, which correspond to terminal symbols in
/// the grammar, such as keywords, identifiers, whitespaces, punctuation, etc.
///
/// The inner (non-leave) nodes in the CST are of type [`Node`].
#[derive(PartialEq, Eq)]
pub struct Token(rowan::SyntaxToken<YARA>);

impl Token {
    #[inline]
    /// Returns the kind of this token.
    pub fn kind(&self) -> SyntaxKind {
        self.0.kind()
    }

    #[inline]
    /// Returns the token as a string.
    pub fn text(&self) -> &str {
        self.0.text()
    }

    /// Returns the span of the token.
    #[inline]
    pub fn span(&self) -> Span {
        Span(self.0.text_range().into())
    }

    #[inline]
    /// Returns the parent of this token.
    pub fn parent(&self) -> Option<Node> {
        self.0.parent().map(Node)
    }

    /// Returns the ancestors of this token.
    ///
    /// The first one is the token's parent, then token's grandparent,
    /// and so on.
    pub fn ancestors(&self) -> impl Iterator<Item = Node> {
        self.0.parent_ancestors().map(Node)
    }

    /// Returns the previous token in the tree.
    ///
    /// The previous token is not necessary a sibling.
    #[inline]
    pub fn prev_token(&self) -> Option<Token> {
        self.0.prev_token().map(Token)
    }

    /// Returns the next token in the tree.
    ///
    /// The next token is not necessary a sibling.
    #[inline]
    pub fn next_token(&self) -> Option<Token> {
        self.0.next_token().map(Token)
    }

    /// Returns the previous sibling in the tree.
    #[inline]
    pub fn prev_sibling_or_token(&self) -> Option<NodeOrToken> {
        self.0.prev_sibling_or_token().map(|x| x.into())
    }

    /// Returns the next sibling in the tree.
    #[inline]
    pub fn next_sibling_or_token(&self) -> Option<NodeOrToken> {
        self.0.next_sibling_or_token().map(|x| x.into())
    }
}

impl Display for Token {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl Debug for Token {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

/// Either a  [`Node`] or a [`Token`].
///
/// In a CST, nodes are the inner nodes of the tree, leaves are tokens.
#[derive(PartialEq, Eq)]
pub enum NodeOrToken {
    Node(Node),
    Token(Token),
}

impl NodeOrToken {
    /// Returns the kind of this node or token.
    pub fn kind(&self) -> SyntaxKind {
        match self {
            NodeOrToken::Node(n) => n.kind(),
            NodeOrToken::Token(t) => t.kind(),
        }
    }

    /// Returns the parent of this node or token.
    pub fn parent(&self) -> Option<Node> {
        match self {
            NodeOrToken::Node(n) => n.parent(),
            NodeOrToken::Token(t) => t.parent(),
        }
    }

    /// Returns the ancestors of this node or token.
    pub fn ancestors(&self) -> impl Iterator<Item = Node> {
        let first = match self {
            NodeOrToken::Node(n) => n.parent(),
            NodeOrToken::Token(t) => t.parent(),
        };
        iter::successors(first, Node::parent)
    }

    /// Returns the previous sibling of this node or token.
    pub fn prev_sibling_or_token(&self) -> Option<NodeOrToken> {
        match self {
            NodeOrToken::Node(n) => n.prev_sibling_or_token(),
            NodeOrToken::Token(t) => t.prev_sibling_or_token(),
        }
    }

    /// Returns the previous sibling of this node or token
    pub fn next_sibling_or_token(&self) -> Option<NodeOrToken> {
        match self {
            NodeOrToken::Node(n) => n.next_sibling_or_token(),
            NodeOrToken::Token(t) => t.next_sibling_or_token(),
        }
    }
}

#[doc(hidden)]
impl From<rowan::SyntaxElement<YARA>> for NodeOrToken {
    fn from(value: rowan::SyntaxElement<YARA>) -> Self {
        match value {
            rowan::SyntaxElement::Node(node) => Self::Node(Node(node)),
            rowan::SyntaxElement::Token(token) => Self::Token(Token(token)),
        }
    }
}

/// A node in the CST.
///
/// Nodes are the inner (non-leave) nodes of the tree, which correspond to
/// non-terminal symbols in the grammar.
///
/// The leaves in a CST are of type [`Token`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node(rowan::SyntaxNode<YARA>);

impl Node {
    /// Returns the kind of this node.
    pub fn kind(&self) -> SyntaxKind {
        self.0.kind()
    }

    /// Returns the text of this node.
    pub fn text(&self) -> Text {
        Text(self.0.text())
    }

    /// Returns the span of this node.
    pub fn span(&self) -> Span {
        Span(self.0.text_range().into())
    }

    /// Returns the parent of this node.
    ///
    /// The result is [`None`] if this is the root node.
    pub fn parent(&self) -> Option<Node> {
        self.0.parent().map(Node)
    }

    /// Returns the ancestors of this node.
    ///
    /// The first one is this node's parent, then node's grandparent,
    /// and so on.
    pub fn ancestors(&self) -> impl Iterator<Item = Node> {
        iter::successors(self.parent(), Node::parent)
    }

    /// Returns the children of this node.
    pub fn children(&self) -> Nodes {
        Nodes(self.0.children())
    }

    /// Returns the children of this node, including tokens.
    pub fn children_with_tokens(&self) -> NodesAndTokens {
        NodesAndTokens(self.0.children_with_tokens())
    }

    /// Returns the first child of this node.
    pub fn first_child(&self) -> Option<Node> {
        self.0.first_child().map(Node)
    }

    /// Returns the last child of this node.
    pub fn last_child(&self) -> Option<Node> {
        self.0.last_child().map(Node)
    }

    /// Returns the first token of this node.
    pub fn first_token(&self) -> Option<Token> {
        self.0.first_token().map(Token)
    }

    /// Returns the last token of this node.
    pub fn last_token(&self) -> Option<Token> {
        self.0.last_token().map(Token)
    }

    /// Returns the first child or token of this node.
    pub fn first_child_or_token(&self) -> Option<NodeOrToken> {
        self.0.first_child_or_token().map(|x| x.into())
    }

    /// Returns the last child or token of this node.
    pub fn first_last_or_token(&self) -> Option<NodeOrToken> {
        self.0.last_child_or_token().map(|x| x.into())
    }

    /// Returns the next sibling of this node.
    pub fn next_sibling(&self) -> Option<Node> {
        self.0.next_sibling().map(Node)
    }

    /// Returns the previous sibling of this node.
    pub fn prev_sibling(&self) -> Option<Node> {
        self.0.prev_sibling().map(Node)
    }

    /// Returns the next sibling or token of this node.
    pub fn next_sibling_or_token(&self) -> Option<NodeOrToken> {
        self.0.next_sibling_or_token().map(|x| x.into())
    }

    /// Returns the previous sibling or token of this node.
    pub fn prev_sibling_or_token(&self) -> Option<NodeOrToken> {
        self.0.prev_sibling_or_token().map(|x| x.into())
    }

    /// Returns an iterator over the siblings of this node.
    pub fn siblings(
        &self,
        direction: Direction,
    ) -> impl Iterator<Item = Node> {
        let direction = match direction {
            Direction::Next => rowan::Direction::Next,
            Direction::Prev => rowan::Direction::Prev,
        };
        self.0.siblings(direction).map(Node)
    }

    /// Returns an iterator over the siblings of this node, including tokens.
    pub fn siblings_with_tokens(
        &self,
        direction: Direction,
    ) -> impl Iterator<Item = NodeOrToken> {
        let direction = match direction {
            Direction::Next => rowan::Direction::Next,
            Direction::Prev => rowan::Direction::Prev,
        };
        self.0.siblings_with_tokens(direction).map(|x| x.into())
    }
}

/// An iterator that returns the children of a CST node, including only
/// nodes, not tokens.
///
/// This is the value returned by [`Node::children`].
pub struct Nodes(rowan::SyntaxNodeChildren<YARA>);

impl Iterator for Nodes {
    type Item = Node;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Node)
    }
}

/// An iterator that returns the children of a CST node, including both nodes
/// and tokens.
///
/// This is the value returned by [`Node::children_with_tokens`].
pub struct NodesAndTokens(rowan::SyntaxElementChildren<YARA>);

impl Iterator for NodesAndTokens {
    type Item = NodeOrToken;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|x| x.into())
    }
}
