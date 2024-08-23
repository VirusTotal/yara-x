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
 */
use rowan::{GreenNodeBuilder, GreenToken, SyntaxNode};
use std::fmt::{Debug, Display, Formatter};
use std::iter;
use std::marker::PhantomData;
use std::str::from_utf8;

use crate::cst::SyntaxKind::{COMMENT, NEWLINE, WHITESPACE};
use crate::{Parser, Span};

pub use syntax_kind::SyntaxKind;

pub(crate) mod syntax_kind;
pub(crate) mod syntax_stream;

#[cfg(test)]
mod tests;

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
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[doc(hidden)]
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
    ///
    /// The node is initially immutable, but it can be converted into a mutable
    /// one by calling [`Node::into_mut`].
    pub fn root(&self) -> Node<Immutable> {
        Node::new(self.tree.clone())
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
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[doc(hidden)]
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
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[derive(PartialEq, Eq)]
#[doc(hidden)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct Mutable;

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct Immutable;

/// A token in the CST.
///
/// Tokens are the leaves of the tree, which correspond to terminal symbols in
/// the grammar, such as keywords, identifiers, whitespaces, punctuation, etc.
///
/// The inner (non-leave) nodes in the CST are of type [`Node`].
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[derive(PartialEq, Eq)]
#[doc(hidden)]
pub struct Token<M> {
    inner: rowan::SyntaxToken<YARA>,
    _state: PhantomData<M>,
}

impl<M> Token<M> {
    fn new(inner: rowan::SyntaxToken<YARA>) -> Self {
        Self { inner, _state: PhantomData }
    }
}

impl<M> Token<M> {
    #[inline]
    /// Returns the kind of this token.
    pub fn kind(&self) -> SyntaxKind {
        self.inner.kind()
    }

    #[inline]
    /// Returns the token as a string.
    pub fn text(&self) -> &str {
        self.inner.text()
    }

    /// Returns the span of the token.
    #[inline]
    pub fn span(&self) -> Span {
        Span(self.inner.text_range().into())
    }

    #[inline]
    /// Returns the parent of this token.
    pub fn parent(&self) -> Option<Node<M>> {
        self.inner.parent().map(Node::new)
    }

    /// Returns the ancestors of this token.
    ///
    /// The first one is the token's parent, then token's grandparent,
    /// and so on.
    pub fn ancestors(&self) -> impl Iterator<Item = Node<M>> {
        self.inner.parent_ancestors().map(Node::new)
    }

    /// Returns the token before the current one.
    ///
    /// The token before the current one is not necessary a sibling of the
    /// current one. This function performs a depth-first traversal of the CST,
    /// returning tokens right-to-left.
    ///
    /// ```rust
    /// # use yara_x_parser::cst::SyntaxKind;
    /// # use yara_x_parser::Parser;
    /// let mut token = Parser::new(b"rule test {condition:true}")
    ///     .into_cst()
    ///     .root()
    ///     .last_token()
    ///     .unwrap();
    ///
    /// assert_eq!(token.kind(), SyntaxKind::R_BRACE);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::TRUE_KW);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::COLON);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::CONDITION_KW);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::L_BRACE);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::WHITESPACE);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::IDENT);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::WHITESPACE);
    /// token = token.prev_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::RULE_KW);
    /// assert_eq!(token.prev_token(), None);
    /// ```
    #[inline]
    pub fn prev_token(&self) -> Option<Token<M>> {
        self.inner.prev_token().map(Token::new)
    }

    /// Returns the token after the current one.
    ///
    /// The next token is not necessary a sibling of the current one. This
    /// function performs a depth-first traversal of the CST, returning
    /// tokens left-to-right.
    ///
    /// ```rust
    /// # use yara_x_parser::cst::SyntaxKind;
    /// # use yara_x_parser::Parser;
    /// let mut token = Parser::new(b"rule test {condition:true}")
    ///     .into_cst()
    ///     .root()
    ///     .first_token()
    ///     .unwrap();
    ///
    /// assert_eq!(token.kind(), SyntaxKind::RULE_KW);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::WHITESPACE);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::IDENT);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::WHITESPACE);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::L_BRACE);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::CONDITION_KW);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::COLON);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::TRUE_KW);
    /// token = token.next_token().unwrap();
    /// assert_eq!(token.kind(), SyntaxKind::R_BRACE);
    /// assert_eq!(token.next_token(), None);
    /// ```
    #[inline]
    pub fn next_token(&self) -> Option<Token<M>> {
        self.inner.next_token().map(Token::new)
    }

    /// Returns the previous sibling in the tree.
    #[inline]
    pub fn prev_sibling_or_token(&self) -> Option<NodeOrToken<M>> {
        self.inner.prev_sibling_or_token().map(|x| x.into())
    }

    /// Returns the next sibling in the tree.
    #[inline]
    pub fn next_sibling_or_token(&self) -> Option<NodeOrToken<M>> {
        self.inner.next_sibling_or_token().map(|x| x.into())
    }
}

impl<M> Display for Token<M> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl<M> Debug for Token<M> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.inner, f)
    }
}

impl Token<Mutable> {
    #[inline]
    /// Detach the token from the CST it belongs to.
    pub fn detach(&self) {
        self.inner.detach()
    }

    pub fn replace(&mut self, text: &str) -> Node<Mutable> {
        Node::new(SyntaxNode::new_root(
            self.inner.replace_with(GreenToken::new(self.kind().into(), text)),
        ))
    }
}

/// Either a  [`Node`] or a [`Token`].
///
/// In a CST, nodes are the inner nodes of the tree, leaves are tokens.
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[derive(PartialEq, Eq, Debug)]
#[doc(hidden)]
pub enum NodeOrToken<M> {
    Node(Node<M>),
    Token(Token<M>),
}

impl<M> NodeOrToken<M> {
    /// Returns the kind of this node or token.
    pub fn kind(&self) -> SyntaxKind {
        match self {
            NodeOrToken::Node(n) => n.kind(),
            NodeOrToken::Token(t) => t.kind(),
        }
    }

    /// Returns the parent of this node or token.
    pub fn parent(&self) -> Option<Node<M>> {
        match self {
            NodeOrToken::Node(n) => n.parent(),
            NodeOrToken::Token(t) => t.parent(),
        }
    }

    /// Returns the ancestors of this node or token.
    pub fn ancestors(&self) -> impl Iterator<Item = Node<M>> {
        let first = match self {
            NodeOrToken::Node(n) => n.parent(),
            NodeOrToken::Token(t) => t.parent(),
        };
        iter::successors(first, Node::parent)
    }

    /// Returns the previous sibling of this node or token.
    pub fn prev_sibling_or_token(&self) -> Option<NodeOrToken<M>> {
        match self {
            NodeOrToken::Node(n) => n.prev_sibling_or_token(),
            NodeOrToken::Token(t) => t.prev_sibling_or_token(),
        }
    }

    /// Returns the previous sibling of this node or token
    pub fn next_sibling_or_token(&self) -> Option<NodeOrToken<M>> {
        match self {
            NodeOrToken::Node(n) => n.next_sibling_or_token(),
            NodeOrToken::Token(t) => t.next_sibling_or_token(),
        }
    }
}

impl NodeOrToken<Mutable> {
    /// Detach the node or token from the CST it belongs to.
    pub fn detach(&self) {
        match self {
            NodeOrToken::Node(n) => n.detach(),
            NodeOrToken::Token(t) => t.detach(),
        }
    }
}

#[doc(hidden)]
impl<M> From<rowan::SyntaxElement<YARA>> for NodeOrToken<M> {
    fn from(value: rowan::SyntaxElement<YARA>) -> Self {
        match value {
            rowan::SyntaxElement::Node(node) => Self::Node(Node::new(node)),
            rowan::SyntaxElement::Token(token) => {
                Self::Token(Token::new(token))
            }
        }
    }
}

#[doc(hidden)]
impl<M> From<NodeOrToken<M>> for rowan::SyntaxElement<YARA> {
    fn from(value: NodeOrToken<M>) -> Self {
        match value {
            NodeOrToken::Node(n) => rowan::SyntaxElement::Node(n.inner),
            NodeOrToken::Token(t) => rowan::SyntaxElement::Token(t.inner),
        }
    }
}

/// A node in the CST.
///
/// Nodes are the inner (non-leave) nodes of the tree, which correspond to
/// non-terminal symbols in the grammar.
///
/// The leaves in a CST are of type [`Token`].
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct Node<M> {
    inner: rowan::SyntaxNode<YARA>,
    _mutability: PhantomData<M>,
}

impl<M> Node<M> {
    fn new(inner: rowan::SyntaxNode<YARA>) -> Self {
        Self { inner, _mutability: PhantomData }
    }
}

impl<M> Node<M> {
    /// Returns the kind of this node.
    pub fn kind(&self) -> SyntaxKind {
        self.inner.kind()
    }

    /// Returns the text of this node.
    pub fn text(&self) -> Text {
        Text(self.inner.text())
    }

    /// Returns the span of this node.
    pub fn span(&self) -> Span {
        Span(self.inner.text_range().into())
    }

    /// Returns the parent of this node.
    ///
    /// The result is [`None`] if this is the root node.
    pub fn parent(&self) -> Option<Node<M>> {
        self.inner.parent().map(Node::new)
    }

    /// Returns the ancestors of this node.
    ///
    /// The first one is this node's parent, then node's grandparent,
    /// and so on.
    pub fn ancestors(&self) -> impl Iterator<Item = Node<M>> {
        iter::successors(self.parent(), Node::parent)
    }

    /// Returns the children of this node.
    pub fn children(&self) -> Nodes<M> {
        Nodes { inner: self.inner.children(), _mutability: PhantomData }
    }

    /// Returns the children of this node, including tokens.
    pub fn children_with_tokens(&self) -> NodesAndTokens<M> {
        NodesAndTokens {
            inner: self.inner.children_with_tokens(),
            _mutability: PhantomData,
        }
    }

    /// Returns the first child of this node.
    pub fn first_child(&self) -> Option<Node<M>> {
        self.inner.first_child().map(Node::new)
    }

    /// Returns the last child of this node.
    pub fn last_child(&self) -> Option<Node<M>> {
        self.inner.last_child().map(Node::new)
    }

    /// Returns the first token of this node.
    ///
    /// The token returned is not necessarily a children of this node, this
    /// function will perform depth-first traversal of the tree and will
    /// return the left-most token that is a descendant of this node.
    pub fn first_token(&self) -> Option<Token<M>> {
        self.inner.first_token().map(Token::new)
    }

    /// Returns the last token of this node.
    ///
    /// The token returned is not necessarily a children of this node, this
    /// function will perform depth-first traversal of the tree and will
    /// return the right-most token that is a descendant of this node.
    pub fn last_token(&self) -> Option<Token<M>> {
        self.inner.last_token().map(Token::new)
    }

    /// Returns the first child or token of this node.
    pub fn first_child_or_token(&self) -> Option<NodeOrToken<M>> {
        self.inner.first_child_or_token().map(|x| x.into())
    }

    /// Returns the last child or token of this node.
    pub fn last_child_or_token(&self) -> Option<NodeOrToken<M>> {
        self.inner.last_child_or_token().map(|x| x.into())
    }

    /// Returns the next sibling of this node.
    pub fn next_sibling(&self) -> Option<Node<M>> {
        self.inner.next_sibling().map(Node::new)
    }

    /// Returns the previous sibling of this node.
    pub fn prev_sibling(&self) -> Option<Node<M>> {
        self.inner.prev_sibling().map(Node::new)
    }

    /// Returns the next sibling or token of this node.
    pub fn next_sibling_or_token(&self) -> Option<NodeOrToken<M>> {
        self.inner.next_sibling_or_token().map(|x| x.into())
    }

    /// Returns the previous sibling or token of this node.
    pub fn prev_sibling_or_token(&self) -> Option<NodeOrToken<M>> {
        self.inner.prev_sibling_or_token().map(|x| x.into())
    }

    /// Returns an iterator over the siblings of this node.
    ///
    /// ```rust
    /// # use yara_x_parser::cst::{Direction, SyntaxKind};
    /// # use yara_x_parser::Parser;
    /// // Get the first child of the root node, which corresponds to the
    /// // rule declaration for `test_1`.
    /// let mut rule_decl = Parser::new(b"
    /// rule test_1 {condition:true}
    /// rule test_2 {condition:true}
    /// ")
    ///     .into_cst()
    ///     .root()
    ///     .first_child()
    ///     .unwrap();
    ///
    /// // The rule `test_1` doesn't have any previous sibling.
    /// let mut sibilings = rule_decl.siblings(Direction::Prev);
    /// assert_eq!(sibilings.next(), None);    ///
    ///
    /// // The rule only sibling after `test_1` is the rule declaration
    /// // for `test_2`.
    /// let mut sibilings = rule_decl.siblings(Direction::Next);
    /// assert_eq!(sibilings.next().map(|node| node.kind()), Some(SyntaxKind::RULE_DECL));
    /// assert_eq!(sibilings.next().map(|node| node.kind()), None);
    /// ```
    pub fn siblings(
        &self,
        direction: Direction,
    ) -> impl Iterator<Item = Node<M>> {
        let direction = match direction {
            Direction::Next => rowan::Direction::Next,
            Direction::Prev => rowan::Direction::Prev,
        };
        // `inner.siblings()` always returns the current node as the first
        // sibling. To me, this is not really helpful, and causes confusion
        // to the API users, so we skip the current node and return only the
        // real siblings.
        self.inner.siblings(direction).skip(1).map(Node::new)
    }

    /// Returns an iterator over the siblings of this node, including tokens.
    ///
    /// Depending on the direction it will return the previous siblings or the
    /// next siblings.
    ///
    /// ```rust
    /// # use yara_x_parser::cst::{Direction, SyntaxKind};
    /// # use yara_x_parser::Parser;     ///
    /// // Get the first child of the root node, which corresponds to the
    /// // rule declaration for `test_1`.
    /// let mut rule_decl = Parser::new(b"
    /// rule test_1 {condition:true}
    /// rule test_2 {condition:true}
    /// ")
    ///     .into_cst()
    ///     .root()
    ///     .first_child()
    ///     .unwrap();
    ///
    /// // The rule `test_1` doesn't have any sibling node before it, but
    /// // there's a newline token before it.
    /// let mut sibilings = rule_decl.siblings_with_tokens(Direction::Prev);
    /// assert_eq!(sibilings.next().map(|node| node.kind()), Some(SyntaxKind::NEWLINE));
    /// assert_eq!(sibilings.next(), None);
    ///
    /// // After the rule `test_1` there's a newline token, followed by the rule
    /// // declaration node for `test_2`, and then another newline.
    /// let mut sibilings = rule_decl.siblings_with_tokens(Direction::Next);
    /// assert_eq!(sibilings.next().map(|node| node.kind()), Some(SyntaxKind::NEWLINE));
    /// assert_eq!(sibilings.next().map(|node| node.kind()), Some(SyntaxKind::RULE_DECL));
    /// assert_eq!(sibilings.next().map(|node| node.kind()), Some(SyntaxKind::NEWLINE));
    /// assert_eq!(sibilings.next().map(|node| node.kind()), None);
    /// ```
    pub fn siblings_with_tokens(
        &self,
        direction: Direction,
    ) -> impl Iterator<Item = NodeOrToken<M>> {
        let direction = match direction {
            Direction::Next => rowan::Direction::Next,
            Direction::Prev => rowan::Direction::Prev,
        };
        // `inner.siblings()` always returns the current node as the first
        // sibling. To me, this is not really helpful, and causes confusion
        // to the API users, so we skip the current node and return only the
        // real siblings.
        self.inner.siblings_with_tokens(direction).skip(1).map(|x| x.into())
    }
}

impl Node<Immutable> {
    /// Converts an immutable node into a mutable one.
    pub fn into_mut(self) -> Node<Mutable> {
        Node::new(self.inner.clone_for_update())
    }
}

impl Node<Mutable> {
    /// Detach the node from the CST it belongs to.
    pub fn detach(&self) {
        self.inner.detach()
    }
}

/// An iterator that returns the children of a CST node, including only
/// nodes, not tokens.
///
/// This is the value returned by [`Node::children`].
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[doc(hidden)]
pub struct Nodes<M> {
    inner: rowan::SyntaxNodeChildren<YARA>,
    _mutability: PhantomData<M>,
}

impl<M> Iterator for Nodes<M> {
    type Item = Node<M>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Node::new)
    }
}

/// An iterator that returns the children of a CST node, including both nodes
/// and tokens.
///
/// This is the value returned by [`Node::children_with_tokens`].
///
/// NOTE: This API is still unstable and should not be used by third-party code.
#[doc(hidden)]
pub struct NodesAndTokens<M> {
    inner: rowan::SyntaxElementChildren<YARA>,
    _mutability: PhantomData<M>,
}

impl<M> Iterator for NodesAndTokens<M> {
    type Item = NodeOrToken<M>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|x| x.into())
    }
}
