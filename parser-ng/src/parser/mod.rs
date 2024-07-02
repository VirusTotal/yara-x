/*! This module contains a handwritten [PEG][1] parser for YARA rules.

The parser receives a sequence of tokens produced by the [`Tokenizer`], and
produces a Concrete Syntax-Tree ([`CST`]), also known as a lossless syntax
tree.

Under the hood, the parser uses the [rowan][2] create.

[1]: https://en.wikipedia.org/wiki/Parsing_expression_grammar
[2]: https://github.com/rust-analyzer/rowan
 */

use std::mem;

pub mod cst;

mod token_stream;

#[cfg(test)]
mod tests;

use crate::parser::cst::{Event, SyntaxKind, SyntaxStream};
use crate::parser::token_stream::TokenStream;
use crate::tokenizer::{Token, Tokenizer};
use crate::Span;

/// Produces a Concrete Syntax-Tree ([`CST`]) for a given YARA source code.
pub struct Parser<'src>(InternalParser<'src>);

impl<'src> Parser<'src> {
    /// Creates a new parser for the given source code.
    pub fn new(source: &'src [u8]) -> Self {
        Self(InternalParser::from(Tokenizer::new(source)))
    }

    /// Returns the source code passed to the parser.
    #[inline]
    pub fn source(&self) -> &'src [u8] {
        self.0.tokens.source()
    }

    /// Returns the CST as a sequence of events.
    #[inline]
    pub fn events(self) -> impl Iterator<Item = Event> + 'src {
        self.0
    }

    /// Consumes the parser and builds a Concrete Syntax Tree (CST).
    #[inline]
    pub fn build_cst(self) -> CST {
        CST::from(self)
    }
}

/// Internal implementation of the parser. The [`Parser`] type is only a
/// wrapper around this type.
struct InternalParser<'src> {
    tokens: TokenStream<'src>,
    output: SyntaxStream,
    failed: bool,
}

impl<'src> From<Tokenizer<'src>> for InternalParser<'src> {
    /// Creates a new parser that receives tokens from the given [`Tokenizer`].
    fn from(tokenizer: Tokenizer<'src>) -> Self {
        Self {
            tokens: TokenStream::new(tokenizer),
            output: SyntaxStream::new(),
            failed: false,
        }
    }
}

/// The parser behaves as an iterator that returns events of type [`Event`].
impl Iterator for InternalParser<'_> {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        // If the output buffer isn't empty, return a buffered event.
        // If the output buffer is empty and there are pending tokens, invoke
        // the parser to consume tokens and put more events in the output
        // buffer.
        //
        // Each call to `next` parses one top-level item (either an import
        // statement or rule declaration). This approach parses the source
        // code lazily, one top-level item at a time, saving memory by
        // avoiding tokenizing the entire input at once, or producing all
        // the events before they are consumed.
        if self.output.is_empty() && self.tokens.has_more() {
            let _ = self.ws();
            let _ = self.top_level_item();
        }
        self.output.pop()
    }
}

/// Parser private API.
///
/// This section contains utility functions that are used by the grammar rules.
impl<'src> InternalParser<'src> {
    /// Returns the next token, without consuming it.
    ///
    /// Returns `None` if there are no more tokens.
    fn peek(&mut self) -> Option<&Token> {
        self.tokens.peek_token(0)
    }

    /// Consumes the next token and returns it. The consumed token is also
    /// appended to the output.
    ///
    /// Returns `None` if there are no more tokens.
    fn bump(&mut self) -> Option<Token> {
        let token = self.tokens.next_token();
        match &token {
            Some(token) => self.output.push_token(token.into(), token.span()),
            None => {}
        }
        token
    }

    /// Sets a bookmark at the current parser state.
    ///
    /// This saves the current parser state, allowing the parser to try
    /// a grammar production, and if it fails, go back to the saved state
    /// and try a different grammar production.
    fn bookmark(&mut self) -> Bookmark {
        Bookmark {
            tokens: self.tokens.bookmark(),
            output: self.output.bookmark(),
        }
    }

    /// Restores the parser to the state indicated by the bookmark.
    fn restore_bookmark(&mut self, bookmark: &Bookmark) {
        self.tokens.restore_bookmark(&bookmark.tokens);
        self.output.truncate(&bookmark.output);
    }

    /// Removes a bookmark.
    ///
    /// Once a bookmark is removed the parser can't be restored to the
    /// state indicated by the bookmark.
    fn remove_bookmark(&mut self, bookmark: Bookmark) {
        self.tokens.remove_bookmark(bookmark.tokens);
        self.output.remove_bookmark(bookmark.output);
    }

    /// Indicates the start of a non-terminal symbol of a given kind.
    ///
    /// Must be followed by a matching [`Parser::end`].
    fn begin(&mut self, kind: SyntaxKind) -> &mut Self {
        self.output.begin(kind);
        self
    }

    /// Indicates the end of the non-terminal symbol that was previously
    /// started with [`Parser::begin`].
    fn end(&mut self) -> &mut Self {
        if self.failed {
            self.output.end_with_error();
        } else {
            self.output.end();
        }
        self
    }

    /// Expects one of the tokens in `expected_tokens`.
    ///
    /// If the next token is not one of the expected ones, the parser enters
    /// the failed state.
    fn expect(&mut self, expected_tokens: &[Token]) -> &mut Self {
        let token = match self.peek() {
            Some(token) => token,
            None => {
                self.failed = true;
                return self;
            }
        };
        if expected_tokens.iter().any(|expected| {
            mem::discriminant(expected) == mem::discriminant(token)
        }) {
            self.bump();
        } else {
            let span = token.span();
            self.bump();
            self.output.push_error("foo", span);
            self.failed = true;
        }
        self
    }

    fn begin_alt(&mut self) -> Alt<'_, 'src> {
        let bookmark = self.bookmark();
        Alt { parser: self, matched: false, bookmark }
    }

    fn opt<P>(&mut self, p: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        if self.failed {
            return self;
        }

        let bookmark = self.bookmark();
        p(self);

        // Any error occurred while parsing the optional production is ignored.
        if self.failed {
            self.failed = false;
            self.restore_bookmark(&bookmark);
        }

        self.remove_bookmark(bookmark);
        self
    }

    /// Matches zero or more instances of whatever the parser `P` matches.
    #[inline]
    fn zero_or_more<P>(&mut self, p: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        self.n_or_more(0, p)
    }

    /// Matches one or more instances of whatever the parser `P` matches.
    #[inline]
    fn one_or_more<P>(&mut self, p: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        self.n_or_more(1, p)
    }

    /// Matches `n` or more instances of whatever the parser `P` matches.
    fn n_or_more<P>(&mut self, n: usize, p: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        if self.failed {
            return self;
        }
        // The first N times that `f` is called it must match.
        for _ in 0..n {
            p(self);
            if self.failed {
                return self;
            }
        }
        // If the first N matches were ok, keep matching `f` as much as
        // possible.
        if !self.failed {
            loop {
                let bookmark = self.bookmark();
                p(self);
                if self.failed {
                    self.failed = false;
                    self.restore_bookmark(&bookmark);
                    self.remove_bookmark(bookmark);
                    break;
                } else {
                    self.remove_bookmark(bookmark);
                }
            }
        }
        self
    }

    fn one<P>(&mut self, p: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        if self.failed {
            return self;
        }
        p(self);
        if self.failed {
            self.failed = true;
        }
        self
    }

    /// Matches zero or more whitespaces, newlines or comments.
    fn ws(&mut self) -> &mut Self {
        if self.failed {
            return self;
        }
        while let Some(WHITESPACE(_)) | Some(NEWLINE(_)) | Some(COMMENT(_)) =
            self.peek()
        {
            self.bump();
        }
        self
    }
}

use crate::cst::{syntax_stream, CST};
use Token::*;

macro_rules! t {
    ($( $tokens:path )|*) => {
       &[$( $tokens(Span::default()) ),*]
    };
}

/// Grammar rules.
///
/// Each function in this section parses a piece of YARA source code. For
/// instance, the `import_stmt` function parses a YARA import statement,
/// `rule_decl` parses a rule declaration, etc. Usually, each function is
/// associated to a non-terminal symbol in the grammar, and the function's
/// code defines the grammar production rule for that symbol.
///
/// Let's use the following grammar rule as an example:
///
/// ```text
/// A := a B (C | D)
/// ```
///
/// `A`, `B`, `C` and `D` are non-terminal symbols, while `a` is a terminal
/// symbol (or token). This rule can be read: `A` is expanded as the token
/// `a` followed by the non-terminal symbol `B`, followed by either `C` or
/// `D`.
///
/// This rule would be expressed as:
///
/// ```text
/// fn A(&mut self) -> &mut Self {
///   self.begin(SyntaxKind::A)
///       .expect(t!(a))
///       .ws()
///       .one(|p| p.B())
///       .ws()
///       .begin_alt()
///          .alt(|p| p.C())
///          .alt(|p| p.D())
///       .end_alt()
///       .end()
/// }
/// ```
///
/// Notice the use of `ws()` to indicate where whitespace, newlines, or
/// comments are allowed. The `ws()` function accepts and consumes zero or
/// more whitespaces newlines or comments.
///
/// Also notice the use of `begin_alt` and `end_alt` for enclosing alternatives
/// like `(C | D)`. In PEG parsers the order of alternatives is important, the
/// parser tries them sequentially and accepts the first successful match.
/// Thus, a rule like `( a | a B )` is problematic because `a B` won't ever
/// match. If `a B` matches, then `a` also matches, but `a` has a higher
/// priority and prevents `a B` from matching.
impl<'src> InternalParser<'src> {
    /// Parses a top-level item in YARA source file.
    ///
    /// A top-level item is either an import statement or a rule declaration.
    ///
    /// ```text
    /// TOP_LEVEL_ITEM ::= ( IMPORT_STMT | RULE_DECL )
    /// ```
    fn top_level_item(&mut self) -> &mut Self {
        let token = match self.peek() {
            Some(token) => token,
            None => {
                self.failed = true;
                return self;
            }
        };
        match token {
            IMPORT_KW(_) => self.import_stmt(),
            GLOBAL_KW(_) | PRIVATE_KW(_) | RULE_KW(_) => self.rule_decl(),
            token => {
                let span = token.span();
                self.output.push_error(
                    "expecting import statement or rule definition",
                    span,
                );
                self.output.begin(SyntaxKind::ERROR);
                self.bump();
                self.output.end();
                self.failed = true;
                self
            }
        }
    }

    /// Parses an import statement.
    ///
    /// ```text
    /// IMPORT_STMT ::= `import` STRING_LIT
    /// ```
    fn import_stmt(&mut self) -> &mut Self {
        self.begin(SyntaxKind::IMPORT_STMT)
            .expect(t!(IMPORT_KW))
            .ws()
            .expect(t!(STRING_LIT))
            .end()
    }

    /// Parses a rule declaration.
    ///
    /// ```text
    /// RULE_DECL ::= RULE_MODS? `rule` IDENT `{`
    ///   META_DEF?
    ///   `condition` `:` BOOLEAN_EXPR
    /// `}`
    /// ```
    fn rule_decl(&mut self) -> &mut Self {
        self.begin(SyntaxKind::RULE_DECL)
            .opt(|p| p.rule_mods())
            .ws()
            .expect(t!(RULE_KW))
            .ws()
            .expect(t!(IDENT))
            .ws()
            .expect(t!(L_BRACE))
            .ws()
            .opt(|p| p.meta_defs())
            .ws()
            .opt(|p| p.pattern_defs())
            .ws()
            .expect(t!(CONDITION_KW))
            .ws()
            .expect(t!(COLON))
            .ws()
            .one(|p| p.boolean_expr())
            .ws()
            .expect(t!(R_BRACE))
            .end()
    }

    /// Parses rule modifiers.
    ///
    /// ```text
    /// RULE_MODS := ( `private` `global`? | `global` `private`? )
    /// ```
    fn rule_mods(&mut self) -> &mut Self {
        self.begin(SyntaxKind::RULE_MODS)
            .begin_alt()
            .alt(|p| {
                p.expect(t!(PRIVATE_KW)).opt(|p| p.ws().expect(t!(GLOBAL_KW)))
            })
            .alt(|p| {
                p.expect(t!(GLOBAL_KW)).opt(|p| p.ws().expect(t!(PRIVATE_KW)))
            })
            .end_alt()
            .end()
    }

    /// Parses metadata definitions
    ///
    /// ```text
    /// META_DEFS :=  `meta` `:` META_DEF+
    /// ``
    fn meta_defs(&mut self) -> &mut Self {
        self.begin(SyntaxKind::META_DEFS)
            .expect(t!(META_KW))
            .ws()
            .expect(t!(COLON))
            .ws()
            .one_or_more(|p| p.meta_def())
            .end()
    }

    /// Parses a metadata definition
    ///
    /// ```text
    /// META_DEF := IDENT `=` (
    ///     `true`      |
    ///     `false`     |
    ///     INTEGER_LIT |
    ///     FLOAT_LIT   |
    ///     STRING_LIT
    /// )
    /// ``
    fn meta_def(&mut self) -> &mut Self {
        self.begin(SyntaxKind::META_DEF)
            .expect(t!(IDENT))
            .ws()
            .expect(t!(EQUAL))
            .ws()
            .expect(t!(TRUE_KW
                | FALSE_KW
                | INTEGER_LIT
                | FLOAT_LIT
                | STRING_LIT))
            .end()
    }

    fn pattern_defs(&mut self) -> &mut Self {
        // TODO
        self
    }

    fn pattern_def(&mut self) -> &mut Self {
        todo!()
    }

    fn pattern_mods(&mut self) -> &mut Self {
        todo!()
    }

    fn hex_pattern(&mut self) -> &mut Self {
        todo!()
    }

    fn hex_tokens(&mut self) -> &mut Self {
        todo!()
    }

    fn hex_alternative(&mut self) -> &mut Self {
        todo!()
    }

    fn hex_jump(&mut self) -> &mut Self {
        todo!()
    }

    /// Parses a boolean expression.
    ///
    /// ```text
    /// BOOLEAN_EXPR := BOOLEAN_TERM ((AND_KW | OR_KW) BOOLEAN_TERM)*
    /// ``
    fn boolean_expr(&mut self) -> &mut Self {
        self.begin(SyntaxKind::BOOLEAN_EXPR)
            .one(|p| p.boolean_term())
            .zero_or_more(|p| {
                p.ws()
                    .expect(t!(AND_KW | OR_KW))
                    .ws()
                    .one(|p| p.boolean_term())
            })
            .end()
    }

    /// Parses a boolean term.
    ///
    /// ```text
    /// BOOLEAN_TERM := (
    ///    TRUE_KW |
    ///    FALSE_KW
    /// )
    /// ``
    fn boolean_term(&mut self) -> &mut Self {
        self.begin(SyntaxKind::BOOLEAN_TERM)
            .begin_alt()
            .alt(|p| p.expect(t!(TRUE_KW)))
            .alt(|p| p.expect(t!(FALSE_KW)))
            .end_alt()
            .end()
    }

    fn expr(&mut self) -> &mut Self {
        todo!()
    }

    fn term(&mut self) -> &mut Self {
        todo!()
    }
}

struct Bookmark {
    tokens: token_stream::Bookmark,
    output: syntax_stream::Bookmark,
}

struct Alt<'a, 'src> {
    parser: &'a mut InternalParser<'src>,
    matched: bool,
    bookmark: Bookmark,
}

impl<'a, 'src> Alt<'a, 'src> {
    fn alt<F>(mut self, f: F) -> Self
    where
        F: Fn(&'a mut InternalParser<'src>) -> &'a mut InternalParser<'src>,
    {
        if self.parser.failed {
            return self;
        }
        // Don't try to match the current alternative if the parser a previous one
        // already matched.
        if !self.matched {
            self.parser = f(self.parser);
            match self.parser.failed {
                // The current alternative matched.
                false => {
                    self.matched = true;
                }
                // The current alternative didn't match, restore the token
                // stream to the position it has before trying to match.
                true => {
                    self.parser.failed = false;
                    self.parser.restore_bookmark(&self.bookmark);
                }
            };
        }
        self
    }

    fn end_alt(self) -> &'a mut InternalParser<'src> {
        self.parser.remove_bookmark(self.bookmark);
        // If none of the alternatives matched, that's a failure.
        self.parser.failed = !self.matched;
        self.parser
    }
}
