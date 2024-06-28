/*! This module contains a handwritten [PEG][1] parser for YARA rules.

The parser receives a sequence of tokens produced by the [`Tokenizer`], and
produces a Concrete Syntax-Tree ([`CST`]), also known as lossless syntax
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

enum Error {
    NoMatch,
}

type ParseResult = Result<(), Error>;

/// Produces a Concrete Syntax-Tree ([`CST`]) for a given YARA source code.
pub struct Parser<'src> {
    tokens: TokenStream<'src>,
    output: SyntaxStream,
}

impl<'src> Parser<'src> {
    /// Creates a new parser for the given source code.
    pub fn new(source: &'src [u8]) -> Self {
        Self {
            tokens: TokenStream::new(Tokenizer::new(source)),
            output: SyntaxStream::new(),
        }
    }

    /// Consumes the parser and builds a Concrete Syntax Tree (CST).
    pub fn build_cst(self) -> CST {
        CST::from(self)
    }
}

impl<'src> From<Tokenizer<'src>> for Parser<'src> {
    /// Creates a new parser that receives tokens from the given [`Tokenizer`].
    fn from(tokenizer: Tokenizer<'src>) -> Self {
        Self {
            tokens: TokenStream::new(tokenizer),
            output: SyntaxStream::new(),
        }
    }
}

impl<'src> Iterator for Parser<'src> {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        // When the output buffer is not empty, return one of buffered
        // events. When the output buffer is empty and there are pending
        // tokens, invoke the parser so that it consumes more tokens and
        // produce events.
        if self.output.is_empty() && self.tokens.has_more() {
            let _ = self.ws();
            let _ = self.top_level_item();
        }
        self.output.pop()
    }
}

// Parser private API.
//
// This section contains utility functions that are used by the grammar rules.
impl<'src> Parser<'src> {
    fn begin<'a>(&'a mut self, kind: SyntaxKind) -> ParserRule<'a, 'src> {
        ParserRule::new(self).begin(kind)
    }

    fn bookmark(&mut self) -> Bookmark {
        Bookmark {
            tokens: self.tokens.bookmark(),
            output: self.output.bookmark(),
        }
    }

    fn restore(&mut self, bookmark: &Bookmark) {
        self.tokens.restore(&bookmark.tokens);
        self.output.truncate(&bookmark.output);
    }

    fn drop(&mut self, bookmark: Bookmark) {
        self.tokens.drop(bookmark.tokens);
        self.output.drop(bookmark.output);
    }

    fn peek(&mut self) -> Option<&Token> {
        self.tokens.peek_token(0)
    }

    fn bump(&mut self) -> Option<Token> {
        let token = self.tokens.next_token();
        match &token {
            Some(token) => self.output.push_token(token.into(), token.span()),
            None => {}
        }
        token
    }

    fn expect(&mut self, expected_tokens: &[Token]) -> ParseResult {
        let token = self.peek().ok_or(NoMatch)?;
        if expected_tokens.iter().any(|expected| {
            mem::discriminant(expected) == mem::discriminant(token)
        }) {
            self.bump();
            Ok(())
        } else {
            let span = token.span();
            self.bump();
            self.output.push_error("foo", span);
            Err(NoMatch)
        }
    }

    fn expect_opt(&mut self, expected_tokens: &[Token]) -> ParseResult {
        match self.peek() {
            Some(token) => {
                if expected_tokens.iter().any(|expected| {
                    mem::discriminant(expected) == mem::discriminant(token)
                }) {
                    self.bump();
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn begin_alt(&mut self) -> Alt {
        let bookmark = self.bookmark();
        Alt { parser: self, matched: false, bookmark }
    }

    fn opt<F>(&mut self, f: F) -> ParseResult
    where
        F: Fn(&mut Parser) -> ParseResult,
    {
        let bookmark = self.bookmark();
        if f(self).is_err() {
            self.restore(&bookmark);
        }
        self.drop(bookmark);
        Ok(())
    }

    fn ws(&mut self) -> ParseResult {
        while let Some(WHITESPACE(_)) | Some(NEWLINE(_)) = self.peek() {
            self.bump();
        }
        Ok(())
    }
}

use crate::cst::{syntax_stream, CST};
use crate::parser::Error::NoMatch;
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
/// These functions return a [`ParseResult`] that will be [`Ok`] if the
/// parsing was successful or [`NoMatch`] if otherwise.
impl<'src> Parser<'src> {
    /// Parses a top-level item in YARA source file.
    ///
    /// A top-level item is either an import statement or a rule declaration.
    ///
    /// ```text
    /// TOP_LEVEL_ITEM ::= ( IMPORT_STMT | RULE_DECL )
    /// ```
    fn top_level_item(&mut self) -> ParseResult {
        match self.peek().ok_or(NoMatch)? {
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
                Err(NoMatch)
            }
        }
    }

    /// Parses an import statement.
    ///
    /// ```text
    /// IMPORT_STMT ::= `import` STRING_LIT
    /// ```
    fn import_stmt(&mut self) -> ParseResult {
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
    fn rule_decl(&mut self) -> ParseResult {
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
            .expect(t!(CONDITION_KW))
            .ws()
            .expect(t!(COLON))
            .ws()
            .expect(t!(R_BRACE))
            .end()
    }

    /// Parses rule modifiers.
    ///
    /// ```text
    /// RULE_MODS := ( `private` `global`? | `global` `private`? )
    /// ```
    fn rule_mods(&mut self) -> ParseResult {
        self.begin(SyntaxKind::RULE_MODS)
            .begin_alt()
            .alt(|p| {
                p.expect(t!(PRIVATE_KW))?;
                p.opt(|p| {
                    p.ws()?;
                    p.expect(t!(GLOBAL_KW))
                })
            })
            .alt(|p| {
                p.expect(t!(GLOBAL_KW))?;
                p.opt(|p| {
                    p.ws()?;
                    p.expect(t!(PRIVATE_KW))
                })
            })
            .end_alt()
            .end()
    }

    fn meta_defs(&mut self) -> ParseResult {
        self.begin(SyntaxKind::META_DEFS)
            .expect(t!(META_KW))
            .ws()
            .expect(t!(COLON))
            .ws()
            .n_or_more(1, |p| p.meta_def())
            .end()
    }

    fn meta_def(&mut self) -> ParseResult {
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

    /// Parses a boolean expression.
    ///
    /// ```text
    /// BOOLEAN_EXPR := BOOLEAN_TERM ((AND_KW | OR_KW) BOOLEAN_TERM)*
    /// ``
    fn boolean_expr(&mut self) -> ParseResult {
        self.begin(SyntaxKind::BOOLEAN_EXPR)
            .then(|p| p.boolean_term())
            .ws()
            .n_or_more(0, |p| todo!())
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
    fn boolean_term(&mut self) -> ParseResult {
        self.begin(SyntaxKind::BOOLEAN_TERM).end()
    }
}

struct Bookmark {
    tokens: token_stream::Bookmark,
    output: syntax_stream::Bookmark,
}

struct Alt<'a, 'src> {
    parser: &'a mut Parser<'src>,
    matched: bool,
    bookmark: Bookmark,
}

impl<'a, 'src> Alt<'a, 'src> {
    fn alt<F>(mut self, f: F) -> Self
    where
        F: Fn(&mut Parser) -> ParseResult,
    {
        // Don't try to match the current alternative if a previous one
        // already matched.
        if !self.matched {
            match f(self.parser) {
                // The current alternative matched.
                Ok(()) => self.matched = true,
                // The current alternative didn't match, restore the token
                // stream to the position it has before trying to match.
                Err(NoMatch) => self.parser.restore(&self.bookmark),
            };
        }
        self
    }

    fn end_alt(self) -> ParserRule<'a, 'src> {
        self.parser.drop(self.bookmark);
        // If none of the alternatives matched, that's a failure.
        let failed = !self.matched;
        ParserRule { parser: self.parser, failed }
    }
}

struct ParserRule<'a, 'src> {
    parser: &'a mut Parser<'src>,
    failed: bool,
}

impl<'a, 'src> ParserRule<'a, 'src> {
    fn new(parser: &'a mut Parser<'src>) -> Self {
        Self { parser, failed: false }
    }

    fn begin(self, kind: SyntaxKind) -> Self {
        self.parser.output.begin(kind);
        self
    }

    fn end(self) -> ParseResult {
        if self.failed {
            self.parser.output.end_with_error();
            Err(NoMatch)
        } else {
            self.parser.output.end();
            Ok(())
        }
    }

    fn ws(self) -> Self {
        if !self.failed {
            let _ = self.parser.ws();
        }
        self
    }

    fn begin_alt(self) -> Alt<'a, 'src> {
        let bookmark = self.parser.bookmark();
        Alt { parser: self.parser, bookmark, matched: false }
    }

    fn expect(mut self, expected_tokens: &[Token]) -> Self {
        if !self.failed && self.parser.expect(expected_tokens).is_err() {
            self.failed = true;
        }
        self
    }

    fn expect_opt(self, expected_tokens: &[Token]) -> Self {
        if !self.failed {
            let _ = self.parser.expect_opt(expected_tokens);
        }
        self
    }

    fn then<F>(mut self, f: F) -> Self
    where
        F: Fn(&mut Parser) -> ParseResult,
    {
        if f(self.parser).is_err() {
            self.failed = true;
        }
        self
    }

    #[inline]
    fn opt<F>(self, f: F) -> Self
    where
        F: Fn(&mut Parser) -> ParseResult,
    {
        let _ = self.parser.opt(f);
        self
    }

    fn n_or_more<F>(mut self, n: usize, f: F) -> Self
    where
        F: Fn(&mut Parser) -> ParseResult,
    {
        // The first N times that `f` is called it must match.
        for _ in 0..n {
            if !self.failed && f(self.parser).is_err() {
                self.failed = true;
            }
        }
        // If the first N matches were ok, keep matching `f` as much as
        // possible.
        if !self.failed {
            loop {
                let bookmark = self.parser.bookmark();
                match f(self.parser) {
                    Ok(()) => self.parser.drop(bookmark),
                    Err(NoMatch) => {
                        self.parser.restore(&bookmark);
                        self.parser.drop(bookmark);
                        break;
                    }
                }
            }
        }
        self
    }
}
