/*! This module contains a handwritten [PEG][1] parser for YARA rules.

The parser receives a sequence of tokens produced by the [`Tokenizer`], and
produces a Concrete Syntax-Tree ([`CST`]), also known as a lossless syntax
tree. The CST is initially represented as a stream of [events][`Event`], but
this stream is later converted to a tree using the [rowan][2] create.

This parser is error-tolerant, it is able to parse YARA code that contains
syntax errors. After each error, the parser recovers and keeps parsing the
remaining code. The resulting CST may contain error nodes containing portions
of the code that are not syntactically correct, but anything outside of those
error nodes is valid YARA code.

[1]: https://en.wikipedia.org/wiki/Parsing_expression_grammar
[2]: https://github.com/rust-analyzer/rowan
 */

use indexmap::map::Entry;
use indexmap::IndexMap;
use std::collections::HashMap;
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
    /// Stream from where the parser consumes the input tokens.
    tokens: TokenStream<'src>,

    /// Stream where the parser puts the events that conform the resulting CST.
    output: SyntaxStream,

    /// If true, the parser is "failure" state. The parser enters the "failure"
    /// state when some syntax rule expects a token that doesn't match the
    /// next token in the input.
    failed: bool,

    /// How deep is the parser into "optional" branches of the grammar. An
    /// optional branch is one that can fail without the whole production
    /// rule failing. For instance, in `A := B? C` the parser can fail while
    /// parsing `B`, but this failure is acceptable because `B` is optional.
    /// Less obvious cases of optional branches are present in alternatives
    /// and the "zero or more" operation (examples: `(A|B)`, `A*`).
    opt_depth: usize,

    /// Errors found during parsing that haven't been sent to `ready_errors`
    /// yet.
    ///
    /// When the parser expects a token, and that tokens is not the next one
    /// in input, it produces an error like `expecting "foo", found "bar"`.
    /// However, these errors are not sent immediately to `ready_errors`
    /// stream because some the errors may occur while parsing optional code,
    /// or while parsing some branch in an alternation. For instance, in the
    /// grammar rule `A := (B | C)`, if the parser finds an error while parsing
    /// `B`, but `C` succeeds, then `A` is successful and the error found while
    /// parsing `B` is not reported.
    ///
    /// In the other hand, if both `B` and `C` produce errors, then `A` has
    /// failed, but only one of the two errors is reported. The error that
    /// gets reported is the one that advanced more in the source code (i.e:
    /// the one with the largest span start). This approach tends to produce
    /// more meaningful errors.
    ///
    /// The items in the vector are error messages accompanied by the span in
    /// the source code where the error occurred.
    pending_errors: Vec<(String, Span)>,

    /// Errors go from `pending_errors` to `ready_errors` before they are
    /// finally pushed to the `output` stream. This extra step has the purpose
    /// of removing duplicate messages for the same code span. In certain cases
    /// the parser can produce two different error messages for the same span,
    /// but this map guarantees that only the first error is taken into account
    /// and that any further error for the same span is ignored.
    ready_errors: IndexMap<Span, String>,

    /// Hash map where keys are positions within the source code, and values
    /// are a list of tokens that were expected to match at that position.
    ///
    /// This hash map plays a crucial role in error reporting during parsing.
    /// Consider the following grammar rule:
    ///
    /// `A := a? b`
    ///
    /// Here, the optional token `a` must be followed by the token `b`. This
    /// can be represented (conceptually, not actual code) as:
    ///
    /// ```text
    /// self.start(A)
    ///     .opt(|p| p.expect(a))
    ///     .expect(b)
    ///     .end()
    /// ```
    ///
    /// If we attempt to parse the sequence `cb`, it will fail at `c` because
    /// the rule matches only `ab` and `b`. The error message should be:
    ///
    /// "expecting `a` or `b`, found `c`"
    ///
    /// This error is generated by the `expect(b)` statement. However, the
    /// `expect` function only knows about the `b` token. So, how do we know
    /// that both `a` and `b` are valid tokens at the position where `c` was
    /// found?
    ///
    /// This is where the `expected_tokens` hash map comes into play. We know
    /// that `a` is also a valid alternative because the `expect(a)` inside the
    /// `opt` was tried and failed. The parser doesn't fail at that point
    /// because `a` is optional, but it records that `a` was expected at the
    /// position of `c`. When `expect(b)` fails later, the parser looks up
    /// any other token (besides `b`) that were expected to match at the
    /// position and produces a comprehensive error message.
    expected_tokens: HashMap<usize, Vec<&'static str>>,
}

impl<'src> From<Tokenizer<'src>> for InternalParser<'src> {
    /// Creates a new parser that receives tokens from the given [`Tokenizer`].
    fn from(tokenizer: Tokenizer<'src>) -> Self {
        Self {
            tokens: TokenStream::new(tokenizer),
            output: SyntaxStream::new(),
            pending_errors: Vec::new(),
            ready_errors: IndexMap::new(),
            expected_tokens: HashMap::new(),
            opt_depth: 0,
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
            let _ = self.trivia();
            let _ = self.top_level_item();
            self.failed = false;
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

    /// Returns the next non-trivia token, without consuming any token.
    ///
    /// Trivia tokens are those that are not really relevant and can be ignored,
    /// like whitespaces, newlines, and comments. This function skips trivia
    /// tokens until finding one that is non-trivia.
    fn peek_non_ws(&mut self) -> Option<&Token> {
        let mut i = 0;
        // First find the position of the first token that is not a whitespace
        // and then use `peek_token` again for returning it. This is necessary
        // due to a current limitation in the borrow checker that doesn't allow
        // this:
        //
        // loop {
        //     match self.tokens.peek_token(i) {
        //         Some(token) => {
        //             if token.is_trivia() {
        //                 i += 1;
        //             } else {
        //                 return Some(token);
        //             }
        //         }
        //         None => return None,
        //     }
        // }
        //
        let token_pos = loop {
            match self.tokens.peek_token(i) {
                Some(token) => {
                    if token.is_trivia() {
                        i += 1;
                    } else {
                        break i;
                    }
                }
                None => return None,
            }
        };
        self.tokens.peek_token(token_pos)
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

    /// Switches to hex pattern mode.
    fn enter_hex_pattern_mode(&mut self) -> &mut Self {
        if self.failed {
            return self;
        }
        self.tokens.enter_hex_pattern_mode();
        self
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

    fn recover(&mut self) -> &mut Self {
        self.failed = false;
        self
    }

    fn sync(&mut self, recovery_set: &TokenSet) -> &mut Self {
        self.trivia();
        match self.peek() {
            None => return self,
            Some(token) if recovery_set.contains(token) => return self,
            Some(token) => {
                let span = token.span();
                let token_str = token.as_str();
                self.unexpected_token_error(token_str, span, recovery_set);
            }
        }
        self.output.begin(SyntaxKind::ERROR);
        while let Some(token) = self.peek() {
            if recovery_set.contains(token) {
                break;
            } else {
                self.bump();
            }
        }
        self.output.end();
        self
    }

    /// Recovers the parser from a previous error, consuming any token that is
    /// not in the recovery set and putting them under an error node in the
    /// resulting tree.
    ///
    /// The purpose of this function is establishing a point for the parser to
    /// recover from parsing errors. For instance, consider the following
    /// grammar rules:
    ///
    /// ```text
    /// A := aBC
    /// B := bb
    /// C := ccc
    /// ```
    ///
    /// `A` is roughly expressed as:
    ///
    /// ```text
    /// self.begin(A)
    ///     .expect(a)
    ///     .one(|p| p.B())
    ///     .one(|p| p.C())
    ///     .end()
    /// ```
    ///
    /// Suppose that we are parsing the sequence `axxc`. The sequence starts
    /// with `a`, so `expect(a)` is successful. However, `one(|p| p.B())`
    /// fails because `x` is found instead of the expected `b`. As a result,
    /// `one(|p| p.C())` is not attempted, and the entire `A` production fails,
    /// resulting a CST that looks like:
    ///
    /// ```text
    /// error
    ///   a
    ///   x
    ///   x
    ///   c
    /// ```
    ///
    /// By inserting `recover_and_sync(c)`, we can recover from previous errors
    /// before trying to match `C`:
    ///
    /// ```text
    /// self.begin(A)
    ///     .expect(a)
    ///     .one(|p| p.B())
    ///     .recover_and_sync(c)
    ///     .one(|p| p.C())
    ///     .end()
    /// ```
    ///
    /// If the parser fails at `one(|p| p.B())`, leaving the `xx` tokens
    /// unconsumed, `recover_and_sync(c)` will consume them until it finds a
    /// `c` token and will recover from the error. This allows `one(|p| p.C())`
    /// to consume the `c` and succeed. The resulting CST would be like:
    ///
    /// ```text
    /// A
    ///   a
    ///   error
    ///     x
    ///     x
    ///   c
    /// ```
    ///
    /// Notice how the error is now more localized.
    fn recover_and_sync(&mut self, recovery_set: &TokenSet) -> &mut Self {
        self.recover();
        /*if let Some(t) = self.peek_non_ws() {
            if recovery_set.contains(t) {
                return self;
            }
        }*/
        self.sync(recovery_set);
        self
    }

    /// Consumes trivia tokens until finding one that is non-trivia.
    ///
    /// Trivia tokens those that are not really part of the language, like
    /// whitespaces, newlines and comments.
    fn trivia(&mut self) -> &mut Self {
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

    /// Checks that the next non-trivia token matches one of the expected
    /// tokens.
    ///
    /// If the next non-trivia token does not match any of the expected tokens,
    /// no token will be consumed, the parser will transition to a failure
    /// state and generate an error message. If it matches, the non-trivia
    /// token and any trivia token that appears in front of it will be
    /// consumed and sent to the output.
    ///
    /// # Panics
    ///
    /// If `expected_tokens` is empty.
    fn expect(&mut self, expected_tokens: &TokenSet) -> &mut Self {
        assert!(!expected_tokens.is_empty());

        if self.failed {
            return self;
        }

        let found_expected_token = match self.peek_non_ws() {
            None => false,
            Some(token) if expected_tokens.contains(token) => true,
            Some(token) => {
                let span = token.span();
                let token_str = token.as_str();
                self.unexpected_token_error(token_str, span, expected_tokens);
                false
            }
        };

        if found_expected_token {
            // Consume any trivia token in front of the non-trivia expected
            // token.
            self.trivia();
            // Consume the expected token.
            self.bump();
            // After matching a token that is not inside an "optional" branch
            // in the grammar, it's guaranteed that the parser won't go back
            // to a position at the left of the matched token. This is a good
            // opportunity for clearing the `expected_tokens` map, as the parser
            // can't fail again at any earlier position.
            if self.opt_depth == 0 {
                self.expected_tokens.clear();
                self.pending_errors.clear();
                for (span, error) in self.ready_errors.drain(0..) {
                    self.output.push_error(error, span);
                }
            }
        } else {
            self.failed = true;
        }

        self
    }

    /// Begins an alternative.
    ///
    /// # Example
    ///
    /// ```text
    /// p.begin_alt()
    ///   .alt(..)
    ///   .alt(..)
    ///  .end_alt()
    /// ```
    fn begin_alt(&mut self) -> Alt<'_, 'src> {
        let bookmark = self.bookmark();
        Alt { parser: self, matched: false, bookmark }
    }

    /// Applies `parser` optionally.
    ///
    /// If `parser` fails, the failure is ignored and the parser is reset to
    /// its previous state.
    ///
    /// # Example
    ///
    /// ```text
    /// p.opt(|p| p.something_optional())
    /// ```
    fn opt<P>(&mut self, parser: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        if self.failed {
            return self;
        }

        let bookmark = self.bookmark();

        self.trivia();
        self.opt_depth += 1;
        parser(self);
        self.opt_depth -= 1;

        // Any error occurred while parsing the optional production is ignored.
        if self.failed {
            self.failed = false;
            self.restore_bookmark(&bookmark);
        }

        self.remove_bookmark(bookmark);
        self
    }

    /// If the next non-trivia token matches one of the expected tokens,
    /// consume all trivia tokens and applies `parser`.
    ///
    /// `if_found(TOKEN, |p| p.expect(TOKEN))` is logically equivalent to
    /// `opt(|p| p.expect(TOKEN))`, but the former is more efficient because it
    /// doesn't do any backtracking. The closure `|p| p.expect(TOKEN)` is
    /// executed only after we are sure that the next non-trivia token is
    /// `TOKEN`.
    ///
    /// This can be used for replacing `opt` when the optional production can
    /// be unequivocally distinguished by its first token. For instance, in a
    /// YARA rule the metadata section is optional, but always starts with
    /// the `meta` keyword, so, instead of:
    ///
    /// `opt(|p| p.meta_blk()`)
    ///
    /// We can use:
    ///
    /// `if_found(t!(META_KW), |p| p.meta_blk())`
    ///
    fn if_found<P>(
        &mut self,
        expected_tokens: &TokenSet,
        parser: P,
    ) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        if self.failed {
            return self;
        }
        match self.peek_non_ws() {
            None => {}
            Some(token) => {
                if expected_tokens.contains(token) {
                    self.trivia();
                    parser(self);
                } else {
                    let span = token.span();
                    let tokens =
                        self.expected_tokens.entry(span.start()).or_default();
                    tokens.extend(expected_tokens.iter().map(|t| t.as_str()));
                }
            }
        }
        self
    }

    /// Applies `parser` zero or more times.
    #[inline]
    fn zero_or_more<P>(&mut self, parser: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        self.n_or_more(0, parser)
    }

    /// Applies `parser` one or more times.
    #[inline]
    fn one_or_more<P>(&mut self, parser: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        self.n_or_more(1, parser)
    }

    /// Applies `parser` N or more times.
    fn n_or_more<P>(&mut self, n: usize, parser: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        if self.failed {
            return self;
        }
        // The first N times that `f` is called it must match.
        for _ in 0..n {
            self.trivia();
            parser(self);
            if self.failed {
                return self;
            }
        }
        // If the first N matches were ok, keep matching `f` as much as
        // possible.
        loop {
            let bookmark = self.bookmark();
            self.trivia();
            self.opt_depth += 1;
            parser(self);
            self.opt_depth -= 1;
            if self.failed {
                self.failed = false;
                self.restore_bookmark(&bookmark);
                self.remove_bookmark(bookmark);
                break;
            } else {
                self.remove_bookmark(bookmark);
            }
        }
        self
    }

    /// Applies `parser` exactly one time.
    fn then<P>(&mut self, parser: P) -> &mut Self
    where
        P: Fn(&mut Self) -> &mut Self,
    {
        if self.failed {
            return self;
        }
        self.trivia();
        parser(self);
        self
    }

    fn unexpected_token_error(
        &mut self,
        token_str: &str,
        span: Span,
        expected_tokens: &TokenSet,
    ) {
        let tokens = self.expected_tokens.entry(span.start()).or_default();
        tokens.extend(expected_tokens.iter().map(|t| t.as_str()));

        let (last, all_except_last) = tokens.split_last().unwrap();

        let error_msg = if all_except_last.is_empty() {
            format!("expecting {last}, found {}", token_str)
        } else {
            format!(
                "expecting {} or {last}, found {}",
                all_except_last.join(", "),
                token_str,
            )
        };

        self.pending_errors.push((error_msg, span));

        if self.opt_depth == 0 {
            // Find the pending error starting at the largest offset. If several
            // errors start at the same offset, the last one is used (this is
            // guaranteed by the `max_by_key` function). `self.pending_errors`
            // is left empty.
            if let Some((error, span)) = self
                .pending_errors
                .drain(0..)
                .max_by_key(|(_, span)| span.start())
            {
                match self.ready_errors.entry(span) {
                    Entry::Occupied(_) => {
                        // already present, don't replace.
                    }
                    Entry::Vacant(v) => {
                        v.insert(error);
                    }
                }
            }
        }
    }
}

use crate::cst::{syntax_stream, CST};
use Token::*;

macro_rules! t {
    ($( $tokens:path )|*) => {
       &TokenSet(&[$( $tokens(Span::default()) ),*])
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
///       .one(|p| p.B())
///       .begin_alt()
///          .alt(|p| p.C())
///          .alt(|p| p.D())
///       .end_alt()
///       .end()
/// }
/// ```
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
                let token_str = token.as_str();
                self.output.push_error(
                    format!("expecting import statement or rule definition, found {}", token_str),
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
            .expect(t!(STRING_LIT))
            .end()
    }

    /// Parses a rule declaration.
    ///
    /// ```text
    /// RULE_DECL ::= RULE_MODS? `rule` IDENT `{`
    ///   META_BLK?
    ///   PATTERNS_BLK?
    ///   CONDITION_BLK
    /// `}`
    /// ```
    fn rule_decl(&mut self) -> &mut Self {
        self.begin(SyntaxKind::RULE_DECL)
            .opt(|p| p.rule_mods())
            .expect(t!(RULE_KW))
            .expect(t!(IDENT))
            .if_found(t!(COLON), |p| p.rule_tags())
            .recover_and_sync(t!(L_BRACE))
            .expect(t!(L_BRACE))
            .recover_and_sync(t!(META_KW | STRINGS_KW | CONDITION_KW))
            .if_found(t!(META_KW), |p| p.meta_blk())
            .recover_and_sync(t!(STRINGS_KW | CONDITION_KW))
            .if_found(t!(STRINGS_KW), |p| p.patterns_blk())
            .recover_and_sync(t!(CONDITION_KW))
            .then(|p| p.condition_blk())
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
            .alt(|p| p.expect(t!(PRIVATE_KW)).opt(|p| p.expect(t!(GLOBAL_KW))))
            .alt(|p| p.expect(t!(GLOBAL_KW)).opt(|p| p.expect(t!(PRIVATE_KW))))
            .end_alt()
            .end()
    }

    /// Parsers rule tags.
    ///
    /// ```text
    /// RULE_TAGS := `:` IDENT+
    /// ```
    fn rule_tags(&mut self) -> &mut Self {
        self.begin(SyntaxKind::RULE_TAGS)
            .expect(t!(COLON))
            .one_or_more(|p| p.expect(t!(IDENT)))
            .end()
    }

    /// Parses metadata block.
    ///
    /// ```text
    /// META_BLK := `meta` `:` META_DEF+
    /// ``
    fn meta_blk(&mut self) -> &mut Self {
        self.begin(SyntaxKind::META_BLK)
            .expect(t!(META_KW))
            .expect(t!(COLON))
            .one_or_more(|p| p.meta_def())
            /*.then(|p| {
                while matches!(p.peek_non_ws(), Some(IDENT(_))) {
                    p.trivia();
                    p.meta_def();
                    p.recover_and_sync(t!(IDENT | STRINGS_KW | CONDITION_KW));
                }
                p
            })*/
            .end()
    }

    /// Parses a metadata definition.
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
            .expect(t!(EQUAL))
            .expect(t!(TRUE_KW
                | FALSE_KW
                | INTEGER_LIT
                | FLOAT_LIT
                | STRING_LIT))
            .end()
    }

    /// Parses the patterns block.
    ///
    /// ```text
    /// PATTERNS_BLK := `strings` `:` PATTERN_DEF+
    /// ``
    fn patterns_blk(&mut self) -> &mut Self {
        self.begin(SyntaxKind::PATTERNS_BLK)
            .expect(t!(STRINGS_KW))
            .expect(t!(COLON))
            .one_or_more(|p| p.pattern_def())
            .end()
    }

    /// Parses a pattern definition.
    ///
    /// ```text
    /// PATTERN_DEF := PATTERN_IDENT `=` (
    ///     STRING_LIT  |
    ///     REGEXP      |
    ///     HEX_PATTERN
    /// )
    /// ``
    fn pattern_def(&mut self) -> &mut Self {
        self.begin(SyntaxKind::PATTERN_DEF)
            .expect(t!(PATTERN_IDENT))
            .expect(t!(EQUAL))
            .begin_alt()
            .alt(|p| p.expect(t!(STRING_LIT)))
            .alt(|p| p.expect(t!(REGEXP)))
            .alt(|p| p.hex_pattern())
            .end_alt()
            .opt(|p| p.pattern_mods())
            .end()
    }

    fn pattern_mods(&mut self) -> &mut Self {
        // TODO
        self.begin(SyntaxKind::PATTERN_MODS)
            .expect(t!(ASCII_KW | WIDE_KW | PRIVATE_KW))
            .end()
    }

    /// Parses the condition block.
    ///
    /// ```text
    /// CONDITION_BLK := `condition` `:` BOOLEAN_EXPR
    /// ``
    fn condition_blk(&mut self) -> &mut Self {
        self.begin(SyntaxKind::CONDITION_BLK)
            .expect(t!(CONDITION_KW))
            .expect(t!(COLON))
            .then(|p| p.boolean_expr())
            .end()
    }

    fn hex_pattern(&mut self) -> &mut Self {
        self.begin(SyntaxKind::HEX_PATTERN)
            .expect(t!(L_BRACE))
            .enter_hex_pattern_mode()
            .then(|p| p.hex_tokens())
            .expect(t!(R_BRACE))
            .end()
    }

    fn hex_tokens(&mut self) -> &mut Self {
        self.one_or_more(|p| p.expect(t!(HEX_BYTE)))
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
            .then(|p| p.boolean_term())
            .zero_or_more(|p| {
                p.expect(t!(AND_KW | OR_KW)).then(|p| p.boolean_term())
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

struct TokenSet<'a>(&'a [Token]);

impl<'a> TokenSet<'a> {
    #[inline]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn contains(&self, token: &Token) -> bool {
        self.0.iter().any(|t| mem::discriminant(t) == mem::discriminant(token))
    }

    fn iter(&self) -> impl Iterator<Item = &'a Token> {
        self.0.iter()
    }
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
        // Don't try to match the current alternative if the parser a previous
        // one already matched.
        if !self.matched {
            self.parser.trivia();
            self.parser.opt_depth += 1;
            self.parser = f(self.parser);
            self.parser.opt_depth -= 1;
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
