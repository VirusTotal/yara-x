/*! This module implements the logic that converts a CST into an AST. */

use std::iter::Peekable;
use std::str;
use std::str::from_utf8;

use bstr::{ByteSlice, ByteVec};
use itertools::Itertools;
use num_traits::{Bounded, CheckedMul, FromPrimitive, Num};

use crate::ast::errors::Error;
use crate::ast::*;
use crate::cst::SyntaxKind::*;
use crate::cst::{Event, SyntaxKind};
use crate::Span;

#[derive(Debug)]
enum BuilderError {
    /// This error indicates that some rule could not be converted into its
    /// AST and the builder aborted the generation of the AST for that rule.
    /// The builder recovers from this error by continuing with the next rule.
    Abort,
    /// This error indicates that the AST builder has reached the maximum
    /// allowed depth for the AST tree. By controlling the maximum depth for
    /// AST tree we avoid stack overflows while traversing the AST with
    /// recursive functions.
    MaxDepthReached,
}

/// Creates an Abstract Syntax Tree from an iterator of [`Event`],
/// like a [`CSTStream`].
pub(super) struct Builder<'src, I>
where
    I: Iterator<Item = Event>,
{
    source: &'src [u8],
    events: Peekable<I>,
    errors: Vec<Error>,
    depth: usize,
}

impl<'src, I> Builder<'src, I>
where
    I: Iterator<Item = Event>,
{
    pub fn new(src: &'src [u8], events: I) -> Self {
        Self {
            source: src,
            events: events.peekable(),
            errors: Vec::new(),
            depth: 0,
        }
    }

    pub fn build_ast(mut self) -> AST<'src> {
        let mut items: Vec<Item> = Vec::new();

        self.begin(SOURCE_FILE).unwrap();

        loop {
            match self.peek() {
                Event::Begin { kind: RULE_DECL, .. } => match self.rule_decl()
                {
                    Ok(rule) => items.push(Item::Rule(rule)),
                    // If `rule_decl` returns an error the rule is ignored,
                    // but we try to continue at the next rule declaration,
                    // import statement, or include statement. The `recover` function discards
                    // everything until finding the next valid item.
                    Err(BuilderError::Abort) => self.recover(),
                    Err(BuilderError::MaxDepthReached) => {}
                },
                Event::Begin { kind: IMPORT_STMT, .. } => {
                    match self.import_stmt() {
                        Ok(import) => items.push(Item::Import(import)),
                        // If `import_stmt` returns an error the import is ignored,
                        // but we try to continue at the next valid item.
                        Err(BuilderError::Abort) => self.recover(),
                        Err(BuilderError::MaxDepthReached) => {}
                    }
                }
                Event::Begin { kind: INCLUDE_STMT, .. } => {
                    match self.include_stmt() {
                        Ok(include) => items.push(Item::Include(include)),
                        // If `include_stmt` returns an error the include is ignored,
                        // but we try to continue at the next valid item.
                        Err(BuilderError::Abort) => self.recover(),
                        Err(BuilderError::MaxDepthReached) => {}
                    }
                }
                Event::End { kind: SOURCE_FILE, .. } => break,
                _ => self.recover(),
            }
        }

        self.end(SOURCE_FILE).unwrap();

        assert_eq!(self.depth, 0);

        AST { items, errors: self.errors }
    }
}

// Macro that returns an AST node for a binary operation.
//
// If `lhs` represents an operation than is equal to the one being processed,
// then `rhs` can be added to `lhs` without creating new nodes in the AST tree.
// For example, if `lhs` is an AST node that represents the expression `a + b`,
// `rhs` represents the expression `c`, and the new operation is `+`, we don't
// need to create a new AST node for representing the sum of `a + b` plus `c`,
// instead, we can simply add `c` to the list of operands of the `lhs` node,
// which becomes `a + b + c`.
//
// This way, instead of having this AST tree:
//
//  add (+)
//  ├ add (+)
//  │ ├─ a
//  │ └─ b
//  └─ c
//
// We have this other AST:
//
//  add (+)
//  ├─ a
//  ├─ b
//  └─ c
//
// The more flat is our AST the better, as it reduces the stack size required
// for recursive tree traversal and the amount of memory required for storing
// the AST.
macro_rules! new_n_ary_expr {
    ($variant:path, $lhs:ident, $rhs:ident) => {{
        match $lhs {
            $variant(ref mut operands) => {
                operands.add($rhs);
                $lhs
            }
            _ => $variant(Box::new(NAryExpr { operands: vec![$lhs, $rhs] })),
        }
    }};
}

macro_rules! new_binary_expr {
    ($variant:path, $lhs:ident, $rhs:ident) => {{
        $variant(Box::new(BinaryExpr { lhs: $lhs, rhs: $rhs }))
    }};
}

impl<'src, I> Builder<'src, I>
where
    I: Iterator<Item = Event>,
{
    const MAX_AST_DEPTH: usize = 3000;

    /// Consumes all events until finding the start of a rule, an import
    /// statement, an include statement, or the end of the file.
    ///
    /// Any [`Event::Error`] found is added to `self.errors`.
    fn recover(&mut self) {
        loop {
            match self.peek() {
                Event::Begin { kind: RULE_DECL, .. }
                | Event::Begin { kind: IMPORT_STMT, .. }
                | Event::Begin { kind: INCLUDE_STMT, .. } => break,
                Event::End { kind: SOURCE_FILE, .. } => break,
                _ => {
                    let _ = self.events.next();
                }
            }
        }
        self.depth = 0;
    }

    /// Consumes errors, whitespaces, newlines and comments, until finding
    /// some other kind of token.
    ///
    /// The consumed errors are appended to `self.errors`.
    fn consume_errors_and_trivia(&mut self) {
        for event in self.events.peeking_take_while(|event| {
            matches!(
                event,
                Event::Error { .. }
                    | Event::Token { kind: WHITESPACE, .. }
                    | Event::Token { kind: NEWLINE, .. }
                    | Event::Token { kind: COMMENT, .. }
            )
        }) {
            if let Event::Error { message, span } = event {
                self.errors.push(Error::SyntaxError { message, span });
            }
        }
    }

    /// Returns the slice of source code defined by `span`.
    fn get_source(&self, span: &Span) -> &'src [u8] {
        self.source.get(span.range()).unwrap()
    }

    /// Returns the slice of source code defined by `span`, and checks if it
    /// is valid UTF-8.
    ///
    /// Most of the tokens returned by the tokenizer are guaranteed to be valid
    /// UTF-8, but there are some exceptions, like literal strings, comments,
    /// regular expressions, and of course, the `INVALID_UTF8` token.
    fn get_source_str(
        &mut self,
        span: &Span,
    ) -> Result<&'src str, BuilderError> {
        from_utf8(self.get_source(span)).map_err(|err| {
            self.errors.push(Error::InvalidUTF8(
                span.subspan(err.valid_up_to(), err.valid_up_to() + 1),
            ));
            BuilderError::Abort
        })
    }

    /// Returns a reference to the next [`Event`] that is not a whitespace,
    /// newline, comment or error. The event is returned without being
    /// consumed, but any whitespace, newline, comment or error that appears
    /// before the event is consumed.
    fn peek(&mut self) -> &Event {
        self.consume_errors_and_trivia();
        self.events.peek().expect("unexpected end of events")
    }

    /// Consumes and returns the next non-error [`Event`] in the CST stream.
    ///
    /// All events of type [`Event::Error`] that appears before the next
    /// non-error event are also consumed. This function fails when it finds
    /// an [`Event::Begin(ERROR)`].
    ///
    /// Notice that [`Event::Error`] and [`Event::Begin(ERROR)`] are not the
    /// same thing. The former is simply an error message issues by the parser,
    /// and it's not actually part of the syntax tree, while the latter is a
    /// CST node that contains portions of the syntax tree that were not
    /// correctly parsed.
    fn next(&mut self) -> Result<Event, BuilderError> {
        if let Event::Begin { kind: ERROR, .. } = self.peek() {
            return Err(BuilderError::Abort);
        }
        Ok(self.events.next().expect("unexpected end of events"))
    }

    fn begin(&mut self, kind: SyntaxKind) -> Result<(), BuilderError> {
        let next = self.next()?;
        assert!(matches!(next, Event::Begin{kind: k, ..} if k == kind));
        if self.depth == Self::MAX_AST_DEPTH {
            return Err(BuilderError::MaxDepthReached);
        }
        self.depth += 1;
        Ok(())
    }

    fn end(&mut self, kind: SyntaxKind) -> Result<(), BuilderError> {
        let next = self.next()?;
        assert!(matches!(next, Event::End{kind: k, ..} if k == kind));
        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }

    /// Makes sure that the next non-error token is of the given kind.
    ///
    /// The token is consumed and the function returns the token's span.
    fn expect(
        &mut self,
        expected_kind: SyntaxKind,
    ) -> Result<Span, BuilderError> {
        match self.next()? {
            Event::Token { kind, span } => {
                if expected_kind != kind {
                    // If this ever happens is because we are finding an
                    // unexpected syntax in the CST. Either the source -> CST
                    // phase is not strict enough, or the CST -> AST phase is
                    // overly strict.
                    panic!("expected {expected_kind:?}, got {kind:?}");
                }
                Ok(span)
            }
            event => panic!("unexpected {expected_kind:?}, got {event:?}"),
        }
    }

    /// Pratt parser that applies operator precedence rules to a sequence
    /// of operations.
    ///
    /// This function is called when we are about to parse a sequence of one or
    /// more expressions with interleaved operators:
    ///
    /// ```text
    /// expression (operator expression)*
    /// ```
    /// `parse_expr` is called for parsing each of the expressions. And the
    /// result of `pratt_parser` is another expression representing the whole
    /// sequence of operations, with operations grouped according to operator
    /// precedence rules.
    ///
    /// Pratt parsing is a well-known algorithm. For more information see [1],
    /// [2] and [3].
    ///
    /// [1]: https://matklad.github.io/2020/04/13/simple-but-powerful-pratt-parsing.html
    /// [2]: https://martin.janiczek.cz/2023/07/03/demystifying-pratt-parsers.html
    /// [3]: https://abarker.github.io/typped/pratt_parsing_intro.html
    fn pratt_parser(
        &mut self,
        parse_expr: fn(&mut Self) -> Result<Expr<'src>, BuilderError>,
        min_bp: u8,
    ) -> Result<Expr<'src>, BuilderError> {
        let mut lhs = parse_expr(self)?;

        // Operator precedence table. For each operator there's a tuple
        // (left binding power, right binding power). The higher the
        // operator's precedence, the higher the binding power. Right
        // binding power is slightly higher than left binding power for
        // left-associative operators.
        let binding_power = |operator| -> (u8, u8) {
            match operator {
                OR_KW => (1, 2),
                AND_KW => (3, 4),
                EQ => (5, 6),
                NE => (5, 6),
                CONTAINS_KW => (5, 6),
                ICONTAINS_KW => (5, 6),
                STARTSWITH_KW => (5, 6),
                ISTARTSWITH_KW => (5, 6),
                ENDSWITH_KW => (5, 6),
                IENDSWITH_KW => (5, 6),
                IEQUALS_KW => (5, 6),
                MATCHES_KW => (5, 6),
                LT => (7, 8),
                LE => (7, 8),
                GT => (7, 8),
                GE => (7, 8),
                BITWISE_OR => (9, 10),
                BITWISE_XOR => (11, 12),
                BITWISE_AND => (13, 14),
                SHL => (15, 16),
                SHR => (15, 16),
                ADD => (17, 18),
                SUB => (17, 18),
                MUL => (19, 20),
                DIV => (19, 20),
                MOD => (19, 20),
                DOT => (21, 22),
                operator => panic!("unknown operator: {operator:?}"),
            }
        };

        loop {
            let (operator, (l_bp, r_bp)) = match self.peek() {
                Event::Token { kind, .. } => (*kind, binding_power(*kind)),
                Event::End { .. } => break,
                event => panic!("unexpected {event:?}"),
            };

            if l_bp < min_bp {
                break;
            }

            self.next()?;

            let rhs = self.pratt_parser(parse_expr, r_bp)?;

            lhs = match operator {
                OR_KW => {
                    new_n_ary_expr!(Expr::Or, lhs, rhs)
                }
                AND_KW => {
                    new_n_ary_expr!(Expr::And, lhs, rhs)
                }
                ADD => {
                    new_n_ary_expr!(Expr::Add, lhs, rhs)
                }
                SUB => {
                    new_n_ary_expr!(Expr::Sub, lhs, rhs)
                }
                MUL => {
                    new_n_ary_expr!(Expr::Mul, lhs, rhs)
                }
                DIV => {
                    new_n_ary_expr!(Expr::Div, lhs, rhs)
                }
                MOD => {
                    new_n_ary_expr!(Expr::Mod, lhs, rhs)
                }
                DOT => {
                    new_n_ary_expr!(Expr::FieldAccess, lhs, rhs)
                }
                EQ => {
                    new_binary_expr!(Expr::Eq, lhs, rhs)
                }
                NE => {
                    new_binary_expr!(Expr::Ne, lhs, rhs)
                }
                CONTAINS_KW => {
                    new_binary_expr!(Expr::Contains, lhs, rhs)
                }
                ICONTAINS_KW => {
                    new_binary_expr!(Expr::IContains, lhs, rhs)
                }
                STARTSWITH_KW => {
                    new_binary_expr!(Expr::StartsWith, lhs, rhs)
                }
                ISTARTSWITH_KW => {
                    new_binary_expr!(Expr::IStartsWith, lhs, rhs)
                }
                ENDSWITH_KW => {
                    new_binary_expr!(Expr::EndsWith, lhs, rhs)
                }
                IENDSWITH_KW => {
                    new_binary_expr!(Expr::IEndsWith, lhs, rhs)
                }
                IEQUALS_KW => {
                    new_binary_expr!(Expr::IEquals, lhs, rhs)
                }
                MATCHES_KW => {
                    new_binary_expr!(Expr::Matches, lhs, rhs)
                }
                LT => {
                    new_binary_expr!(Expr::Lt, lhs, rhs)
                }
                LE => {
                    new_binary_expr!(Expr::Le, lhs, rhs)
                }
                GT => {
                    new_binary_expr!(Expr::Gt, lhs, rhs)
                }
                GE => {
                    new_binary_expr!(Expr::Ge, lhs, rhs)
                }
                BITWISE_OR => {
                    new_binary_expr!(Expr::BitwiseOr, lhs, rhs)
                }
                BITWISE_XOR => {
                    new_binary_expr!(Expr::BitwiseXor, lhs, rhs)
                }
                BITWISE_AND => {
                    new_binary_expr!(Expr::BitwiseAnd, lhs, rhs)
                }
                SHL => {
                    new_binary_expr!(Expr::Shl, lhs, rhs)
                }
                SHR => {
                    new_binary_expr!(Expr::Shr, lhs, rhs)
                }
                operator => panic!("unknown operator: {operator:?}"),
            };
        }

        Ok(lhs)
    }
}

impl<'src, I> Builder<'src, I>
where
    I: Iterator<Item = Event>,
{
    fn include_stmt(&mut self) -> Result<Include<'src>, BuilderError> {
        self.begin(INCLUDE_STMT)?;
        let span = self.expect(INCLUDE_KW)?;
        let (file_name, file_name_span) = self.utf8_string_lit()?;
        self.end(INCLUDE_STMT)?;
        Ok(Include { file_name, span: span.combine(&file_name_span) })
    }

    fn import_stmt(&mut self) -> Result<Import<'src>, BuilderError> {
        self.begin(IMPORT_STMT)?;
        let span = self.expect(IMPORT_KW)?;
        let (module_name, module_name_span) = self.utf8_string_lit()?;
        self.end(IMPORT_STMT)?;
        Ok(Import { module_name, span: span.combine(&module_name_span) })
    }

    fn rule_decl(&mut self) -> Result<Rule<'src>, BuilderError> {
        self.begin(RULE_DECL)?;

        let flags = if let Event::Begin { kind: RULE_MODS, .. } = self.peek() {
            self.rule_mods()?
        } else {
            RuleFlags::empty()
        };

        self.expect(RULE_KW)?;

        let identifier = self.identifier()?;

        let tags = if let Event::Begin { kind: RULE_TAGS, .. } = self.peek() {
            Some(self.rule_tags()?)
        } else {
            None
        };

        self.expect(L_BRACE)?;

        let meta = if let Event::Begin { kind: META_BLK, .. } = self.peek() {
            Some(self.meta_blk()?)
        } else {
            None
        };

        let patterns =
            if let Event::Begin { kind: PATTERNS_BLK, .. } = self.peek() {
                Some(self.patterns_blk()?)
            } else {
                None
            };

        self.begin(CONDITION_BLK)?;
        self.expect(CONDITION_KW)?;
        self.expect(COLON)?;

        let condition = self.boolean_expr()?;

        self.end(CONDITION_BLK)?;
        self.expect(R_BRACE)?;
        self.end(RULE_DECL)?;

        Ok(Rule { flags, identifier, tags, meta, patterns, condition })
    }

    fn rule_mods(&mut self) -> Result<RuleFlags, BuilderError> {
        self.begin(RULE_MODS)?;

        let mut flags = RuleFlags::empty();

        loop {
            match self.peek() {
                Event::Token { kind: GLOBAL_KW, .. } => {
                    self.next()?;
                    flags.insert(RuleFlags::Global)
                }
                Event::Token { kind: PRIVATE_KW, .. } => {
                    self.next()?;
                    flags.insert(RuleFlags::Private)
                }
                Event::End { kind: RULE_MODS, .. } => {
                    break;
                }
                event => panic!("unexpected {event:?}"),
            }
        }

        self.end(RULE_MODS)?;
        Ok(flags)
    }

    fn rule_tags(&mut self) -> Result<Vec<Ident<'src>>, BuilderError> {
        self.begin(RULE_TAGS)?;
        self.expect(COLON)?;

        let mut tags = Vec::new();

        while let Event::Token { kind: IDENT, .. } = self.peek() {
            tags.push(self.identifier()?);
        }

        self.end(RULE_TAGS)?;

        Ok(tags)
    }

    fn meta_blk(&mut self) -> Result<Vec<Meta<'src>>, BuilderError> {
        self.begin(META_BLK)?;
        self.expect(META_KW)?;
        self.expect(COLON)?;

        let mut meta = Vec::new();

        while let Event::Begin { kind: META_DEF, .. } = self.peek() {
            meta.push(self.meta_def()?)
        }

        self.end(META_BLK)?;

        Ok(meta)
    }

    fn patterns_blk(&mut self) -> Result<Vec<Pattern<'src>>, BuilderError> {
        self.begin(PATTERNS_BLK)?;
        self.expect(STRINGS_KW)?;
        self.expect(COLON)?;

        let mut patterns = Vec::new();

        while let Event::Begin { kind: PATTERN_DEF, .. } = self.peek() {
            patterns.push(self.pattern_def()?);
        }

        self.end(PATTERNS_BLK)?;

        Ok(patterns)
    }

    fn meta_def(&mut self) -> Result<Meta<'src>, BuilderError> {
        self.begin(META_DEF)?;

        let identifier = self.identifier()?;

        self.expect(EQUAL)?;

        let multiplier: i64 =
            if matches!(self.peek(), &Event::Token { kind: MINUS, .. }) {
                self.expect(MINUS)?;
                -1
            } else {
                1
            };

        let value = match self.peek() {
            Event::Token { kind: INTEGER_LIT, .. } => {
                let (value, _, span) = self.integer_lit::<i64>()?;
                MetaValue::Integer((multiplier * value, span))
            }
            Event::Token { kind: FLOAT_LIT, .. } => {
                let (value, _, span) = self.float_lit()?;
                MetaValue::Float((multiplier as f64 * value, span))
            }
            Event::Token { kind: STRING_LIT, .. } => {
                match self.string_lit(true)? {
                    // If the result is a string borrowed directly from the
                    // source code, we can be sure that it's a valid UTF-8
                    // string.
                    (Cow::Borrowed(s), _lit, span) => MetaValue::String((
                        unsafe { s.to_str_unchecked() },
                        span,
                    )),
                    // If the result is an owned string is because it contains
                    // some escaped character, this string is not guaranteed
                    // to be a valid UTF-8 string.
                    (Cow::Owned(s), _lit, span) => MetaValue::Bytes((s, span)),
                }
            }
            Event::Token { kind: TRUE_KW, .. } => {
                MetaValue::Bool((true, self.expect(TRUE_KW)?))
            }
            Event::Token { kind: FALSE_KW, .. } => {
                MetaValue::Bool((false, self.expect(FALSE_KW)?))
            }
            event => panic!("unexpected {event:?}"),
        };

        self.end(META_DEF)?;

        Ok(Meta { identifier, value })
    }

    fn pattern_def(&mut self) -> Result<Pattern<'src>, BuilderError> {
        self.begin(PATTERN_DEF)?;
        let identifier = self.pattern_ident()?;
        self.expect(EQUAL)?;

        let pattern = match self.peek() {
            Event::Token { kind: STRING_LIT, .. } => {
                let (value, literal, span) = self.string_lit(true)?;
                let modifiers = self.pattern_mods_opt()?;

                Pattern::Text(Box::new(TextPattern {
                    identifier,
                    text: LiteralString { span, literal, value },
                    modifiers,
                }))
            }
            Event::Token { kind: REGEXP, .. } => {
                let regexp = self.regexp()?;
                let modifiers = self.pattern_mods_opt()?;

                Pattern::Regexp(Box::new(RegexpPattern {
                    identifier,
                    regexp,
                    modifiers,
                }))
            }
            Event::Begin { kind: HEX_PATTERN, span } => {
                let span = span.clone();
                let tokens = self.hex_pattern()?;
                let modifiers = self.pattern_mods_opt()?;

                Pattern::Hex(Box::new(HexPattern {
                    sub_patterns: tokens,
                    span,
                    identifier,
                    modifiers,
                }))
            }
            event => panic!("unexpected {event:?}"),
        };

        self.end(PATTERN_DEF)?;

        Ok(pattern)
    }

    fn pattern_mods_opt(
        &mut self,
    ) -> Result<PatternModifiers<'src>, BuilderError> {
        if let Event::Begin { kind: PATTERN_MODS, .. } = self.peek() {
            self.pattern_mods()
        } else {
            Ok(PatternModifiers::default())
        }
    }

    fn pattern_mods(
        &mut self,
    ) -> Result<PatternModifiers<'src>, BuilderError> {
        self.begin(PATTERN_MODS)?;

        let mut modifiers = Vec::new();

        while let Event::Begin { kind: PATTERN_MOD, .. } = self.peek() {
            self.begin(PATTERN_MOD)?;
            match self.next()? {
                Event::Token { kind: ASCII_KW, span } => {
                    modifiers.push(PatternModifier::Ascii { span });
                }
                Event::Token { kind: WIDE_KW, span } => {
                    modifiers.push(PatternModifier::Wide { span });
                }
                Event::Token { kind: PRIVATE_KW, span } => {
                    modifiers.push(PatternModifier::Private { span });
                }
                Event::Token { kind: FULLWORD_KW, span } => {
                    modifiers.push(PatternModifier::Fullword { span });
                }
                Event::Token { kind: NOCASE_KW, span } => {
                    modifiers.push(PatternModifier::Nocase { span });
                }
                Event::Token { kind: XOR_KW, mut span } => {
                    let mut start = 0;
                    let mut end = 255;

                    if let Event::Token { kind: L_PAREN, .. } = self.peek() {
                        self.expect(L_PAREN)?;
                        start = self.integer_lit::<u8>()?.0;

                        match self.next()? {
                            Event::Token {
                                kind: R_PAREN,
                                span: r_paren_span,
                            } => {
                                end = start;
                                span = span.combine(&r_paren_span);
                            }
                            Event::Token { kind: HYPHEN, .. } => {
                                end = self.integer_lit::<u8>()?.0;
                                span = span.combine(&self.expect(R_PAREN)?);
                            }
                            event => panic!("unexpected {event:?}"),
                        }
                    }
                    modifiers.push(PatternModifier::Xor { span, start, end });
                }
                token @ Event::Token {
                    kind: BASE64_KW | BASE64WIDE_KW,
                    ..
                } => {
                    let mut alphabet = None;
                    if let Event::Token { kind: L_PAREN, .. } = self.peek() {
                        self.expect(L_PAREN)?;
                        let (value, literal, span) = self.string_lit(false)?;
                        self.expect(R_PAREN)?;
                        alphabet =
                            Some(LiteralString { value, literal, span });
                    }
                    match token {
                        Event::Token { kind: BASE64_KW, span } => {
                            modifiers.push(PatternModifier::Base64 {
                                span,
                                alphabet,
                            });
                        }
                        Event::Token { kind: BASE64WIDE_KW, span } => {
                            modifiers.push(PatternModifier::Base64Wide {
                                span,
                                alphabet,
                            });
                        }
                        event => panic!("unexpected {event:?}"),
                    };
                }
                event => panic!("unexpected {event:?}"),
            }
            self.end(PATTERN_MOD)?;
        }

        self.end(PATTERN_MODS)?;

        Ok(PatternModifiers::new(modifiers))
    }

    fn hex_pattern(&mut self) -> Result<HexSubPattern, BuilderError> {
        self.begin(HEX_PATTERN)?;
        self.expect(L_BRACE)?;

        let sub_pattern = self.hex_sub_pattern()?;

        self.expect(R_BRACE)?;
        self.end(HEX_PATTERN)?;

        Ok(sub_pattern)
    }

    fn hex_sub_pattern(&mut self) -> Result<HexSubPattern, BuilderError> {
        self.begin(HEX_SUB_PATTERN)?;

        let mut sub_patterns = Vec::new();

        loop {
            sub_patterns.push(match self.peek() {
                Event::Token { kind: HEX_BYTE, .. } => {
                    let span = self.expect(HEX_BYTE)?;
                    let mut byte_literal = self.get_source_str(&span)?;

                    let mut value: u8 = 0x00;
                    let mut mask: u8 = 0xFF;
                    let mut negated = false;

                    // If the byte starts with `~` is a negated byte.
                    if let Some(b) = byte_literal.strip_prefix('~') {
                        negated = true;
                        byte_literal = b;
                    }

                    let mut nibbles = byte_literal.chars();

                    let high = nibbles.next().unwrap();
                    // High nibble is `?`, then it should be masked out.
                    if high == '?' {
                        mask &= 0x0F;
                    } else {
                        value |= (high.to_digit(16).unwrap() << 4) as u8;
                    }

                    let low = nibbles.next().unwrap();
                    // Low nibble is `?`, then it should be masked out.
                    if low == '?' {
                        mask &= 0xF0;
                    } else {
                        value |= low.to_digit(16).unwrap() as u8;
                    }

                    if negated {
                        HexToken::NotByte(HexByte { span, value, mask })
                    } else {
                        HexToken::Byte(HexByte { span, value, mask })
                    }
                }
                Event::Begin { kind: HEX_ALTERNATIVE, .. } => {
                    HexToken::Alternative(Box::new(self.hex_alternative()?))
                }
                Event::Begin { kind: HEX_JUMP, .. } => {
                    HexToken::Jump(self.hex_jump()?)
                }
                _ => break,
            });
        }

        self.end(HEX_SUB_PATTERN)?;

        Ok(HexSubPattern(sub_patterns))
    }

    fn hex_alternative(&mut self) -> Result<HexAlternative, BuilderError> {
        self.begin(HEX_ALTERNATIVE)?;
        let l_paren_span = self.expect(L_PAREN)?;

        let mut alternatives = vec![self.hex_sub_pattern()?];

        while let Event::Token { kind: PIPE, .. } = self.peek() {
            self.expect(PIPE)?;
            alternatives.push(self.hex_sub_pattern()?);
        }

        let r_paren_span = self.expect(R_PAREN)?;
        self.end(HEX_ALTERNATIVE)?;

        Ok(HexAlternative {
            span: l_paren_span.combine(&r_paren_span),
            alternatives,
        })
    }

    fn hex_jump(&mut self) -> Result<HexJump, BuilderError> {
        self.begin(HEX_JUMP)?;
        let l_bracket_span = self.expect(L_BRACKET)?;

        let mut start = None;
        let mut end = None;

        if let Event::Token { kind: INTEGER_LIT, .. } = self.peek() {
            let (value, _lit, _span) = self.integer_lit::<u32>()?;
            start = Some(value);
        };

        if let Event::Token { kind: HYPHEN, .. } = self.peek() {
            self.expect(HYPHEN)?;
            if let Event::Token { kind: INTEGER_LIT, .. } = self.peek() {
                let (value, _lit, _span) = self.integer_lit::<u32>()?;
                end = Some(value);
            };
        } else {
            end = start;
        }

        let r_bracket_span = self.expect(R_BRACKET)?;
        self.end(HEX_JUMP)?;

        Ok(HexJump {
            span: l_bracket_span.combine(&r_bracket_span),
            start,
            end,
        })
    }

    fn boolean_expr(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(BOOLEAN_EXPR)?;
        let expr = self.pratt_parser(Self::boolean_term, 0)?;
        self.end(BOOLEAN_EXPR)?;
        Ok(expr)
    }

    fn boolean_expr_tuple(&mut self) -> Result<Vec<Expr<'src>>, BuilderError> {
        self.begin(BOOLEAN_EXPR_TUPLE)?;
        self.expect(L_PAREN)?;

        let mut exprs = vec![self.boolean_expr()?];

        while let Event::Token { kind: COMMA, .. } = self.peek() {
            self.expect(COMMA)?;
            exprs.push(self.boolean_expr()?);
        }

        self.expect(R_PAREN)?;
        self.end(BOOLEAN_EXPR_TUPLE)?;

        Ok(exprs)
    }

    fn boolean_term(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(BOOLEAN_TERM)?;

        let expr = match self.peek() {
            Event::Token { kind: FALSE_KW, .. } => {
                let span = self.expect(FALSE_KW)?;
                Expr::False { span }
            }
            Event::Token { kind: TRUE_KW, .. } => {
                let span = self.expect(TRUE_KW)?;
                Expr::True { span }
            }
            Event::Token { kind: NOT_KW, .. } => {
                let span = self.expect(NOT_KW)?;
                let term = self.boolean_term()?;
                let span = span.combine(&term.span());
                Expr::Not(Box::new(UnaryExpr { operand: term, span }))
            }
            Event::Token { kind: DEFINED_KW, .. } => {
                let span = self.expect(DEFINED_KW)?;
                let term = self.boolean_term()?;
                let span = span.combine(&term.span());
                Expr::Defined(Box::new(UnaryExpr { operand: term, span }))
            }
            Event::Token { kind: L_PAREN, .. } => {
                self.expect(L_PAREN)?;
                let expr = self.boolean_expr()?;
                self.expect(R_PAREN)?;
                expr
            }
            Event::Token { kind: PATTERN_IDENT, .. } => {
                Expr::PatternMatch(Box::new(PatternMatch {
                    identifier: self.pattern_ident()?,
                    anchor: self.anchor()?,
                }))
            }
            Event::Begin { kind: FOR_EXPR, .. } => self.for_expr()?,
            Event::Begin { kind: OF_EXPR, .. } => self.of_expr()?,
            Event::Begin { kind: WITH_EXPR, .. } => self.with_expr()?,
            Event::Begin { kind: EXPR, .. } => {
                self.pratt_parser(Self::expr, 0)?
            }
            event => panic!("unexpected {event:?}"),
        };

        self.end(BOOLEAN_TERM)?;

        Ok(expr)
    }

    fn for_expr(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(FOR_EXPR)?;

        let for_span = self.expect(FOR_KW)?;
        let quantifier = self.quantifier()?;

        let mut pattern_set = None;
        let mut iterable = None;
        let mut variables = Vec::new();

        match self.peek() {
            Event::Token { kind: OF_KW, .. } => {
                self.expect(OF_KW)?;
                pattern_set = match self.peek() {
                    Event::Token { kind: THEM_KW, .. } => {
                        Some(PatternSet::Them { span: self.expect(THEM_KW)? })
                    }
                    Event::Begin { kind: PATTERN_IDENT_TUPLE, .. } => {
                        Some(PatternSet::Set(self.pattern_ident_tuple()?))
                    }
                    event => panic!("unexpected {event:?}"),
                };
            }
            Event::Token { kind: IDENT, .. } => {
                loop {
                    variables.push(self.identifier()?);
                    match self.next()? {
                        Event::Token { kind: COMMA, .. } => {}
                        Event::Token { kind: IN_KW, .. } => {
                            break;
                        }
                        event => panic!("unexpected {event:?}"),
                    }
                }
                iterable = Some(self.iterable()?);
            }
            event => panic!("unexpected {event:?}"),
        }

        self.expect(COLON)?;
        self.expect(L_PAREN)?;

        let body = self.boolean_expr()?;

        // The span goes form the `for` keyword to the closing parenthesis.
        let span = for_span.combine(&self.expect(R_PAREN)?);

        self.end(FOR_EXPR)?;

        let expr = if let Some(pattern_set) = pattern_set {
            Expr::ForOf(Box::new(ForOf {
                span,
                quantifier,
                pattern_set,
                body,
            }))
        } else if let Some(iterable) = iterable {
            Expr::ForIn(Box::new(ForIn {
                span,
                quantifier,
                variables,
                iterable,
                body,
            }))
        } else {
            unreachable!()
        };

        Ok(expr)
    }

    fn of_expr(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(OF_EXPR)?;
        let quantifier = self.quantifier()?;
        self.expect(OF_KW)?;

        let items = match self.peek() {
            Event::Token { kind: THEM_KW, .. } => {
                OfItems::PatternSet(PatternSet::Them {
                    span: self.expect(THEM_KW)?,
                })
            }
            Event::Begin { kind: PATTERN_IDENT_TUPLE, .. } => {
                OfItems::PatternSet(PatternSet::Set(
                    self.pattern_ident_tuple()?,
                ))
            }
            Event::Begin { kind: BOOLEAN_EXPR_TUPLE, .. } => {
                OfItems::BoolExprTuple(self.boolean_expr_tuple()?)
            }
            event => panic!("unexpected {event:?}"),
        };

        let anchor = self.anchor()?;

        self.end(OF_EXPR)?;

        let mut span = quantifier.span().combine(&items.span());

        if let Some(anchor) = &anchor {
            span = span.combine(&anchor.span())
        }

        Ok(Expr::Of(Box::new(Of { span, quantifier, items, anchor })))
    }

    fn with_expr(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(WITH_EXPR)?;

        let mut span = self.expect(WITH_KW)?;

        self.begin(WITH_DECLS)?;

        let declaration =
            |i: &mut Self| -> Result<WithDeclaration<'src>, BuilderError> {
                i.begin(WITH_DECL)?;

                let identifier = i.identifier()?;
                let mut span = identifier.span();
                span = span.combine(&i.expect(EQUAL)?);
                let expression = i.expr()?;
                span = span.combine(&expression.span());

                i.end(WITH_DECL)?;

                Ok(WithDeclaration { span, identifier, expression })
            };

        let mut declarations = vec![declaration(self)?];

        while let Event::Token { kind: COMMA, .. } = self.peek() {
            self.expect(COMMA)?;
            declarations.push(declaration(self)?);
        }

        self.end(WITH_DECLS)?;

        self.expect(COLON)?;
        self.expect(L_PAREN)?;

        let body = self.boolean_expr()?;

        span = span.combine(&self.expect(R_PAREN)?);

        self.end(WITH_EXPR)?;

        Ok(Expr::With(Box::new(With { span, declarations, body })))
    }

    fn quantifier(&mut self) -> Result<Quantifier<'src>, BuilderError> {
        self.begin(QUANTIFIER)?;

        let quantifier = match self.peek() {
            Event::Token { kind: ALL_KW, .. } => {
                Quantifier::All { span: self.expect(ALL_KW)? }
            }
            Event::Token { kind: NONE_KW, .. } => {
                Quantifier::None { span: self.expect(NONE_KW)? }
            }
            Event::Token { kind: ANY_KW, .. } => {
                Quantifier::Any { span: self.expect(ANY_KW)? }
            }
            Event::Begin { kind: TERM, .. } => {
                let expr = self.term()?;
                self.expect(PERCENT)?;
                Quantifier::Percentage(expr)
            }
            Event::Begin { kind: EXPR, .. } => Quantifier::Expr(self.expr()?),
            event => panic!("unexpected {event:?}"),
        };

        self.end(QUANTIFIER)?;

        Ok(quantifier)
    }

    fn iterable(&mut self) -> Result<Iterable<'src>, BuilderError> {
        self.begin(ITERABLE)?;

        let iterable = match self.peek() {
            Event::Begin { kind: RANGE, .. } => Iterable::Range(self.range()?),
            Event::Begin { kind: EXPR_TUPLE, .. } => {
                Iterable::ExprTuple(self.expr_tuple()?)
            }
            Event::Begin { kind: EXPR, .. } => Iterable::Expr(self.expr()?),
            event => panic!("unexpected {event:?}"),
        };

        self.end(ITERABLE)?;

        Ok(iterable)
    }

    fn anchor(&mut self) -> Result<Option<MatchAnchor<'src>>, BuilderError> {
        match self.peek() {
            Event::Token { kind: AT_KW, .. } => {
                let at_span = self.expect(AT_KW)?;
                let expr = self.expr()?;
                Ok(Some(MatchAnchor::At(Box::new(At {
                    span: at_span.combine(&expr.span()),
                    expr,
                }))))
            }
            Event::Token { kind: IN_KW, .. } => {
                let in_span = self.expect(IN_KW)?;
                let range = self.range()?;
                Ok(Some(MatchAnchor::In(Box::new(In {
                    span: in_span.combine(&range.span()),
                    range,
                }))))
            }
            _ => Ok(None),
        }
    }

    fn range(&mut self) -> Result<Range<'src>, BuilderError> {
        self.begin(RANGE)?;

        let l_paren_span = self.expect(L_PAREN)?;
        let lower_bound = self.expr()?;

        self.expect(DOT)?;
        self.expect(DOT)?;

        let upper_bound = self.expr()?;
        let r_paren_span = self.expect(R_PAREN)?;

        self.end(RANGE)?;

        Ok(Range {
            span: l_paren_span.combine(&r_paren_span),
            lower_bound,
            upper_bound,
        })
    }

    fn expr(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(EXPR)?;
        let expr = self.pratt_parser(Self::term, 0)?;
        self.end(EXPR)?;
        Ok(expr)
    }

    fn expr_tuple(&mut self) -> Result<Vec<Expr<'src>>, BuilderError> {
        self.begin(EXPR_TUPLE)?;
        self.expect(L_PAREN)?;

        let mut exprs = vec![self.expr()?];

        while let Event::Token { kind: COMMA, .. } = self.peek() {
            self.expect(COMMA)?;
            exprs.push(self.expr()?);
        }

        self.expect(R_PAREN)?;
        self.end(EXPR_TUPLE)?;

        Ok(exprs)
    }

    fn primary_expr(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(PRIMARY_EXPR)?;

        let mut expr = match self.peek() {
            Event::Begin { kind: FUNC_CALL, .. } => self.func_call(None)?,
            Event::Token { kind: IDENT, .. } => {
                Expr::Ident(Box::new(self.identifier()?))
            }
            expr => panic!("unexpected {expr:?}"),
        };

        if let Event::Token { kind: L_BRACKET, .. } = self.peek() {
            self.expect(L_BRACKET)?;
            let span = expr.span();
            let index = self.expr()?;
            let span = span.combine(&self.expect(R_BRACKET)?);

            expr =
                Expr::Lookup(Box::new(Lookup { primary: expr, index, span }))
        }

        self.end(PRIMARY_EXPR)?;

        Ok(expr)
    }

    fn func_call(
        &mut self,
        object: Option<Expr<'src>>,
    ) -> Result<Expr<'src>, BuilderError> {
        self.begin(FUNC_CALL)?;

        let identifier = self.identifier()?;
        let l_paren_span = self.expect(L_PAREN)?;
        let mut args = Vec::new();

        while let Event::Begin { kind: BOOLEAN_EXPR, .. } = self.peek() {
            args.push(self.boolean_expr()?);
            if let Event::Token { kind: COMMA, .. } = self.peek() {
                self.expect(COMMA)?;
            }
        }

        let r_paren_span = self.expect(R_PAREN)?;

        let expr = Expr::FuncCall(Box::new(FuncCall {
            args_span: l_paren_span.combine(&r_paren_span),
            object,
            identifier,
            args,
        }));

        self.end(FUNC_CALL)?;

        Ok(expr)
    }

    fn term(&mut self) -> Result<Expr<'src>, BuilderError> {
        self.begin(TERM)?;

        let expr = match self.peek() {
            Event::Token { kind: FLOAT_LIT, .. } => {
                let (value, literal, span) = self.float_lit()?;
                Expr::LiteralFloat(Box::new(LiteralFloat {
                    span,
                    literal,
                    value,
                }))
            }
            Event::Token { kind: INTEGER_LIT, .. } => {
                let (value, literal, span) = self.integer_lit()?;
                Expr::LiteralInteger(Box::new(LiteralInteger {
                    span,
                    literal,
                    value,
                }))
            }
            Event::Token { kind: STRING_LIT, .. } => {
                let (value, literal, span) = self.string_lit(true)?;
                Expr::LiteralString(Box::new(LiteralString {
                    span,
                    literal,
                    value,
                }))
            }
            Event::Token { kind: REGEXP, .. } => {
                Expr::Regexp(Box::new(self.regexp()?))
            }
            Event::Token { kind: FILESIZE_KW, .. } => {
                Expr::Filesize { span: self.expect(FILESIZE_KW)? }
            }
            Event::Token { kind: ENTRYPOINT_KW, .. } => {
                Expr::Entrypoint { span: self.expect(ENTRYPOINT_KW)? }
            }
            Event::Token { kind: PATTERN_COUNT, .. } => {
                let span = self.expect(PATTERN_COUNT)?;
                let name = self.get_source_str(&span)?;

                let (span_with_range, range) =
                    if let Event::Token { kind: IN_KW, .. } = self.peek() {
                        self.expect(IN_KW)?;
                        let range = self.range()?;
                        (span.combine(&range.span()), Some(range))
                    } else {
                        (span.clone(), None)
                    };

                Expr::PatternCount(Box::new(IdentWithRange {
                    span: span_with_range,
                    identifier: Ident { span, name },
                    range,
                }))
            }
            Event::Token { kind: PATTERN_OFFSET, .. } => {
                let span = self.expect(PATTERN_OFFSET)?;
                let name = self.get_source_str(&span)?;

                let (span_with_index, index) = if let Event::Token {
                    kind: L_BRACKET,
                    ..
                } = self.peek()
                {
                    self.expect(L_BRACKET)?;
                    let index = self.expr()?;
                    let r_bracket_span = self.expect(R_BRACKET)?;
                    (span.combine(&r_bracket_span), Some(index))
                } else {
                    (span.clone(), None)
                };

                Expr::PatternOffset(Box::new(IdentWithIndex {
                    span: span_with_index,
                    identifier: Ident { span, name },
                    index,
                }))
            }
            Event::Token { kind: PATTERN_LENGTH, .. } => {
                let span = self.expect(PATTERN_LENGTH)?;
                let name = self.get_source_str(&span)?;

                let (span_with_index, index) = if let Event::Token {
                    kind: L_BRACKET,
                    ..
                } = self.peek()
                {
                    self.expect(L_BRACKET)?;
                    let index = self.expr()?;
                    let r_bracket_span = self.expect(R_BRACKET)?;
                    (span.combine(&r_bracket_span), Some(index))
                } else {
                    (span.clone(), None)
                };

                Expr::PatternLength(Box::new(IdentWithIndex {
                    span: span_with_index,
                    identifier: Ident { span, name },
                    index,
                }))
            }
            Event::Token { kind: BITWISE_NOT, .. } => {
                let span = self.expect(BITWISE_NOT)?;
                let operand = self.term()?;
                Expr::BitwiseNot(Box::new(UnaryExpr {
                    span: span.combine(&operand.span()),
                    operand,
                }))
            }
            Event::Token { kind: MINUS, .. } => {
                let operator_span = self.expect(MINUS)?;
                let operand = self.term()?;
                let operand_span = operand.span();
                let span = operator_span.combine(&operand_span);
                let literal = self.get_source_str(&span)?;

                match operand {
                    // Special case: if a minus sign is immediately followed
                    // by a positive literal integer, we don't construct a
                    // `Expr::Minus` with a `Expr::LiteralInteger` operand.
                    //
                    // Instead, we merge them into a single `Expr::LiteralInteger`
                    // with a negative value, updating its span and literal to
                    // include the minus sign.
                    //
                    // This optimization is applied only if the original integer
                    // is positive and not parenthesized. This avoids cases like
                    // `--1` (which would become `--1`) or `-(1)` (which would
                    // become `-(1`).
                    Expr::LiteralInteger(mut integer)
                        if integer.value.is_positive()
                            && !literal.contains('(') =>
                    {
                        integer.value = -integer.value;
                        integer.literal = literal;
                        integer.span = span;
                        Expr::LiteralInteger(integer)
                    }
                    _ => Expr::Minus(Box::new(UnaryExpr { span, operand })),
                }
            }
            Event::Token { kind: L_PAREN, .. } => {
                self.expect(L_PAREN)?;
                let expr = self.expr()?;
                self.expect(R_PAREN)?;
                expr
            }
            Event::Begin { kind: PRIMARY_EXPR, .. } => {
                let mut exprs = vec![self.primary_expr()?];

                while let Event::Token { kind: DOT, .. } = self.peek() {
                    self.expect(DOT)?;
                    exprs.push(self.primary_expr()?);
                }

                // Consecutive dot-separated expressions can be coalesced
                // into a single one based on the operands types. For
                // example `a.b` (identifier . identifier), is merged into
                // one FieldAccess expression. Similarly, if the left side
                // is already a FieldAccess, and the right is an identifier,
                // the identifier is simply added to the operand list of
                // the FieldAccess. There are more cases, all covered below.
                let mut coalesced: Vec<Expr> = exprs
                    .into_iter()
                    .coalesce(|x, y| match (x, y) {
                        // Two consecutive identifiers, this is a field access.
                        (left @ Expr::Ident(_), right @ Expr::Ident(_)) => {
                            Ok(Expr::FieldAccess(Box::new(NAryExpr::from(
                                vec![left, right],
                            ))))
                        }
                        // A field access followed by some identifier, add the
                        // identifier as another operator of the field access.
                        (
                            Expr::FieldAccess(mut field_access),
                            ident @ Expr::Ident(_),
                        ) => {
                            field_access.operands.push(ident);
                            Ok(Expr::FieldAccess(field_access))
                        }
                        //  A field access followed by a function call, the
                        // field access is the target object for the function.
                        (
                            field_access @ Expr::FieldAccess(_),
                            Expr::FuncCall(mut func_call),
                        ) => {
                            func_call.object = Some(field_access);
                            Ok(Expr::FuncCall(func_call))
                        }
                        // An identifier followed by a function call, the
                        // identifier is the target object for the function.
                        (
                            ident @ Expr::Ident(_),
                            Expr::FuncCall(mut func_call),
                        ) => {
                            func_call.object = Some(ident);
                            Ok(Expr::FuncCall(func_call))
                        }
                        // An identifier followed by a lookup expression.
                        (ident @ Expr::Ident(_), Expr::Lookup(mut lookup)) => {
                            lookup.span = ident.span().combine(&lookup.span);
                            lookup.primary = Expr::FieldAccess(Box::new(
                                NAryExpr::from(vec![ident, lookup.primary]),
                            ));
                            Ok(Expr::Lookup(lookup))
                        }
                        // Field access followed by a lookup expression.
                        (
                            Expr::FieldAccess(mut fa),
                            Expr::Lookup(mut lookup),
                        ) => {
                            fa.operands.push(lookup.primary);
                            lookup.span = fa.span().combine(&lookup.span);
                            lookup.primary = Expr::FieldAccess(fa);
                            Ok(Expr::Lookup(lookup))
                        }
                        (x, y) => Err((x, y)),
                    })
                    .collect();

                if coalesced.len() == 1 {
                    coalesced.pop().unwrap()
                } else {
                    Expr::FieldAccess(Box::new(NAryExpr::from(coalesced)))
                }
            }
            event => panic!("unexpected {event:?}"),
        };

        self.end(TERM)?;

        Ok(expr)
    }

    fn identifier(&mut self) -> Result<Ident<'src>, BuilderError> {
        let span = self.expect(IDENT)?;
        Ok(Ident { name: self.get_source_str(&span)?, span })
    }

    fn pattern_ident(&mut self) -> Result<Ident<'src>, BuilderError> {
        let span = self.expect(PATTERN_IDENT)?;
        Ok(Ident { name: self.get_source_str(&span)?, span })
    }

    fn pattern_ident_tuple(
        &mut self,
    ) -> Result<Vec<PatternSetItem<'src>>, BuilderError> {
        self.begin(PATTERN_IDENT_TUPLE)?;
        self.expect(L_PAREN)?;

        let item =
            |s: &mut Self| -> Result<PatternSetItem<'src>, BuilderError> {
                let ident = s.pattern_ident()?;
                let mut span = ident.span();
                let wildcard =
                    if matches!(s.peek(), Event::Token { kind: ASTERISK, .. })
                    {
                        span = span.combine(&s.expect(ASTERISK)?);
                        true
                    } else {
                        false
                    };
                Ok(PatternSetItem { span, identifier: ident.name, wildcard })
            };

        let mut items = vec![item(self)?];

        while let Event::Token { kind: COMMA, .. } = self.peek() {
            self.expect(COMMA)?;
            items.push(item(self)?);
        }

        self.expect(R_PAREN)?;
        self.end(PATTERN_IDENT_TUPLE)?;

        Ok(items)
    }

    fn integer_lit<T>(&mut self) -> Result<(T, &'src str, Span), BuilderError>
    where
        T: Num + Bounded + CheckedMul + FromPrimitive + std::fmt::Display,
    {
        let span = self.expect(INTEGER_LIT)?;
        let mut literal = self.get_source_str(&span)?;
        let mut multiplier = 1;

        if let Some(without_suffix) = literal.strip_suffix("KB") {
            literal = without_suffix;
            multiplier = 1024;
        }

        if let Some(without_suffix) = literal.strip_suffix("MB") {
            literal = without_suffix;
            multiplier = 1024 * 1024;
        }

        let literal_no_underscores = literal.replace('_', "");
        let value = if literal_no_underscores.as_str().starts_with("0x") {
            T::from_str_radix(
                literal_no_underscores.strip_prefix("0x").unwrap(),
                16,
            )
        } else if literal.starts_with("0o") {
            T::from_str_radix(
                literal_no_underscores.strip_prefix("0o").unwrap(),
                8,
            )
        } else {
            T::from_str_radix(literal_no_underscores.as_str(), 10)
        };

        let build_error = |span: &Span| Error::InvalidInteger {
            message: format!(
                "this number is out of the valid range: [{}, {}]",
                T::min_value(),
                T::max_value()
            ),
            span: span.clone(),
        };

        // Report errors that occur while parsing the literal. Some errors
        // (like invalid characters or empty literals) never occur, because
        // the grammar ensures that only valid integers reach this point,
        // however the grammar doesn't make sure that the integer fits in
        // type T.
        let value = value.map_err(|_| {
            self.errors.push(build_error(&span));
            BuilderError::Abort
        })?;

        // The multiplier may not fit in type T.
        let multiplier = T::from_i32(multiplier).ok_or_else(|| {
            self.errors.push(build_error(&span));
            BuilderError::Abort
        })?;

        // The value after applying the multiplier may not fit in type T.
        let value = value.checked_mul(&multiplier).ok_or_else(|| {
            self.errors.push(build_error(&span));
            BuilderError::Abort
        })?;

        Ok((value, literal, span))
    }

    fn float_lit(&mut self) -> Result<(f64, &'src str, Span), BuilderError> {
        let span = self.expect(FLOAT_LIT)?;
        let literal = self.get_source_str(&span)?;
        let value =
            literal.replace('_', "").parse::<f64>().map_err(|err| {
                self.errors.push(Error::InvalidFloat {
                    message: err.to_string(),
                    span: span.clone(),
                });
                BuilderError::Abort
            })?;

        Ok((value, literal, span))
    }

    fn regexp(&mut self) -> Result<Regexp<'src>, BuilderError> {
        let span = self.expect(REGEXP)?;
        let re = self.get_source_str(&span)?;

        // Regular expressions must start with a slash (/)
        debug_assert!(re.starts_with('/'));

        // It must contain a closing slash too, but not necessarily at the end
        // because the closing slash may be followed by a regexp modifier like "i"
        // and "s" (e.g. /foo/i)
        let closing_slash = re.rfind('/').unwrap();

        let mut case_insensitive = false;
        let mut dot_matches_new_line = false;

        for (i, modifier) in re[closing_slash + 1..].char_indices() {
            match modifier {
                'i' => case_insensitive = true,
                's' => dot_matches_new_line = true,
                c => {
                    let span = span.subspan(
                        closing_slash + 1 + i,
                        closing_slash + 1 + i + c.len_utf8(),
                    );

                    self.errors.push(Error::InvalidRegexpModifier {
                        message: format!("{c}"),
                        span,
                    });

                    return Err(BuilderError::Abort);
                }
            }
        }

        Ok(Regexp {
            span,
            literal: re,
            src: &re[1..closing_slash],
            case_insensitive,
            dot_matches_new_line,
        })
    }

    /// This function is similar [`string_lit`] but guarantees that the
    /// string is a valid UTF-8 string.
    fn utf8_string_lit(&mut self) -> Result<(&'src str, Span), BuilderError> {
        // Call `string_lit` with `allow_escape_char` set to false. This
        // guarantees that the returned string is borrowed from the source code
        // and is valid UTF-8, therefore is safe to convert it to &str without
        // additional checks.
        match self.string_lit(false)? {
            (Cow::Borrowed(a), _, span) => unsafe {
                Ok((a.to_str_unchecked(), span))
            },
            _ => unreachable!(),
        }
    }

    /// Returns a string literal.
    ///
    /// `allow_escape_char` controls whether escaped characters are accepted or
    /// not.
    ///
    /// This function returns a [`Cow<'src, BStr>`]. If the string literal doesn't
    /// contain escaped characters, the literal is exactly as it appears in the
    /// source code, and we can return a reference to the code in the form of a
    /// &[`BStr`]. However, when the literal string contains escaped characters
    /// they must be unescaped, and hence, this function returns a [`BString`]
    /// instead.
    ///
    /// As escape characters can introduce arbitrary bytes in the string,
    /// including zeroes, they can't be represented by a Rust [`String`] or
    /// &[`str`] which requires valid UTF-8. For that reason we use [`BString`]
    /// and &[`BStr`] instead.
    ///
    /// When called with `allow_escaped_char: false`, the returned string can
    /// be safely converted to [`String`] or &[`str`].
    fn string_lit(
        &mut self,
        allow_escape_char: bool,
    ) -> Result<(Cow<'src, BStr>, &'src str, Span), BuilderError> {
        let span = self.expect(STRING_LIT)?;
        let literal = self.get_source_str(&span)?;

        let num_quotes = if literal.starts_with("\"\"\"") {
            debug_assert!(literal.starts_with("\"\"\""));
            debug_assert!(literal.ends_with("\"\"\""));
            3
        } else {
            debug_assert!(literal.starts_with('\"'));
            debug_assert!(literal.ends_with('\"'));
            1
        };

        // A span that doesn't include the quotes.
        let string_span = span.subspan(num_quotes, literal.len() - num_quotes);

        // Remove the quotes.
        let without_quotes = &literal[num_quotes..literal.len() - num_quotes];

        // Check if the string contains some backslash.
        let first_backslash = if let Some(pos) = without_quotes.find('\\') {
            if !allow_escape_char {
                self.errors.push(Error::UnexpectedEscapeSequence(span));
                return Err(BuilderError::Abort);
            }
            pos
        } else {
            // If the literal does not contain a backslash it can't contain escaped
            // characters, the literal is exactly as it appears in the source code.
            // Therefore, we can return a reference to it in the form of a &BStr,
            // allocating a new BString is not necessary.
            return Ok((Cow::from(BStr::new(without_quotes)), literal, span));
        };

        // Initially the result is a copy of the literal string up to the first
        // backslash found.
        let mut result = BString::from(&without_quotes[..first_backslash]);

        // Process the remaining part of the literal, starting at the backslash.
        let remaining = &without_quotes[first_backslash..];
        let mut chars = remaining.char_indices();

        while let Some((backslash, b)) = chars.next() {
            match b {
                // The backslash indicates an escape sequence.
                '\\' => {
                    // Consume the backslash and see what's next. A character must
                    // follow the backslash, this is guaranteed by the grammar
                    // itself.
                    let escaped_char = if let Some(x) = chars.next() {
                        x
                    } else {
                        //
                        panic!()
                    };

                    match escaped_char.1 {
                        '\\' => result.push(b'\\'),
                        'n' => result.push(b'\n'),
                        'r' => result.push(b'\r'),
                        't' => result.push(b'\t'),
                        '0' => result.push(b'\0'),
                        '"' => result.push(b'"'),
                        'x' => {
                            match (chars.next(), chars.next()) {
                                (
                                    Some((start, first_char)),
                                    Some((end, second_char)),
                                ) if first_char.is_ascii_hexdigit()
                                    && second_char.is_ascii_hexdigit() =>
                                {
                                    let hex_value = u8::from_str_radix(
                                        &remaining[start..=end],
                                        16,
                                    )
                                    .unwrap();

                                    result.push(hex_value);
                                }
                                _ => {
                                    let (escaped_char_pos, _) = escaped_char;

                                    self.errors
                                    .push(Error::InvalidEscapeSequence {
                                    message:
                                        r"expecting two hex digits after `\x`"
                                            .to_string(),
                                    span: string_span.offset(first_backslash as isize).subspan(
                                        backslash,
                                        escaped_char_pos + 1,
                                    ),
                                });

                                    return Err(BuilderError::Abort);
                                }
                            }
                        }
                        _ => {
                            let (escaped_char_pos, escaped_char) =
                                escaped_char;

                            let escaped_char_end_pos =
                                escaped_char_pos + escaped_char.len_utf8();

                            self.errors.push(Error::InvalidEscapeSequence {
                                message: format!(
                                    "invalid escape sequence `{}`",
                                    &remaining
                                        [backslash..escaped_char_end_pos]
                                ),
                                span: string_span
                                    .offset(first_backslash as isize)
                                    .subspan(backslash, escaped_char_end_pos),
                            });

                            return Err(BuilderError::Abort);
                        }
                    }
                }
                // Non-escaped characters are copied as is.
                c => result.push_char(c),
            }
        }

        Ok((Cow::Owned(result), literal, span))
    }
}
