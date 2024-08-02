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
use crate::cst::{CSTStream, Event, SyntaxKind};
use crate::Span;

#[derive(Debug)]
struct Abort;

/// Creates an Abstract Syntax Tree from a [`Parser`].
pub(super) struct Builder<'src> {
    source: &'src [u8],
    events: Peekable<CSTStream<'src>>,
    errors: Vec<Error>,
}

impl<'src> Builder<'src> {
    pub fn new(parser: Parser<'src>) -> Self {
        Self {
            errors: Vec::new(),
            source: parser.source(),
            events: parser
                .into_cst_stream()
                .whitespaces(false)
                .newlines(false)
                .comments(false)
                .peekable(),
        }
    }

    pub fn build_ast(mut self) -> AST<'src> {
        let mut imports: Vec<Import> = Vec::new();
        let mut rules: Vec<Rule> = Vec::new();

        self.begin(SOURCE_FILE).unwrap();

        loop {
            match self.peek() {
                Event::Begin(RULE_DECL) => match self.rule_decl() {
                    Ok(rule) => rules.push(rule),
                    // If `rule_decl` returns an error the rule is ignored,
                    // but we try to continue at the next rule declaration
                    // or import statement. The `recover` function discards
                    // everything until finding the next rule or import.
                    Err(Abort) => self.recover(),
                },
                Event::Begin(IMPORT_STMT) => match self.import_stmt() {
                    Ok(import) => imports.push(import),
                    // If `import_stmt` returns an error the import is ignored,
                    // but we try to continue at the next rule declaration
                    // or import statement. The `recover` function discards
                    // everything until finding the next rule or import.
                    Err(Abort) => self.recover(),
                },
                Event::End(SOURCE_FILE) => break,
                _ => self.recover(),
            }
        }

        self.end(SOURCE_FILE).unwrap();

        AST { imports, rules, errors: self.errors }
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

impl<'src> Builder<'src> {
    /// Consumes all events until finding the start of a rule, an import
    /// statement or the end of the file.
    ///
    /// Any [`Event::Error`] found is added to `self.errors`.
    fn recover(&mut self) {
        loop {
            match self.peek() {
                Event::Begin(RULE_DECL) | Event::Begin(IMPORT_STMT) => break,
                Event::End(SOURCE_FILE) => break,
                _ => {
                    let _ = self.events.next();
                }
            }
        }
    }

    /// Consumes events of type [`Event::Error`] until finding one that
    /// is not an error.
    ///
    /// The consumed errors are appended to `self.errors`.
    fn consume_errors(&mut self) {
        self.errors.extend(
            self.events
                .peeking_take_while(|event| {
                    matches!(event, Event::Error { .. })
                })
                .map(|event| {
                    // The event is guaranteed to be an Event::Error by the
                    // predicate passed to `peeking_take_while`.
                    if let Event::Error { message, span } = event {
                        Error::SyntaxError { message, span }
                    } else {
                        unreachable!()
                    }
                }),
        );
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
    fn get_source_str(&mut self, span: &Span) -> Result<&'src str, Abort> {
        from_utf8(self.get_source(span)).map_err(|err| {
            self.errors.push(Error::InvalidUTF8(
                span.subspan(err.valid_up_to(), err.valid_up_to() + 1),
            ));
            Abort
        })
    }

    /// Returns a reference to the next non-error [`Event`] in the CST stream
    /// without consuming it.
    ///
    /// All events of type [`Event::Error`] that appears before the next non-error
    /// event are consumed.
    fn peek(&mut self) -> &Event {
        // Any Event::Error at the front of the event stream is consumed and
        // added to `self.errors`.
        self.consume_errors();
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
    fn next(&mut self) -> Result<Event, Abort> {
        if let Event::Begin(ERROR) = self.peek() {
            return Err(Abort);
        }
        Ok(self.events.next().expect("unexpected end of events"))
    }

    fn begin(&mut self, kind: SyntaxKind) -> Result<(), Abort> {
        assert_eq!(self.next()?, Event::Begin(kind));
        Ok(())
    }

    fn end(&mut self, kind: SyntaxKind) -> Result<(), Abort> {
        assert_eq!(self.next()?, Event::End(kind));
        Ok(())
    }

    /// Makes sure that the next non-error token is of the given kind.
    ///
    /// The token is consumed and the function returns the token's span.
    fn expect(&mut self, expected_kind: SyntaxKind) -> Result<Span, Abort> {
        match self.next()? {
            Event::Token { kind, span } => {
                if expected_kind != kind {
                    panic!("expected {:?}, got {:?}", expected_kind, kind);
                }
                Ok(span)
            }
            event @ Event::Begin(_) => {
                panic!("expected {:?}, got {:?}", expected_kind, event);
            }
            _ => panic!("unexpected end of events"),
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
        parse_expr: fn(&mut Self) -> Result<Expr<'src>, Abort>,
        min_bp: u8,
    ) -> Result<Expr<'src>, Abort> {
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
                Event::End(_) => break,
                event => panic!("unexpected {:?}", event),
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

impl<'src> Builder<'src> {
    fn import_stmt(&mut self) -> Result<Import<'src>, Abort> {
        self.begin(IMPORT_STMT)?;
        let span = self.expect(IMPORT_KW)?;
        let (module_name, module_name_span) = self.utf8_string_lit()?;
        self.end(IMPORT_STMT)?;
        Ok(Import { module_name, span: span.combine(&module_name_span) })
    }

    fn rule_decl(&mut self) -> Result<Rule<'src>, Abort> {
        self.begin(RULE_DECL)?;

        let flags = if let Event::Begin(RULE_MODS) = self.peek() {
            self.rule_mods()?
        } else {
            RuleFlags::none()
        };

        self.expect(RULE_KW)?;

        let identifier = self.identifier()?;

        let tags = if let Event::Begin(RULE_TAGS) = self.peek() {
            Some(self.rule_tags()?)
        } else {
            None
        };

        self.expect(L_BRACE)?;

        let meta = if let Event::Begin(META_BLK) = self.peek() {
            Some(self.meta_blk()?)
        } else {
            None
        };

        let patterns = if let Event::Begin(PATTERNS_BLK) = self.peek() {
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

    fn rule_mods(&mut self) -> Result<RuleFlags, Abort> {
        self.begin(RULE_MODS)?;

        let mut flags = RuleFlags::none();

        loop {
            match self.next()? {
                Event::Token { kind: GLOBAL_KW, .. } => {
                    flags.set(RuleFlag::Global)
                }
                Event::Token { kind: PRIVATE_KW, .. } => {
                    flags.set(RuleFlag::Private)
                }
                Event::End(RULE_MODS) => break,
                event => panic!("unexpected {:?}", event),
            }
        }

        Ok(flags)
    }

    fn rule_tags(&mut self) -> Result<Vec<Ident<'src>>, Abort> {
        self.begin(RULE_TAGS)?;
        self.expect(COLON)?;

        let mut tags = Vec::new();

        while let Event::Token { kind: IDENT, .. } = self.peek() {
            tags.push(self.identifier()?);
        }

        self.end(RULE_TAGS)?;

        Ok(tags)
    }

    fn meta_blk(&mut self) -> Result<Vec<Meta<'src>>, Abort> {
        self.begin(META_BLK)?;
        self.expect(META_KW)?;
        self.expect(COLON)?;

        let mut meta = Vec::new();

        while let Event::Begin(META_DEF) = self.peek() {
            meta.push(self.meta_def()?)
        }

        self.end(META_BLK)?;

        Ok(meta)
    }

    fn patterns_blk(&mut self) -> Result<Vec<Pattern<'src>>, Abort> {
        self.begin(PATTERNS_BLK)?;
        self.expect(STRINGS_KW)?;
        self.expect(COLON)?;

        let mut patterns = Vec::new();

        while let Event::Begin(PATTERN_DEF) = self.peek() {
            patterns.push(self.pattern_def()?);
        }

        self.end(PATTERNS_BLK)?;

        Ok(patterns)
    }

    fn meta_def(&mut self) -> Result<Meta<'src>, Abort> {
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
                let (value, _, _) = self.integer_lit::<i64>()?;
                MetaValue::Integer(multiplier * value)
            }
            Event::Token { kind: FLOAT_LIT, .. } => {
                let (value, _, _) = self.float_lit()?;
                MetaValue::Float(multiplier as f64 * value)
            }
            Event::Token { kind: STRING_LIT, .. } => {
                match self.string_lit(true)? {
                    // If the result is a string borrowed directly from the
                    // source code, we can be sure that it's a valid UTF-8
                    // string.
                    (Cow::Borrowed(s), _lit, _span) => {
                        MetaValue::String(unsafe { s.to_str_unchecked() })
                    }
                    // If the result is an owned string is because it contains
                    // some escaped character, this string is not guaranteed
                    // to be a valid UTF-8 string.
                    (Cow::Owned(s), _lit, _span) => MetaValue::Bytes(s),
                }
            }
            Event::Token { kind: TRUE_KW, .. } => {
                self.expect(TRUE_KW)?;
                MetaValue::Bool(true)
            }
            Event::Token { kind: FALSE_KW, .. } => {
                self.expect(FALSE_KW)?;
                MetaValue::Bool(false)
            }
            event => panic!("unexpected {:?}", event),
        };

        self.end(META_DEF)?;

        Ok(Meta { identifier, value })
    }

    fn pattern_def(&mut self) -> Result<Pattern<'src>, Abort> {
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
            Event::Begin(HEX_PATTERN) => {
                let tokens = self.hex_pattern()?;
                let modifiers = self.pattern_mods_opt()?;

                Pattern::Hex(Box::new(HexPattern {
                    identifier,
                    tokens,
                    modifiers,
                }))
            }
            event => panic!("unexpected {:?}", event),
        };

        self.end(PATTERN_DEF)?;

        Ok(pattern)
    }

    fn pattern_mods_opt(&mut self) -> Result<PatternModifiers<'src>, Abort> {
        if let Event::Begin(PATTERN_MODS) = self.peek() {
            self.pattern_mods()
        } else {
            Ok(PatternModifiers::default())
        }
    }

    fn pattern_mods(&mut self) -> Result<PatternModifiers<'src>, Abort> {
        self.begin(PATTERN_MODS)?;

        let mut modifiers = Vec::new();

        while let Event::Begin(PATTERN_MOD) = self.peek() {
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
                            event => panic!("unexpected {:?}", event),
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
                        event => panic!("unexpected {:?}", event),
                    };
                }
                event => panic!("unexpected {:?}", event),
            }
            self.end(PATTERN_MOD)?;
        }

        self.end(PATTERN_MODS)?;

        Ok(PatternModifiers::new(modifiers))
    }

    fn hex_pattern(&mut self) -> Result<HexTokens, Abort> {
        self.begin(HEX_PATTERN)?;
        self.expect(L_BRACE)?;

        let sub_pattern = self.hex_sub_pattern()?;

        self.expect(R_BRACE)?;
        self.end(HEX_PATTERN)?;

        Ok(sub_pattern)
    }

    fn hex_sub_pattern(&mut self) -> Result<HexTokens, Abort> {
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
                Event::Begin(HEX_ALTERNATIVE) => {
                    HexToken::Alternative(Box::new(self.hex_alternative()?))
                }
                Event::Begin(HEX_JUMP) => HexToken::Jump(self.hex_jump()?),
                _ => break,
            });
        }

        self.end(HEX_SUB_PATTERN)?;

        Ok(HexTokens { tokens: sub_patterns })
    }

    fn hex_alternative(&mut self) -> Result<HexAlternative, Abort> {
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

    fn hex_jump(&mut self) -> Result<HexJump, Abort> {
        self.begin(HEX_JUMP)?;
        let l_bracket_span = self.expect(L_BRACKET)?;

        let mut start = None;
        let mut end = None;

        if let Event::Token { kind: INTEGER_LIT, .. } = self.peek() {
            let (value, _lit, _span) = self.integer_lit::<u16>()?;
            start = Some(value);
        };

        if let Event::Token { kind: HYPHEN, .. } = self.peek() {
            self.expect(HYPHEN)?;
            if let Event::Token { kind: INTEGER_LIT, .. } = self.peek() {
                let (value, _lit, _span) = self.integer_lit::<u16>()?;
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

    fn boolean_expr(&mut self) -> Result<Expr<'src>, Abort> {
        self.begin(BOOLEAN_EXPR)?;
        let expr = self.pratt_parser(Self::boolean_term, 0)?;
        self.end(BOOLEAN_EXPR)?;
        Ok(expr)
    }

    fn boolean_expr_tuple(&mut self) -> Result<Vec<Expr<'src>>, Abort> {
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

    fn boolean_term(&mut self) -> Result<Expr<'src>, Abort> {
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
            Event::Begin(FOR_EXPR) => self.for_expr()?,
            Event::Begin(OF_EXPR) => self.of_expr()?,
            Event::Begin(EXPR) => self.pratt_parser(Self::expr, 0)?,
            event => panic!("unexpected {:?}", event),
        };

        self.end(BOOLEAN_TERM)?;

        Ok(expr)
    }

    fn for_expr(&mut self) -> Result<Expr<'src>, Abort> {
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
                    Event::Begin(PATTERN_IDENT_TUPLE) => {
                        Some(PatternSet::Set(self.pattern_ident_tuple()?))
                    }
                    event => panic!("unexpected {:?}", event),
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
                        event => panic!("unexpected {:?}", event),
                    }
                }
                iterable = Some(self.iterable()?);
            }
            event => panic!("unexpected {:?}", event),
        }

        self.expect(COLON)?;
        self.expect(L_PAREN)?;

        let condition = self.boolean_expr()?;

        // The span goes form the `for` keyword to the closing parenthesis.
        let span = for_span.combine(&self.expect(R_PAREN)?);

        self.end(FOR_EXPR)?;

        let expr = if let Some(pattern_set) = pattern_set {
            Expr::ForOf(Box::new(ForOf {
                span,
                quantifier,
                pattern_set,
                condition,
            }))
        } else if let Some(iterable) = iterable {
            Expr::ForIn(Box::new(ForIn {
                span,
                quantifier,
                variables,
                iterable,
                condition,
            }))
        } else {
            unreachable!()
        };

        Ok(expr)
    }

    fn of_expr(&mut self) -> Result<Expr<'src>, Abort> {
        self.begin(OF_EXPR)?;
        let quantifier = self.quantifier()?;
        self.expect(OF_KW)?;

        let items = match self.peek() {
            Event::Token { kind: THEM_KW, .. } => {
                OfItems::PatternSet(PatternSet::Them {
                    span: self.expect(THEM_KW)?,
                })
            }
            Event::Begin(PATTERN_IDENT_TUPLE) => OfItems::PatternSet(
                PatternSet::Set(self.pattern_ident_tuple()?),
            ),
            Event::Begin(BOOLEAN_EXPR_TUPLE) => {
                OfItems::BoolExprTuple(self.boolean_expr_tuple()?)
            }
            event => panic!("unexpected {:?}", event),
        };

        let anchor = self.anchor()?;

        self.end(OF_EXPR)?;

        let mut span = quantifier.span().combine(&items.span());

        if let Some(anchor) = &anchor {
            span = span.combine(&anchor.span())
        }

        Ok(Expr::Of(Box::new(Of { span, quantifier, items, anchor })))
    }

    fn quantifier(&mut self) -> Result<Quantifier<'src>, Abort> {
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
            Event::Begin(PRIMARY_EXPR) => {
                let expr = self.primary_expr()?;
                self.expect(PERCENT)?;
                Quantifier::Percentage(expr)
            }
            Event::Begin(EXPR) => Quantifier::Expr(self.expr()?),
            event => panic!("unexpected {:?}", event),
        };

        self.end(QUANTIFIER)?;

        Ok(quantifier)
    }

    fn iterable(&mut self) -> Result<Iterable<'src>, Abort> {
        self.begin(ITERABLE)?;

        let iterable = match self.peek() {
            Event::Begin(RANGE) => Iterable::Range(self.range()?),
            Event::Begin(EXPR_TUPLE) => {
                Iterable::ExprTuple(self.expr_tuple()?)
            }
            Event::Begin(EXPR) => Iterable::Expr(self.expr()?),
            event => panic!("unexpected {:?}", event),
        };

        self.end(ITERABLE)?;

        Ok(iterable)
    }

    fn anchor(&mut self) -> Result<Option<MatchAnchor<'src>>, Abort> {
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

    fn range(&mut self) -> Result<Range<'src>, Abort> {
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

    fn expr(&mut self) -> Result<Expr<'src>, Abort> {
        self.begin(EXPR)?;
        let expr = self.pratt_parser(Self::term, 0)?;
        self.end(EXPR)?;
        Ok(expr)
    }

    fn expr_tuple(&mut self) -> Result<Vec<Expr<'src>>, Abort> {
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

    fn term(&mut self) -> Result<Expr<'src>, Abort> {
        self.begin(TERM)?;

        let mut expr = self.primary_expr()?;

        match self.peek() {
            // Array or dictionary lookup.
            Event::Token { kind: L_BRACKET, .. } => {
                self.expect(L_BRACKET)?;
                let index = self.expr()?;
                let span = expr.span();
                let span = span.combine(&self.expect(R_BRACKET)?);
                expr = Expr::Lookup(Box::new(Lookup {
                    primary: expr,
                    index,
                    span,
                }));
            }
            // Function call
            Event::Token { kind: L_PAREN, .. } => {
                let l_paren_span = self.expect(L_PAREN)?;
                let mut args = Vec::new();

                while let Event::Begin(BOOLEAN_EXPR) = self.peek() {
                    args.push(self.boolean_expr()?);
                    if let Event::Token { kind: COMMA, .. } = self.peek() {
                        self.expect(COMMA)?;
                    }
                }

                let r_paren_span = self.expect(R_PAREN)?;

                expr = Expr::FuncCall(Box::new(FuncCall {
                    span: expr.span().combine(&r_paren_span),
                    args_span: l_paren_span.combine(&r_paren_span),
                    callable: expr,
                    args,
                }));
            }
            _ => {}
        }

        self.end(TERM)?;

        Ok(expr)
    }

    fn primary_expr(&mut self) -> Result<Expr<'src>, Abort> {
        self.begin(PRIMARY_EXPR)?;

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

                let ident = Ident { span, name };

                Expr::PatternCount(Box::new(IdentWithRange {
                    span: span_with_range,
                    ident,
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

                let ident = Ident { span, name };

                Expr::PatternOffset(Box::new(IdentWithIndex {
                    span: span_with_index,
                    ident,
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

                let ident = Ident { span, name };

                Expr::PatternLength(Box::new(IdentWithIndex {
                    span: span_with_index,
                    ident,
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
                let span = self.expect(MINUS)?;
                let operand = self.term()?;
                Expr::Minus(Box::new(UnaryExpr {
                    span: span.combine(&operand.span()),
                    operand,
                }))
            }
            Event::Token { kind: L_PAREN, .. } => {
                self.expect(L_PAREN)?;
                let expr = self.expr()?;
                self.expect(R_PAREN)?;
                expr
            }
            Event::Token { kind: IDENT, .. } => {
                let mut idents =
                    vec![Expr::Ident(Box::new(self.identifier()?))];

                while let Event::Token { kind: DOT, .. } = self.peek() {
                    self.expect(DOT)?;
                    idents.push(Expr::Ident(Box::new(self.identifier()?)));
                }

                if idents.len() == 1 {
                    idents.pop().unwrap()
                } else {
                    Expr::FieldAccess(Box::new(NAryExpr::from(idents)))
                }
            }
            event => panic!("unexpected {:?}", event),
        };

        self.end(PRIMARY_EXPR)?;

        Ok(expr)
    }

    fn identifier(&mut self) -> Result<Ident<'src>, Abort> {
        let span = self.expect(IDENT)?;
        Ok(Ident { name: self.get_source_str(&span)?, span })
    }

    fn pattern_ident(&mut self) -> Result<Ident<'src>, Abort> {
        let span = self.expect(PATTERN_IDENT)?;
        Ok(Ident { name: self.get_source_str(&span)?, span })
    }

    fn pattern_ident_tuple(
        &mut self,
    ) -> Result<Vec<PatternSetItem<'src>>, Abort> {
        self.begin(PATTERN_IDENT_TUPLE)?;
        self.expect(L_PAREN)?;

        let item = |s: &mut Self| -> Result<PatternSetItem<'src>, Abort> {
            let ident = s.pattern_ident()?;
            let mut span = ident.span();
            let wildcard =
                if matches!(s.peek(), Event::Token { kind: ASTERISK, .. }) {
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

    fn integer_lit<T>(&mut self) -> Result<(T, &'src str, Span), Abort>
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

        let value = if literal.starts_with("0x") {
            T::from_str_radix(literal.strip_prefix("0x").unwrap(), 16)
        } else if literal.starts_with("0o") {
            T::from_str_radix(literal.strip_prefix("0o").unwrap(), 8)
        } else {
            T::from_str_radix(literal, 10)
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
            Abort
        })?;

        // The multiplier may not fit in type T.
        let multiplier = T::from_i32(multiplier).ok_or_else(|| {
            self.errors.push(build_error(&span));
            Abort
        })?;

        // The value after applying the multiplier may not fit in type T.
        let value = value.checked_mul(&multiplier).ok_or_else(|| {
            self.errors.push(build_error(&span));
            Abort
        })?;

        Ok((value, literal, span))
    }

    fn float_lit(&mut self) -> Result<(f64, &'src str, Span), Abort> {
        let span = self.expect(FLOAT_LIT)?;
        let literal = self.get_source_str(&span)?;
        let value = literal.parse::<f64>().map_err(|err| {
            self.errors.push(Error::InvalidFloat {
                message: err.to_string(),
                span: span.clone(),
            });
            Abort
        })?;

        Ok((value, literal, span))
    }

    fn regexp(&mut self) -> Result<Regexp<'src>, Abort> {
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
                        message: format!("{}", c),
                        span,
                    });

                    return Err(Abort);
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
    fn utf8_string_lit(&mut self) -> Result<(&'src str, Span), Abort> {
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
    ) -> Result<(Cow<'src, BStr>, &'src str, Span), Abort> {
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
        let backslash_pos = if let Some(backslash_pos) =
            without_quotes.find('\\')
        {
            if !allow_escape_char {
                self.errors.push(Error::UnexpectedEscapeSequence(span));
                return Err(Abort);
            }
            backslash_pos
        } else {
            // If the literal does not contain a backslash it can't contain escaped
            // characters, the literal is exactly as it appears in the source code.
            // Therefore, we can return a reference to it in the form of a &BStr,
            // allocating a new BString is not necessary.
            return Ok((Cow::from(BStr::new(without_quotes)), literal, span));
        };

        // Initially the result is a copy of the literal string up to the first
        // backslash found.
        let mut result = BString::from(&without_quotes[..backslash_pos]);

        // Process the remaining part of the literal, starting at the backslash.
        let without_quotes = &without_quotes[backslash_pos..];
        let mut chars = without_quotes.char_indices();

        while let Some((backslash_pos, b)) = chars.next() {
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
                        'x' => match (chars.next(), chars.next()) {
                            (Some((start, _)), Some((end, _))) => {
                                if let Ok(hex_value) = u8::from_str_radix(
                                    &without_quotes[start..=end],
                                    16,
                                ) {
                                    result.push(hex_value);
                                } else {
                                    self.errors.push(
                                        Error::InvalidEscapeSequence {
                                            message: format!(
                                                r"invalid hex value `{}` after `\x`",
                                                &without_quotes[start..=end]
                                            ),
                                            span: string_span
                                                .subspan(start, end + 1),
                                        }
                                    );
                                    return Err(Abort);
                                }
                            }
                            _ => {
                                self.errors
                                    .push(Error::InvalidEscapeSequence {
                                    message:
                                        r"expecting two hex digits after `\x`"
                                            .to_string(),
                                    span: string_span.subspan(
                                        backslash_pos,
                                        escaped_char.0 + 1,
                                    ),
                                });

                                return Err(Abort);
                            }
                        },
                        _ => {
                            let (escaped_char_pos, escaped_char) =
                                escaped_char;

                            let escaped_char_end_pos =
                                escaped_char_pos + escaped_char.len_utf8();

                            self.errors.push(Error::InvalidEscapeSequence {
                                message: format!(
                                    "invalid escape sequence `{}`",
                                    &without_quotes
                                        [backslash_pos..escaped_char_end_pos]
                                ),
                                span: string_span.subspan(
                                    backslash_pos,
                                    escaped_char_end_pos,
                                ),
                            });

                            return Err(Abort);
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
