/*! This module implements the logic that converts a CST into an AST. */

use std::iter::Peekable;
use std::str;
use std::str::from_utf8;

use bstr::{ByteSlice, ByteVec};
use itertools::Itertools;
use num_traits::{Bounded, CheckedMul, FromPrimitive, Num};

use crate::ast::*;
use crate::cst::SyntaxKind::*;
use crate::cst::{CSTStream, Event, SyntaxKind};
use crate::Span;

#[derive(Debug)]
struct Abort;

#[derive(Debug)]
enum Error {
    SyntaxError { message: String, span: Span },
    UnexpectedEscapeSequence(Span),
    InvalidEscapeSequence { message: String, span: Span },
    InvalidInteger { message: String, span: Span },
    InvalidFloat { message: String, span: Span },
}

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
                &Event::Begin(RULE_DECL) => match self.rule_decl() {
                    Ok(rule) => rules.push(rule),
                    // If `rule_decl` returns an error the rule is ignored,
                    // but we try to continue at the next rule declaration
                    // or import statement. The `recover` function discards
                    // everything until finding the next rule or import.
                    Err(Abort) => self.recover(),
                },
                &Event::Begin(IMPORT_STMT) => match self.import_stmt() {
                    Ok(import) => imports.push(import),
                    // If `import_stmt` returns an error the import is ignored,
                    // but we try to continue at the next rule declaration
                    // or import statement. The `recover` function discards
                    // everything until finding the next rule or import.
                    Err(Abort) => self.recover(),
                },
                &Event::End(SOURCE_FILE) => break,
                event => unreachable!("unexpected event {:?}", event),
            }
        }

        self.end(SOURCE_FILE).unwrap();

        AST { imports, rules }
    }
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

    /// Returns the fragment of source code defined by `span`.
    fn get_span(&self, span: &Span) -> &'src [u8] {
        self.source.get(span.range()).unwrap()
    }

    /// Returns the fragment of source code defined by `span` as a UTF-8
    /// string.
    ///
    /// # Panics
    ///
    /// If the source code contains non-valid UTF-8 characters in the given
    /// span.
    fn get_span_utf8(&self, span: &Span) -> &'src str {
        from_utf8(self.get_span(span)).unwrap()
    }

    /// Returns a reference to the next non-error [`Event`] in the CST stream
    /// without consuming it.
    ///
    /// All events of type [`Event::Error`] that appears before the next non-error
    /// event are consumed.
    fn peek(&mut self) -> &Event {
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
            _ => panic!("unexpected end of events"),
        }
    }

    fn pratt_parser(
        &mut self,
        f: fn(&mut Self) -> Result<Expr<'src>, Abort>,
        min_bp: u8,
    ) -> Result<Expr<'src>, Abort> {
        let mut lhs = f(self)?;

        loop {
            let (operator, (l_bp, r_bp)) = match self.peek() {
                Event::Token { kind, .. } => {
                    (*kind, infix_binding_power(*kind))
                }
                Event::End(_) => break,
                event => panic!("unexpected {:?}", event),
            };

            if l_bp < min_bp {
                break;
            }

            self.next()?;

            let rhs = self.pratt_parser(f, r_bp)?;
            let e = Box::new(NAryExpr::new(lhs, rhs));

            lhs = match operator {
                OR_KW => Expr::Or(e),
                AND_KW => Expr::And(e),
                _ => unreachable!(),
            };
        }

        Ok(lhs)
    }
}

impl<'src> Builder<'src> {
    fn import_stmt(&mut self) -> Result<Import<'src>, Abort> {
        self.begin(IMPORT_STMT)?;
        self.expect(IMPORT_KW)?;
        let (module_name, _span) = self.utf8_string_lit()?;
        self.end(IMPORT_STMT)?;
        Ok(Import { module_name })
    }

    fn rule_decl(&mut self) -> Result<Rule<'src>, Abort> {
        self.begin(RULE_DECL)?;

        let flags = if self.peek() == &Event::Begin(RULE_MODS) {
            self.rule_mods()?
        } else {
            RuleFlags::none()
        };

        self.expect(RULE_KW)?;

        let identifier = self.identifier()?;

        self.expect(L_BRACE)?;

        let meta = if self.peek() == &Event::Begin(META_BLK) {
            Some(self.meta_blk()?)
        } else {
            None
        };

        let patterns = if self.peek() == &Event::Begin(PATTERNS_BLK) {
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

        Ok(Rule { flags, identifier, tags: None, meta, patterns, condition })
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

    fn meta_blk(&mut self) -> Result<Vec<Meta<'src>>, Abort> {
        self.begin(META_BLK)?;
        self.expect(META_KW)?;
        self.expect(COLON)?;

        let mut meta = Vec::new();

        loop {
            match self.peek() {
                Event::Begin(META_DEF) => meta.push(self.meta_def()?),
                Event::End(META_BLK) => break,
                event => panic!("unexpected {:?}", event),
            }
        }

        self.end(META_BLK)?;

        Ok(meta)
    }

    fn patterns_blk(&mut self) -> Result<Vec<Pattern<'src>>, Abort> {
        self.begin(PATTERNS_BLK)?;
        self.expect(STRINGS_KW)?;
        self.expect(COLON)?;

        let mut patterns = Vec::new();

        loop {
            match self.peek() {
                Event::Begin(PATTERN_DEF) => {
                    patterns.push(self.pattern_def()?);
                }
                Event::End(PATTERNS_BLK) => break,
                event => panic!("unexpected {:?}", event),
            }
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
                    (Cow::Borrowed(s), _span) => {
                        MetaValue::String(unsafe { s.to_str_unchecked() })
                    }
                    // If the result is an owned string is because it contains
                    // some escaped character, this string is not guaranteed
                    // to be a valid UTF-8 string.
                    (Cow::Owned(s), _span) => MetaValue::Bytes(s),
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
                let (text, span) = self.string_lit(true)?;

                let mods = if let Event::Begin(PATTERN_MODS) = self.peek() {
                    self.pattern_mods()?
                } else {
                    PatternModifiers::default()
                };

                Pattern::Text(Box::new(TextPattern {
                    span,
                    identifier,
                    text,
                    modifiers: mods,
                }))
            }
            Event::Token { kind: REGEXP, .. } => {
                todo!()
            }
            Event::Begin(HEX_PATTERN) => todo!(),
            event => panic!("unexpected {:?}", event),
        };

        self.end(PATTERN_DEF)?;

        Ok(pattern)
    }

    fn pattern_mods(&mut self) -> Result<PatternModifiers<'src>, Abort> {
        self.begin(PATTERN_MODS)?;

        let mut modifiers = BTreeMap::new();

        loop {
            match self.peek() {
                Event::End(PATTERN_MODS) => break,
                Event::Begin(PATTERN_MOD) => {
                    self.begin(PATTERN_MOD)?;
                    match self.next()? {
                        Event::Token { kind: ASCII_KW, span } => {
                            modifiers.insert(
                                ASCII_KW,
                                PatternModifier::Ascii { span },
                            );
                        }
                        Event::Token { kind: WIDE_KW, span } => {
                            modifiers.insert(
                                WIDE_KW,
                                PatternModifier::Wide { span },
                            );
                        }
                        Event::Token { kind: PRIVATE_KW, span } => {
                            modifiers.insert(
                                PRIVATE_KW,
                                PatternModifier::Private { span },
                            );
                        }
                        Event::Token { kind: FULLWORD_KW, span } => {
                            modifiers.insert(
                                FULLWORD_KW,
                                PatternModifier::Fullword { span },
                            );
                        }
                        Event::Token { kind: NOCASE_KW, span } => {
                            modifiers.insert(
                                NOCASE_KW,
                                PatternModifier::Nocase { span },
                            );
                        }
                        Event::Token { kind: XOR_KW, span } => {
                            let mut start = 0;
                            let mut end = 0;

                            if let Event::Token { kind: L_PAREN, .. } =
                                self.peek()
                            {
                                self.expect(L_PAREN)?;
                                start = self.integer_lit::<u8>()?.0;

                                match self.next()? {
                                    Event::Token { kind: R_PAREN, .. } => {}
                                    Event::Token { kind: HYPHEN, .. } => {
                                        end = self.integer_lit::<u8>()?.0;
                                        self.expect(R_PAREN)?;
                                    }
                                    event => panic!("unexpected {:?}", event),
                                }
                            }

                            modifiers.insert(
                                XOR_KW,
                                PatternModifier::Xor { span, start, end },
                            );
                        }
                        Event::Token {
                            kind: BASE64_KW | BASE64WIDE_KW,
                            span,
                        } => {
                            todo!()
                        }
                        event => panic!("unexpected {:?}", event),
                    }

                    self.end(PATTERN_MOD)?;
                }
                event => panic!("unexpected {:?}", event),
            }
        }

        self.end(PATTERN_MODS)?;

        Ok(PatternModifiers::new(modifiers))
    }

    fn boolean_expr(&mut self) -> Result<Expr<'src>, Abort> {
        self.begin(BOOLEAN_EXPR)?;
        let expr = self.pratt_parser(Self::boolean_term, 0)?;
        self.end(BOOLEAN_EXPR)?;
        Ok(expr)
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
                Expr::Not(Box::new(UnaryExpr::new(term, span)))
            }
            Event::Token { kind: DEFINED_KW, .. } => {
                let span = self.expect(DEFINED_KW)?;
                let term = self.boolean_term()?;
                let span = span.combine(&term.span());
                Expr::Defined(Box::new(UnaryExpr::new(term, span)))
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
            Event::Begin(EXPR) => self.expr()?,
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
                    Event::Token { kind: L_PAREN, .. } => {
                        Some(PatternSet::Set(self.pattern_ident_tuple()?))
                    }
                    event => panic!("unexpected {:?}", event),
                };
            }
            Event::Token { kind: IDENT, .. } => loop {
                variables.push(self.identifier()?);
                match self.next()? {
                    Event::Token { kind: COMMA, .. } => {
                        variables.push(self.identifier()?);
                    }
                    Event::Token { kind: IN_KW, .. } => {
                        break;
                    }
                    event => panic!("unexpected {:?}", event),
                }

                iterable = Some(self.iterable()?);
            },
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
        self.end(OF_EXPR)?;
        todo!()
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
                let expr = self.expr()?;
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
        todo!()
    }

    fn anchor(&mut self) -> Result<Option<MatchAnchor<'src>>, Abort> {
        match self.peek() {
            Event::Token { kind: AT_KW, .. } => {
                let span = self.expect(AT_KW)?;
                Ok(Some(MatchAnchor::At(Box::new(At {
                    span,
                    expr: self.expr()?,
                }))))
            }
            Event::Token { kind: IN_KW, .. } => {
                let span = self.expect(IN_KW)?;
                Ok(Some(MatchAnchor::In(Box::new(In {
                    span,
                    range: self.range()?,
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
                let span = self.expect(L_PAREN)?;
                todo!()
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
            _ => unreachable!(),
        };

        self.end(PRIMARY_EXPR)?;

        Ok(expr)
    }

    fn identifier(&mut self) -> Result<Ident<'src>, Abort> {
        let span = self.expect(IDENT)?;
        Ok(Ident { name: self.get_span_utf8(&span), span })
    }

    fn pattern_ident(&mut self) -> Result<Ident<'src>, Abort> {
        let span = self.expect(PATTERN_IDENT)?;
        Ok(Ident { name: self.get_span_utf8(&span), span })
    }

    fn pattern_ident_tuple(
        &mut self,
    ) -> Result<Vec<PatternSetItem<'src>>, Abort> {
        todo!()
    }

    fn integer_lit<T>(&mut self) -> Result<(T, &'src str, Span), Abort>
    where
        T: Num + Bounded + CheckedMul + FromPrimitive + std::fmt::Display,
    {
        let span = self.expect(INTEGER_LIT)?;
        let mut literal = self.get_span_utf8(&span);
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
        let literal = self.get_span_utf8(&span);
        let value = literal.parse::<f64>().map_err(|err| {
            self.errors.push(Error::InvalidFloat {
                message: err.to_string(),
                span: span.clone(),
            });
            Abort
        })?;

        Ok((value, literal, span))
    }

    /// This function is similar [`string_lit`] but guarantees that the
    /// string is a valid UTF-8 string.
    fn utf8_string_lit(&mut self) -> Result<(&'src str, Span), Abort> {
        // Call `string_lit` with `allow_escape_char` set to false. This
        // guarantees that the returned string is borrowed from the source code
        // and is valid UTF-8, therefore is safe to convert it to &str without
        // additional checks.
        match self.string_lit(false)? {
            (Cow::Borrowed(a), span) => unsafe {
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
    ) -> Result<(Cow<'src, BStr>, Span), Abort> {
        let span = self.expect(STRING_LIT)?;
        let literal = self.get_span_utf8(&span);

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
        let literal = self.get_span_utf8(&span).trim_matches('"');

        // Check if the string contains some backslash.
        let backslash_pos = if let Some(backslash_pos) = literal.find('\\') {
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
            return Ok((Cow::from(BStr::new(literal)), span));
        };

        // Initially the result is a copy of the literal string up to the first
        // backslash found.
        let mut result = BString::from(&literal[..backslash_pos]);

        // Process the remaining part of the literal, starting at the backslash.
        let literal = &literal[backslash_pos..];
        let mut chars = literal.char_indices();

        while let Some((backslash_pos, b)) = chars.next() {
            match b {
                // The backslash indicates an escape sequence.
                '\\' => {
                    // Consume the backslash and see what's next. A character must
                    // follow the backslash, this is guaranteed by the grammar
                    // itself.
                    let escaped_char = chars.next().unwrap();

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
                                    &literal[start..=end],
                                    16,
                                ) {
                                    result.push(hex_value);
                                } else {
                                    self.errors.push(
                                        Error::InvalidEscapeSequence {
                                            message: format!(
                                                r"invalid hex value `{}` after `\x`",
                                                &literal[start..=end]
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
                                    &literal
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

        Ok((Cow::Owned(result), span))
    }
}

fn infix_binding_power(op: SyntaxKind) -> (u8, u8) {
    match op {
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
        op => panic!("unknown operator: {op:?}"),
    }
}
