use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::{Debug, Display, Formatter};
use std::mem::replace;

use regex_syntax as re;
use regex_syntax::ast::{AssertionKind, Ast, ErrorKind, Literal, LiteralKind};
use thiserror::Error;

use yara_x_parser::ast;

use crate::re::hir::Hir;
use crate::types;

#[derive(Error, Debug)]
pub(crate) enum Error {
    SyntaxError {
        msg: String,
        span: re::ast::Span,
        note: Option<String>,
    },
    MixedGreediness {
        is_greedy_1: bool,
        is_greedy_2: bool,
        span_1: re::ast::Span,
        span_2: re::ast::Span,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SyntaxError { msg, .. } => write!(f, "{}", msg),
            Error::MixedGreediness { .. } => write!(f, "mixed greediness"),
        }
    }
}

/// The [`Regexp`] trait represents a regular expression.
pub(crate) trait Regexp {
    /// Must return the regular expression source code, without any delimiters
    /// like `/`. For instance, if the regexp is `/foo/i`, this must return
    /// "foo".
    fn source(&self) -> &str;
    /// Must return true if the regexp is case-sensitive. For instance, this
    /// is true for `/foo/i`.
    fn case_insensitive(&self) -> bool;
    /// Must return true if the dot (.) should match newline characters. For
    /// instance, this is true for `/foo/s`.
    fn dot_matches_new_line(&self) -> bool;
}

impl Regexp for ast::Regexp<'_> {
    #[inline]
    fn source(&self) -> &str {
        self.src
    }

    #[inline]
    fn case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    #[inline]
    fn dot_matches_new_line(&self) -> bool {
        self.dot_matches_new_line
    }
}

impl Regexp for types::Regexp {
    #[inline]
    fn source(&self) -> &str {
        self.naked()
    }

    #[inline]
    fn case_insensitive(&self) -> bool {
        self.case_insensitive()
    }

    #[inline]
    fn dot_matches_new_line(&self) -> bool {
        self.dot_matches_new_line()
    }
}

/// A regular expression parser.
///
/// Takes an [`ast::Regexp`] and produces its corresponding [`re::hir::Hir`].
pub(crate) struct Parser {
    force_case_insensitive: bool,
    allow_mixed_greediness: bool,
    relaxed_re_syntax: bool,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            force_case_insensitive: false,
            allow_mixed_greediness: true,
            relaxed_re_syntax: false,
        }
    }

    /// Parses the regexp as a case-insensitive one, no matter whether the regexp
    /// was actually flagged as case-insensitive or not.
    pub fn force_case_insensitive(mut self, yes: bool) -> Self {
        self.force_case_insensitive = yes;
        self
    }

    /// If true, allows regular expressions that mixes greedy and non-greedy
    /// quantifiers (e.g: `/ab.*cd.*?ef/`). When mixed greediness is not allowed
    /// [`Parser::parse`] returns an error if the regular expression contains
    /// both greedy and non-greedy quantifiers. By default, mixed greediness is
    /// allowed.
    pub fn allow_mixed_greediness(mut self, yes: bool) -> Self {
        self.allow_mixed_greediness = yes;
        self
    }

    /// Enables a more relaxed syntax check for regular expressions.
    ///
    /// YARA-X enforces stricter regular expression syntax compared to YARA.
    /// For instance, YARA accepts invalid escape sequences and treats them
    /// as literal characters (e.g., \R is interpreted as a literal 'R'). It
    /// also allows some special characters to appear unescaped, inferring
    /// their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
    /// literal, but in `/foo{0,1}bar/` they form the repetition operator
    /// `{0,1}`).
    ///
    /// This setting controls whether the parser should mimic YARA's behavior,
    /// allowing constructs that YARA-X doesn't accept by default.
    pub fn relaxed_re_syntax(mut self, yes: bool) -> Self {
        self.relaxed_re_syntax = yes;
        self
    }

    /// Parses the regexp and returns its HIR.
    pub fn parse(&self, regexp: &impl Regexp) -> Result<Hir, Error> {
        let mut re_src = Cow::Borrowed(regexp.source());
        let mut span_delta = 0_isize;

        // Utility function that given a span and a `delta` amount, adds that
        // amount to both the starting and ending points of the span. It will
        // be used for adjusting error spans after we have modified the
        // original regular expression. See comment below.
        let adjust_span = |span: &re::ast::Span, delta| {
            re::ast::Span::new(
                re::ast::Position::new(
                    span.start.offset.saturating_add_signed(delta),
                    span.start.line,
                    span.start.column.saturating_add_signed(delta),
                ),
                re::ast::Position::new(
                    span.end.offset.saturating_add_signed(delta),
                    span.end.line,
                    span.end.column.saturating_add_signed(delta),
                ),
            )
        };

        // YARA-X enforces stricter regular expression syntax compared to YARA.
        // For instance, YARA accepts invalid escape sequences and treats them
        // as literal characters (e.g., \R is interpreted as 'R'). It also
        // allows some special characters to appear unescaped, inferring their
        // meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
        // literal, but in `/foo{0,1}bar/` they form the repetition operator
        // `{0,1}`).
        //
        // When `relaxed_re_syntax` is set to true, YARA-X mimics YARA's
        // behavior by "fixing" the regular expressions. For instance, it
        // removes the backslash before invalid escape sequences like \R and
        // adds a backslash before `{` in cases like `/foo{}bar/`.
        let ast = loop {
            // The parser can't be reused, a new one must be created on
            // each iteration.
            let mut parser = re::ast::parse::ParserBuilder::new()
                .empty_min_range(true)
                .build();

            match parser.parse(re_src.as_ref()) {
                Ok(ast) => {
                    break Ok(ast);
                }
                Err(err) => {
                    if !self.relaxed_re_syntax {
                        break Err(err);
                    }
                    match err.kind() {
                        ErrorKind::EscapeUnrecognized
                        | ErrorKind::ClassEscapeInvalid => {
                            let span = err.span();
                            let mut s = re_src.into_owned();
                            // Remove the backslash (\) from the original regexp.
                            s.remove(span.start.offset);
                            re_src = Cow::Owned(s);
                            // By removing the backslash we are altering the spans
                            // of any other error that is found after this change,
                            // we need to account for that change. The new spans
                            // are one byte before they should be because we removed
                            // one byte, so we need to add 1 to fix those spans.
                            span_delta += 1;
                        }
                        ErrorKind::RepetitionMissing
                        | ErrorKind::RepetitionCountInvalid
                        | ErrorKind::RepetitionCountUnclosed
                        | ErrorKind::RepetitionCountDecimalEmpty => {
                            let span = err.span();
                            // Find the `{` that needs to be escaped. In some
                            // cases the error span starts exactly at the
                            // position where the `{` is, but in some other
                            // cases it starts a few characters after the `{`.
                            let curly_brace = re_src.as_ref()
                                [0..=span.start.offset]
                                .rfind('{')
                                .unwrap();
                            let mut s = re_src.into_owned();
                            // Insert a backslash in front of the `{`.
                            s.insert(curly_brace, '\\');
                            re_src = Cow::Owned(s);
                            span_delta -= 1;
                        }
                        _ => {
                            break Err(err);
                        }
                    }
                }
            };
        }
        .map_err(|err| {
            let span = err.span();
            let note = match err.kind() {
                ErrorKind::EscapeUnrecognized => {
                    let esc_seq = &re_src[span.start.offset..span.end.offset];
                    Some(format!(
                        "did you mean `\\{}` instead of `{}`?",
                        esc_seq, esc_seq
                    ))
                }
                ErrorKind::RepetitionMissing
                | ErrorKind::RepetitionCountInvalid
                | ErrorKind::RepetitionCountUnclosed
                | ErrorKind::RepetitionCountDecimalEmpty => {
                    Some("did you mean `\\{` instead of `{`?".to_string())
                }
                _ => None,
            };

            Error::SyntaxError {
                msg: err.kind().to_string(),
                span: adjust_span(span, span_delta),
                note,
            }
        })?;

        let ast = Transformer::new().transform(ast);
        let greedy = Validator::new().validate(&ast);

        // `greedy` is set to Some(true) if all regexp quantifiers are greedy,
        // Some(false) if all are non-greedy, and None if there's a mix of
        // greedy and non-greedy quantifiers, like in `foo.*bar.*?baz`. Mixed
        // greediness is allowed only if allow_mixed_greediness is true, an
        // error is returned if otherwise.
        let greedy = if self.allow_mixed_greediness {
            greedy.unwrap_or(None)
        } else {
            greedy?
        };

        let case_insensitive = if self.force_case_insensitive {
            true
        } else {
            regexp.case_insensitive()
        };

        let mut translator = re::hir::translate::TranslatorBuilder::new()
            .case_insensitive(case_insensitive)
            .dot_matches_new_line(regexp.dot_matches_new_line())
            .unicode(false)
            .utf8(false)
            .build();

        let hir =
            translator.translate(re_src.as_ref(), &ast).map_err(|err| {
                Error::SyntaxError {
                    msg: err.kind().to_string(),
                    span: adjust_span(err.span(), span_delta),
                    note: None,
                }
            })?;

        Ok(Hir { inner: hir, greedy })
    }
}

struct Validator {
    first_rep: Option<(bool, re::ast::Span)>,
}

impl Validator {
    fn new() -> Self {
        Self { first_rep: None }
    }

    fn validate(&mut self, ast: &Ast) -> Result<Option<bool>, Error> {
        re::ast::visit(ast, self)
    }
}

impl re::ast::Visitor for &mut Validator {
    type Output = Option<bool>;
    type Err = Error;

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(self.first_rep.map(|rep| rep.0))
    }

    fn visit_pre(&mut self, ast: &Ast) -> Result<(), Self::Err> {
        if let Ast::Repetition(rep) = ast {
            if let Some(first_rep) = self.first_rep {
                if rep.greedy != first_rep.0 {
                    return Err(Error::MixedGreediness {
                        is_greedy_1: rep.greedy,
                        is_greedy_2: first_rep.0,
                        span_1: *ast.span(),
                        span_2: first_rep.1,
                    });
                }
            } else {
                self.first_rep = Some((rep.greedy, rep.span));
            }
        }
        Ok(())
    }
}

/// Performs some transformations to the regexp AST.
///
/// This type takes an AST produced by the `regex_syntax` crate and returns
/// it with some changes that are necessary to ensure that regexps are
/// compatible with YARA.
///
/// At this moment the only change applied is the replacement of AST nodes
/// `WordBoundaryStartAngle` and `WordBoundaryEndAngle` with literals `<` and
/// `>` respectively. This is necessary because the `regex_syntax` crate
/// interprets sequences `\<` and `\>` as word start and word end boundaries,
/// equivalent to `\b{start}` and `\b{end}`, respectively. See [documentation][1]
///
/// YARA in the other hand, interprets these sequences as the escaped form for
/// literals `<` and `>`.
///
/// [1]: https://docs.rs/regex/latest/regex/#empty-matches
struct Transformer {}

impl Transformer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn transform(&self, mut ast: Ast) -> Ast {
        self.traverse(&mut ast);
        ast
    }
}

impl Transformer {
    fn traverse(&self, ast: &mut Ast) {
        let mut stack = VecDeque::new();

        stack.push_back(ast);

        while let Some(ast) = stack.pop_front() {
            match ast {
                Ast::Empty(_) => {}
                Ast::Flags(_) => {}
                Ast::Literal(_) => {}
                Ast::Dot(_) => {}
                Ast::Assertion(assertion) => match assertion.kind {
                    AssertionKind::WordBoundaryStartAngle => {}
                    AssertionKind::WordBoundaryEndAngle => {}
                    _ => {}
                },
                Ast::ClassUnicode(_) => {}
                Ast::ClassPerl(_) => {}
                Ast::ClassBracketed(_) => {}
                Ast::Repetition(rep) => {
                    self.replace_word_boundary_assertions(rep.ast.as_mut());
                    stack.push_back(rep.ast.as_mut());
                }
                Ast::Group(group) => {
                    self.replace_word_boundary_assertions(group.ast.as_mut());
                    stack.push_back(group.ast.as_mut());
                }
                Ast::Alternation(alternation) => {
                    for ast in alternation.asts.iter_mut() {
                        self.replace_word_boundary_assertions(ast);
                    }
                    for ast in alternation.asts.iter_mut() {
                        stack.push_back(ast);
                    }
                }
                Ast::Concat(concat) => {
                    for ast in concat.asts.iter_mut() {
                        self.replace_word_boundary_assertions(ast);
                    }
                    for ast in concat.asts.iter_mut() {
                        stack.push_back(ast);
                    }
                }
            }
        }
    }

    fn replace_word_boundary_assertions(&self, ast: &mut Ast) {
        if let Ast::Assertion(ref assertion) = ast {
            match assertion.kind {
                AssertionKind::WordBoundaryStartAngle => {
                    let _ = replace(
                        ast,
                        Ast::literal(Literal {
                            span: assertion.span,
                            kind: LiteralKind::Verbatim,
                            c: '<',
                        }),
                    );
                }
                AssertionKind::WordBoundaryEndAngle => {
                    let _ = replace(
                        ast,
                        Ast::literal(Literal {
                            span: assertion.span,
                            kind: LiteralKind::Verbatim,
                            c: '>',
                        }),
                    );
                }
                _ => {}
            }
        }
    }
}
