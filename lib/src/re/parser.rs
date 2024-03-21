use std::fmt::{Debug, Display, Formatter};

use regex_syntax as re;
use thiserror::Error;

use crate::re::hir::Hir;
use crate::types;

use yara_x_parser::ast;

#[derive(Error, Debug)]
pub(crate) enum Error {
    SyntaxError {
        msg: String,
        span: re::ast::Span,
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
}

impl Parser {
    pub fn new() -> Self {
        Self { force_case_insensitive: false, allow_mixed_greediness: true }
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

    /// Parses the regexp and returns its HIR.
    pub fn parse(&self, regexp: &impl Regexp) -> Result<Hir, Error> {
        let mut parser =
            re::ast::parse::ParserBuilder::new().empty_min_range(true).build();

        let ast = parser.parse(regexp.source()).map_err(|err| {
            Error::SyntaxError {
                msg: err.kind().to_string(),
                span: *err.span(),
            }
        })?;

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
            translator.translate(regexp.source(), &ast).map_err(|err| {
                Error::SyntaxError {
                    msg: err.kind().to_string(),
                    span: *err.span(),
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

    fn validate(&mut self, ast: &re::ast::Ast) -> Result<Option<bool>, Error> {
        re::ast::visit(ast, self)
    }
}

impl re::ast::Visitor for &mut Validator {
    type Output = Option<bool>;
    type Err = Error;

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(self.first_rep.map(|rep| rep.0))
    }

    fn visit_pre(&mut self, ast: &re::ast::Ast) -> Result<(), Self::Err> {
        if let re::ast::Ast::Repetition(rep) = ast {
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
