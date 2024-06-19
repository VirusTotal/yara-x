use crate::ast::{Span, AST};
use crate::cst::CST;
use bstr::{BStr, ByteSlice};
use pest::Parser as PestParser;
use std::num::NonZeroUsize;

#[doc(inline)]
pub use crate::parser::errors::*;
pub use crate::parser::grammar::Rule as GrammarRule;

pub(crate) use crate::parser::context::*;
pub(crate) use crate::parser::cst2ast::*;
pub(crate) use crate::report::*;

mod context;
mod cst2ast;
mod errors;

#[cfg(test)]
mod tests;

/// A structure that describes some YARA source code.
///
/// This structure contains a `&str` pointing to the code itself, and an
/// optional `origin` that tells where the source code came from. The
/// most common use for `origin` is indicating the path of the file from
/// where the source code was obtained, but it can contain any arbitrary
/// string. This string, if provided, will appear in error messages. For
/// example, in this error message `origin` was set to `some_file.yar`:
///
/// ```text
/// error: syntax error
///  --> some_file.yar:4:17
///   |
/// 4 | ... more details
/// ```
///
/// # Example
///
/// ```
/// use yara_x_parser::SourceCode;
/// let src = SourceCode::from("rule test { condition: true }").with_origin("some_file.yar");
/// ```
///
#[derive(Debug, Clone)]
pub struct SourceCode<'src> {
    /// A reference to the source code itself. This is a BStr because the
    /// source code could contain non-UTF8 content.
    pub(crate) raw: &'src BStr,
    /// A reference to the source code after validating that it is valid
    /// UTF-8.
    pub(crate) valid: Option<&'src str>,
    /// An optional string that tells which is the origin of the code. Usually
    /// a file path.
    pub(crate) origin: Option<String>,
}

impl<'src> SourceCode<'src> {
    /// Sets a string that describes the origin of the source code.
    ///
    /// This is usually the path of the file that contained the source code,
    /// but it can be an arbitrary string. The origin appears in error and
    /// warning messages.
    pub fn with_origin(self, origin: &str) -> Self {
        Self {
            raw: self.raw,
            valid: self.valid,
            origin: Some(origin.to_owned()),
        }
    }

    /// Returns the source code as a `&str`.
    ///
    /// If the source code is not valid UTF-8 it will return an error.
    fn as_str(&mut self) -> Result<&'src str, bstr::Utf8Error> {
        match self.valid {
            // We already know that source code is valid UTF-8, return it
            // as is.
            Some(s) => Ok(s),
            // We don't know yet if the source code is valid UTF-8, some
            // validation must be done. If validation fails an error is
            // returned.
            None => {
                let src = self.raw.to_str()?;
                self.valid = Some(src);
                Ok(src)
            }
        }
    }
}

impl<'src> From<&'src str> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&str`.
    fn from(src: &'src str) -> Self {
        // The input is a &str, therefore it's guaranteed to be valid UTF-8
        // and the `valid` field can be initialized.
        Self { raw: BStr::new(src), valid: Some(src), origin: None }
    }
}

impl<'src> From<&'src [u8]> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&[u8]`.
    ///
    /// As `src` is not guaranteed to be a valid UTF-8 string, the parser will
    /// verify it and return an error if invalid UTF-8 characters are found.
    fn from(src: &'src [u8]) -> Self {
        // The input is a &[u8], its content is not guaranteed to be valid
        // UTF-8 so the `valid` field is set to `None`. The `validate_utf8`
        // function will be called for validating the source code before
        // being parsed.
        Self { raw: BStr::new(src), valid: None, origin: None }
    }
}

/// Receives YARA source code and produces either a Concrete Syntax Tree (CST)
/// or an Abstract Syntax Tree (AST).
#[derive(Default)]
pub struct Parser<'a> {
    external_report_builder: Option<&'a ReportBuilder>,
    own_report_builder: ReportBuilder,
}

impl<'a> Parser<'a> {
    /// Creates a new YARA parser.
    pub fn new() -> Self {
        // This imposes a limit on the number of calls that can be made to some
        // of the Pest parser's internal functions. The purpose of this limit
        // is preventing pathological cases from running forever, as certain
        // expressions, particularly nested parenthesised expressions, exhibit
        // an exponential behaviour.
        //
        // This limit also affects source files that are too large. The current
        // value has been determined experimentally, it's high enough to cause
        // errors with very few rules, while at the same time keeping rule
        // compile time reasonably low (~1 min) with pathological cases.
        pest::set_call_limit(NonZeroUsize::new(250_000_000));

        Self {
            external_report_builder: None,
            own_report_builder: ReportBuilder::new(),
        }
    }

    /// Specifies whether the parser should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn colorize_errors(&mut self, yes: bool) -> &mut Self {
        self.own_report_builder.with_colors(yes);
        self
    }

    /// Builds the Abstract Syntax Tree (AST) for some YARA source code.
    ///
    /// `src` can be any type that implements [`Into<SourceCode>`], which
    /// includes `&str`, `&[u8]`, and [`SourceCode`] itself. By passing a
    /// [`SourceCode`] you can provide additional information about the
    /// source code, like the path of the file that originally contained the
    /// code.
    ///
    /// The AST returned by this function holds references to the original
    /// source code. For example, identifiers in the AST point to the
    /// corresponding strings in the code. This avoids making copies of the
    /// strings representing the identifiers, but also implies that the
    /// memory backing the source code can't be dropped until the AST is
    /// dropped.
    ///
    /// # Examples
    ///
    /// Passing the source code directly to `build_ast`:
    ///
    /// ```
    /// use yara_x_parser::Parser;
    /// let src = "rule example { condition: true }";
    /// let ast = Parser::new().build_ast(src).unwrap();
    /// ```
    ///
    /// Passing a [`SourceCode`] structure:
    ///
    /// ```
    /// use yara_x_parser::{Parser, SourceCode};
    /// let src = SourceCode::from("rule example { condition: true }").with_origin("some_rule.yar");
    /// let ast = Parser::new().build_ast(src).unwrap();
    /// ```
    pub fn build_ast<'src, S>(&self, src: S) -> Result<AST<'src>, Error>
    where
        S: Into<SourceCode<'src>>,
    {
        let src = src.into();

        // Create the CST but ignore comments and whitespaces. They won't
        // be visible while traversing the CST as we don't need them for
        // building the AST.
        let cst =
            self.build_cst(src.clone())?.comments(false).whitespaces(false);

        // The root of the CST must be the grammar rule `source_file`.
        let root = cst.into_iter().next().unwrap();
        assert_eq!(root.as_rule(), GrammarRule::source_file);

        let report_builder = self.get_report_builder();

        let mut ctx = Context::new(report_builder);

        let (imports, rules) = ast_from_cst(&mut ctx, root.into_inner())?;

        Ok(AST { source: src, imports, rules })
    }

    /// Build the Concrete Syntax Tree (CST) for a YARA source.
    ///
    /// `src` can be any type that implements [`Into<SourceCode>`], which
    /// includes `&str`, `&[u8]`, and [`SourceCode`] itself. By passing a
    /// [`SourceCode`] you can provide additional information about the
    /// source code, like the path of the file that originally contained the
    /// code.
    ///
    /// The CST returned by this function holds references to the original
    /// source code. This implies that the memory backing the source code
    /// can't be dropped until the CST is dropped.
    ///
    /// # Examples
    ///
    /// Passing the source code directly to `build_cst`:
    ///
    /// ```
    /// use yara_x_parser::Parser;
    /// let src = "rule example { condition: true }";
    /// let cst = Parser::new().build_cst(src).unwrap();
    /// ```
    ///
    /// Passing a [`SourceCode`] structure:
    ///
    /// ```
    /// use yara_x_parser::{Parser, SourceCode};
    /// let src = SourceCode::from("rule example { condition: true }").with_origin("some_rule.yar");
    /// let cst = Parser::new().build_cst(src).unwrap();
    /// ```
    #[inline(always)]
    pub fn build_cst<'src, S>(&self, src: S) -> Result<CST<'src>, Error>
    where
        S: Into<SourceCode<'src>>,
    {
        self.build_rule_cst(GrammarRule::source_file, src)
    }

    /// Builds the CST for a specific grammar rule.
    ///
    /// The code in `src` must be in concordance with the grammar rule, for
    /// example if the rule is [`GrammarRule::boolean_expr`] the content of
    /// `src` must be something like `$a and $b`, passing a full YARA rule
    /// will fail because this grammar rule doesn't parse a full rule.
    ///
    /// This API is for internal use only.
    pub(crate) fn build_rule_cst<'src, S>(
        &self,
        rule: GrammarRule,
        src: S,
    ) -> Result<CST<'src>, Error>
    where
        S: Into<SourceCode<'src>>,
    {
        let report_builder = self.get_report_builder();
        let mut src = src.into();

        // Register the source code with the report builder, even if the code
        // is not valid UTF-8, so that we can build the report that tells
        // about the invalid UTF-8. In the registered source code invalid
        // characters are replaced with the Unicode replacement character.
        // https://www.compart.com/en/unicode/U+FFFD
        report_builder.register_source(&src);

        match src.as_str() {
            Ok(src) => {
                let pairs = grammar::ParserImpl::parse(rule, src).map_err(
                    |pest_error| report_builder.convert_pest_error(pest_error),
                )?;

                Ok(CST {
                    comments: false,
                    whitespaces: false,
                    pairs: Box::new(pairs),
                })
            }
            Err(err) => {
                let span_start = err.valid_up_to();
                let span_end = if let Some(error_len) = err.error_len() {
                    // `error_len` is the number of invalid UTF-8 bytes found
                    // after `span_start`. Round the number up to the next 3
                    // bytes boundary because invalid bytes are replaced with
                    // the Unicode replacement characters that takes 3 bytes.
                    // This way the span ends at a valid UTF-8 character
                    // boundary.
                    span_start + error_len.next_multiple_of(3)
                } else {
                    span_start
                };

                Err(Error::from(ErrorInfo::invalid_utf_8(
                    report_builder,
                    Span::new(
                        report_builder.current_source_id().unwrap(),
                        span_start,
                        span_end,
                    ),
                )))
            }
        }
    }

    /// Sets the report builder used by the Parser.
    ///
    /// This is optional, if the report builder is not set the Parser will
    /// create its own. However, this allows sharing the same report builder
    /// with the compiler. Setting a report builder overrides any color
    /// setting specified with [`Parser::colorize_errors`], the errors will
    /// be colorized depending on the settings of the report builder.
    ///
    /// This API is for internal use only.
    #[doc(hidden)]
    pub fn set_report_builder(
        &mut self,
        report_builder: &'a ReportBuilder,
    ) -> &mut Self {
        self.external_report_builder = Some(report_builder);
        self
    }

    /// Returns the report builder associated to the parser.
    ///
    /// If an external report builder was previously set using
    /// [`Parser::set_report_builder`] the external report builder is returned,
    /// if not, the report builder owned by the parser is returned instead.
    fn get_report_builder(&self) -> &ReportBuilder {
        self.external_report_builder.unwrap_or(&self.own_report_builder)
    }
}

mod grammar {
    #[derive(pest_derive::Parser)]
    #[grammar = "parser/grammar.pest"]
    pub struct ParserImpl;
}
