use crate::ast::{Span, AST};
use crate::cst::CST;
use bstr::{BStr, ByteSlice};
use pest::Parser as PestParser;

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
///    ╭─[some_file.yar:8:6]
///    │
///    ... more details
/// ```
///
/// # Example
///
/// ```
/// use yara_x_parser::SourceCode;
/// let src = SourceCode::from("rule test { condition: true }").origin("some_file.yar");
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
    /// This is usually the path of the file that contained the source code
    /// but it can be an arbitrary string. The origin appears in error and
    /// warning messages.
    pub fn origin(self, origin: &str) -> Self {
        Self {
            raw: self.raw,
            valid: self.valid,
            origin: Some(origin.to_owned()),
        }
    }

    /// Make sure that the source code is valid UTF-8. If that's the case
    /// sets the `valid` field, if not, returns an error.
    fn validate_utf8(&mut self) -> Result<(), bstr::Utf8Error> {
        if self.valid.is_none() {
            self.valid = Some(self.raw.to_str()?);
        }
        Ok(())
    }
}

impl<'src> From<&'src str> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&str`.
    fn from(src: &'src str) -> Self {
        // Because the input is a &str we know that the code is valid UTF-8,
        // so the `valid` field can be set to the provided reference.
        Self { raw: BStr::new(src), valid: Some(src), origin: None }
    }
}

impl<'src> From<&'src [u8]> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&[u8]`.
    fn from(src: &'src [u8]) -> Self {
        // Because the input is a &[u8], the code can contain invalid UTF-8,
        // so the `valid` field is set to `None`. The `validate_utf8` function
        // must be used for validating the source code.
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
        Self {
            external_report_builder: None,
            own_report_builder: ReportBuilder::new(),
        }
    }

    /// Specifies whether the parser should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn colorize_errors(&mut self, b: bool) -> &mut Self {
        self.own_report_builder.with_colors(b);
        self
    }

    /// Builds the Abstract Syntax Tree (AST) for some YARA source code.
    ///
    /// The `src` argument can be either a `&str` pointing to the source code,
    /// or a [`SourceCode`] structure. With a [`SourceCode`] structure you can
    /// provide additional information about the source code, like the path
    /// of the file from where the code was read.
    ///
    /// The AST returned by this function holds references to the original
    /// source code. For example, identifiers in the AST point to the
    /// corresponding identifiers in the source code. This avoids making copies
    /// of the strings representing the identifiers, but also implies that the
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
    /// let src = SourceCode::from("rule example { condition: true }").origin("some_rule.yar");
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

        let mut ctx = Context::new(src.clone(), self.get_report_builder());

        let namespace = namespace_from_cst(&mut ctx, root.into_inner())?;
        let namespaces = vec![namespace];

        Ok(AST { source: src, namespaces, warnings: ctx.warnings })
    }

    /// Build the Concrete Syntax Tree (CST) for a YARA source.
    ///
    /// The `src` argument can either a `&str` pointing to the source code, or
    /// a [`SourceCode`] structure. With a [`SourceCode`] structure you can
    /// provide additional information about the source code, like the path
    /// of the file from where the code was read.
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
    /// let src = SourceCode::from("rule example { condition: true }").origin("some_rule.yar");
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

        // Make sure that source code is valid UTF-8.
        let utf8_validation = src.validate_utf8();

        // Register the source code with the report builder, even if the code
        // is not valid UTF-8, so that we can build the report that tells
        // about the invalid UTF-8.
        report_builder.register_source(&src);

        // If the code is not valid UTF-8 fail with an error.
        if let Err(err) = utf8_validation {
            let span_start = err.valid_up_to();
            let span_end = if let Some(len) = err.error_len() {
                span_start + len
            } else {
                span_start
            };
            return Err(Error::new(ErrorInfo::invalid_utf_8(
                report_builder,
                &src,
                Span { start: span_start, end: span_end },
            )));
        }

        let pairs = grammar::ParserImpl::parse(rule, src.valid.unwrap())
            .map_err(|pest_error| {
                report_builder.convert_pest_error(&src, pest_error)
            })?;

        Ok(CST { comments: false, whitespaces: false, pairs: Box::new(pairs) })
    }

    /// Sets the report builder used by the Parser.
    ///
    /// This is optional, if the report builder is not set the Parser will
    /// create its own. However this allows sharing the same report builder
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
