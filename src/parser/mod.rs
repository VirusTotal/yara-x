/*! Parses YARA source code and produces a Concrete Syntax Tree (CST) or an
Abstract Syntax Tree (AST).

A CST is a structured representation of the source code that retains all its
details, including punctuation, spacing, comments, etc. Each node in the CST
corresponds to a [`GrammarRule`], a rule in YARA's grammar.

The CST is appropriate for traversing the structure of the code as it appears
in its original form. Typical uses of CSTs are code formatters, documentation
generators, source code analysis, etc. One of the limitations of the CST is
that it doesn't know about operator's associativity or precedence rules.
Expressions appear in the CST as they are in the source code, without any
attempt from the parser to group them according to operator precedence
rules.

In the other hand, an AST is a simplified, more abstract representation
of the code. The AST drops comments, spacing and syntactic details and focus
on the code semantics. When building an AST, operator precedence rules are
applied, providing a more accurate representation of expressions.

Deciding whether to use a CST or AST depends on the kind of problem you want
to solve.

# Examples

Building a CST...

```
use yara_x::parser::{Parser, GrammarRule};
let rule = r#"
 rule test {
   condition:
     true
 }
"#;

let mut cst = Parser::new().build_cst(rule).unwrap();

// The CST is an iterator that returns nodes of type CSTNode. At the top level
// the iterator returns a single node, corresponding to the grammar rule
// source_file, which is the grammar's top-level rule.
let root = cst.next().unwrap();
assert_eq!(root.as_rule(), GrammarRule::source_file);

// With into_inner we get another CST with the children of the top-level node.
// At this level there are two possible grammar rules, import_stmt and rule_decl
for child in root.into_inner() {
    match child.as_rule() {
        GrammarRule::import_stmt => {
            // import statement
        },
        GrammarRule::rule_decl => {
            // rule declaration
        },
        GrammarRule::EOI => {
            // end of input
        },
        _ => unreachable!()
    }
}
```

Building an AST...


```
use yara_x::parser::{Parser, GrammarRule};
let rule = r#"
 rule test {
   condition:
     true
 }
"#;

let ast = Parser::new().build_ast(rule).unwrap();


```

 */

use std::collections::HashMap;

use crate::ast::AST;
use pest::Parser as PestParser;

#[doc(inline)]
pub use crate::parser::cst::*;
pub use crate::parser::errors::*;
pub use crate::parser::grammar::Rule as GrammarRule;

pub(crate) use crate::parser::ast_builder::*;
pub(crate) use crate::parser::context::*;
pub(crate) use crate::report::*;

mod ast_builder;
mod context;
mod cst;
mod errors;

#[cfg(test)]
mod tests;

/// A structure that describes a YARA source code.
///
/// This structure contains a `&str` that points to the code itself, and an optional
/// `String` with information about the origin of the source code. The most common use
/// for the `origin` field is indicating the path of the file from where the source
/// code was obtained, but the string can be actually anything. This string, if provided,
/// will appear in error messages.
#[derive(Debug, Clone)]
pub struct SourceCode<'src> {
    /// A reference to the source code itself in text form.
    pub text: &'src str,
    /// An optional string that tells which is the origin of the code. Usually
    /// a file path.
    pub origin: Option<std::string::String>,
}

impl<'src> SourceCode<'src> {
    /// Create a new SourceCode structure that can be passed later to [`Parser::build_ast`]
    pub fn new(src: &'src str) -> Self {
        Self { text: src, origin: None }
    }

    pub fn origin(self, origin: &str) -> Self {
        Self { text: self.text, origin: Some(origin.to_owned()) }
    }
}

impl<'src> From<&'src str> for SourceCode<'src> {
    fn from(src: &'src str) -> Self {
        Self { text: src, origin: None }
    }
}

/// Receives YARA source code and produces either a Concrete Syntax Tree (CST)
/// or an Abstract Syntax Tree (AST).
#[derive(Default)]
pub struct Parser<'a> {
    colorize_errors: bool,
    report_builder: Option<&'a ReportBuilder>,
}

impl<'a> Parser<'a> {
    /// Creates a new YARA parser.
    pub fn new() -> Self {
        Self { colorize_errors: false, report_builder: None }
    }

    /// Specifies whether the parser should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn colorize_errors(&mut self, b: bool) -> &mut Self {
        self.colorize_errors = b;
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
    /// use yara_x::parser::Parser;
    /// let src = "rule example { condition: true }";
    /// let ast = Parser::new().build_ast(src).unwrap();
    /// ```
    ///
    /// Passing a [`SourceCode`] structure:
    ///
    /// ```
    /// use yara_x::parser::{Parser, SourceCode};
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

        // If self.report_builder is None, create my own.
        let owned_report_builder = if self.report_builder.is_none() {
            let mut r = ReportBuilder::new();
            r.with_colors(self.colorize_errors);
            Some(r)
        } else {
            None
        };

        // Use self.report_builder if not None, or my own report builder
        // if otherwise.
        let report_builder =
            self.report_builder.or(owned_report_builder.as_ref()).unwrap();

        report_builder.register_source(&src);

        let mut ctx = Context::new(src, report_builder);

        let namespaces = HashMap::from([(
            "default",
            namespace_from_cst(&mut ctx, root.into_inner())?,
        )]);

        Ok(AST { namespaces, warnings: ctx.warnings })
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
    /// use yara_x::parser::Parser;
    /// let src = "rule example { condition: true }";
    /// let cst = Parser::new().build_cst(src).unwrap();
    /// ```
    ///
    /// Passing a [`SourceCode`] structure:
    ///
    /// ```
    /// use yara_x::parser::{Parser, SourceCode};
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
        let src = src.into();
        let mut error_builder = ReportBuilder::new();

        error_builder.with_colors(self.colorize_errors).register_source(&src);

        Ok(CST {
            comments: false,
            whitespaces: false,
            pairs: Box::new(
                grammar::ParserImpl::parse(rule, src.text)
                    .map_err(|pest_error| {
                        error_builder.convert_pest_error(&src, pest_error)
                    })?
                    .filter(|_| true),
            ),
        })
    }

    /// Sets the report builder used by the Parser.
    ///
    /// This is optional, if the report builder is not set the Parser will
    /// create its own. However this allows sharing the same report builder
    /// with the [`Compiler`]. Setting a report builder overrides the color
    /// setting specified with [`Compiler::colorize_errors`], the errors will
    /// colorized depending on the settings of the report builder.
    ///
    /// This API is for internal use only.
    pub(crate) fn set_report_builder(
        &mut self,
        report_builder: &'a ReportBuilder,
    ) -> &mut Self {
        self.report_builder = Some(report_builder);
        self
    }
}

mod grammar {
    #[derive(pest_derive::Parser)]
    #[grammar = "parser/grammar.pest"]
    pub struct ParserImpl;
}
