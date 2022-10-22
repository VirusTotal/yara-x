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

let mut cst = Parser::new().build_cst(rule, None).unwrap();

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

let ast = Parser::new().build_ast(rule, None).unwrap();


```

 */

use pest::Parser as PestParser;
use std::collections::HashMap;
use std::string;

pub(crate) use crate::parser::context::*;
pub(crate) use crate::report::*;

#[doc(inline)]
pub use crate::parser::ast::*;
pub use crate::parser::cst::*;
pub use crate::parser::errors::*;
pub use crate::parser::expr::*;
pub use crate::parser::grammar::Rule as GrammarRule;
pub use crate::parser::span::*;

mod ast;
mod context;
mod cst;
mod errors;
mod expr;
mod span;
mod warnings;

#[cfg(test)]
mod tests;

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
    pub fn colorize_errors(self, b: bool) -> Self {
        Self { colorize_errors: b, report_builder: self.report_builder }
    }

    /// Build the Abstract Syntax Tree (AST) for a YARA source.
    pub fn build_ast<'src>(
        &self,
        src: &'src str,
        origin: Option<String>,
    ) -> Result<AST<'src>, Error> {
        // Create the CST but ignore comments and whitespaces. They won't
        // be visible while traversing the CST as we don't need them for
        // building the AST.
        let cst = self
            .build_cst(src, origin.clone())?
            .comments(false)
            .whitespaces(false);

        // The root of the CST must be the grammar rule `source_file`.
        let root = cst.into_iter().next().unwrap();
        assert_eq!(root.as_rule(), GrammarRule::source_file);

        let src = SourceCode { text: src, origin };

        // If self.report_builder is None, create my own.
        let owned_report_builder = if self.report_builder.is_none() {
            let mut r = ReportBuilder::new();
            r.with_colors(self.colorize_errors);
            r.register_source(&src);
            Some(r)
        } else {
            None
        };

        // Use self.report_builder if not None, or my own report builder
        // if otherwise
        let report_builder =
            self.report_builder.or(owned_report_builder.as_ref()).unwrap();

        report_builder.register_source(&src);

        let mut ctx = Context::new(src, report_builder);

        let namespaces = HashMap::from([(
            "default",
            Namespace::from_cst(&mut ctx, root.into_inner())?,
        )]);

        Ok(AST { namespaces, warnings: ctx.warnings })
    }

    /// Build the Concrete Syntax Tree (CST) for a YARA source.
    #[inline(always)]
    pub fn build_cst<'src>(
        &self,
        src: &'src str,
        origin: Option<string::String>,
    ) -> Result<CST<'src>, Error> {
        self.build_rule_cst(GrammarRule::source_file, src, origin)
    }

    /// Builds the CST for a specific grammar rule.
    ///
    /// The code in `src` must be in concordance with the grammar rule, for
    /// example if the rule is [`GrammarRule::boolean_expr`] the content of
    /// `src` must be something like `$a and $b`, passing a full YARA rule
    /// will fail because this grammar rule doesn't parse a full rule.
    pub fn build_rule_cst<'src>(
        &self,
        rule: GrammarRule,
        src: &'src str,
        origin: Option<string::String>,
    ) -> Result<CST<'src>, Error> {
        let src = SourceCode { text: src, origin };
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
    /// create its own when necessary. However this allows sharing the same
    /// report builder with other components, like [`Compiler`].
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
