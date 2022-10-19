/*! Parses YARA source code and produces a Concrete Syntax Tree (CST) or an
Abstract Syntax Tree (AST).

A CST is a structured representation of the source code that retains all its
details, including punctuation, comments, etc. Each node in the CST
corresponds to a [`GrammarRule`], a rule in YARA's grammar.

The CST is appropriate for traversing the structure of the code as it appears
in its original form. Typical uses of CSTs are code formatters, documentation
generators, etc. One of the limitations of the CST is that it doesn't know
about operator's associativity or precedence rules. As a result, certain
expressions appear in the CST as they are in the source code, without any
attempt from the parser to group them according to operator precedence
rules.

In the other hand, an AST is a simplified, more abstract representation
of the code. The AST drops the syntactic details and focus on the semantics.
Operator precedence rules are applied for getting an accurate representation
of expressions. The AST is what you need in most cases.

# Examples

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
        _ => {}
    }
}
```

 */

use pest::Parser as PestParser;
use std::collections::HashMap;
use std::string;

use crate::parser::context::*;
use crate::parser::report::ReportBuilder;

#[doc(inline)]
pub use crate::parser::ast::*;
pub use crate::parser::cst::*;
pub use crate::parser::errors::*;
pub use crate::parser::expr::*;
pub use crate::parser::span::*;

pub use crate::parser::grammar::Rule as GrammarRule;

mod ast;
mod context;
mod cst;
mod errors;
mod expr;
mod report;
mod span;
mod warnings;

#[cfg(test)]
mod tests;

/// Receives YARA source code and produces either a Concrete Syntax Tree (CST)
/// or an Abstract Syntax Tree (AST).
#[derive(Default)]
pub struct Parser {
    colorize_errors: bool,
}

impl Parser {
    pub fn new() -> Parser {
        Self { colorize_errors: false }
    }

    pub fn colorize_errors(self, b: bool) -> Self {
        Self { colorize_errors: b }
    }

    /// Build the Abstract Syntax Tree (AST) for a YARA source.
    pub fn build_ast<'src>(
        &self,
        src: &'src str,
        origin: Option<string::String>,
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
        assert_eq!(GrammarRule::source_file, root.as_rule());

        let mut ctx = Context::new(SourceCode { text: src, origin });
        ctx.colorize_errors(self.colorize_errors);

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
}

mod grammar {
    #[derive(pest_derive::Parser)]
    #[grammar = "parser/grammar.pest"]
    pub struct ParserImpl;
}
