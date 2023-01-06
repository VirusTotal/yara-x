/*! Parses YARA source code and produces a Concrete Syntax Tree (CST) or an
Abstract Syntax Tree (AST).

A CST is a structured representation of the source code that retains all its
details, including punctuation, spacing, comments, etc. Each node in the CST
corresponds to a [`GrammarRule`] (a rule in YARA's grammar).

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
use yara_x_parser::{Parser, GrammarRule};
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
use yara_x_parser::{Parser, GrammarRule};
let rule = r#"
 rule test {
   condition:
     true
 }
"#;

let ast = Parser::new().build_ast(rule).unwrap();
```
 */

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod ast;
pub mod cst;
pub use parser::*;
pub use warnings::*;

mod parser;

#[doc(hidden)]
pub mod report;
#[doc(hidden)]
pub mod types;
#[doc(hidden)]
pub mod warnings;
