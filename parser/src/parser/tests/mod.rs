use pretty_assertions::assert_eq;

use crate::parser::Parser;

#[cfg(feature = "ascii-tree")]
#[test]
fn newlines_and_spaces() {
    let cst = Parser::new()
        .build_cst("rule\n\rtest\r\n{ condition:\ntrue\n }")
        .unwrap()
        .whitespaces(true)
        .ascii_tree_string();

    assert_eq!(
        cst,
        r#" source_file
 └─ rule_decl
    ├─ k_RULE "rule"
    ├─ WHITESPACE ""
    ├─ WHITESPACE ""
    ├─ ident "test"
    ├─ WHITESPACE ""
    ├─ LBRACE "{"
    ├─ WHITESPACE ""
    ├─ k_CONDITION "condition"
    ├─ COLON ":"
    ├─ WHITESPACE ""
    ├─ boolean_expr
    │  ├─ boolean_term
    │  │  └─ k_TRUE "true"
    │  ├─ WHITESPACE ""
    │  └─ WHITESPACE ""
    └─ RBRACE "}"
"#
    );
}

#[test]
fn identifiers() {
    // The following identifiers are ok, even if they are prefixed by a
    // keyword.
    assert!(Parser::new().build_cst("rule true_ { condition: true }").is_ok());
    assert!(Parser::new()
        .build_cst("rule false_ { condition: false }")
        .is_ok());
    assert!(Parser::new().build_cst("rule rules { condition: true }").is_ok());
    assert!(Parser::new().build_cst("rule _true { condition: true }").is_ok());
}

#[test]
fn pathological_case() {
    // Make sure that pathologically bad rules don't take forever to parse.
    // Parsing this rule must fail.
    assert!(Parser::new()
        .build_cst(r#"rule bug { condition: ((((((((((((false)))))))))))) }"#)
        .is_err());
}

mod ast;
mod cst;
