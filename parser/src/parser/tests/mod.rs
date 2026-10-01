use crate::ast::{AST, Error};
use rayon::prelude::*;
use std::fs;
use std::io::BufWriter;
use std::io::Write;

use crate::cst::{CST, CSTStream};
use crate::{Parser, Span};

#[test]
fn cst() {
    env_logger::init();

    let files: Vec<_> = globwalk::glob("src/parser/tests/testdata/*.in")
        .unwrap()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    files.into_par_iter().for_each(|path| {
        let mut mint = goldenfile::Mint::new(".");
        // Path to the .out file, replace the .in extension with .out.
        let output_path = path.with_extension("cst");
        let output_file = mint.new_goldenfile(output_path).unwrap();

        let source = fs::read_to_string(path).unwrap();
        let cst = CST::try_from(Parser::new(source.as_bytes())).unwrap();
        let mut w = BufWriter::new(output_file);
        write!(&mut w, "{cst:?}").unwrap();
    });
}

#[test]
fn cst_stream() {
    let files: Vec<_> = globwalk::glob("src/parser/tests/testdata/*.in")
        .unwrap()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    files.into_par_iter().for_each(|path| {
        let mut mint = goldenfile::Mint::new(".");
        // Path to the .out file, replace the .in extension with .out.
        let output_path = path.with_extension("cststream");
        let output_file = mint.new_goldenfile(output_path).unwrap();

        let source = fs::read_to_string(path).unwrap();
        let cst = CSTStream::from(Parser::new(source.as_bytes()));
        let mut w = BufWriter::new(output_file);

        for event in cst {
            writeln!(&mut w, "{event:?}").unwrap();
        }
    });
}

#[test]
fn ast() {
    let files: Vec<_> = globwalk::glob("src/parser/tests/testdata/*.in")
        .unwrap()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    files.into_iter().for_each(|path| {
        let mut mint = goldenfile::Mint::new(".");
        // Path to the .out file, replace the .in extension with .out.
        let output_path = path.with_extension("ast");
        let output_file = mint.new_goldenfile(output_path).unwrap();

        println!("file: {path:?}");
        let source = fs::read_to_string(path).unwrap();
        let ast = AST::from(source.as_str());
        let mut w = BufWriter::new(output_file);
        write!(&mut w, "{ast:?}").unwrap();
    });
}

#[test]
fn utf8_error_1() {
    // Invalid UTF-8 anywhere.
    let rules = b"
rule test_1 { \xFF\xFF condition: true }
rule test_2 { condition: true }";

    let ast = AST::from(rules.as_slice());

    assert_eq!(
        &ast.errors()[0],
        &Error::SyntaxError {
            message: "invalid UTF-8 character".to_string(),
            span: Span(15..16)
        }
    );

    // The second rule is correctly parsed because it doesn't have any errors.
    assert_eq!(ast.rules().count(), 1);
}

#[test]
fn utf8_error_2() {
    // Invalid UTF-8 in string literal.
    let rules = b"
rule test_1 { condition: \"\xFF\xFF\" contains \"foo\" }
rule test_2 { condition: true }";

    let ast = AST::from(rules.as_slice());

    assert_eq!(&ast.errors()[0], &Error::InvalidUTF8(Span(27..28)));

    // The second rule is correctly parsed because it doesn't have any errors.
    assert_eq!(ast.rules().count(), 1);
}

#[test]
fn utf8_error_3() {
    // Invalid UTF-8 in a comment.
    let rules = b"
/* \xFF\xFF */
rule test_1 { condition: true }";

    let ast = AST::from(rules.as_slice());
    assert_eq!(ast.rules().count(), 1);
}

#[test]
fn utf8_error_4() {
    // Invalid UTF-8 in a regular expression.
    let rules = b"
rule test_1 { strings: $a = /foo\xFF\xFFbar/ condition: $a }\
rule test_2 { condition: true }";

    let ast = AST::from(rules.as_slice());

    assert_eq!(&ast.errors()[0], &Error::InvalidUTF8(Span(33..34)));
    assert_eq!(ast.rules().count(), 1);
}

#[test]
fn clear_speculative_errors_after_top_level_item() {
    let rules = br#"
rule test_1 {
  condition:
    true
}
rule test_2 {
  condition:
    true
}
"#;

    let mut parser = Parser::new(rules.as_slice());
    // Give the parser just enough fuel to finish parsing `test_1` (5 `begin`
    // calls: RULE_DECL, RULE_MODS, CONDITION_BLK, BOOLEAN_EXPR, BOOLEAN_TERM),
    // so that it runs out of fuel at the very first `begin(RULE_DECL)` of
    // `test_2`. When `test_2` aborts with `State::OutOfFuel`, `end()` invokes
    // `handle_errors()`. If speculative errors from `test_1` were not cleared
    // in `flush_errors()`, `handle_errors()` would emit a spurious syntax error
    // (`expecting operator, found `}`) pointing back to the closing brace of
    // the valid `test_1` rule.
    parser.parser.fuel = 5;

    let errors: Vec<_> = parser
        .filter_map(|event| match event {
            crate::cst::Event::Error { message, span } => {
                Some((message, span))
            }
            _ => None,
        })
        .collect();

    assert!(errors.is_empty(), "unexpected errors emitted: {errors:?}");
}
