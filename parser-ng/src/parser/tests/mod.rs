use crate::ast::{Error, AST};
use rayon::prelude::*;
use std::fs;
use std::io::BufWriter;
use std::io::Write;

use crate::cst::CST;
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
        let cst = CST::from(Parser::new(source.as_bytes()));
        let mut w = BufWriter::new(output_file);
        write!(&mut w, "{:?}", cst).unwrap();
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

        println!("file: {:?}", path);
        let source = fs::read_to_string(path).unwrap();
        let ast = AST::from(Parser::new(source.as_bytes()));
        let mut w = BufWriter::new(output_file);
        write!(&mut w, "{:?}", ast).unwrap();
    });
}

#[test]
fn utf8_error_1() {
    // Invalid UTF-8 anywhere.
    let rules = b"
rule test_1 { \xFF\xFF condition: true }
rule test_2 { condition: true }";

    let ast = AST::from(Parser::new(rules));

    assert_eq!(
        &ast.errors()[0],
        &Error::SyntaxError {
            message: "invalid UTF-8 character".to_string(),
            span: Span(15..16)
        }
    );

    // The second rule is correctly parsed because it doesn't have any errors.
    assert_eq!(ast.rules().len(), 1);
}

#[test]
fn utf8_error_2() {
    // Invalid UTF-8 in string literal.
    let rules = b"
rule test_1 { condition: \"\xFF\xFF\" contains \"foo\" }
rule test_2 { condition: true }";

    let ast = AST::from(Parser::new(rules));

    assert_eq!(&ast.errors()[0], &Error::InvalidUTF8(Span(27..28)));

    // The second rule is correctly parsed because it doesn't have any errors.
    assert_eq!(ast.rules().len(), 1);
}

#[test]
fn utf8_error_3() {
    // Invalid UTF-8 in a comment.
    let rules = b"
/* \xFF\xFF */
rule test_1 { condition: true }";

    let ast = AST::from(Parser::new(rules));
    assert_eq!(ast.rules().len(), 1);
}

#[test]
fn utf8_error_4() {
    // Invalid UTF-8 in a regular expression.
    let rules = b"
rule test_1 { strings: $a = /foo\xFF\xFFbar/ condition: $a }\
rule test_2 { condition: true }";

    let ast = AST::from(Parser::new(rules));

    assert_eq!(&ast.errors()[0], &Error::InvalidUTF8(Span(33..34)));
    assert_eq!(ast.rules().len(), 1);
}
