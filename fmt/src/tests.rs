use std::io::Cursor;
use std::path::PathBuf;
use std::{fs, str};

use bstr::ByteSlice;
use pretty_assertions::assert_eq;
use rayon::prelude::*;

use yara_x_parser::{Parser, Span};

use crate::tokens::{TokenStream, Tokens};
use crate::{Error, Formatter};

#[test]
fn spacer() {
    let tests = vec![
        (
            // Spacer's input
            r#"rule test {condition  :  true}"#,
            // Spacer's expected output
            r#"rule test { condition: true }"#,
        ),
        (
            r#"  rule  test  :  tag1  tag2  {  strings : $a  =  "foo"  condition  :  true  }"#,
            r#"rule test: tag1 tag2 { strings: $a = "foo" condition: true }"#,
        ),
        (
            r#"  rule test {  strings : $a  =  {  00  01  }  condition  :  true  }"#,
            r#"rule test { strings: $a = { 00 01 } condition: true }"#,
        ),
    ];

    for t in tests {
        let mut output = Vec::new();
        let rules = t.0.as_bytes();
        let events = Parser::new(rules).into_cst_stream().whitespaces(false);
        let tokens = Tokens::new(rules, events);

        Formatter::add_spacing(tokens).write_to(&mut output).unwrap();
        assert_eq!(str::from_utf8(&output).unwrap(), t.1);
    }
}

#[test]
fn invalid_utf8() {
    let mut output = Cursor::new(Vec::new());

    match Formatter::new()
        .format(b"\xFF\xFF".as_bytes(), &mut output)
        .expect_err("expected UTF-8 error")
    {
        Error::InvalidUTF8(span) => {
            assert_eq!(span, Span(0..1))
        }
        _ => panic!(),
    }
}

#[test]
fn format() {
    let files: Vec<_> =
        globwalk::glob("src/testdata/default_tests/*.unformatted")
            .unwrap()
            .flatten()
            .map(|entry| entry.into_path())
            .collect();

    files.into_par_iter().for_each(|path| {
        let mut mint = goldenfile::Mint::new(".");
        let output_path = path.with_extension("formatted");

        let input = fs::read_to_string(&path).expect("error reading file");
        let mut output = mint.new_goldenfile(&output_path).unwrap();

        let changed = Formatter::new()
            .format(input.as_bytes(), &mut output)
            .expect("format failed");

        if !changed {
            panic!("{:?} and {:?} are equal", path, output_path)
        }
    });
}

#[test]
fn format_config_options() {
    // Tuples for tests. First item is the formatter config to use. Second item
    // is the unformatted test file. Third item is expected formatted file.
    let tests = vec![
        (
            Formatter::new().indent_section_headers(false),
            "generic_rule.unformatted",
            "indent_section_headers_false.formatted",
        ),
        (
            Formatter::new().indent_section_contents(false),
            "generic_rule.unformatted",
            "indent_section_contents_false.formatted",
        ),
        (
            Formatter::new().indent_spaces(0),
            "generic_rule.unformatted",
            "indent_spaces_zero.formatted",
        ),
        (
            Formatter::new().indent_spaces(1),
            "generic_rule.unformatted",
            "indent_spaces_one.formatted",
        ),
        (
            Formatter::new().newline_before_curly_brace(true),
            "generic_rule.unformatted",
            "newline_before_curly_brace_true.formatted",
        ),
        (
            Formatter::new().empty_line_before_section_header(false),
            "generic_rule.unformatted",
            "empty_line_before_section_header_false.formatted",
        ),
        (
            Formatter::new().empty_line_after_section_header(true),
            "generic_rule.unformatted",
            "empty_line_after_section_header_true.formatted",
        ),
        (
            Formatter::new().align_metadata(false),
            "align_rule.unformatted",
            "align_metadata_false.formatted",
        ),
        (
            Formatter::new().align_patterns(false),
            "align_rule.unformatted",
            "align_patterns_false.formatted",
        ),
    ];

    let base = PathBuf::from("src/testdata/config_tests/");
    for (formatter, unformatted, formatted) in tests {
        let input = fs::read_to_string(base.join(unformatted))
            .expect("error reading unformatted file");
        let expected = fs::read_to_string(base.join(formatted))
            .expect("error reading formatted file");
        let mut output = Vec::new();

        formatter
            .format(input.as_bytes(), &mut output)
            .expect("format failed");
        assert_eq!(
            str::from_utf8(&output).unwrap(),
            expected,
            "Formatted file: {}",
            formatted
        );
    }
}
