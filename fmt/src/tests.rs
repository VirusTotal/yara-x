use std::{fs, str};

use pretty_assertions::assert_eq;
use rayon::prelude::*;
use yara_x_parser::Parser;

use crate::tokens::{TokenStream, Tokens};
use crate::Formatter;

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
        let tokens = Tokens::new(events);

        Formatter::add_spacing(tokens).write_to(&mut output).unwrap();
        assert_eq!(str::from_utf8(&output).unwrap(), t.1);
    }
}

#[test]
fn format() {
    let files: Vec<_> = globwalk::glob("src/testdata/*.unformatted")
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
