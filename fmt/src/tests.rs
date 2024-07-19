use anyhow::Context;
use std::io::Cursor;
use std::path::PathBuf;
use std::{fs, str};

use pretty_assertions::assert_eq;
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
fn format() -> Result<(), anyhow::Error> {
    let mut tests_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    tests_data_dir.push("src/testdata");

    for entry in fs::read_dir(tests_data_dir).unwrap() {
        let mut path = entry?.path();

        if let Some(extension) = path.extension() {
            if extension == "unformatted" {
                let input = fs::read_to_string(&path)
                    .context(format!("error reading file {:?}", path))?;

                path.set_extension("formatted");
                let expected = fs::read_to_string(&path)
                    .context(format!("error reading file {:?}", path))?;

                let mut output = Cursor::new(Vec::new());
                Formatter::new().format(input.as_bytes(), &mut output)?;

                let output = String::from_utf8(output.into_inner())?;

                assert_eq!(
                    expected, output,
                    "\n\nfile {:?}\n\n{}",
                    path, input
                );
            }
        }
    }

    Ok(())
}
