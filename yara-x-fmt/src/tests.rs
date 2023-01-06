use std::io::Cursor;
use std::path::PathBuf;
use std::{fs, str, string};

use pretty_assertions::assert_eq;
use yaml_rust::{Yaml, YamlLoader};

use crate::tokens::{TokenStream, Tokens};
use crate::Formatter;
use yara_x_parser::Parser;

#[test]
fn spacer() {
    let tests = vec![
        (
            // Spacer's input
            r#"
            rule test {
              condition  :  true
            }"#,
            // Spacer's expected output
            r#"rule test { condition: true }"#,
        ),
        (
            r#"  rule  test  :  tag1  tag2  {  strings : $a  =  "foo"  condition  :  true  }"#,
            r#"rule test : tag1 tag2 { strings: $a = "foo" condition: true }"#,
        ),
        (
            r#"  rule test {  strings : $a  =  {  00  01  }  condition  :  true  }"#,
            r#"rule test { strings: $a = { 00 01 } condition: true }"#,
        ),
    ];

    for t in tests {
        let mut output = Vec::new();
        let tokens = Tokens::new(Parser::new().build_cst(t.0).unwrap());

        Formatter::add_spacing(tokens).write_to(&mut output, "  ").unwrap();
        assert_eq!(str::from_utf8(&output).unwrap(), t.1);
    }
}

#[test]
fn format() {
    let mut tests_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    tests_data_dir.push("src/testdata");

    for entry in fs::read_dir(tests_data_dir).unwrap() {
        let path = entry.unwrap().path();
        let metadata = fs::metadata(&path).unwrap();
        if metadata.is_file() {
            let tests_file = fs::read_to_string(&path).unwrap();
            let tests = YamlLoader::load_from_str(tests_file.as_str())
                .unwrap()
                .pop()
                .unwrap();

            for test in tests {
                let hash = test.into_hash().unwrap();

                let unformatted = hash
                    .get(&Yaml::String("unformatted".to_string()))
                    .unwrap()
                    .as_str()
                    .unwrap();

                let expected = hash
                    .get(&Yaml::String("formatted".to_string()))
                    .unwrap()
                    .as_str()
                    .unwrap();

                let mut output = Cursor::new(Vec::new());

                Formatter::new()
                    .format(unformatted.as_bytes(), &mut output)
                    .unwrap();

                let output =
                    string::String::from_utf8(output.into_inner()).unwrap();

                assert_eq!(
                    expected, output,
                    "\n\nfile {:?}\n\n{}",
                    path, unformatted
                );
            }
        }
    }
}
