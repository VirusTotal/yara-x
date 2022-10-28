use std::{fs, str, string};
use std::io::Cursor;
use std::path::PathBuf;

use pretty_assertions::assert_eq;
use yaml_rust::{Yaml, YamlLoader};

use crate::formatter;
use crate::formatter::Formatter;
use crate::formatter::tokens::{Tokens, TokenStream};
use crate::parser::Parser;

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
        let tokens =
            Tokens::new(Parser::new().build_cst(t.0).unwrap());

        Formatter::add_spacing(tokens).write_to(&mut output, "  ").unwrap();
        assert_eq!(str::from_utf8(&output).unwrap(), t.1);
    }
}
      /*
#[test]
fn formatter() {
    let source = r#"
// Some comment
import "foo" // foo
import "bar" /* bar */  
import "baz"
rule test {
  strings: $short = "foo" ascii
    $very_long = "bar" ascii wide
  condition:
    true
}"#;

    let tokens = Tokens::new(
        Parser::new()
            .build_cst(source, Option::None)
            .unwrap()
            .comments(true)
            .whitespaces(true),
    );

    let output: Vec<Token> = Formatter::formatter(tokens).collect();

    assert_eq!(
        output,
        vec![
            Begin(GrammarRule::source_file),
            Newline,
            Comment("// Some comment"),
            Newline,
            Begin(GrammarRule::import_stmt),
            Keyword("import"),
            Whitespace,
            Literal("\"foo\""),
            End(GrammarRule::import_stmt),
            Comment("// foo"),
            Newline,
            Begin(GrammarRule::import_stmt),
            Keyword("import"),
            Whitespace,
            Literal("\"bar\""),
            End(GrammarRule::import_stmt),
            Comment("/* bar */"),
            Newline,
            Begin(GrammarRule::import_stmt),
            Keyword("import"),
            Whitespace,
            Literal("\"baz\""),
            End(GrammarRule::import_stmt),
            Newline,
            Newline,
            Begin(GrammarRule::rule_decl),
            Keyword("rule"),
            Whitespace,
            Identifier("test"),
            Whitespace,
            Punctuation("{"),
            Indentation(1),
            Newline,
            Begin(GrammarRule::pattern_defs),
            Keyword("strings"),
            Punctuation(":"),
            Indentation(1),
            Begin(GrammarRule::pattern_def),
            Newline,
            Identifier("$short"),
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Punctuation("="),
            Whitespace,
            Literal("\"foo\""),
            Begin(GrammarRule::pattern_mods),
            Whitespace,
            Keyword("ascii"),
            Newline,
            End(GrammarRule::pattern_mods),
            End(GrammarRule::pattern_def),
            Begin(GrammarRule::pattern_def),
            Identifier("$very_long"),
            Whitespace,
            Punctuation("="),
            Whitespace,
            Literal("\"bar\""),
            Begin(GrammarRule::pattern_mods),
            Whitespace,
            Keyword("ascii"),
            Whitespace,
            Keyword("wide"),
            End(GrammarRule::pattern_mods),
            End(GrammarRule::pattern_def),
            Indentation(-1),
            End(GrammarRule::pattern_defs),
            Newline,
            Keyword("condition"),
            Punctuation(":"),
            Indentation(1),
            Newline,
            Begin(GrammarRule::boolean_expr),
            Begin(GrammarRule::boolean_term),
            Keyword("true"),
            End(GrammarRule::boolean_term),
            Indentation(-1),
            End(GrammarRule::boolean_expr),
            Indentation(-1),
            Newline,
            Punctuation("}"),
            End(GrammarRule::rule_decl),
            End(GrammarRule::source_file),
        ]
    );
}

#[test]
fn formatter2() {
    let source = r#"
rule test {
  condition:
    true
    
}"#;

    let tokens = Tokens::new(
        Parser::new()
            .build_cst(source, Option::None)
            .unwrap()
            .comments(true)
            .whitespaces(true),
    );

    let output: Vec<Token> = Formatter::formatter(tokens).collect();

    assert_eq!(
        output,
        vec![
            Begin(GrammarRule::source_file),
            Newline,
            Newline,
            Begin(GrammarRule::rule_decl),
            Keyword("rule"),
            Whitespace,
            Identifier("test"),
            Whitespace,
            Punctuation("{"),
            Indentation(1),
            Newline,
            Keyword("condition"),
            Punctuation(":"),
            Indentation(1),
            Newline,
            Begin(GrammarRule::boolean_expr),
            Begin(GrammarRule::boolean_term),
            Keyword("true"),
            End(GrammarRule::boolean_term),
            Indentation(-1),
            Indentation(-1),
            End(GrammarRule::boolean_expr),
            Newline,
            Newline,
            Punctuation("}"),
            End(GrammarRule::rule_decl),
            End(GrammarRule::source_file),
        ]
    );
}
          */
#[test]
fn format() {
    let mut tests_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    tests_data_dir.push("src/formatter/testdata");

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

                let mut output = Cursor::new(vec![]);

                formatter::Formatter::new()
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
