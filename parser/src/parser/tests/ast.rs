use std::fmt::Write;
use std::fs;
use std::path::PathBuf;

use pretty_assertions::assert_eq;
use yaml_rust::{Yaml, YamlLoader};

use crate::parser::Parser;

#[cfg(feature = "ascii-tree")]
#[test]
fn ast() {
    let mut tests_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    tests_data_dir.push("src/parser/tests/testdata");

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

                let rule = hash
                    .get(&Yaml::String("rule".to_string()))
                    .unwrap()
                    .as_str()
                    .unwrap();

                let ast = hash
                    .get(&Yaml::String("ast".to_string()))
                    .unwrap()
                    .as_str()
                    .unwrap();

                // The expected ASCII tree obtained from the test file doesn't
                // have the one space indentation that ascii_tree::write_tree
                // produces. Add the indentation before comparing the trees.
                let mut expected = String::new();

                write!(
                    indenter::indented(&mut expected).with_str(" "),
                    "{}",
                    ast
                )
                .unwrap();

                let ascii_tree = match Parser::new().build_ast(rule) {
                    Ok(ast) => ast.ascii_tree(),
                    Err(err) => {
                        panic!("error while parsing rule:\n{:?}\n", err)
                    }
                };

                let mut output = String::new();
                ascii_tree::write_tree(&mut output, &ascii_tree).unwrap();

                assert_eq!(
                    expected, output,
                    "\n\nfile {:?}\n\n{}",
                    path, rule
                );
            }
        }
    }
}
