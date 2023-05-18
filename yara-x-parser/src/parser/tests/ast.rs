use std::collections::hash_map::DefaultHasher;
use std::fmt::Write;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

use pretty_assertions::{assert_eq, assert_ne};
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

fn hash<T: Hash>(obj: T) -> u64 {
    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn pattern_hashes() {
    let ast = Parser::new()
        .build_ast(
            r#"rule test { 
            strings: 
                $0 = "abc"
                $1 = "abc"
                $2 = "abc" nocase
                $3 = "abcd"
                $4 = "abc" wide
                $5 = "abc" nocase wide
                $6 = "abc" wide nocase
                $7 = "abc" xor(1)
                $8 = "abc" xor(1)
                $9 = "abc" xor(2)
                $10 = { 00 ?1 [0-1] 02 [1-] 03 [10] 04 [-] 05 ( 06 | 07 ) 08 ?? 09 }
                $11 = { 00 ?1 [0-1] 02 [1-] 03 [10] 04 [-] 05 ( 06 | 07 ) 08 ?? 09 }
                $12= { 00 01 02 }
                $13 = { 0? 01 02 }
            condition: 
                all of them
            }"#,
        )
        .unwrap();

    let patterns = ast.rules[0].patterns.as_ref().unwrap();

    // "abc" == "abc"
    assert_eq!(hash(&patterns[0]), hash(&patterns[1]));

    // "abc" != "abc" nocase
    assert_ne!(hash(&patterns[0]), hash(&patterns[2]));

    // "abc" != "abcd"
    assert_ne!(hash(&patterns[0]), hash(&patterns[3]));

    // "abc" nocase != "abc" wide
    assert_ne!(hash(&patterns[2]), hash(&patterns[4]));

    // "abc" wide != "abc" nocase wide
    assert_ne!(hash(&patterns[4]), hash(&patterns[5]));

    // "abc" nocase wide == "abc" wide nocase. The order is not relevant.
    assert_eq!(hash(&patterns[5]), hash(&patterns[6]));

    // "abc" xor(1) == "abc" xor(1)
    assert_eq!(hash(&patterns[7]), hash(&patterns[8]));

    // "abc" xor(1) != "abc" xor(2)
    assert_ne!(hash(&patterns[8]), hash(&patterns[9]));

    // { 00 ?1 [0-1] 02 [1-] 03 [10] 04 [-] 05 ( 06 | 07 ) 08 ?? 09 }
    assert_eq!(hash(&patterns[10]), hash(&patterns[11]));

    // { 0? 01 02 } != { 00 01 02 }
    assert_ne!(hash(&patterns[12]), hash(&patterns[13]));
}
