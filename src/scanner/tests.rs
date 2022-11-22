use crate::compiler::{Compiler, IdentId};
use crate::scanner::Scanner;

#[test]
fn scan() {
    let rules = Compiler::new()
        .add_source(
            r#"
rule test {
  condition:
    "foo" == "bar"
}"#,
        )
        .unwrap()
        .build()
        .unwrap();

    let mut scanner = Scanner::new(&rules);
    let data = [];
    let res = scanner.scan(&data);

    //assert!(false);
}

#[test]
fn iterators() {
    let rules = Compiler::new()
        .add_source(
            r#"
rule rule_1 { condition: true }
rule rule_2 { condition: false }
rule rule_3 { condition: true }
rule rule_4 { condition: false }
"#,
        )
        .unwrap()
        .build()
        .unwrap();

    let mut scanner = Scanner::new(&rules);
    let data = &[];
    let results = scanner.scan(data);

    assert_eq!(results.matching_rules(), 2);

    let mut iter = results.iter();

    assert_eq!(iter.next().unwrap().ident.id(), 0);

    let mut iter = results.iter_non_matches();

    assert_eq!(iter.next().unwrap().ident.id(), 1);
}
