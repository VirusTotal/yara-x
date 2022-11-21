use crate::compiler::{Compiler, IdentId};
use crate::scanner::Scanner;
use string_interner::Symbol;

#[test]
fn scan() {
    let rules = Compiler::new()
        .add_source(
            r#"
rule test {
  strings: 
    $a = "foo" 
  condition:
    $a
}"#,
        )
        .unwrap()
        .build()
        .unwrap();

    let scanner = Scanner::new(&rules).scan(&[]);

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

    let results = {
        let data = &[];
        scanner.scan(data)
    };

    assert_eq!(results.matching_rules(), 2);

    let mut iter = results.iter();

    assert_eq!(
        iter.next().unwrap().ident,
        IdentId::try_from_usize(0).unwrap()
    );

    let mut iter = results.iter_non_matches();

    assert_eq!(
        iter.next().unwrap().ident,
        IdentId::try_from_usize(1).unwrap()
    );
}
