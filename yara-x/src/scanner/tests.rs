use crate::compiler::Compiler;
use crate::scanner::Scanner;

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
    let results = scanner.scan(&[]);

    assert_eq!(results.num_matching_rules(), 2);

    let mut iter = results.iter();

    assert_eq!(iter.next().unwrap().name(), "rule_1");
    assert_eq!(iter.next().unwrap().name(), "rule_3");
    assert!(iter.next().is_none());

    let mut iter = results.iter_non_matches();

    assert_eq!(iter.next().unwrap().name(), "rule_2");
    assert_eq!(iter.next().unwrap().name(), "rule_4");
    assert!(iter.next().is_none());
}

#[test]
fn test() {
    let rules = Compiler::new()
        .add_source(
            r#"
rule rule_1 { 
    strings:
        $a = "issi"
        $b = "IssI" nocase
        $c = "ssippis"
    condition: 
        $a and $b and not $c
}
"#,
        )
        .unwrap()
        .build()
        .unwrap();

    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan("mississippi".as_bytes());
    assert_eq!(results.num_matching_rules(), 1);
}
