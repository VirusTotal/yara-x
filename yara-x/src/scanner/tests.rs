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

    assert_eq!(u32::from(iter.next().unwrap().ident), 0);
    assert_eq!(u32::from(iter.next().unwrap().ident), 2);

    let mut iter = results.iter_non_matches();

    assert_eq!(u32::from(iter.next().unwrap().ident), 1);
    assert_eq!(u32::from(iter.next().unwrap().ident), 3);
}
