/*! End-to-end tests.*/
use pretty_assertions::assert_eq;

macro_rules! condition_true {
    ($condition:literal) => {{
        let src = format!("rule t {{condition: {} }}", $condition);
        let rules = crate::compiler::Compiler::new()
            .add_source(src.as_str())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            crate::scanner::Scanner::new(&rules).scan(&[]).matching_rules(),
            1,
            "`{}` should be true, but it is false",
            $condition
        );
    }};
}

#[test]
fn arithmetic_expressions() {
    condition_true!("1 == 1");
    condition_true!("1 + 1 == 2");
    condition_true!("2 * 2 == 4");
    condition_true!("4 \\ 2 == 2");
    condition_true!("5 % 2 == 1");
    condition_true!("2 * (1 + 1) == 4");
    condition_true!("2 * (1 + -1) == 0");
    condition_true!("2 * -(1) == -2");
    condition_true!("(1 + 1) * 2 == (9 - 1) \\ 2 ");
    condition_true!("5 % 2 == 1");
    condition_true!("1.5 + 1.5 == 3");
    condition_true!("3 \\ 2 == 1");
    condition_true!("3.0 \\ 2 == 1.5");
    condition_true!("1 + -1 == 0");
    condition_true!("-1 + -1 == -2");
    condition_true!("4 --2 * 2 == 8");
    condition_true!("-1.0 * 1 == -1.0");
    condition_true!("1-1 == 0");
    condition_true!("-2.0-3.0 == -5");
    condition_true!("--1 == 1");
    condition_true!("1--1 == 2");
    condition_true!("2 * -2 == -4");
    condition_true!("-4 * 2 == -8");
    condition_true!("-4 * -4 == 16");
    //condition_true!("-0x01 == -1");
    condition_true!("0o10 == 8");
    condition_true!("0o100 == 64");
    condition_true!("0o755 == 493");
    assert_eq!(-0x01, -1);
}
