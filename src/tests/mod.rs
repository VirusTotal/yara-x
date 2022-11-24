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

macro_rules! condition_false {
    ($condition:literal) => {{
        let src = format!("rule t {{condition: {} }}", $condition);
        let rules = crate::compiler::Compiler::new()
            .add_source(src.as_str())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            crate::scanner::Scanner::new(&rules).scan(&[]).matching_rules(),
            0,
            "`{}` should be false, but it is true",
            $condition
        );
    }};
}

#[test]
fn arithmetic_operations() {
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
    condition_true!("-0x01 == -1");
    condition_true!("-0o10 == -8");
    condition_true!("0o100 == 64");
    condition_true!("0o755 == 493");
}

#[test]
fn bitwise_operations() {
    condition_true!("0x55 | 0xAA == 0xFF");
    condition_true!("0x55555555 | 0xAAAAAAAA == 0xFFFFFFFF");
    condition_true!("0x55555555 | 0xAAAAAAAA == 0xFFFFFFFF");
    condition_true!("~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF)");
    condition_true!("~0xAA ^ 0x5A & 0xFF != 0x0F");
    condition_true!("~0x55 & 0xFF == 0xAA");
    condition_true!("1 << 0 == 1");
    condition_true!("1 >> 0 == 1");
    condition_true!("1 << 3 == 8");
    condition_true!("8 >> 2 == 2");
    condition_true!("1 << 64 == 0");
    condition_true!("1 >> 64 == 0");
    condition_true!("1 << 65 == 0");
    condition_true!("1 >> 65 == 0");
    condition_true!("1 | 3 ^ 3 != (1 | 3) ^ 3");
}

#[test]
fn string_operations() {
    condition_true!(r#""foo" == "foo""#);
    condition_true!(r#""foo" != "bar""#);
    condition_true!(r#""aab" > "aaa""#);
    condition_true!(r#""aab" >= "aaa""#);
    condition_true!(r#""aaa" >= "aaa""#);
    condition_true!(r#""aaa" < "aab""#);
    condition_true!(r#""aaa" <= "aab""#);
    condition_true!(r#""aaa" <= "aaa""#);

    condition_true!(r#""foo" contains "foo""#);
    condition_true!(r#""foo" contains "oo""#);
    condition_true!(r#""foo" startswith "fo""#);
    condition_true!(r#""foo" endswith "oo""#);

    condition_true!(r#""foo" icontains "FOO""#);
    condition_true!(r#""foo" icontains "OO""#);
    condition_true!(r#""foo" istartswith "Fo""#);
    condition_true!(r#""foo" iendswith "OO""#);

    condition_false!(r#""foo" contains "OO""#);
    condition_false!(r#""foo" startswith "Fo""#);
    condition_false!(r#""foo" endswith "OO""#);

    condition_true!(r#""foo" iequals "FOO""#);
    condition_true!(r#""foo" iequals "FoO""#);
    condition_false!(r#""foo" iequals "bar""#);
}

#[test]
fn boolean_casting() {
    condition_true!("1");
    condition_false!("0");
    condition_true!("1 and true");
    condition_false!("0 and true");
    condition_true!("1.0 and true");
    condition_false!("0.0 and true");
    condition_true!("1 or false");
    condition_false!("0 or false");
    condition_true!("1.0 or false");
    condition_false!("0.0 or false");
    condition_true!("not 0");
    condition_false!("not 1");
    condition_true!("not 0.0");
    condition_false!("not 1.0");
}

#[test]
fn filesize() {
    let rules = crate::compiler::Compiler::new()
        .add_source(
            r#"        
        rule filesize_0 {
          condition:
            filesize == 0 
        }
        rule filesize_1 {
          condition:
            filesize == 1 
        }
        "#,
        )
        .unwrap()
        .build()
        .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);

    assert_eq!(scanner.scan(&[]).matching_rules(), 1);
    assert_eq!(scanner.scan(&[1]).matching_rules(), 1);
}

#[test]
#[cfg(feature = "test_proto2-module")]
fn test_proto2_module() {
    let rules = crate::compiler::Compiler::new()
        .add_source(
            r#"
        import "test_proto2"
        
        //rule test {
        //  condition:
        //    test_proto2.enum.ENUM_ITEM_1 == 1 
        //}
        "#,
        )
        .unwrap()
        .build()
        .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);
    assert_eq!(scanner.scan(&[]).matching_rules(), 0);
}
