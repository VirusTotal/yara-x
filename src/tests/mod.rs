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
    condition_true!(r#""foo\nbar" == "foo\nbar""#);
    condition_true!(r#""foo\x00bar" == "foo\x00bar""#);

    condition_true!(r#""foo" != "bar""#);
    condition_true!(r#""aab" > "aaa""#);
    condition_true!(r#""aab" >= "aaa""#);
    condition_true!(r#""aaa" >= "aaa""#);
    condition_true!(r#""aaa" < "aab""#);
    condition_true!(r#""aaa" <= "aab""#);
    condition_true!(r#""aaa" <= "aaa""#);

    condition_true!(r#""foo" contains "foo""#);
    condition_true!(r#""foo\x00" contains "\x00""#);
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
fn boolean_operations() {
    condition_true!("true");
    condition_false!("false");
    condition_true!("true and true");
    condition_false!("true and false");
    condition_true!("false or true");
    condition_true!("not false");
    condition_false!("not true");
    condition_true!("true or (false and false)");
    condition_false!("not (true or true)");
}

#[test]
fn boolean_casting() {
    condition_true!("1");
    condition_true!("0.5");
    condition_false!("0.0");
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
    condition_true!(r#""foo""#);
    condition_false!(r#""""#);
}

#[test]
fn for_in() {
    condition_true!("for all i in (0..0) : ( true )");
    condition_false!("for all i in (0..0) : ( false )");
    condition_false!("for none i in (0..0) : ( true )");
    condition_true!("for none i in (0..0) : ( false )");
    condition_true!("for none i in (0..10) : ( false )");
    condition_false!("for none i in (0..10) : ( true )");
    condition_true!("for all i in (0..10) : ( true )");
    condition_false!("for all i in (0..10) : ( false )");
    condition_true!("for any i in (0..10) : ( i == 5 )");
    condition_false!("for none i in (0..10) : ( i == 5 )");
    condition_true!("for all i in (0..10) : ( i <= 10 )");
    condition_true!("for none i in (0..10) : ( i > 10 )");
    condition_true!("for all i in (3..5) : ( i >= 3 and i <= 5 )");
    condition_true!(
        "for all i in (0..10) : (
            for all j in (i..10) : (
                 j >= i
            )
        )"
    );

    condition_true!("for 1 i in (0..10) : ( i == 0 )");
    condition_true!("for 11 i in (0..10) : ( i == i )");
    condition_true!("for 1 i in (0..10) : ( i <= 1 )");
    condition_true!("for 2 i in (0..10) : ( i <= 1 )");
    condition_true!("for 50% i in (0..10) : ( i < 6 )");
    condition_false!("for 50% i in (0..10) : ( i >= 6 )");
    condition_true!("for 10% i in (0..9) : ( i == 0 )");
    condition_false!("for 11% i in (0..9) : ( i == 0 )");

    // If the range's lower bound is greater than the upper bound
    // the `for` loop is always false.
    condition_false!("for all i in (5..2) : ( true )");
    condition_false!("for all i in (5..2) : ( false )");
    condition_false!("for none i in (5..2) : ( true )");
    condition_false!("for none i in (5..2) : ( false )");
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
        rule test_1 {
          condition:
            test_proto2.int64_zero == 0 and 
            test_proto2.int64_one == 1 and
            test_proto2.int64_one + test_proto2.int64_zero == 1 and
            test_proto2.int64_one + test_proto2.int64_one == 2 and
            test_proto2.int64_one * test_proto2.int64_one == 1 and
            test_proto2.int64_one - test_proto2.int64_one == 0 and 
           
            test_proto2.nested.nested_int64_zero == 0 and
            test_proto2.nested.nested_int64_one == 1 and
           
            test_proto2.string_foo != test_proto2.string_bar and
            test_proto2.string_foo == "foo" and
            test_proto2.string_bar == "bar" and
            test_proto2.string_foo contains "oo" and
            test_proto2.string_foo endswith "oo" and
            test_proto2.string_foo startswith "foo" and
            test_proto2.string_bar icontains "AR" and
            test_proto2.string_bar iendswith "AR" and
            test_proto2.string_bar istartswith "BAR" and
            test_proto2.string_bar iequals "BAR" and
            
            test_proto2.array_int64[0] == 10 and
            test_proto2.array_int64[1] == 20

        }
        rule test_2 {
          condition:
            // Make sure that undef or true is true.
            test_proto2.int64_undef == 0 or true
        }

        rule test_3 {
          condition:
            // Make sure that undef and true is false
            not (test_proto2.int64_undef == 0 and true)
        }
        "#,
        )
        .unwrap()
        .build()
        .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);
    assert_eq!(scanner.scan(&[]).matching_rules(), 3);
}
