/*! End-to-end tests.*/
use pretty_assertions::assert_eq;

macro_rules! condition_true {
    ($condition:literal, $data:expr) => {{
        let src = if cfg!(feature = "test_proto2-module") {
            format!(
                r#"import "test_proto2" rule t {{condition: {} }}"#,
                $condition
            )
        } else {
            format!("rule t {{condition: {} }}", $condition)
        };

        let rules = crate::compiler::Compiler::new()
            .add_source(src.as_str())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            crate::scanner::Scanner::new(&rules)
                .scan($data)
                .num_matching_rules(),
            1,
            "`{}` should be true, but it is false",
            $condition
        );
    }};
    ($condition:literal) => {{
        condition_true!($condition, &[]);
    }};
}

macro_rules! condition_false {
    ($condition:literal) => {{
        let src = if cfg!(feature = "test_proto2-module") {
            format!(
                r#"import "test_proto2" rule t {{condition: {} }}"#,
                $condition
            )
        } else {
            format!("rule t {{condition: {} }}", $condition)
        };

        let rules = crate::compiler::Compiler::new()
            .add_source(src.as_str())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            crate::scanner::Scanner::new(&rules)
                .scan(&[])
                .num_matching_rules(),
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
fn uintxx() {
    condition_true!("uint8(0) == 0", &[0]);
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

    // `for 0..` must behave as `for none...`
    condition_true!("for 0 i in (0..10) : ( i > 10 )");
    condition_false!("for 0 i in (0..10) : ( i == 5 )");

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

    assert_eq!(scanner.scan(&[]).num_matching_rules(), 1);
    assert_eq!(scanner.scan(&[1]).num_matching_rules(), 1);
}

#[test]
fn rule_reuse() {
    let rules = crate::compiler::Compiler::new()
        .add_source(
            r#"
        rule rule_1 {
          condition:
            true
        }
        rule rule_2 {
          condition:
            rule_1
        }
        rule rule_3 {
          condition:
            rule_2
        }
        rule rule_4 {
          condition:
            rule_3
        }
        rule rule_5 {
          condition:
            rule_4
        }
        rule rule_6 {
          condition:
            rule_5
        }
        rule rule_7 {
          condition:
            rule_6
        }
        rule rule_8 {
          condition:
            rule_7
        }
        rule rule_9 {
          condition:
            rule_8
        }
        "#,
        )
        .unwrap()
        .build()
        .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);

    assert_eq!(scanner.scan(&[]).num_matching_rules(), 9);
}

#[test]
#[cfg(feature = "test_proto2-module")]
fn test_proto2_module() {
    condition_true!(r#"test_proto2.add(1,2) == 3"#);
    condition_true!(r#"test_proto2.add(1.0,2.0) == 3.0"#);

    condition_true!(r#"test_proto2.uppercase("foo") == "FOO""#);
    condition_true!(r#"test_proto2.nested.nested_func()"#);

    condition_false!(r#"test_proto2.undef_i64() == 0"#);
    condition_false!(r#"test_proto2.undef_i64() != 0"#);

    condition_true!(r#"test_proto2.int64_zero == 0"#);
    condition_true!(r#"test_proto2.int64_one == 1"#);
    condition_true!(r#"test_proto2.int64_one + test_proto2.int64_zero == 1"#);
    condition_true!(r#"test_proto2.int64_one + test_proto2.int64_one == 2"#);
    condition_true!(r#"test_proto2.int64_one * test_proto2.int64_one == 1"#);
    condition_true!(r#"test_proto2.int64_one - test_proto2.int64_one == 0"#);

    condition_true!(r#"test_proto2.float_zero == 0.0"#);
    condition_true!(r#"test_proto2.float_one == 1.0"#);
    condition_true!(r#"test_proto2.double_zero == 0.0"#);
    condition_true!(r#"test_proto2.double_one == 1.0"#);

    condition_true!(
        r#"test_proto2.double_one + test_proto2.float_one == 2.0"#
    );

    condition_true!(
        r#"test_proto2.double_one - test_proto2.float_one == 0.0"#
    );

    condition_true!(
        r#"test_proto2.double_one * test_proto2.float_one == 1.0"#
    );

    condition_true!(r#"test_proto2.double_one \ 2 == 0.5"#);

    condition_true!(r#"test_proto2.nested.nested_int64_zero == 0"#);
    condition_true!(r#"test_proto2.nested.nested_int64_one == 1"#);

    condition_true!(r#"test_proto2.string_foo != test_proto2.string_bar"#);
    condition_true!(r#"test_proto2.string_foo == "foo""#);
    condition_true!(r#"test_proto2.string_bar == "bar""#);
    condition_true!(r#"test_proto2.string_foo > "fo""#);
    condition_true!(r#"test_proto2.string_bar < "bara""#);
    condition_true!(r#"test_proto2.string_foo >= "fo""#);
    condition_true!(r#"test_proto2.string_bar <= "bara""#);
    condition_true!(r#"test_proto2.string_foo contains "oo""#);
    condition_true!(r#"test_proto2.string_foo endswith "oo""#);
    condition_true!(r#"test_proto2.string_foo startswith "foo""#);
    condition_true!(r#"test_proto2.string_bar icontains "AR""#);
    condition_true!(r#"test_proto2.string_bar iendswith "AR""#);
    condition_true!(r#"test_proto2.string_bar istartswith "BAR""#);
    condition_true!(r#"test_proto2.string_bar iequals "BAR""#);

    condition_true!(r#"test_proto2.array_int64[0] == 1"#);
    condition_true!(r#"test_proto2.array_int64[1] == 10"#);
    condition_true!(r#"test_proto2.array_int64[2] == 100"#);

    condition_true!(r#"test_proto2.array_float[0] == 1.0"#);
    condition_true!(r#"test_proto2.array_float[1] == 10.0"#);
    condition_true!(r#"test_proto2.array_float[2] == 100.0"#);

    condition_false!(r#"test_proto2.array_bool[0]"#);
    condition_true!(r#"test_proto2.array_bool[1]"#);

    // array_int64[3] is undefined, so both conditions are false.
    condition_false!(r#"test_proto2.array_int64[3] == 0"#);
    condition_false!(r#"test_proto2.array_int64[3] != 0"#);

    condition_true!(r#"test_proto2.array_string[0] == "foo""#);
    condition_true!(r#"test_proto2.array_string[1] == "bar""#);
    condition_true!(r#"test_proto2.array_string[2] == "baz""#);

    // array_string[3] is undefined, so both conditions are false.
    condition_false!(r#"test_proto2.array_string[3] == """#);
    condition_false!(r#"test_proto2.array_string[3] != """#);

    condition_true!(r#"test_proto2.array_struct[0].nested_int64_one == 1"#);

    condition_true!(
        r#"test_proto2.array_struct[0].nested_array_int64[0] == 2"#
    );
    condition_true!(
        r#"test_proto2.array_struct[0].nested_array_int64[1] == 20"#
    );

    condition_true!(r#"test_proto2.Enumeration.ITEM_0 == 0"#);
    condition_true!(r#"test_proto2.Enumeration.ITEM_1 == 1"#);

    condition_true!(
        r#"test_proto2.TopLevelEnumeration.ITEM_0x1000 == 0x1000"#
    );

    condition_true!(r#"test_proto2.map_string_int64["one"] == 1"#);

    condition_true!(
        r#"test_proto2.map_string_struct["foo"].nested_int64_one == 1"#
    );

    // test_proto2.map_string_struct["bar"] is undefined.
    condition_false!(
        r#"test_proto2.map_string_struct["bar"].nested_int64_one == 1"#
    );

    condition_true!(
        r#"test_proto2.array_int64[test_proto2.array_int64[0]] == 10"#
    );

    // Make sure that undef or true is true.
    condition_true!(r#"test_proto2.int64_undef == 0 or true"#);

    // Make sure that undef and true is false
    condition_true!(r#"not (test_proto2.int64_undef == 0 and true)"#);

    condition_true!(r#"test_proto2.map_int64_string[100] == "one hundred""#);
    condition_true!(r#"test_proto2.map_int64_int64[100] == 100"#);
    condition_true!(
        r#"test_proto2.map_int64_struct[100].nested_int64_one == 1"#
    );

    condition_true!(r#"for any i in test_proto2.array_int64 : (i == 10)"#);
    condition_true!(r#"for all i in test_proto2.array_int64 : (i < 10000)"#);
    condition_true!(r#"for any s in test_proto2.array_string : (s == "foo")"#);

    condition_true!(
        r#"for all s in test_proto2.array_string : (
            s == "foo" or s == "bar" or s == "baz"
        )"#
    );

    condition_true!(
        r#"for any s in test_proto2.array_struct : (
            s.nested_int32_zero == 0 and s.nested_int32_one == 1
          )"#
    );

    condition_true!(
        r#"for any s in test_proto2.array_struct : (
            s.nested_int32_zero == 0 and
            s.nested_int32_one == 1 and

            for any s in test_proto2.array_struct : (
                s.nested_int32_zero == 0
            )

            and for any s in test_proto2.array_string : (s == "foo")
          )"#
    );

    condition_true!(r#"for any e in (1,2,3) : (e == 3)"#);
    condition_true!(r#"for any e in (1+1,2+2) : (e == 2)"#);
    condition_false!(r#"for any e in (1+1,2+2) : (e == 3)"#);
    condition_true!(r#"for all e in (1+1,2+2) : (e < 5)"#);
    condition_true!(r#"for 2 s in ("foo", "bar", "baz") : (s contains "ba")"#);
    condition_true!(r#"for all x in (1.0, 2.0, 3.0) : (x >= 1.0)"#);
    condition_true!(r#"for none x in (1.0, 2.0, 3.0) : (x > 4.0)"#);

    // This field is named `bool_proto` in the protobuf definition, but it's
    // name for YARA wsa changed to `bool_yara`, with:
    //
    //   [(yara.field_options).name = "bool_yara"];
    //
    condition_true!(r#"test_proto2.bool_yara"#);
}
