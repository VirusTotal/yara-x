/*! End-to-end tests.*/
use pretty_assertions::assert_eq;

macro_rules! test_condition {
    ($condition:literal, $data:expr, $expected_result:expr) => {{
        let mut src = String::new();

        if cfg!(feature = "test_proto2-module") {
            src.push_str(r#"import "test_proto2""#);
        }

        if cfg!(feature = "test_proto3-module") {
            src.push_str(r#"import "test_proto3""#);
        }

        src.push_str(
            format!("rule t {{condition: {} }}", $condition).as_str(),
        );

        let rules = crate::compile(src.as_str()).unwrap();

        let num_matching_rules = crate::scanner::Scanner::new(&rules)
            .scan($data)
            .matching_rules()
            .len();

        assert_eq!(
            num_matching_rules, $expected_result as usize,
            "\n\n`{}` should be {}, but it is {}",
            $condition, $expected_result, !$expected_result
        );
    }};
}

macro_rules! condition_true {
    ($condition:literal,  $data:expr) => {{
        test_condition!($condition, $data, true);
    }};
    ($condition:literal) => {{
        test_condition!($condition, &[], true);
    }};
}

macro_rules! condition_false {
    ($condition:literal,  $data:expr) => {{
        test_condition!($condition, $data, false);
    }};
    ($condition:literal) => {{
        test_condition!($condition, &[], false);
    }};
}

macro_rules! test_rule {
    ($rule:expr,  $data:expr, $expected_result:expr) => {{
        let rules = crate::compile($rule).unwrap();

        let num_matching_rules = crate::scanner::Scanner::new(&rules)
            .scan($data)
            .matching_rules()
            .len();

        assert_eq!(
            num_matching_rules, $expected_result as usize,
            "\n\n`{}` should be {}, but it is {}",
            $rule, $expected_result, !$expected_result
        );
    }};
    ($rule:expr) => {{
        rule_true!($rule, &[]);
    }};
}

macro_rules! rule_true {
    ($rule:expr,  $data:expr) => {{
        test_rule!($rule, $data, true);
    }};
    ($rule:expr) => {{
        test_rule!($rule, &[], true);
    }};
}

macro_rules! rule_false {
    ($rule:expr,  $data:expr) => {{
        test_rule!($rule, $data, false);
    }};
    ($rule:expr) => {{
        test_rule!($rule, &[], false);
    }};
}

macro_rules! pattern_true {
    ($pattern:literal,  $data:expr) => {{
        rule_true!(
            format!("rule test {{ strings: $a = {} condition: $a}}", $pattern)
                .as_str(),
            $data
        );
    }};
}

macro_rules! pattern_false {
    ($pattern:literal,  $data:expr) => {{
        rule_false!(
            format!("rule test {{ strings: $a = {} condition: $a}}", $pattern)
                .as_str(),
            $data
        );
    }};
}

#[test]
fn arithmetic_operations() {
    condition_true!("1 == 1");
    condition_true!("1 + 1 == 2");
    condition_true!("1 - 1 == 0");
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
fn test_comparison_operations() {
    condition_true!("2 > 1");
    condition_true!("1 < 2");
    condition_true!("2 >= 1");
    condition_true!("2 >= 2");
    condition_true!("1 <= 1");
    condition_true!("1 <= 2");
    condition_true!("1 == 1");
    condition_true!("1.5 == 1.5");
    condition_true!("1.0 == 1");
    condition_true!("1.0 != 1.000000000000001");
    condition_true!("1.0 < 1.000000000000001");
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

    condition_true!(r#""foo" matches /foo/"#);
    condition_true!(r#""foo" matches /FOO/i"#);
    condition_false!(r#""foo" matches /bar/"#);
    condition_true!(r#""xxFoOxx" matches /fOo/i"#);
    condition_false!(r#""xxFoOxx" matches /^fOo/i"#);
    condition_false!(r#""xxFoOxx" matches /fOo$/i"#);
    condition_true!(r#""foobar" matches /^foo/"#);
    condition_true!(r#""foobar" matches /bar$/"#);
    condition_true!(r#""foobar" matches /^foobar$/"#);
    condition_true!(r#""foo\nbar" matches /foo.*bar/s"#);
    condition_false!(r#""foo\nbar" matches /foo.*bar/"#);
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
    let data = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];

    condition_true!("uint8(0) == 0x01", &data);
    condition_true!("uint8(1) == 0x02", &data);
    condition_true!("uint8(2) == 0x03", &data);

    condition_true!("uint16(0) == 0x0201", &data);
    condition_true!("uint16(1) == 0x0302", &data);
    condition_true!("uint16(2) == 0x0403", &data);

    condition_true!("uint32(0) == 0x04030201", &data);
    condition_true!("uint32(1) == 0x05040302", &data);
    condition_true!("uint32(2) == 0x06050403", &data);

    condition_true!("uint16be(0) == 0x0102", &data);
    condition_true!("uint16be(1) == 0x0203", &data);
    condition_true!("uint16be(2) == 0x0304", &data);

    condition_true!("uint32be(0) == 0x01020304", &data);
    condition_true!("uint32be(1) == 0x02030405", &data);
    condition_true!("uint32be(2) == 0x03040506", &data);
    condition_true!("uint32be(11) == 0xffffffff", &data);

    condition_false!("uint8(20) == 0", &data);
    condition_false!("uint8(20) != 0", &data);
    condition_false!("uint16(19) == 0", &data);
    condition_false!("uint16(19) != 0", &data);
    condition_false!("uint32(17) == 0", &data);
    condition_false!("uint32(17) != 0", &data);
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
    // the `for` loop is always false. The outer loop is only for
    // being able to write a loop with a range (i+1..i) where
    // the lower bound is greater than the higher bound, without
    // using constants. Writing a range like (2..1) is not possible
    // because it raises an error.
    condition_false!(
        "for any i in (1..1) : ( 
            for all j in (i + 1..i) : ( 
                true 
            ) 
        )"
    );

    condition_false!(
        "for any i in (1..1) : (
            for all j in (i + 1..i) : (
                false
            )
        )"
    );

    condition_false!(
        "for any i in (1..1) : (
            for none j in (i + 1..i) : (
                true        
            ) 
        )"
    );

    condition_false!(
        "for any i in (1..1) : (
            for none j in (i + 1..i) : ( 
                false 
            ) 
        )"
    );

    condition_true!(r#"for any e in (1,2,3) : (e == 3)"#);
    condition_true!(r#"for any e in (1+1,2+2) : (e == 2)"#);
    condition_false!(r#"for any e in (1+1,2+2) : (e == 3)"#);
    condition_true!(r#"for all e in (1+1,2+2) : (e < 5)"#);
    condition_true!(r#"for 2 s in ("foo", "bar", "baz") : (s contains "ba")"#);
    condition_true!(r#"for all x in (1.0, 2.0, 3.0) : (x >= 1.0)"#);
    condition_true!(r#"for none x in (1.0, 2.0, 3.0) : (x > 4.0)"#);
}

#[test]
fn text_patterns() {
    pattern_true!(r#""issi""#, b"mississippi");
    pattern_true!(r#""issi" ascii"#, b"mississippi");
    pattern_false!(r#""issi" wide "#, b"mississippi");
    pattern_false!(r#""ssippis""#, b"mississippi");
    pattern_true!(r#""IssI" nocase"#, b"mississippi");

    pattern_true!(
        r#""issi" wide "#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""issi" ascii wide"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
}

#[test]
fn match_at() {
    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "foo" 
            condition: 
                $a at 0
        }
        "#,
        b"foobar"
    );

    rule_false!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                $a at 3
        }
        "#,
        b"foobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                $a at 3
        }
        "#,
        b"barfoo"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "fofo"
            condition:
                $a at 0 and 
                $a at 2 and
                $a at 4
        }
        "#,
        b"fofofofo"
    );
}

#[test]
fn match_in() {
    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "foo" 
            condition: 
                $a in (0..1)
        }
        "#,
        b"foobar"
    );

    rule_false!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                $a in (1..6)
        }
        "#,
        b"foobar"
    );

    rule_false!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                $a in (2..6)
        }
        "#,
        b"foobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "fofo"
            condition:
                $a in (0..1) and 
                $a in (2..3) and
                $a in (4..5)
        }
        "#,
        b"fofofofo"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "sippi" 
            condition: 
                $a in (0..6)
        }
        "#,
        b"mississippi"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "sippi" 
            condition: 
                $a in (6..6)
        }
        "#,
        b"mississippi"
    );

    rule_false!(
        r#"
        rule test {
            strings: 
                $a = "sippi" 
            condition: 
                $a in (7..20)
        }
        "#,
        b"mississippi"
    );
}

#[test]
fn match_count() {
    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                #a == 1
        }
        "#,
        b"foobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo" private
            condition:
                #a == 1
        }
        "#,
        b"foobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                #a == 2
        }
        "#,
        b"foobarfoo"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                #a in (0..5) == 1
        }
        "#,
        b"foobarfoo"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                #a in (0..6) == 2
        }
        "#,
        b"foobarfoo"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "aaaa"
            condition:
                #a == 3
        }
        "#,
        b"aaaaaa"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "aaa" 
            condition: 
                #a in (4..5) == 2
        }
        "#,
        b"xxxaaaaa"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                for all of them : ( # == 2 )
        }
        "#,
        b"foobarfoobar"
    );
}

#[test]
fn match_offset() {
    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                @a == 0 and @b == 3
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                @a[1] == 0 and @b[1] == 3
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                @a[2] == 6 and @b[2] == 9
        }
        "#,
        b"foobarfoobar"
    );

    rule_false!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                @a[3] == 0 or @b[3] == 0
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                for all of ($a, $b) : ( @ <= 3 )
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                for all of ($a, $b) : ( @[2] >= 6 )
        }
        "#,
        b"foobarfoobar"
    );
}

#[test]
fn match_length() {
    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                !a == 3
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                !a[1] == 3
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                !a[2] == 3
        }
        "#,
        b"foobarfoobar"
    );

    rule_false!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                !a[3] == 3
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                for all of ($a, $b) : ( ! == 3 )
        }
        "#,
        b"foobarfoobar"
    );

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                for all of ($a, $b) : ( ![2] == 3 )
        }
        "#,
        b"foobarfoobar"
    );
}

#[test]
fn xor() {
    pattern_true!(r#""mississippi" xor"#, b"lhrrhrrhqqh");
    pattern_true!(r#""ssi" xor"#, b"lhrrhrrhqqh");
    pattern_false!(r#""miss" xor fullword"#, b"lhrrhrrhqqh");
    pattern_false!(r#""ppi" xor fullword"#, b"lhrrhrrhqqh");
    pattern_false!(r#""ssi" xor fullword"#, b"lhrrhrrhqqh");
    pattern_false!(r#""ssis" xor fullword"#, b"lhrrhrrhqqh");

    pattern_true!(
        r#""mississippi" xor fullword "#,
        b"y!lhrrhrrhqqh" // "x mississippi"
    );

    pattern_true!(
        r#""mississippi" xor fullword "#,
        b"lhrrhrrhqqh!y" // "mississippi x"
    );

    pattern_false!(
        r#""mississippi" xor fullword "#,
        b"ylhrrhrrhqqh" // "xmississippi"
    );

    pattern_false!(
        r#""mississippi" xor fullword "#,
        b"lhrrhrrhqqhy" // "mississippix"
    );

    pattern_true!(r#""mississippi" xor ascii"#, b"lhrrhrrhqqh");
    pattern_true!(r#""mississippi" xor ascii wide"#, b"lhrrhrrhqqh");
    pattern_false!(r#""mississippi" xor wide"#, b"lhrrhrrhqqh");

    // YARA 4.x doesn't XOR the bytes before and after the matching
    // pattern, so `mississippi" xor(1) fullword` matches `{lhrrhrrhqqh}`.
    // In YARA-X `{lhrrhrrhqqh}` becomes `zmississipiz`, which
    // doesn't match.
    pattern_false!(
        r#""mississippi" xor(1) fullword"#,
        b"{lhrrhrrhqqh}" // zmississippiz xor 1
    );

    pattern_true!(
        r#""mississippi" xor wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );

    pattern_true!(
        r#""mississippi" xor fullword wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );

    pattern_false!(
        r#""mississippi" xor fullword wide"#,
        b"y\x01l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );

    pattern_true!(
        r#""mississippi" xor fullword wide"#,
        b"\x01\x02l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );

    pattern_true!(
        r#""mississippi" xor fullword wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01\x02\x01"
    );

    pattern_false!(
        r#""mississippi" xor fullword wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01y\x01"
    );

    pattern_true!(
        r#""mississippi" xor ascii wide"#,
        b"l\x01h\x01r\x01r\x01h\x01r\x01r\x01h\x01q\x01q\x01h\x01"
    );

    pattern_false!(r#""mississippi" xor(2-255)"#, b"lhrrhrrhqqh");
    pattern_true!(
        r#""mississippi" xor(255)"#,
        &[0x92, 0x96, 0x8C, 0x8C, 0x96, 0x8C, 0x8C, 0x96, 0x8F, 0x8F, 0x96]
    );
}

#[test]
fn fullword() {
    pattern_true!(r#""mississippi" fullword"#, b"mississippi");
    pattern_true!(r#""mississippi" fullword"#, b"mississippi ");
    pattern_true!(r#""mississippi" fullword"#, b" mississippi");
    pattern_true!(r#""mississippi" fullword"#, b" mississippi ");
    pattern_true!(r#""mississippi" fullword"#, b"\x00mississippi\x00");
    pattern_true!(r#""mississippi" fullword"#, b"\x01mississippi\x02");
    pattern_false!(r#""miss" fullword"#, b"mississippi");
    pattern_false!(r#""ippi" fullword"#, b"mississippi");
    pattern_false!(r#""issi" fullword"#, b"mississippi");

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00 \0x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b" \x00m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b" \x00m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00 \x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,  
        b"\x00\x00m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00\x00\x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"\x00m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"\x00\x00m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"\x00\x01m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"x\x01m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00x\x01"
    );

    pattern_true!(
        r#""mississippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00\x01\x00"
    );

    pattern_false!(
        r#""miss" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_false!(
        r#""ippi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_false!(
        r#""issi" wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );
}

#[test]
fn base64() {
    pattern_true!(
        r#""foobar" base64"#,
        b"Zm9vYmFy" // base64("foobar")
    );

    pattern_true!(
        r#""foobar" base64"#,
        b"eGZvb2Jhcg" // base64("xfoobar")
    );

    pattern_true!(
        r#""foobar" base64"#,
        b"eHhmb29iYXI" // base64("xxfoobar")
    );

    pattern_true!(
        r#""foobar" base64"#,
        b"eHh4Zm9vYmFy" // base64("xxxfoobar")
    );

    pattern_true!(
        r#""fooba" base64"#,
        b"Zm9vYmE" // base64("fooba")
    );

    pattern_true!(
        r#""fooba" base64"#,
        b"eGZvb2Jh" // base64("xfooba")
    );

    pattern_true!(
        r#""fooba" base64"#,
        b"eHhmb29iYQ" // base64("xxfooba")
    );

    pattern_true!(
        r#""foob" base64"#,
        b"Zm9vYg" // base64("foob")
    );

    pattern_true!(
        r#""foob" base64"#,
        b"eGZvb2I" // base64("xfoob")
    );

    pattern_true!(
        r#""foob" base64"#,
        b"eHhmb29i" // base64("xxfoob")
    );

    pattern_true!(
        r#""foob" base64"#,
        b"eHhmb29i\x01" // base64("xxfoob")
    );

    pattern_true!(
        r#""foobar" base64("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")"#,
        b"Xk7tWkDw"
    );

    // When `base64` is combined with `wide` the latter if applied first,
    // so it must match base64("f\x00o\x00o\x00b\x00a\x00r\x00").
    pattern_true!(
        r#""foobar" base64 wide"#,
        b"ZgBvAG8AYgBhAHIA" // base64("f\x00o\x00o\x00b\x00a\x00r\x00")
    );

    // When `base64` is combined with `wide` the latter if applied first,
    // so it does NOT match base64("foobar").
    pattern_false!(
        r#""foobar" base64 wide"#,
        b"Zm9vYmFy" // base64("foobar")
    );

    // When `base64` is combined with both `wide` and `ascii` it should
    // match base64("f\x00o\x00o\x00b\x00a\x00r\x00") and base64("foobar").
    pattern_true!(
        r#""foobar" base64 wide ascii"#,
        b"Zm9vYmFy" // base64("foobar")
    );

    pattern_false!(r#""foobar" base64"#, b"foobar");
    pattern_false!(r#""foobar" base64 ascii"#, b"foobar");
    pattern_false!(
        r#""foobar" base64 wide"#,
        b"f\x00o\x00o\x00b\x00a\x00r\x00"
    );

    pattern_false!(
        r#""foobar" base64"#,
        b"Zm9vYmE" // base64("fooba"))
    );

    pattern_false!(
        r#""foobar" base64"#,
        b"eHhmb29iYQ" // base64("xxfooba"))
    );

    pattern_false!(
        r#""foobar" base64"#,
        b"eHhmb29i" // base64("xxfoob"))
    );

    pattern_false!(r#""foobar" base64"#, b"Zvb2Jhcg");
    pattern_false!(r#""foobar" base64"#, b"mb29iYQ");
    pattern_false!(r#""foobar" base64"#, b":::mb29iYXI");

    // In the C implementation of YARA the `base64` modifier could produce
    // false positives like this. In this implementation the issue is fixed.
    pattern_false!(
        r#""Dhis program cannow" base64"#,
        // base64("This program cannot")
        b"QVRoaXMgcHJvZ3JhbSBjYW5ub3Q"
    );

    pattern_true!(
        r#""This program cannot" base64"#,
        // base64("This program cannot")
        b"QVRoaXMgcHJvZ3JhbSBjYW5ub3Q"
    );

    pattern_true!(
        r#""foobar" base64wide"#,
        // base64("foobar") in wide form
        b"Z\x00m\x009\x00v\x00Y\x00m\x00F\x00y\x00"
    );

    // The the last byte should be 0, but it's 1, so the pattern doesn't match.
    pattern_false!(
        r#""foobar" base64wide"#,
        // base64("foobar") in wide form
        b"Z\x00m\x009\x00v\x00Y\x00m\x00F\x00y\x01"
    );

    pattern_true!(
        r#""foobar" base64wide"#,
        // base64("xfoobar") in wide form
        b"e\x00G\x00Z\x00v\x00b\x002\x00J\x00h\x00c\x00g\x00"
    );

    pattern_true!(
        r#""foobar" base64wide"#,
        // base64("xxfoobar") in wide form
        b"e\x00H\x00h\x00m\x00b\x002\x009\x00i\x00Y\x00X\x00I\x00"
    );

    pattern_true!(
        r#""foobar" base64wide"#,
        // base64("xxxfoobar") in wide form
        b"e\x00H\x00h\x004\x00Z\x00m\x009\x00v\x00Y\x00m\x00F\x00y\x00"
    );

    pattern_true!(
        r#""foobar" base64wide wide"#,
        // base64("f\x00o\x00o\x00b\x00a\x00r\x00") in wide form
        b"Z\x00g\x00B\x00v\x00A\x00G\x008\x00A\x00Y\x00g\x00B\x00h\x00A\x00H\x00I\x00A\x00" 
    );

    pattern_true!(
        r#""foobar" base64wide("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")"#,
        b"X\x00k\x007\x00t\x00W\x00k\x00D\x00w\x00"
    );

    pattern_true!(
        r#""foobar" 
            base64wide("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
            base64("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")"#,
        b"X\x00k\x007\x00t\x00W\x00k\x00D\x00w\x00"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississippi" base64
            condition: 
                $a at 6 and !a == 14
        }
        "#,
        // base64("the mississippi river")
        b"dGhlIG1pc3Npc3NpcHBpIHJpdmVy"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississippi" base64
            condition: 
                $a at 7 and !a == 14
        }
        "#,
        // base64(" the mississippi river")
        b"IHRoZSBtaXNzaXNzaXBwaSByaXZlcg"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississippi" base64
            condition: 
                $a at 8 and !a == 14
        }
        "#,
        // base64("  the mississippi river")
        b"ICB0aGUgbWlzc2lzc2lwcGkgcml2ZXI"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississipp" base64
            condition: 
                $a at 6 and !a == 12
        }
        "#,
        // base64("the mississippi river")
        b"dGhlIG1pc3Npc3NpcHBpIHJpdmVy"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississipp" base64
            condition: 
                $a at 7 and !a == 13
        }
        "#,
        // base64(" the mississippi river")
        b"IHRoZSBtaXNzaXNzaXBwaSByaXZlcg"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississipp" base64
            condition: 
                $a at 8 and !a == 13
        }
        "#,
        // base64("  the mississippi river")
        b"ICB0aGUgbWlzc2lzc2lwcGkgcml2ZXI"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississip" base64
            condition: 
                $a at 6 and !a == 11
        }
        "#,
        // base64("  the mississippi river")
        b"dGhlIG1pc3Npc3NpcHBpIHJpdmVy"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississip" base64
            condition: 
                $a at 7 and !a == 11
        }
        "#,
        // base64(" the mississippi river")
        b"IHRoZSBtaXNzaXNzaXBwaSByaXZlcg"
    );

    rule_true!(
        r#"
        rule test {
            strings: 
                $a = "mississip" base64
            condition: 
                $a at 8 and !a == 12
        }
        "#,
        // base64("  the mississippi river")
        b"ICB0aGUgbWlzc2lzc2lwcGkgcml2ZXI"
    );
}

#[test]
fn filesize() {
    let rules = crate::compile(
        r#"
        rule filesize_0 {
          condition:
            filesize == 0
        }
        rule filesize_1 {
          condition:
            filesize == 1
        }
        rule filesize_2 {
          condition:
            filesize == 2
        }
        "#,
    )
    .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);

    assert_eq!(scanner.scan(b"").matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"a").matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"ab").matching_rules().len(), 1);
}

#[test]
fn for_of() {
    rule_true!(
        r#"
        rule test {
          strings:
            $a = "foo"
            $b = "bar"
          condition:
            for none of ($a, $b) : ($)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        rule test {
          strings:
            $a = "foo"
            $b = "bar"
          condition:
            for all of them : ($)
        }
        "#,
        b"foobar"
    );
}

#[test]
fn of() {
    condition_true!(r#"any of (false, true)"#);
    condition_true!(r#"all of (true, true)"#);
    condition_true!(r#"none of (false, false)"#);
    condition_false!(r#"any of (false, false)"#);
    condition_false!(r#"all of (false, true)"#);

    condition_true!(r#"none of (1 == 0, 2 == 0)"#);
    condition_true!(r#"all of (1 == 1, 2 == 2)"#);

    condition_true!(
        r#"
        all of (
            all of (true, true),
            none of (false, false),
            any of (false, true)
        )
        "#
    );

    rule_true!(
        r#"
        rule test {
          strings:
            $a1 = "foo"
            $a2 = "bar"
            $b1 = "baz"
          condition:
            none of ($a*, $b1)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        rule test {
          strings:
            $a1 = "foo"
            $a2 = "bar"
            $b1 = "baz"
          condition:
            none of them
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        rule test {
          strings:
            $a1 = "foo"
            $a2 = "bar"
            $b1 = "baz"
          condition:
            all of ($a*, $b*)
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        rule test {
          strings:
            $ = "foo"
            $ = "bar"
            $ = "baz"
          condition:
            all of them
        }
        "#,
        b"foobarbaz"
    );

    rule_false!(
        r#"
        rule test {
          strings:
            $ = "foo"
            $ = "bar"
            $ = "baz"
          condition:
            100% of them
        }
        "#,
        b"barbaz"
    );
}

#[test]
fn rule_reuse() {
    let rules = crate::compile(
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
    .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);

    assert_eq!(scanner.scan(&[]).matching_rules().len(), 9);
}

#[test]
fn test_defined_1() {
    condition_true!(r#"defined 1"#);
    condition_true!(r#"defined 1.0"#);
    condition_true!(r#"defined false"#);
    condition_true!(r#"defined "foo""#);
    condition_false!(r#"defined 1 and false"#);
    condition_true!(r#"defined (true and false)"#);
    condition_false!(r#"defined true and false"#);
}

#[test]
#[cfg(feature = "test_proto2-module")]
fn test_defined_2() {
    condition_false!(r#"defined test_proto2.undef_i64()"#);
    condition_true!(r#"not defined test_proto2.undef_i64()"#);
    condition_true!(
        r#"defined (for any x in (0..10) : (test_proto2.undef_i64() == 0))"#
    );
}

#[test]
#[cfg(feature = "test_proto3-module")]
fn test_defined_3() {
    // In modules defined with a proto3 there's no such thing as undefined
    // fields. If the field was not explicitly set to some value, it will
    // have the default value for the type.
    condition_true!(r#"defined test_proto3.int64_undef"#);
    condition_false!(r#"not defined test_proto3.int64_undef"#);
    condition_true!(r#"test_proto3.int64_undef == 0"#);
    condition_true!(r#"test_proto3.fixed64_undef == 0.0"#);
    condition_false!(r#"test_proto3.bool_undef"#);
    condition_true!(r#"not test_proto3.bool_undef"#);
    condition_true!(r#"test_proto3.string_undef == """#);
}

#[test]
#[cfg(feature = "test_proto2-module")]
fn test_proto2_module() {
    condition_true!(r#"test_proto2.add(1,2) == 3"#);
    condition_true!(r#"test_proto2.add(1.0,2.0) == 3.0"#);

    condition_true!(r#"test_proto2.uppercase("foo") == "FOO""#);
    condition_true!(r#"test_proto2.nested.nested_func()"#);
    condition_true!(
        r#"test_proto2.head(3) == "\x01\x02\x03""#,
        &[0x01, 0x02, 0x03, 0x04]
    );

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
        r#"test_proto2.array_struct[0].nested_array_int64[0] == 1"#
    );
    condition_true!(
        r#"test_proto2.array_struct[0].nested_array_int64[1] == 10"#
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

    condition_true!(r#"test_proto2.map_int64_string[100] == "one thousand""#);
    condition_true!(r#"test_proto2.map_int64_int64[100] == 1000"#);
    condition_true!(
        r#"test_proto2.map_int64_struct[100].nested_int64_one == 1"#
    );

    condition_true!(r#"test_proto2.map_string_string["foo"] == "FOO""#);

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

    condition_true!(
        r#"for any key, value in test_proto2.map_int64_int64 : (
                key == 100 and value == 1000
          )"#
    );

    condition_true!(
        r#"for any key, value in test_proto2.map_int64_string : (
                key == 100 and value == "one thousand"
          )"#
    );

    condition_true!(
        r#"for any key, value in test_proto2.map_int64_bool : (
                key == 100 and value
          )"#
    );

    condition_true!(
        r#"for any key, value in test_proto2.map_int64_struct : (
                key == 100 and value.nested_int64_one == 1
          )"#
    );

    condition_true!(
        r#"for any key, value in test_proto2.map_string_int64 : (
                key == "one" and value == 1
          )"#
    );

    condition_true!(
        r#"for any key, value in test_proto2.map_string_bool : (
                key == "foo" and value
          )"#
    );

    condition_true!(
        r#"for any key, value in test_proto2.map_string_string : (
                key == "foo" and value == "FOO"
          )"#
    );

    condition_true!(
        r#"for any key, value in test_proto2.map_string_struct : (
                key == "foo" and value.nested_int64_one == 1
          )"#
    );

    condition_true!(r#"test_proto2.get_foo() == "foo""#);
    condition_true!(r#"test_proto2.to_int("123") == 123"#);

    // This field is named `bool_proto` in the protobuf definition, but it's
    // name for YARA wsa changed to `bool_yara`, with:
    //
    //   [(yara.field_options).name = "bool_yara"];
    //
    condition_true!(r#"test_proto2.bool_yara"#);
}
