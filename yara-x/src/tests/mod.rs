/*! End-to-end tests. */
use bstr::ByteSlice;
use goldenfile::Mint;
use ihex::Reader;
use pretty_assertions::assert_eq;
use protobuf::MessageDyn;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

const JUMPS_DATA: &[u8; 1664] = include_bytes!("testdata/jumps.bin");

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
            .expect("scan should not fail")
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
            .expect("scan should not fail")
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

macro_rules! pattern_match {
    ($pattern:literal, $data:expr, $expected_result:expr) => {{
        let src =
            format!("rule test {{ strings: $a = {} condition: $a}}", $pattern);

        let rules = crate::compile(src.as_str()).unwrap();

        let mut scanner = crate::scanner::Scanner::new(&rules);
        let scan_results = scanner.scan($data).expect("scan should not fail");
        let matching_data = scan_results
            .matching_rules()
            .next()
            .expect(format!("pattern `{}` should match `{:?}`", $pattern, $data).as_str())
            .patterns()
            .next()
            .unwrap()
            .matches()
            .next()
            .unwrap()
            .data;

        assert_eq!(
            matching_data, $expected_result,
            "\n\n`{}` applied to data `{:?}` should match `{:?}`, but it is matching `{:?}`",
            $pattern, $data, $expected_result, matching_data
        );
    }};
}

macro_rules! create_binary_from_ihex {
    ($filename:expr) => {{
        let mut file = fs::File::open($filename).expect("Unable to open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Unable to read file");

        let mut reader = Reader::new(&contents);
        let mut data = Vec::new();
        while let Some(Ok(record)) = reader.next() {
            if let ihex::Record::Data { value, .. } = record {
                data.extend(value);
            }
        }

        Ok(data)
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
    condition_true!("--1.0 == 1.0");
    condition_true!("-1.0-1.5 == -2.5");
    condition_true!("1--1 == 2");
    condition_true!("2 * -2 == -4");
    condition_true!("-4 * 2 == -8");
    condition_true!("-4 * -4 == 16");
    condition_true!("-0x01 == -1");
    condition_true!("-0o10 == -8");
    condition_true!("0o100 == 64");
    condition_true!("0o755 == 493");
    condition_true!("1 + 2 + 3 == 6");
    condition_true!("2 - 1 - 1 == 0");
    condition_true!("2 * 3 * 4 == 24");
    condition_true!("5 \\ 2 \\ 2 == 1");
    condition_true!("7 \\ 2 \\ 2.0 == 1.5");
    condition_true!("7 % 4 % 2 == 1");
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
    condition_true!(r#""foobar" matches /fo{,2}bar/"#);
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
fn intxx() {
    let data = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];

    condition_true!("int8(0) == 0x01", &data);
    condition_true!("int8(1) == 0x02", &data);
    condition_true!("int8(2) == 0x03", &data);
    condition_true!("int8(10) == -1", &data);

    condition_true!("int16(0) == 0x0201", &data);
    condition_true!("int16(1) == 0x0302", &data);
    condition_true!("int16(2) == 0x0403", &data);
    condition_true!("int16(10) == -1", &data);

    condition_true!("int32(0) == 0x04030201", &data);
    condition_true!("int32(1) == 0x05040302", &data);
    condition_true!("int32(2) == 0x06050403", &data);
    condition_true!("int32(10) == -1", &data);

    condition_true!("int16be(0) == 0x0102", &data);
    condition_true!("int16be(1) == 0x0203", &data);
    condition_true!("int16be(2) == 0x0304", &data);
    condition_true!("int16be(10) == -1", &data);

    condition_true!("int32be(0) == 0x01020304", &data);
    condition_true!("int32be(1) == 0x02030405", &data);
    condition_true!("int32be(2) == 0x03040506", &data);
    condition_true!("int32be(10) == -1", &data);

    condition_false!("int8(20) == 0", &data);
    condition_false!("int8(20) != 0", &data);
    condition_false!("int16(19) == 0", &data);
    condition_false!("int16(19) != 0", &data);
    condition_false!("int32(17) == 0", &data);
    condition_false!("int32(17) != 0", &data);
}

#[test]
fn for_in() {
    condition_true!("for any i in (0..1): ( 1 )");
    condition_false!("for any i in (0..1): ( 0 )");
    condition_true!(r#"for any i in (0..1): ( "a" )"#);
    condition_false!(r#"for any i in (0..1): ( "" )"#);
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
    pattern_true!(r#""IssISSi" nocase"#, b"mississippi");
    pattern_false!(r#""IssISi" nocase"#, b"mississippi");

    pattern_true!(
        r#""issi" wide "#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""issi" ascii wide"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_true!(
        r#""🙈🙉🙊""#,
        b"\xF0\x9F\x99\x88\xF0\x9F\x99\x89\xF0\x9F\x99\x8A"
    );
}

#[test]
fn hex_patterns() {
    pattern_true!(r#"{ 01 }"#, &[0x01]);
    pattern_true!(r#"{ 01 02 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_true!(r#"{ 01 ?? 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);

    pattern_false!(r#"{ 01 1? 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_true!(r#"{ 01 0? 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_false!(r#"{ 01 ?0 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_true!(r#"{ 01 ?2 03 04 }"#, &[0x01, 0x02, 0x03, 0x04]);

    pattern_true!(
        r#"{ (01 02 03 04 | 05 06 07 08) }"#,
        &[0x01, 0x02, 0x03, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [-] 03 04 }"#,
        &[0x01, 0x02, 0x03, 0x04],
        &[0x01, 0x02, 0x03, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [-] 03 04 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04],
        &[0x01, 0x02, 0xFF, 0x03, 0x04]
    );

    pattern_match!(
        r#"{ 01 ?? 02 [-] 03 ?? 04 }"#,
        &[0x01, 0xFF, 0x02, 0x03, 0xFF, 0x04],
        &[0x01, 0xFF, 0x02, 0x03, 0xFF, 0x04]
    );

    pattern_match!(
        r#"{ 01 ?? 02 [-] 03 ?? 04 }"#,
        &[0x01, 0xFF, 0x02, 0xFF, 0x03, 0xFF, 0x04],
        &[0x01, 0xFF, 0x02, 0xFF, 0x03, 0xFF, 0x04]
    );

    pattern_match!(
        r#"{ 01 ?? 02 [-] 03 ?? 04 }"#,
        &[0x01, 0xFF, 0x02, 0xFF, 0xFF, 0x03, 0xFF, 0x04],
        &[0x01, 0xFF, 0x02, 0xFF, 0xFF, 0x03, 0xFF, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [-] 03 04 [-] 05 06 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    );

    pattern_match!(
        r#"{ 01 02 [-] 03 04 [-] 05 06 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0xFF, 0x05, 0x06],
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0xFF, 0x05, 0x06]
    );

    pattern_match!(
        r#"{ 01 02 [-] 03 04 [-] 05 06 }"#,
        &[0x01, 0x02, 0xFF, 0xFF, 0x03, 0x04, 0xFF, 0x05, 0x06],
        &[0x01, 0x02, 0xFF, 0xFF, 0x03, 0x04, 0xFF, 0x05, 0x06]
    );

    pattern_match!(
        r#"{ 01 02 [1] 03 04 [2] 05 06 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0xFF, 0xFF, 0x05, 0x06],
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0xFF, 0xFF, 0x05, 0x06]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 04 05 [1] 06 07 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ 01 02 [1-] 03 04 05 [1-] 06 07 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ 01 02 [0-3] 03 04 05 [1-] 06 07 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ 01 02 [0-3] 03 04 05 [1-] 06 07 }"#,
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ ?? 02 [0-3] 03 04 05 [1-] 06 ?? }"#,
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ 01 02 [0-1] 04 05 [0-2] 06 07 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ 01 02 [0-1] 04 05 [0-2] 06 07 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ 01 02 [0-5] 04 05 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x05],
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x05]
    );

    pattern_match!(
        r#"{ 01 02 [0-5] 04 05 }"#,
        &[0x01, 0x02, 0xFF, 0xFF, 0x03, 0x04, 0x05],
        &[0x01, 0x02, 0xFF, 0xFF, 0x03, 0x04, 0x05]
    );

    pattern_match!(
        r#"{ 01 02 [0-5] 04 05 }"#,
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0x04, 0x05],
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0x04, 0x05]
    );

    pattern_match!(
        r#"{ 01 02 03 [0-6] 04 05 06 }"#,
        &[0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0x04, 0xFF, 0x04, 0x05, 0x06],
        &[0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0x04, 0xFF, 0x04, 0x05, 0x06]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 03 }"#,
        &[0x01, 0x2, 0x03, 0x03, 0x03, 0x03],
        &[0x01, 0x2, 0x03, 0x03]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 03 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x03, 0x03, 0x03],
        &[0x01, 0x02, 0xFF, 0x03, 0x03]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 03 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0xFF, 0x03],
        &[0x01, 0x02, 0xFF, 0x03, 0xFF, 0x03]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 04 [2-3] 04 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x04],
        &[0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 04 [2-3] 04 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04],
        &[0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 04 [2-3] 04 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04],
        &[0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 04 [2-3] 04 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x04, 0x04, 0x04],
        &[0x01, 0x02, 0xFF, 0x03, 0x04, 0x04, 0x04, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [0-2] 03 [0-2] 04 [2-3] 04 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0xFF, 0x04, 0x04, 0x04, 0x04],
        &[0x01, 0x02, 0xFF, 0x03, 0xFF, 0x04, 0x04, 0x04, 0x04]
    );

    pattern_false!(
        r#"{ 01 02 [0-2] 03 [0-2] 04 [2-3] 04 }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0xFF, 0xFF, 0xFF, 0x04, 0x04, 0x04, 0x04]
    );

    pattern_match!(
        r#"{ 01 [-] [4-] [-] 02 }"#,
        &[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x02],
        &[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]
    );

    pattern_false!(
        r#"{ 01 [-] [5-] [-] 02 }"#,
        &[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]
    );

    pattern_false!(r#"{ 03 04 [-] 01 02 }"#, &[0x01, 0x02, 0x03, 0x04]);
    pattern_false!(r#"{ 01 02 [2-] 03 04 }"#, &[0x01, 0x02, 0xFF, 0x03, 0x04]);

    pattern_false!(
        r#"{ 01 03 03 [1-3] 03 04 05 06 07 }"#,
        &[0x01, 0x03, 0x03, 0x03, 0x04, 0x05, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ 01 02 ~03 04 05 }"#,
        &[0x01, 0x02, 0xFF, 0x04, 0x05],
        &[0x01, 0x02, 0xFF, 0x04, 0x05]
    );

    pattern_match!(
        r#"{ (01 02 ~03 04 05 | 01 02 ~00 04 05) }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        &[0x01, 0x02, 0x03, 0x04, 0x05]
    );

    pattern_match!(
        r#"{ 01 02 ~?2 04 05 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        &[0x01, 0x02, 0x03, 0x04, 0x05]
    );

    pattern_match!(
        r#"{ 01 02 ~2? 04 05 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        &[0x01, 0x02, 0x03, 0x04, 0x05]
    );

    pattern_false!(r#"{ 01 02 ~03 04 05 }"#, &[0x01, 0x02, 0x03, 0x04, 0x05]);
    pattern_false!(r#"{ 01 02 ~?3 04 05 }"#, &[0x01, 0x02, 0x03, 0x04, 0x05]);
    pattern_false!(r#"{ 01 02 ~2? 04 05 }"#, &[0x01, 0x02, 0x20, 0x04, 0x05]);

    pattern_match!(
        r#"{ (01 02 ~0? 04 05 | 01 02 ~?2 04 05) }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        &[0x01, 0x02, 0x03, 0x04, 0x05]
    );

    pattern_match!(
        r#"{ (01|11) (02|12) (03|13) (04|14) (05|15) (06|16) (07|17) }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
    );

    pattern_match!(
        r#"{ (01|11) (02|12) (03|13) (04|14) (05|15) (06|16) (07|17) }"#,
        &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
        &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]
    );

    pattern_match!(
        r#"{ (01|11) (02|12) (03|13) (04|14) (05|15) (06|16) (07|17) }"#,
        &[0x01, 0x12, 0x03, 0x14, 0x05, 0x16, 0x07],
        &[0x01, 0x12, 0x03, 0x14, 0x05, 0x16, 0x07]
    );

    pattern_match!(
        r#"{ (01 02 | 11 12) (03 04 | 13 14) (05 06 | 15 16) }"#,
        &[0x01, 0x02, 0x13, 0x14, 0x05, 0x06],
        &[0x01, 0x02, 0x13, 0x14, 0x05, 0x06]
    );

    pattern_match!(
        r#"{ (01 02 | 11 12) (03 04 | 13 14) (05 06 | 15 16) 07 08 09 }"#,
        &[0x01, 0x02, 0x13, 0x14, 0x05, 0x06, 0x07, 0x08, 0x09],
        &[0x01, 0x02, 0x13, 0x14, 0x05, 0x06, 0x07, 0x08, 0x09]
    );

    pattern_match!(
        r#"{ 01 02 (03 04 | FF FF) (05 06 | FF FF) 07 08 09 }"#,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
    );

    pattern_match!(
        r#"{ 01 02 (03 04 | FF FF) (05 06 | FF FF) 07 08 09 }"#,
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x08, 0x09],
        &[0x01, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x08, 0x09]
    );

    pattern_match!(
        r#"{ 01 02 (0? | 1? | 2?) 03 04 }"#,
        &[0x01, 0x02, 0x0F, 0x03, 0x04],
        &[0x01, 0x02, 0x0F, 0x03, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 (0? | 1? | 2?) 03 04 }"#,
        &[0x01, 0x02, 0x1F, 0x03, 0x04],
        &[0x01, 0x02, 0x1F, 0x03, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 (0? | 1? | 2?) 03 04 }"#,
        &[0x01, 0x02, 0x0F, 0x03, 0x04],
        &[0x01, 0x02, 0x0F, 0x03, 0x04]
    );

    pattern_match!(
        r#"{ 01 02 [0-4] 03 ( 1? | 2? | 3? ) }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x11],
        &[0x01, 0x02, 0xFF, 0x03, 0x11]
    );

    pattern_match!(
        r#"{ 01 02 [0-4] 03 ( 1? | 2? | 3? ) }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x22],
        &[0x01, 0x02, 0xFF, 0x03, 0x22]
    );

    pattern_match!(
        r#"{ 01 02 [0-4] 03 ( 1? | 2? | 3? ) }"#,
        &[0x01, 0x02, 0xFF, 0x03, 0x33],
        &[0x01, 0x02, 0xFF, 0x03, 0x33]
    );

    pattern_match!(
        r#"{ 01 ?? 2? 3? }"#,
        &[0x01, 0xFF, 0x22, 0x33],
        &[0x01, 0xFF, 0x22, 0x33]
    );

    pattern_match!(
        r#"{ E8 ?? ?? [1-512] (AA | BB B?) 01 02 03 04 }"#,
        &[0xE8, 0xFF, 0xFF, 0xFF, 0xBB, 0xB1, 0x01, 0x02, 0x03, 0x04],
        &[0xE8, 0xFF, 0xFF, 0xFF, 0xBB, 0xB1, 0x01, 0x02, 0x03, 0x04]
    );

    pattern_match!(
        r#"{ E8 ?? ?? [1-512] (AA | BB B?) 01 02 03 04 }"#,
        &[0xE8, 0xFF, 0xFF, 0xFF, 0xAA, 0x01, 0x02, 0x03, 0x04],
        &[0xE8, 0xFF, 0xFF, 0xFF, 0xAA, 0x01, 0x02, 0x03, 0x04]
    );
}

#[test]
fn regexp_patterns_1() {
    pattern_match!(r#"/abc/"#, b"abc", b"abc");
    pattern_false!(r#"/abc/"#, b"xbc");
    pattern_match!(r#"/abc/"#, b"xabcx", b"abc");
    pattern_match!(r#"/abc/"#, b"ababc", b"abc");
    pattern_match!(r#"/a.c/"#, b"abc", b"abc");
    pattern_false!(r#"/a.{4,5}b/"#, b"acc\nccb");
    pattern_match!(r#"/a.b/"#, b"a\rb", b"a\rb");
    pattern_match!(r#"/ab*c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab*c/"#, b"ac", b"ac");
    pattern_match!(r#"/ab*bc/"#, b"abc", b"abc");
    pattern_match!(r#"/ab*bc/"#, b"abbc", b"abbc");
    pattern_match!(r#"/a.*bb/"#, b"abbbb", b"abbbb");
    pattern_match!(r#"/a.*?bbb/"#, b"abbbbbb", b"abbb");
    pattern_match!(r#"/a.*c/"#, b"ac", b"ac");
    pattern_match!(r#"/a.*c/"#, b"axyzc", b"axyzc");
    pattern_match!(r#"/ab+c/"#, b"abbc", b"abbc");
    pattern_false!(r#"/ab+c/"#, b"ac");
    pattern_match!(r#"/ab+/"#, b"abbbb", b"abbbb");
    pattern_match!(r#"/ab+?/"#, b"abbbb", b"ab");
    pattern_false!(r#"/ab+bc/"#, b"abc");
    pattern_false!(r#"/ab+bc/"#, b"abq");
    pattern_match!(r#"/a+b+c/"#, b"aabbabc", b"abc");
    pattern_false!(r#"/ab?bc/"#, b"abbbbc");
    pattern_match!(r#"/ab?c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab?c/"#, b"ac", b"ac");
    pattern_match!(r#"/ab*?/"#, b"abbb", b"a");
    pattern_match!(r#"/ab??/"#, b"ab", b"a");
    pattern_match!(r#"/a(b|x)c/"#, b"abc", b"abc");
    pattern_match!(r#"/a(b|x)c/"#, b"axc", b"axc");
    pattern_match!(r#"/a(b|.)c/"#, b"axc", b"axc");
    pattern_match!(r#"/a(b|x|y)c/"#, b"ayc", b"ayc");
    pattern_match!(r#"/(a+|b)*/"#, b"a", b"a");
    pattern_match!(r#"/(a+|b)*/"#, b"aa", b"aa");
    pattern_match!(r#"/(a+|b)*/"#, b"ab", b"ab");
    pattern_match!(r#"/(a+|b)*/"#, b"aab", b"aab");
    pattern_match!(r#"/a|b|c|d|e/"#, b"e", b"e");
    pattern_match!(r#"/(a|b|c|d|e)f/"#, b"ef", b"ef");
    pattern_match!(r#"/a|b/"#, b"a", b"a");

    pattern_match!(r#"/abcd.*ef/"#, b"abcdef", b"abcdef");
    pattern_match!(r#"/ab.*cdef/"#, b"abcdef", b"abcdef");
    pattern_match!(r#"/abcd.*ef/"#, b"abcdxef", b"abcdxef");
    pattern_match!(r#"/ab.*cdef/"#, b"abxcdef", b"abxcdef");
    pattern_false!(r#"/abcd.*ef/"#, b"abcd\nef");
    pattern_false!(r#"/ab.*cdef/"#, b"ab\ncdef");
    pattern_false!(r#"/abcd.{3}aaa/"#, b"abcd\naaaaaa");
    pattern_false!(r#"/ab.{3}aaa/"#, b"ab\naaaaaa");
    pattern_match!(r#"/abcd.*ef/s"#, b"abcd\nef", b"abcd\nef");
    pattern_match!(r#"/ab.*cdef/s"#, b"ab\ncdef", b"ab\ncdef");
    pattern_match!(r#"/abcd.{3}aaa/s"#, b"abcd\naaaaaaaaa", b"abcd\naaaaa");
    pattern_match!(r#"/ab.{3}aaa/s"#, b"ab\naaaaaaaaa", b"ab\naaaaa");
    pattern_false!(r#"/abcd.{1,2}ef/"#, b"abcdef");
    pattern_false!(r#"/ab.{1,2}cdef/"#, b"abcdef");
    pattern_match!(r#"/abcd.{1,2}ef/"#, b"abcdxef", b"abcdxef");
    pattern_match!(r#"/ab.{1,2}cdef/"#, b"abxcdef", b"abxcdef");

    // TODO: known issue related to exact atoms. The matching string
    // should be "abbb" and not "abb".
    pattern_match!(r#"/a(bb|b)b/"#, b"abbbbbbbb", b"abb");
    pattern_match!(r#"/a(b|bb)b/"#, b"abbbbbbbb", b"abb");

    pattern_match!(
        r#"/the (caterpillar|cat)/"#,
        b"the caterpillar",
        b"the caterpillar"
    );

    pattern_match!(
        r#"/the (cat|caterpillar)/"#,
        b"the caterpillar",
        b"the cat"
    );
}

#[test]
fn regexp_patterns_2() {
    pattern_match!(r#"/.b{2}/"#, b"abb", b"abb");
    pattern_match!(r#"/.b{2,3}/"#, b"abb", b"abb");
    pattern_match!(r#"/.b{2,3}/"#, b"abbb", b"abbb");
    pattern_match!(r#"/.b{2,3}?/"#, b"abbb", b"abb");
    pattern_match!(r#"/ab{2,3}?c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/.b{2,3}cccc/"#, b"abbbcccc", b"abbbcccc");
    pattern_match!(r#"/.b{2,3}?cccc/"#, b"abbbcccc", b"abbbcccc");
    pattern_match!(r#"/a.b{2,3}cccc/"#, b"aabbbcccc", b"aabbbcccc");
    pattern_match!(r#"/ab{2,3}c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/ab{2,3}?c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/ab{0,1}?c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab{,1}?c/"#, b"abc", b"abc");
    pattern_match!(r#"/a{0,1}bc/"#, b"bbc", b"bc");
    pattern_match!(r#"/ab{0,}c/"#, b"ac", b"ac");
    pattern_match!(r#"/ab{0,}c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab{0,}c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/a{0,1}?bc/"#, b"abc", b"abc");
    pattern_match!(r#"/a{0,1}?bc/"#, b"bc", b"bc");
    pattern_match!(r#"/aa{0,1}?bc/"#, b"abc", b"abc");
    pattern_match!(r#"/aa{0,1}bc/"#, b"abc", b"abc");
    pattern_match!(r#"/ab{1}c/"#, b"abc", b"abc");
    pattern_false!(r#"/ab{1}c/"#, b"abbc");
    pattern_false!(r#"/ab{1}c/"#, b"ac");
    pattern_match!(r#"/ab{1,2}c/"#, b"abbc", b"abbc");
    pattern_false!(r#"/ab{1,2}c/"#, b"abbbc");
    pattern_match!(r#"/ab{1,}c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/ab{4,}c/"#, b"abbbbc", b"abbbbc");
    pattern_match!(r#"/ab{4,}?c/"#, b"abbbbc", b"abbbbc");
    pattern_false!(r#"/ab{1,}b/"#, b"ab");
    pattern_match!(r#"/ab{1,1}c/"#, b"abc", b"abc");
    pattern_match!(r#"/ab{0,3}c/"#, b"abbbc", b"abbbc");
    pattern_match!(r#"/ab{,3}c/"#, b"abbbc", b"abbbc");
    pattern_false!(r#"/ab{0,2}c/"#, b"abbbc");
    pattern_false!(r#"/ab{,2}c/"#, b"abbbc");
    pattern_false!(r#"/ab{4,5}c/"#, b"abbbc");
    pattern_false!(r#"/ab{3}c/"#, b"abbbbc");
    pattern_false!(r#"/ab{4}c/"#, b"abbbbbc");
    pattern_false!(r#"/ab{5}c/"#, b"abbbbbbc");
    pattern_match!(r#"/ab{0,1}/"#, b"abbbbb", b"ab");
    pattern_match!(r#"/ab{0,2}/"#, b"abbbbb", b"abb");
    pattern_match!(r#"/ab{0,3}/"#, b"abbbbb", b"abbb");
    pattern_match!(r#"/ab{0,4}/"#, b"abbbbb", b"abbbb");
    pattern_match!(r#"/ab{1,1}/"#, b"abbbbb", b"ab");
    pattern_match!(r#"/ab{1,2}/"#, b"abbbbb", b"abb");
    pattern_match!(r#"/ab{1,3}/"#, b"abbbbb", b"abbb");
    pattern_match!(r#"/ab{2,2}/"#, b"abbbbb", b"abb");
    pattern_match!(r#"/ab{2,3}/"#, b"abbbbb", b"abbb");
    pattern_match!(r#"/ab{2,4}/"#, b"abbbbc", b"abbbb");
    pattern_match!(r#"/ab{3,4}/"#, b"abbb", b"abbb");
    pattern_match!(r#"/ab{3,5}/"#, b"abbbbb", b"abbbbb");
    pattern_false!(r#"/ab{3,4}c/"#, b"abbbbbc");
    pattern_false!(r#"/ab{3,4}c/"#, b"abbc");
    pattern_false!(r#"/ab{3,5}c/"#, b"abbbbbbc");
    pattern_match!(r#"/ab{1,3}?/"#, b"abbbbb", b"ab");
    pattern_match!(r#"/ab{0,1}?/"#, b"abbbbb", b"a");
    pattern_match!(r#"/ab{0,2}?/"#, b"abbbbb", b"a");
    pattern_match!(r#"/ab{0,3}?/"#, b"abbbbb", b"a");
    pattern_match!(r#"/ab{0,4}?/"#, b"abbbbb", b"a");
    pattern_match!(r#"/ab{1,1}?/"#, b"abbbbb", b"ab");
    pattern_match!(r#"/ab{1,2}?/"#, b"abbbbb", b"ab");
    pattern_match!(r#"/ab{1,3}?/"#, b"abbbbb", b"ab");
    pattern_match!(r#"/ab{2,2}?/"#, b"abbbbb", b"abb");
    pattern_match!(r#"/ab{2,3}?/"#, b"abbbbb", b"abb");
    pattern_match!(r#"/(a{2,3}b){2,3}/"#, b"aabaaabaab", b"aabaaabaab");
    pattern_match!(r#"/(a{2,3}?b){2,3}?/"#, b"aabaaabaab", b"aabaaab");
    pattern_match!(
        r#"/(a{4,5}b){4,5}/"#,
        b"aaaabaaaabaaaaabaaaaab",
        b"aaaabaaaabaaaaabaaaaab"
    );
    pattern_false!(r#"/(a{4,5}b){4,5}/"#, b"aaaabaaaabaaaaab");
    pattern_match!(r#"/.(abc){0,1}/"#, b"xabcabcabcabc", b"xabc");
    pattern_match!(r#"/.(abc){0,2}/"#, b"xabcabcabcabc", b"xabcabc");
    pattern_match!(r#"/x{1,2}abcd/"#, b"xxxxabcd", b"xxabcd");
    pattern_match!(r#"/x{1,2}abcd/"#, b"xxxxabcd", b"xxabcd");
    // TODO
    //pattern_match!(r#"/ab{.*}/"#, b"ab{c}", b"ab{c}");
    pattern_match!(r#"/.(aa){1,2}/"#, b"aaaaaaaaaa", b"aaaaa");
    pattern_match!(r#"/a.(bc.){2}/"#, b"aabcabca", b"aabcabca");
    pattern_match!(r#"/(ab{1,2}c){1,3}/"#, b"abbcabc", b"abbcabc");
    pattern_match!(r#"/ab(c|cc){1,3}d/"#, b"abccccccd", b"abccccccd");
    pattern_match!(r#"/abc.{0,3}def/s"#, b"abcdef", b"abcdef");
    pattern_match!(r#"/ab.{0,3}cdef/s"#, b"abcdef", b"abcdef");
    pattern_match!(r#"/abc.{1,3}def/s"#, b"abcxdef", b"abcxdef");
    pattern_match!(r#"/ab.{1,3}cdef/s"#, b"abxcdef", b"abxcdef");
    pattern_match!(r#"/abc.{0,3}ddd/s"#, b"abcdddddd", b"abcdddddd");
    pattern_false!(r#"/abc.{1,3}def/s"#, b"abcxxxxdef");
    pattern_false!(r#"/ab.{1,3}cdef/s"#, b"abxxxxcdef");
    pattern_match!(r#"/abc.*ddd/s"#, b"abcdddddd", b"abcdddddd");
    pattern_match!(r#"/abc.*?ddd/s"#, b"abcdddddd", b"abcddd");
    pattern_match!(r#"/abc.*ddd/s"#, b"abcabcdddddd", b"abcabcdddddd");
}

#[test]
fn regexp_patterns_3() {
    pattern_match!(r#"/a[bx]c/"#, b"abc", b"abc");
    pattern_match!(r#"/a[bx]c/"#, b"axc", b"axc");
    pattern_match!(r#"/a[0-9]*b/"#, b"ab", b"ab");
    pattern_match!(r#"/a[0-9]*b/"#, b"a0123456789b", b"a0123456789b");
    pattern_match!(r#"/[0-9a-f]+/"#, b"0123456789abcdef", b"0123456789abcdef");
    pattern_match!(r#"/[0-9a-f]+/"#, b"xyz0123456789xyz", b"0123456789");
    pattern_false!(r#"/[x-z]+/"#, b"abc");
    pattern_match!(r#"/[a-z]{1,2}ab/"#, b"xyab", b"xyab");
    pattern_match!(r#"/[a-z]{1,2}ab/"#, b"xyzab", b"yzab");
    pattern_match!(r#"/a[-]?c/"#, b"ac", b"ac");
    pattern_match!(r#"/a[-b]/"#, b"a-", b"a-");
    pattern_match!(r#"/a[-b]/"#, b"ab", b"ab");
    pattern_match!(r#"/a[b-]/"#, b"a-", b"a-");
    pattern_match!(r#"/a[b-]/"#, b"ab", b"ab");
    pattern_match!(r#"/[a-c-e]/"#, b"b", b"b");
    pattern_match!(r#"/[a-c-e]/"#, b"-", b"-");
    pattern_false!(r#"/[a-c-e]/"#, b"d");
    pattern_match!(r#"/a[\-b]/"#, b"a-", b"a-");
    pattern_match!(r#"/a[\-b]/"#, b"ab", b"ab");
    pattern_match!(r#"/a]/"#, b"a]", b"a]");
    pattern_match!(r#"/a[]]b/"#, b"a]b", b"a]b");
    pattern_match!(r#"/[a-z]-b/"#, b"c-b-c", b"c-b");
    pattern_match!(r#"/a[]-]b/"#, b"a]b", b"a]b");
    pattern_match!(r#"/a[]-]b/"#, b"a-b", b"a-b");
    pattern_match!(r#"/[\.-z]*/"#, b"...abc", b"...abc");
    pattern_match!(r#"/[\.-]*/"#, b"...abc", b"...");
    pattern_match!(r#"/a[\]]b/"#, b"a]b", b"a]b");
    pattern_match!(r#"/a[^bc]d/"#, b"aed", b"aed");
    pattern_false!(r#"/a[^bc]d/"#, b"abd");
    pattern_match!(r#"/a[^-b]c/"#, b"adc", b"adc");
    pattern_false!(r#"/a[^-b]c/"#, b"a-c");
    pattern_false!(r#"/a[^]b]c/"#, b"a]c");
    pattern_match!(r#"/a[^]b]c/"#, b"adc", b"adc");
    pattern_match!(r#"/[^ab]*/"#, b"cde", b"cde");
    pattern_match!(r#"/a[\s]b/"#, b"a b", b"a b");
    pattern_false!(r#"/a[\S]b/"#, b"a b");
    pattern_match!(r#"/a[\d]b/"#, b"a1b", b"a1b");
    pattern_false!(r#"/a[\D]b/"#, b"a1b");
    pattern_match!(r#"/a\sb/"#, b"a b", b"a b");
    pattern_match!(r#"/a\sb/"#, b"a\tb", b"a\tb");
    pattern_match!(r#"/a\sb/"#, b"a\rb", b"a\rb");
    pattern_match!(r#"/a\sb/"#, b"a\nb", b"a\nb");
    pattern_match!(r#"/a\sb/"#, b"a\x0bb", b"a\x0bb");
    pattern_match!(r#"/a\sb/"#, b"a\x0cb", b"a\x0cb");
    pattern_false!(r#"/a\Sb/"#, b"a b");
    pattern_false!(r#"/a\Sb/"#, b"a\tb");
    pattern_false!(r#"/a\Sb/"#, b"a\rb");
    pattern_false!(r#"/a\Sb/"#, b"a\nb");
    pattern_false!(r#"/a\Sb/"#, b"a\x0bb");
    pattern_false!(r#"/a\Sb/"#, b"a\x0cb");
    pattern_match!(r#"/a[\s]*b/"#, b"a \t\r\n\x0b\x0cb", b"a \t\r\n\x0b\x0cb");
    pattern_match!(
        r#"/a[^\S]*b/"#,
        b"a \t\r\n\x0b\x0cb",
        b"a \t\r\n\x0b\x0cb"
    );
    pattern_match!(r#"/foo[^\s]*/"#, b"foobar\n", b"foobar");
    pattern_match!(r#"/foo[^\s]*/"#, b"foobar\r\n", b"foobar");
    pattern_match!(r#"/\n\r\t\f\a/"#, b"\n\r\t\x0c\x07", b"\n\r\t\x0c\x07");
    pattern_match!(
        r#"/[\n][\r][\t][\f][\a]/"#,
        b"\n\r\t\x0c\x07",
        b"\n\r\t\x0c\x07"
    );
    pattern_match!(r#"/\x01\x02\x03/"#, b"\x01\x02\x03", b"\x01\x02\x03");
    pattern_match!(r#"/[\x01-\x03]+/"#, b"\x01\x02\x03", b"\x01\x02\x03");
    pattern_false!(r#"/[\x00-\x02]+/"#, b"\x03\x04\x05");
    pattern_match!(r#"/[\x5D]/"#, b"]", b"]");
    pattern_match!(r#"/a\wc/"#, b"abc", b"abc");
    pattern_match!(r#"/a\wc/"#, b"a_c", b"a_c");
    pattern_match!(r#"/a\wc/"#, b"a0c", b"a0c");
    pattern_false!(r#"/a\wc/"#, b"a*c");
    pattern_match!(r#"/\w+/"#, b"--ab_cd0123--", b"ab_cd0123");
    pattern_match!(r#"/[\w]+/"#, b"--ab_cd0123--", b"ab_cd0123");
    pattern_match!(r#"/\D+/"#, b"1234abc5678", b"abc");
    pattern_match!(r#"/[\d]+/"#, b"0123456789", b"0123456789");
    pattern_match!(r#"/[\D]+/"#, b"1234abc5678", b"abc");
    pattern_match!(r#"/[\da-fA-F]+/"#, b"123abcDEF", b"123abcDEF");
    pattern_match!(r#"/(abc|)ef/"#, b"abcdef", b"ef");
    pattern_match!(r#"/(abc|)ef/"#, b"abcef", b"abcef");
    pattern_match!(r#"/(abc|)ef/"#, b"abcef", b"abcef");
    pattern_match!(r#"/(|abc)ef/"#, b"abcef", b"abcef");
    pattern_match!(r#"/((a)(b)c)(d)/"#, b"abcd", b"abcd");
    pattern_match!(r#"/(a|b)c*d/"#, b"abcd", b"bcd");
    pattern_match!(r#"/(ab|ab*)bc/"#, b"abc", b"abc");
    pattern_match!(r#"/a([bc]*)c*/"#, b"abc", b"abc");
    pattern_match!(r#"/a([bc]*)c*/"#, b"ac", b"ac");
    pattern_match!(r#"/a([bc]*)c*/"#, b"a", b"a");
    pattern_match!(r#"/a([bc]*)(c*d)/"#, b"abcd", b"abcd");
    pattern_match!(r#"/a([bc]+)(c*d)/"#, b"abcd", b"abcd");
    pattern_match!(r#"/a([bc]*)(c+d)/"#, b"abcd", b"abcd");
    pattern_match!(r#"/a[bcd]*dcdcde/"#, b"adcdcde", b"adcdcde");
    pattern_false!(r#"/a[bcd]+dcdcde/"#, b"adcdcde");
    pattern_match!(r#"/\((.*), (.*)\)/"#, b"(a, b)", b"(a, b)");
    pattern_match!(r#"/whatever|   x.   x/"#, b"   xy   x", b"   xy   x");
    pattern_match!(r#"/^abc/"#, b"abc", b"abc");
    pattern_match!(r#"/^abc/"#, b"abcd", b"abc");
    pattern_false!(r#"/abc^/"#, b"abc");
    pattern_false!(r#"/ab^c/"#, b"abc");
    pattern_false!(r#"/a^bcdef/"#, b"abcdef");
    pattern_false!(r#"/^(ab|cd)e/"#, b"abcde");
    pattern_match!(r#"/abc|^123/"#, b"123", b"123");
    pattern_false!(r#"/abc|^123/"#, b"x123");
    pattern_match!(r#"/abc|123$/"#, b"abcx", b"abc");
    pattern_false!(r#"/abc|123$/"#, b"123x");
    pattern_match!(r#"/^abc$/"#, b"abc", b"abc");
    pattern_false!(r#"/^abc$/"#, b"abcc");
    pattern_match!(r#"/abc$/"#, b"aabc", b"abc");
    pattern_false!(r#"/$abc/"#, b"abc");
    pattern_match!(r#"/(a|a$)bcd/"#, b"abcd", b"abcd");
    pattern_false!(r#"/(a$|a$)bcd/"#, b"abcd");
    pattern_false!(r#"/(abc$|ab$)/"#, b"abcd");
    pattern_match!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"effgz", b"effgz");
    pattern_match!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"ij", b"ij");
    pattern_false!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"effg");
    pattern_false!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"bcdd");
    pattern_match!(r#"/(bc+d$|ef*g.|h?i(j|k))/"#, b"reffgz", b"effgz");
    pattern_match!(r#"/\babc/"#, b"abc", b"abc");
    pattern_match!(r#"/abc\b/"#, b"abc", b"abc");
    pattern_false!(r#"/\babc/"#, b"1abc");
    pattern_false!(r#"/abc\b/"#, b"abc1");
    pattern_match!(r#"/abc\s\b/"#, b"abc x", b"abc ");
    pattern_false!(r#"/abc\s\b/"#, b"abc  ");
    pattern_match!(r#"/\babc\b/"#, b" abc ", b"abc");
    pattern_match!(r#"/\b\w\w\w\b/"#, b" abc ", b"abc");
    pattern_match!(r#"/\w\w\w\b/"#, b"abcd", b"bcd");
    pattern_match!(r#"/\b\w\w\w/"#, b"abcd", b"abc");
    pattern_false!(r#"/\b\w\w\w\b/"#, b"abcd");
    pattern_false!(r#"/\Babc/"#, b"abc");
    pattern_false!(r#"/abc\B/"#, b"abc");
    pattern_match!(r#"/\Babc/"#, b"1abc", b"abc");
    pattern_match!(r#"/abc\B/"#, b"abc1", b"abc");
    pattern_false!(r#"/abc\s\B/"#, b"abc x");
    pattern_match!(r#"/abc\s\B/"#, b"abc  ", b"abc ");
    pattern_match!(r#"/\w\w\w\B/"#, b"abcd", b"abc");
    pattern_match!(r#"/\B\w\w\w/"#, b"abcd", b"bcd");
    pattern_false!(r#"/\B\w\w\w\B/"#, b"abcd");
    pattern_false!(r#"/a.b/"#, b"a\nb");
    pattern_false!(r#"/a.*b/"#, b"acc\nccb");
    pattern_match!(r#"/foo/"#, b"foo", b"foo");
    pattern_match!(r#"/bar/i"#, b"bar", b"bar");

    pattern_match!(r#"/foo|bar|baz/"#, b"foo", b"foo");
    pattern_match!(r#"/foo|bar|baz/"#, b"bar", b"bar");
    pattern_match!(r#"/foo|bar|baz/"#, b"baz", b"baz");
    pattern_true!(r#"/(foo|bar|baz)/"#, b"foo");

    pattern_false!(r#"/foo|bar|baz/"#, b"FOO");
    pattern_false!(r#"/foo|bar|baz/"#, b"BAR");
    pattern_false!(r#"/foo|bar|baz/"#, b"BAZ");

    pattern_match!(r#"/foo|bar|baz/i"#, b"foo", b"foo");
    pattern_match!(r#"/foo|bar|baz/i"#, b"bar", b"bar");
    pattern_match!(r#"/foo|bar|baz/i"#, b"baz", b"baz");

    pattern_match!(r#"/foo|bar|baz/i"#, b"FOO", b"FOO");
    pattern_match!(r#"/foo|bar|baz/i"#, b"BAR", b"BAR");
    pattern_match!(r#"/foo|bar|baz/i"#, b"BAZ", b"BAZ");

    pattern_match!(r#"/foo\x01bar/"#, b"foo\x01bar", b"foo\x01bar");

    /*
    TODO: YARA accepts unicode characters in regexps but regexp_syntax either
    accepts unicode characters or escape sequences like \x01, but not both
    at the same time. Presumably this is because with escape sequence you can't
    create non-valid unicode codepoints, so when you enable unicode it disables
    escape sequences.
    pattern_true!(
        r#"/🙈🙉🙊/i"#,
        b"\xF0\x9F\x99\x88\xF0\x9F\x99\x89\xF0\x9F\x99\x8A"
    );
    */
}

#[test]
fn regexp_patterns_4() {
    rule_true!(
        r#"rule test {
            strings:
                $a = /a{1,}/
            condition:
                #a == 5
        }"#,
        b"aaaaa"
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = /.b{2,3}?cccc/

            condition:
                #a == 2 and
                @a[1] == 0 and
                @a[2] == 1
        }"#,
        b"abbbcccc"
    );
}

#[test]
fn regexp_nocase() {
    pattern_match!(r#"/abc/ nocase"#, b"ABC", b"ABC");
    pattern_match!(r#"/a[bx]c/ nocase"#, b"ABC", b"ABC");
    pattern_match!(r#"/a[bx]c/ nocase"#, b"AXC", b"AXC");
    pattern_match!(r#"/a[0-9]*b/ nocase"#, b"AB", b"AB");
    pattern_match!(r#"/[a-z]+/ nocase"#, b"AbC", b"AbC");
    pattern_match!(r#"/(abc|xyz)+/ nocase"#, b"AbCxYz", b"AbCxYz");
    pattern_match!(r#"/(a|x)bc/ nocase"#, b"ABC", b"ABC");
    pattern_match!(r#"/(a|x)bc/ nocase"#, b"XBC", b"XBC");
    pattern_match!(r#"/abc[^d]/ nocase"#, b"abce", b"abce");
    pattern_match!(r#"/abc[^d]/ nocase"#, b"ABCE", b"ABCE");
    pattern_false!(r#"/abc[^d]/ nocase"#, b"abcd");
    pattern_false!(r#"/abc[^d]/ nocase"#, b"ABCD");
}

#[test]
fn regexp_wide() {
    pattern_match!(r#"/foo(a|b)/ wide"#, b"f\0o\0o\0b\0", b"f\0o\0o\0b\0");
    pattern_match!(r#"/bar/ wide"#, b"b\0a\0r\0", b"b\0a\0r\0");
    pattern_false!(r#"/bar/ wide"#, b"bar");
    pattern_match!(r#"/foo.*?bar/s ascii wide nocase"#, b"FOOBAR", b"FOOBAR");
    pattern_match!(r#"/foo.*?bar/s ascii wide nocase"#, b"foobar", b"foobar");

    pattern_match!(
        r#"/foo.*?bar/s wide"#,
        b"f\0o\0o\0b\0a\0r\0",
        b"f\0o\0o\0b\0a\0r\0"
    );

    pattern_match!(
        r#"/fo.bar/ wide"#,
        b"f\0o\0o\0b\0a\0r\0",
        b"f\0o\0o\0b\0a\0r\0"
    );

    pattern_match!(
        r#"/(foo|bar)+/ wide"#,
        b"f\0o\0o\0b\0a\0r\0",
        b"f\0o\0o\0b\0a\0r\0"
    );

    pattern_match!(
        r#"/foo|bar|baz/ wide"#,
        b"f\x00o\x00o\x00",
        b"f\x00o\x00o\x00"
    );

    pattern_match!(
        r#"/foo|bar|baz/ wide"#,
        b"\x00b\x00a\x00r\x00",
        b"b\x00a\x00r\x00"
    );

    pattern_match!(
        r#"/foo|bar|baz/ wide"#,
        b"b\x00a\x00z\x00",
        b"b\x00a\x00z\x00"
    );

    pattern_match!(
        r#"/bar/ wide nocase"#,
        b"B\x00A\x00R\x00",
        b"B\x00A\x00R\x00"
    );

    pattern_match!(
        r#"/foo.*?bar/s ascii wide nocase"#,
        b"F\x00O\x00O\x00B\x00A\x00R\x00",
        b"F\x00O\x00O\x00B\x00A\x00R\x00"
    );
    pattern_match!(
        r#"/foo.*?bar/s ascii wide nocase"#,
        b"f\x00o\x00o\x00b\x00a\x00r\x00",
        b"f\x00o\x00o\x00b\x00a\x00r\x00"
    );

    pattern_match!(
        r#"/foo.*?bar/s wide nocase"#,
        b"F\x00O\x00O\x00B\x00A\x00R\x00",
        b"F\x00O\x00O\x00B\x00A\x00R\x00"
    );

    pattern_match!(
        r#"/foo.*?bar/s ascii wide nocase"#,
        b"F\x00O\x00O\x00B\x00A\x00R\x00",
        b"F\x00O\x00O\x00B\x00A\x00R\x00"
    );

    pattern_match!(
        r#"/foo.*?bar/s wide"#,
        b"f\x00o\x00o\x00b\x00a\x00r\x00",
        b"f\x00o\x00o\x00b\x00a\x00r\x00"
    );

    pattern_match!(
        r#"/foo.{1,3}?bar/s wide"#,
        b"f\x00o\x00o\x00X\x00b\x00a\x00r\x00",
        b"f\x00o\x00o\x00X\x00b\x00a\x00r\x00"
    );

    pattern_match!(
        r#"/fo.{0,3}?bar/s wide"#,
        b"f\x00o\x00b\x00a\x00r\x00",
        b"f\x00o\x00b\x00a\x00r\x00"
    );

    pattern_match!(
        r#"/fo.{0,3}?bar/s wide"#,
        b"f\x00o\x00o\x00b\x00a\x00r\x00",
        b"f\x00o\x00o\x00b\x00a\x00r\x00"
    );

    pattern_match!(
        r#"/fo.{0,3}?bar/s wide"#,
        b"f\x00o\x00o\x00o\x00b\x00a\x00r\x00",
        b"f\x00o\x00o\x00o\x00b\x00a\x00r\x00"
    );
}

#[test]
fn hex_large_jumps() {
    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [-] 62 62 62 62 [-] 63 63 63 63 [-] 64 64 64 64 }
            condition:
                #a == 4 and
                @a[1] == 0x4 and !a[1] == 0x604 and
                @a[2] == 0x24 and !a[2] == 0x5e4 and
                @a[3] == 0x44 and !a[3] == 0x5c4 and
                @a[4] == 0x324 and !a[4] == 0x2e4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [0-0x1fc] 62 62 62 62 [0-0x1fc] 63 63 63 63 [0-0x1fc] 64 64 64 64 }
            condition:
                #a == 4 and
                @a[1] == 0x4 and !a[1] == 0x604 and
                @a[2] == 0x24 and !a[2] == 0x5e4 and
                @a[3] == 0x44 and !a[3] == 0x5c4 and
                @a[4] == 0x324 and !a[4] == 0x2e4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [0-0x1dc] 62 62 62 62 [0-0x1fc] 63 63 63 63 [0-0x1fc] 64 64 64 64 }
            condition:
                #a == 3 and
                @a[1] == 0x24 and !a[1] == 0x5e4 and
                @a[2] == 0x44 and !a[2] == 0x5c4 and
                @a[3] == 0x324 and !a[3] == 0x2e4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [0-0x1dc] 62 62 62 62 [0-0x1dc] 63 63 63 63 [0-0x1fc] 64 64 64 64 }
            condition:
                #a == 2 and
                @a[1] == 0x44 and !a[1] == 0x5c4 and
                @a[2] == 0x324 and !a[2] == 0x2e4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [0-0x1bc] 62 62 62 62 [0-0x1fc] 63 63 63 63 [0-0x1fc] 64 64 64 64 }
            condition:
                #a == 2 and
                @a[1] == 0x44 and !a[1] == 0x5c4 and
                @a[2] == 0x324 and !a[2] == 0x2e4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [0-0x1bc] 62 62 62 62 [0x1d-0x1fc] 63 63 63 63 [0-0x1fc] 64 64 64 64 }
            condition:
                #a == 1 and @a[1] == 0x44 and !a[1] == 0x5c4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [0-0x1bc] 62 62 62 62 [0-0x1dc] 63 63 63 63 [0-0x1fc] 64 64 64 64 }
            condition:
                #a == 1 and @a[1] == 0x324 and !a[1] == 0x2e4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = { 61 61 61 61 [-] 00 00 00 00 [-] 63 63 63 63 }
            condition:
                #a == 4 and
                @a[1] == 0x4 and !a[1] == 0x404 and
                @a[2] == 0x24 and !a[2] == 0x3e4 and
                @a[3] == 0x44 and !a[3] == 0x3c4 and
                @a[4] == 0x324 and !a[4] == 0xe4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    pattern_false!(
        "{ 61 61 61 61 [0-0x17b] 62 62 62 62 [-] 63 63 63 63 [-] 64 64 64 64 }",
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
            strings:
                $a = /aaaa.*?bbbb.*?cccc.*?dddd/s
            condition:
                #a == 4 and
                @a[1] == 0x4 and !a[1] == 0x604 and
                @a[2] == 0x24 and !a[2] == 0x5e4 and
                @a[3] == 0x44 and !a[3] == 0x5c4 and
                @a[4] == 0x324 and !a[4] == 0x2e4
        }"#,
        JUMPS_DATA.as_bytes()
    );

    rule_true!(
        r#"rule test {
                strings:
                    $a = /AAAA.*?bbbb.*?CCCC.*?DdDd/si
                condition:
                    #a == 4 and
                    @a[1] == 0x4 and !a[1] == 0x604 and
                    @a[2] == 0x24 and !a[2] == 0x5e4 and
                    @a[3] == 0x44 and !a[3] == 0x5c4 and
                    @a[4] == 0x324 and !a[4] == 0x2e4
            }"#,
        JUMPS_DATA.as_bytes()
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

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
                $b = "bar"
            condition:
                2 of ($a, $b) or $b at 0
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

    #[cfg(feature = "test_proto2-module")]
    rule_false!(
        r#"
        import "test_proto2"

        rule test {
            strings:
                $a = "foo"
            condition:
                $a at test_proto2.add(-1,-1)
        }
        "#,
        b"barfoo"
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

    #[cfg(feature = "test_proto2-module")]
    rule_true!(
        r#"
        import "test_proto2"

        rule test {
            strings:
                $a = "foo"
            condition:
                // Use the `add` function to force negative bounds in a range.
                // We can't use constants as YARA will know that they are
                // negative and raise an error. YARA is not smart enough to
                // realize that the result of `add` is negative.
                $a in (test_proto2.add(-1,0)..0)
        }
        "#,
        b"foobar"
    );

    #[cfg(feature = "test_proto2-module")]
    rule_false!(
        r#"
        import "test_proto2"

        rule test {
            strings:
                $a = "foo"
            condition:
                // Use the `add` function to force negative bounds in a range.
                // We can't use constants as YARA will know that they are
                // negative and raise an error. YARA is not smart enough to
                // realize that the result of `add` is negative.
                $a in (test_proto2.add(-1,-1)..test_proto2.add(-1,0))
        }
        "#,
        b"foobar"
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

    #[cfg(feature = "test_proto2-module")]
    rule_false!(
        r#"
        import "test_proto2"

        rule test {
            strings:
                $a = "aaa"
            condition:
                #a in (0..test_proto2.add(-1,-1)) == 2
        }
        "#,
        b"xxxaaaaa"
    );

    #[cfg(feature = "test_proto2-module")]
    rule_false!(
        r#"
        import "test_proto2"

        rule test {
            strings:
                $a = "aaa"
            condition:
                #a in (test_proto2.add(-1,-1)..5) == 2
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

    rule_true!(
        r#"
        rule test {
            strings:
                $a = "foo"
            condition:
                for any i in (1..#a) : ( @a[i] >= 6 )
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

    pattern_true!(r#"/mississippi/ fullword"#, b"mississippi");
    pattern_true!(r#"/mississippi/ fullword"#, b"mississippi ");
    pattern_true!(r#"/mississippi/ fullword"#, b" mississippi");
    pattern_true!(r#"/mississippi/ fullword"#, b" mississippi ");
    pattern_true!(r#"/mississippi/ fullword"#, b"\x00mississippi\x00");
    pattern_true!(r#"/mississippi/ fullword"#, b"\x01mississippi\x02");
    pattern_true!(r#"/mi.*pi/ fullword"#, b"mississippi");
    pattern_true!(r#"/mi.*pi/ fullword"#, b"mississippi ");
    pattern_true!(r#"/mi.*pi/ fullword"#, b" mississippi");
    pattern_true!(r#"/mi.*pi/ fullword"#, b" mississippi ");
    pattern_true!(r#"/mi.*pi/ fullword"#, b"\x00mississippi\x00");
    pattern_true!(r#"/mi.*pi/ fullword"#, b"\x01mississippi\x02");

    pattern_true!(r#"/mississippi|missouri/ fullword"#, b"mississippi");
    pattern_false!(r#"/mississippi|missouri/ fullword"#, b"xmississippix");
    pattern_false!(r#"/ssissi/ fullword"#, b"mississippi");
    pattern_false!(r#"/ss.ssi/ fullword"#, b"mississippi");

    pattern_true!(r#"/mis.*?ppi/s fullword"#, b"mississippi");
    pattern_true!(r#"/mis.*?ss.*?ppi/s fullword"#, b"x mississippi x");

    pattern_false!(r#"/mis.*?ppi/s fullword"#, b"xmississippi");
    pattern_false!(r#"/mis.*?ppi/s fullword"#, b"mississippix");

    pattern_false!(r#"/miss/ fullword"#, b"mississippi");
    pattern_false!(r#"/issi/ fullword"#, b"mississippi");
    pattern_false!(r#"/issi/ fullword"#, b"mississippi");
    pattern_false!(r#"/miss|ippi/ fullword"#, b"mississippi");

    pattern_true!(r#"/miss|ippi/ fullword"#, b"miss issippi");
    pattern_true!(r#"/miss|ippi/ fullword"#, b"mississ ippi");

    pattern_true!("/^mississippi/ fullword", b"mississippi\tmississippi");

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

    pattern_false!(
        r#"/mis{2}/ wide fullword"#,
        b"m\x00i\x00s\x00s\x00i\x00s\x00s\x00i\x00p\x00p\x00i\x00"
    );

    pattern_false!(
        r#"/ip{2}i/ wide fullword"#,
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

    assert_eq!(
        scanner
            .scan(b"")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );
    assert_eq!(
        scanner
            .scan(b"a")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );
    assert_eq!(
        scanner
            .scan(b"ab")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );
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

    rule_true!(
        r#"
        rule test {
          strings:
            $a = "foo"
            $b = "bar"
          condition:
            for 1 of them : ( # == 2 )
        }
        "#,
        b"foobarbar"
    );

    rule_true!(
        r#"
        rule test {
          strings:
            $a = "foo"
            $b = "bar"
          condition:
            for 1 of them : ( @ > 0 )
        }
        "#,
        b"foobarbar"
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

    rule_true!(
        r#"
        rule test {
          strings:
            $ = "foo"
            $ = "bar"
            $ = "baz"
          condition:
            any of them in (3..3)
        }
        "#,
        b"barbaz"
    );

    rule_true!(
        r#"
        rule test {
          strings:
            $ = "foo"
            $ = "bar"
            $ = "baz"
          condition:
            any of them at 3
        }
        "#,
        b"barbaz"
    );
}

#[test]
fn rule_reuse_1() {
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

    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        9
    );
}

#[test]
fn duplicate_pattern() {
    rule_true!(
        r#"rule test {
            strings:
                $a = "foo"
                $b = "foo"
            condition:
                $a and $b
        }"#,
        b"foo"
    );
}

#[test]
fn rule_reuse_2() {
    let rules = crate::compile(
        r#"
        rule rule_1 {
          condition:
            true
        }
        rule rule_2 {
          condition:
            false
        }
        rule rule_3 {
          condition:
            rule_1 and not rule_2
        }
        "#,
    )
    .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);

    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        2
    );
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
#[cfg(feature = "hash-module")]
fn test_hash_module() {
    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.md5(0, filesize) == "6df23dc03f9b54cc38a0fc1483df6e21" and
            hash.md5(3, 3) == "37b51d194a7513e45b56f6524f2d51f2" and
            hash.md5(0, filesize) == hash.md5("foobarbaz") and
            hash.md5(3, 3) ==  hash.md5("bar")
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.sha1(0, filesize) == "5f5513f8822fdbe5145af33b64d8d970dcf95c6e" and
            hash.sha1(3, 3) == "62cdb7020ff920e5aa642c3d4066950dd1f01f4d" and
            hash.sha1(0, filesize) == hash.sha1("foobarbaz") and
            hash.sha1(3, 3) ==  hash.sha1("bar")
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.sha256(0, filesize) == "97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d" and
            hash.sha256(3, 3) == "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9" and
            hash.sha256(0, filesize) == hash.sha256("foobarbaz") and
            hash.sha256(3, 3) ==  hash.sha256("bar")
        }
        "#,
        b"foobarbaz"
    );
}

#[test]
#[cfg(feature = "macho-module")]
fn test_macho_module() {
    let data: Result<Vec<u8>, Box<dyn std::error::Error>> = create_binary_from_ihex!(
        "src/modules/macho/tests/input/tiny_universal.in"
    );
    let macho_data = data.unwrap();

    let data_additional: Result<Vec<u8>, Box<dyn std::error::Error>> = create_binary_from_ihex!(
        "src/modules/macho/tests/input/macho_x86_64_dylib_file.in"
    );
    let dylib_data = data_additional.unwrap();

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeedface and
            macho.MH_NO_REEXPORTED_DYLIBS == 0x00100000 and
            macho.MH_CIGAM == 0xcefaedfe and
            macho.CPU_TYPE_MIPS == 0x00000008
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeedface and
            macho.MH_NO_REEXPORTED_DYLIBS == 0x00100000 and
            macho.MH_CIGAM == 0xcefaedfe and
            macho.CPU_TYPE_MIPS == 0x00000008
        }
        "#,
        &macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeeeeeee or
            macho.MH_NO_REEXPORTED_DYLIBS == 0x99999999 or
            macho.MH_CIGAM == 0xaaaaaaaa or
            macho.CPU_TYPE_MIPS == 0x00000000
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000007) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x01000007) == 1
        }
        "#,
        &macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000008) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x01000008)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000007, 0x00000003) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(16777223, 2147483651) == 1
        }
        "#,
        &macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000008, 0x00000004) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x00000008, 0x00000004)
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x00000007, 0x00000003)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000007) == 0x00001EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x01000007) == 0x00004EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000007, 0x00000003) == 0x00001EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(16777223, 2147483651) == 0x00004EE0
        }
        "#,
        &macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000008, 0x00000003) == 0x00001EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.entry_point_for_arch(0x00000007, 0x00000003)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
    import "macho"
    rule test {
        condition:
            macho.dylibs[0].timestamp == 1 and
            macho.dylibs[1].timestamp == 2
    }
    "#,
        &dylib_data
    );

    rule_true!(
        r#"
    import "macho"
    rule test {
        condition:
            macho.dylibs[0].compatibility_version == 0 and
            macho.dylibs[1].compatibility_version == 65536
    }
    "#,
        &dylib_data
    );

    rule_true!(
        r#"
    import "macho"
    rule test {
        condition:
            macho.dylibs[0].current_version == 0 and
            macho.dylibs[1].current_version == 79495168
    }
    "#,
        &dylib_data
    );

    rule_true!(
        r#"
    import "macho"
    rule test {
        condition:
            macho.dylibs[0].name == "fact_x86_64.dylib" and 
            macho.dylibs[1].name == "/usr/lib/libSystem.B.dylib"
    }
    "#,
        &dylib_data
    );
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
    condition_true!(r#"test_proto2.Enumeration.ITEM_2 == 0x7fffffffffff"#);
    condition_true!(r#"test_proto2.Enumeration.ITEM_3 == -1"#);

    condition_true!(r#"test_proto2.INLINE_0x1000 == 0x1000"#);

    condition_true!(
        r#"test_proto2.TopLevelEnumeration.ITEM_0x1000 == 0x1000"#
    );

    condition_true!(r#"test_proto2.map_string_int64["one"] == 1"#);
    condition_true!(r#"test_proto2.map_string_float["one"] == 1.0"#);

    condition_true!(r#"test_proto2.map_string_bool["foo"]"#);

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
    condition_true!(r#"test_proto2.map_int64_float[100] == 1000.0"#);

    condition_true!(r#"test_proto2.map_int64_bool[100]"#);

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

#[test]
fn test_modules() {
    // Create goldenfile mint
    let mut mint = Mint::new("src/modules");

    // Get all directories in "src/modules/"
    let module_dirs =
        fs::read_dir("src/modules").expect("Failed to read directory");

    // Iterate over the directories
    for dir in module_dirs {
        let dir = dir.expect("Failed to read directory entry");
        if dir.file_type().expect("Failed to get file type").is_dir() {
            // Get the name of the directory
            let module_name = dir
                .file_name()
                .into_string()
                .expect("Failed to convert OsString");

            // Skip the "protos" directory
            if module_name == "protos" {
                continue;
            }

            // Construct the rule
            let rule = format!(
                r#"
                import "{}"
                rule test {{
                    condition: false
                }}"#,
                module_name
            );

            // Compile the rule
            let rules = crate::compile(rule.as_str()).unwrap();
            let mut scanner = crate::scanner::Scanner::new(&rules);

            // Get all ".in" files in the directory
            let input_files = fs::read_dir(dir.path().join("tests/input"))
                .expect("Failed to read directory");
            for file in input_files {
                let file = file.expect("Failed to read directory entry");
                if file.file_type().expect("Failed to get file type").is_file()
                {
                    let file_path = file.path();
                    if file_path.extension()
                        == Some(Path::new("in").as_os_str())
                    {
                        // Read the ".in" file and create a binary from it
                        let data: Result<Vec<u8>, Box<dyn std::error::Error>> =
                            create_binary_from_ihex!(file_path
                                .to_str()
                                .unwrap());
                        let data = data.unwrap();

                        // Scan the data
                        let scan_results =
                            scanner.scan(&data).expect("scan should not fail");

                        // Get the module output
                        let output = scan_results
                            .module_output(&module_name)
                            .unwrap_or_else(|| {
                                panic!(
                                    "{} should produce some output",
                                    module_name
                                )
                            });

                        // Downcast the output
                        let output: &crate::modules::protos::macho::Macho =
                            <dyn MessageDyn>::downcast_ref(output).unwrap();

                        // Create a Goldenfile test
                        let mut output_file = mint
                            .new_goldenfile(format!(
                                "{}/tests/output/{}.out",
                                module_name,
                                file_path
                                    .file_stem()
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                            ))
                            .unwrap();
                        write!(output_file, "{:#?}", output).unwrap();
                    }
                }
            }
        }
    }
}
