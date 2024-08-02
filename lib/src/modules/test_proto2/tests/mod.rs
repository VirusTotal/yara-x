use crate::tests;
use tests::*;

#[test]
fn test_proto2_module() {
    condition_true!(r#"test_proto2.add(1,2) == 3"#);
    condition_true!(r#"test_proto2.add(1.0,2.0) == 3.0"#);
    condition_true!(r#"test_proto2.nested.nested_func()"#);
    condition_true!(r#"test_proto2.uppercase("foo") == "FOO""#);

    condition_true!(
        r#"test_proto2.uppercase(test_proto2.string_foo) == "FOO""#
    );

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

    condition_true!(r"test_proto2.double_one \ 2 == 0.5");

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

    condition_false!(r#"test_proto2.array_bool[0] == 1"#);
    condition_true!(r#"test_proto2.array_bool[0] == 0"#);
    condition_false!(r#"1 == test_proto2.array_bool[0]"#);
    condition_true!(r#"0 == test_proto2.array_bool[0]"#);

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
        r#"for 1 s in test_proto2.array_struct : (
            s.nested_int32_zero == 0
          )"#
    );

    condition_false!(
        r#"for 3 s in test_proto2.array_struct : (
            s.nested_int32_zero == 0
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
        r#"for 1 key, value in test_proto2.map_int64_int64 : (
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
    // name for YARA was changed to `bool_yara`, with:
    //
    //   [(yara.field_options).name = "bool_yara"];
    //
    condition_true!(r#"test_proto2.bool_yara"#);

    condition_true!(
        r#"
        test_proto2.add(test_proto2.int64_one, test_proto2.int64_one) == 2 and
        test_proto2.add(test_proto2.int64_one, test_proto2.int64_zero) == 1
        "#
    );

    condition_true!(
        r#"
        not test_proto2.nested.nested_method()
        "#
    );

    condition_true!(
        r#"
        not test_proto2.array_struct[0].nested_method()
        "#
    );

    condition_true!(
        r#"
        test_proto2.array_struct[1].nested_method()
        "#
    );

    condition_true!(
        r#"
        test_proto2.NestedProto2.NestedEnumeration.ITEM_1 == 1
        "#
    );
}
