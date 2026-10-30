use std::fs;
use std::io::Write;
use std::mem::size_of;

use pretty_assertions::assert_eq;
use serde_json::json;

use crate::compiler::{IgnoredRuleReason, SubPattern, VarStack, linters};
use crate::errors::{SerializationError, VariableError};
use crate::types::Type;
use crate::{Compiler, Rules, Scanner, SourceCode, compile};

#[test]
fn serialization() {
    assert!(matches!(
        Rules::deserialize([]).err().unwrap(),
        SerializationError::InvalidFormat
    ));

    assert!(matches!(
        Rules::deserialize(b"YARA-X").err().unwrap(),
        SerializationError::InvalidFormat
    ));

    // A valid file starts with `MAGIC` and a version number, but the rest of
    // the content is invalid because it is too short. This must produce a
    // `DecodeError`.
    let mut data = Vec::new();
    data.extend(b"YARA-X\0\0");
    data.extend(10u32.to_le_bytes());
    data.extend(b"foo");

    assert!(matches!(
        Rules::deserialize(&data).err().unwrap(),
        SerializationError::DecodeError(_)
    ));

    // This is a valid file, but with a version number that is not the current
    // one. This must produce an `InvalidVersion` error.
    let mut data = Vec::new();
    data.extend(b"YARA-X\0\0");
    data.extend(0u32.to_le_bytes());
    data.extend(b"foo");

    assert!(matches!(
        Rules::deserialize(&data).err().unwrap(),
        SerializationError::InvalidVersion { expected: _, actual: 0 }
    ));

    // A mismatched rules profiling flag should produce an InvalidWASM error.
    let mut rules = compile(r#"rule test { condition: true }"#).unwrap();
    rules.rules_profiling_enabled = !rules.rules_profiling_enabled;

    let rules_bytes = rules.serialize().unwrap();

    assert!(matches!(
        Rules::deserialize(&rules_bytes).err().unwrap(),
        SerializationError::InvalidWASM(_)
    ));

    let rules = compile(r#"rule test { strings: $a = "foo" condition: $a }"#)
        .unwrap()
        .serialize()
        .unwrap();

    let rules = Rules::deserialize(rules).unwrap();

    let mut scanner = Scanner::new(&rules);
    assert_eq!(
        scanner
            .scan(b"foo")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(size_of::<SubPattern>(), 24);
}

#[test]
fn namespaces() {
    // `foo` and `bar` are both in the default namespace, this compiles
    // correctly.
    let mut compiler = Compiler::new();

    assert!(
        compiler
            .add_source("rule foo {condition: true}")
            .unwrap()
            .add_source("rule bar {condition: foo}")
            .is_ok()
    );

    let mut compiler = Compiler::new();

    // `bar` can't use `foo` because they are in different namespaces, this
    // be a compilation error.
    assert!(
        compiler
            .add_source("rule foo {condition: true}")
            .unwrap()
            .new_namespace("bar")
            .add_source("rule bar {condition: foo}")
            .is_err()
    );

    let mut compiler = Compiler::new();

    // `bar` can use `foo` because they are in the same namespace, the second
    // call to `new_namespace` has no effect.
    assert!(
        compiler
            .new_namespace("foo")
            .add_source("rule foo {condition: true}")
            .unwrap()
            .new_namespace("foo")
            .add_source("rule bar {condition: foo}")
            .is_ok()
    );
}

#[test]
fn var_stack() {
    let mut stack = VarStack::new();

    let mut frame1 = stack.new_frame(4).unwrap();
    let mut frame2 = stack.new_frame(4).unwrap();

    let var = frame1.new_var(Type::Integer);

    assert_eq!(var.ty(), Type::Integer);
    assert_eq!(var.frame_id(), 1);
    assert_eq!(var.index(), 0);

    let var = frame1.new_var(Type::String);

    assert_eq!(var.ty(), Type::String);
    assert_eq!(var.frame_id(), 1);
    assert_eq!(var.index(), 1);

    // The first variable in the second frame goes after the first two
    // variables already allocated in the stack.
    let var = frame2.new_var(Type::Integer);

    assert_eq!(var.ty(), Type::Integer);
    assert_eq!(var.frame_id(), 2);
    assert_eq!(var.index(), 4);

    let var = frame2.new_var(Type::Bool);

    assert_eq!(var.ty(), Type::Bool);
    assert_eq!(var.frame_id(), 2);
    assert_eq!(var.index(), 5);

    stack.unwind(&frame1);

    assert_eq!(stack.used(), 0);
}

#[test]
fn snapshots() {
    let mut compiler = Compiler::new();

    compiler
        .add_source(r#"rule test { strings: $a = "foo" condition: $a }"#)
        .unwrap();
    let snapshot = compiler.take_snapshot();

    compiler
        .add_source(r#"rule test { strings: $a = /{}/ condition: $a }"#)
        .expect_err("compilation should fail");

    assert_eq!(compiler.take_snapshot(), snapshot);

    // `$a` is an anchored literal (added to `anchored_sub_patterns`), while
    // `$b` fails later during regexp compilation because it can match an empty
    // string. Rolling back the failed rule must also roll back
    // `anchored_sub_patterns`.
    compiler
        .add_source(
            r#"rule bad {
                strings:
                    $a = "abcd"
                    $b = /(a|)/
                condition:
                    $a at 0 and $b
            }"#,
        )
        .expect_err("compilation should fail");

    assert_eq!(compiler.take_snapshot(), snapshot);

    compiler
        .add_source(r#"rule test_2 { strings: $x = "bar" condition: $x }"#)
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(b"foobar").unwrap();
    assert_eq!(results.matching_rules().len(), 2);
}

#[test]
fn globals() {
    let mut compiler = Compiler::new();

    assert_eq!(
        compiler.define_global("#invalid", true).err().unwrap(),
        VariableError::InvalidIdentifier("#invalid".to_string())
    );

    let mut compiler = Compiler::new();

    assert_eq!(
        compiler
            .define_global("a", true)
            .unwrap()
            .define_global("a", false)
            .err()
            .unwrap(),
        VariableError::AlreadyExists("a".to_string())
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("int_1", 1u8)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("int_1", 1u16)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("int_1", 1u32)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("int_1", 1i8)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("int_1", 1i16)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("int_1", 1i32)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("int_1", 1i64)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("float_1", 1_f32)
        .unwrap()
        .add_source("rule foo {condition: float_1 == 1.0}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("float_1", 1_f64)
        .unwrap()
        .add_source("rule foo {condition: float_1 == 1.0}")
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("str_foo", "foo")
        .unwrap()
        .add_source(r#"rule foo {condition: str_foo == "foo"}"#)
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("bstr_foo", b"\0\0".as_slice())
        .unwrap()
        .add_source(r#"rule foo {condition: bstr_foo == "\0\0"}"#)
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .define_global("str_foo", "foo".to_string())
        .unwrap()
        .add_source(r#"rule foo {condition: str_foo == "foo"}"#)
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    let mut compiler = Compiler::new();

    compiler
        .new_namespace("test")
        .add_source(
            r#"
            rule foo {strings: $a = "foo" condition: $a}
            global rule always_true { condition: true }"#,
        )
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(b"foo")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        2
    );

    #[cfg(feature = "test_proto2-module")]
    {
        let mut compiler = Compiler::new();

        compiler
            .define_global("str_foo", "foo")
            .unwrap()
            .add_source(
                r#"
            import "test_proto2"
            rule foo {
                condition:
                    str_foo == "foo" and
                    for any s in test_proto2.array_string: (s == str_foo)
             }"#,
            )
            .unwrap();

        let rules = compiler.build();

        assert_eq!(
            Scanner::new(&rules)
                .scan(&[])
                .expect("scan should not fail")
                .matching_rules()
                .len(),
            1
        );
    }
}

#[test]
fn globals_json() {
    let mut compiler = Compiler::new();

    compiler
        .define_global(
            "some_struct",
            json!({
                "some_int": 1,
                "some_bool": true,
                "some_string": "foo",
                "some_int_array": [1,2,3],
                "some_float_array": [1.0, 2.0, 3.0]
            }),
        )
        .unwrap()
        .add_source(
            r#"
            rule foo {
            condition:
                some_struct.some_int == 1 and
                some_struct.some_bool and
                some_struct.some_string == "foo" and
                some_struct.some_int_array[0] == 1 and
                some_struct.some_float_array[1] == 2.0
            }"#,
        )
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_array", json!([1, "foo", 3]))
            .unwrap_err(),
        VariableError::InvalidArray
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_array", json!([1, [2, 3], 4]))
            .unwrap_err(),
        VariableError::InvalidArray
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_array", json!([1, null]))
            .unwrap_err(),
        VariableError::InvalidArray
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_struct", json!({ "foo": null }))
            .unwrap_err(),
        VariableError::UnexpectedNull
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_struct", json!({ "/foo": 1 }))
            .unwrap_err(),
        VariableError::InvalidIdentifier("/foo".to_string())
    );
}

#[test]
fn relaxed_re_syntax() {
    let mut compiler = Compiler::new();

    compiler.relaxed_re_syntax(true);
    compiler
        .add_source(r#"rule test_1 { strings: $a = /\X\Y\Z/ condition: $a }"#)
        .unwrap()
        .add_source(r#"rule test_2 { strings: $a = /xyz{/ condition: $a }"#)
        .unwrap()
        .add_source(r#"rule test_3 { strings: $a = /xyz[\>]/ condition: $a }"#)
        .unwrap()
        .add_source(
            r#"rule test_4 { strings: $a = /{(foo|bar)/ condition: $a }"#,
        )
        .unwrap()
        .add_source(r#"rule test_5 { strings: $a = /a{你好/ condition: $a }"#)
        .unwrap()
        .add_source(
            r#"rule test_6 { strings: $a = /a{1,你好/ condition: $a }"#,
        )
        .unwrap()
        .add_source(r#"rule test_7 { strings: $a = /你好{/ condition: $a }"#)
        .unwrap()
        .add_source(r#"rule test_8 { strings: $a = /a{1{/ condition: $a }"#)
        .unwrap()
        .add_source(r#"rule test_9 { strings: $a = /a{2,1}/ condition: $a }"#)
        .unwrap();

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(b"XYZ")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan(b"xyz{")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan(b"xyz>")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan(b"{foo")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan("a{你好".as_bytes())
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan("a{1,你好".as_bytes())
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan("你好{".as_bytes())
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan(b"a{1{")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Scanner::new(&rules)
            .scan(b"a{2,1}")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source("rule test { strings: $a = /+/ condition: $a }")
            .unwrap_err()
            .to_string(),
        r#"error[E014]: invalid regular expression
 --> line:1:28
  |
1 | rule test { strings: $a = /+/ condition: $a }
  |                            ^ repetition operator missing expression
  |
  = note: did you mean `\+` instead of `+`?"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source("rule test { strings: $a = /?/ condition: $a }")
            .unwrap_err()
            .to_string(),
        r#"error[E014]: invalid regular expression
 --> line:1:28
  |
1 | rule test { strings: $a = /?/ condition: $a }
  |                            ^ repetition operator missing expression
  |
  = note: did you mean `\?` instead of `?`?"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source("rule test { strings: $a = /a|*/ condition: $a }")
            .unwrap_err()
            .to_string(),
        r#"error[E014]: invalid regular expression
 --> line:1:30
  |
1 | rule test { strings: $a = /a|*/ condition: $a }
  |                              ^ repetition operator missing expression
  |
  = note: did you mean `\*` instead of `*`?"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source(r#"rule test { strings: $a = /\X|+/ condition: $a }"#)
            .unwrap_err()
            .to_string(),
        r#"error[E014]: invalid regular expression
 --> line:1:31
  |
1 | rule test { strings: $a = /\X|+/ condition: $a }
  |                               ^ repetition operator missing expression
  |
  = note: did you mean `\+` instead of `+`?"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source(r#"rule test { condition: "foo" matches /+/ }"#)
            .unwrap_err()
            .to_string(),
        r#"error[E014]: invalid regular expression
 --> line:1:39
  |
1 | rule test { condition: "foo" matches /+/ }
  |                                       ^ repetition operator missing expression
  |
  = note: did you mean `\+` instead of `+`?"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source(
                "rule test { strings: $a = /{{{{.*a.*?/ condition: $a }"
            )
            .unwrap_err()
            .to_string(),
        r#"error[E015]: mixing greedy and non-greedy quantifiers in regular expression
 --> line:1:32
  |
1 | rule test { strings: $a = /{{{{.*a.*?/ condition: $a }
  |                                ^^ ^^^ this is non-greedy
  |                                |
  |                                this is greedy"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source(
                r#"rule test { strings: $a = /\X\Y.*a.*?/ condition: $a }"#
            )
            .unwrap_err()
            .to_string(),
        r#"error[E015]: mixing greedy and non-greedy quantifiers in regular expression
 --> line:1:32
  |
1 | rule test { strings: $a = /\X\Y.*a.*?/ condition: $a }
  |                                ^^ ^^^ this is non-greedy
  |                                |
  |                                this is greedy"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source(
                r#"rule test { strings: $a = /{{{{(?u)\b/ condition: $a }"#
            )
            .unwrap_err()
            .to_string(),
        r#"error[E014]: invalid regular expression
 --> line:1:36
  |
1 | rule test { strings: $a = /{{{{(?u)\b/ condition: $a }
  |                                    ^^ this is unsupported in Unicode regular expressions"#
    );

    assert_eq!(
        Compiler::new()
            .relaxed_re_syntax(true)
            .add_source(
                "rule test { strings: $a = /({{{{|.*)a/s condition: $a }"
            )
            .unwrap_err()
            .to_string(),
        r#"error[E045]: arbitrary regular expression prefix
 --> line:1:34
  |
1 | rule test { strings: $a = /({{{{|.*)a/s condition: $a }
  |                                  ^^ this prefix can be arbitrarily long and matches all bytes"#
    );
}

#[test]
fn unsupported_modules() {
    let mut compiler = Compiler::new();

    compiler
        .ignore_module("foo_module")
        .add_source(
            r#"
            import "foo_module"

            // This rule is ignored because it uses an ignored module.
            rule ignored_1 { condition: foo_module.some_field == 1 }

            // This rule is ignored because it depends on a rule that directly
            // depends on an ignored moduled.
            rule ignored_2 { condition: ignored_1 }

            // This rule is ignored because it depends on a rule that indirectly
            // depends on an ignored module.
            rule ignored_3 { condition: ignored_2 }

            // This rule should match even if the previous ones were ignored.
            rule always_true { condition: true }
            "#,
        )
        .unwrap();

    let ignored: Vec<_> = compiler.ignored_rules().collect();
    assert_eq!(
        ignored,
        vec![
            ("ignored_1", IgnoredRuleReason::IgnoredModule("foo_module")),
            ("ignored_2", IgnoredRuleReason::IgnoredRule("ignored_1")),
            ("ignored_3", IgnoredRuleReason::IgnoredRule("ignored_2")),
        ]
    );

    let rules = compiler.build();

    assert_eq!(
        Scanner::new(&rules)
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );
}

#[test]
fn test_ignored_rules() {
    let mut compiler = Compiler::new();
    compiler.ignore_module("unsupported_mod");

    let _ = compiler.add_source(
        r#"
        import "unsupported_mod"

        rule rule_ok { condition: true }
        rule rule_ignored_module { condition: unsupported_mod.field == 1 }
        rule rule_failed_compile { condition: undefined_symbol == 1 }
        "#,
    );

    let ignored: Vec<_> = compiler.ignored_rules().collect();
    assert_eq!(ignored.len(), 2);

    assert_eq!(ignored[0].0, "rule_ignored_module");
    assert_eq!(
        ignored[0].1,
        IgnoredRuleReason::IgnoredModule("unsupported_mod")
    );

    assert_eq!(ignored[1].0, "rule_failed_compile");
    assert!(matches!(ignored[1].1, IgnoredRuleReason::CompileError(_)));
}

#[cfg(feature = "test_proto2-module")]
#[test]
fn banned_modules() {
    let mut compiler = Compiler::new();

    assert_eq!(
        compiler
            .ban_module(
                "test_proto2",
                "module `test_proto2` can't be used",
                "module `test_proto2` is used here",
            )
            .add_source(
                r#"
            import "test_proto2"
            rule test { condition: test_proto2.int32_zero == 0}
            "#,
            )
            .expect_err("expected error")
            .to_string(),
        r#"error[E100]: module `test_proto2` can't be used
 --> line:2:13
  |
2 |             import "test_proto2"
  |             ^^^^^^^^^^^^^^^^^^^^ module `test_proto2` is used here"#
    );

    // The only error should be the error about the use of a banned module,
    // the condition `test_proto2.int32_zero == 0` should not produce any
    // error.
    assert_eq!(compiler.errors().len(), 1);
}

#[test]
fn linter_tag_list() {
    assert!(Compiler::new()
        .add_linter(linters::tags_allowed(vec![
            "foo".to_string(),
            "bar".to_string()
        ]))
        .add_source(
            r#"rule test : foo bar { strings: $foo = "foo" condition: $foo }"#
        )
        .unwrap()
        .warnings()
        .is_empty());

    // This linter should return multiple warnings.
    assert_eq!(
        Compiler::new()
            .add_linter(linters::tags_allowed(vec![
                "foo".to_string(),
                "bar".to_string(),
            ]))
            .add_source(
                r#"rule test : axs ers { strings: $foo = "foo" condition: $foo }"#
            )
            .unwrap()
            .warnings()
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>(),
        &[r#"warning[unknown_tag]: tag not in allowed list
 --> line:1:13
  |
1 | rule test : axs ers { strings: $foo = "foo" condition: $foo }
  |             --- tag `axs` not in allowed list
  |
  = note: allowed tags: foo, bar"#,
             r#"warning[unknown_tag]: tag not in allowed list
 --> line:1:17
  |
1 | rule test : axs ers { strings: $foo = "foo" condition: $foo }
  |                 --- tag `ers` not in allowed list
  |
  = note: allowed tags: foo, bar"#,
        ]
    );

    // Only the first error should be reported.
    assert_eq!(
        Compiler::new()
            .add_linter(linters::tags_allowed(vec![
                "foo".to_string(),
                "bar".to_string(),
            ]).error(true))
            .add_source(
                r#"rule test : axs ers { strings: $foo = "foo" condition: $foo }"#
            )
            .expect_err("expected error")
            .to_string(),
        r#"error[E040]: tag not in allowed list
 --> line:1:13
  |
1 | rule test : axs ers { strings: $foo = "foo" condition: $foo }
  |             ^^^ tag `axs` not in allowed list
  |
  = note: allowed tags: foo, bar"#);
}

#[test]
fn linter_tags_regexp() {
    assert!(Compiler::new()
        .add_linter(linters::tag_regex("^(foo|bar)").unwrap())
        .add_source(
            r#"rule test : foo1 bar2 { strings: $foo = "foo" condition: $foo }"#
        )
        .unwrap()
        .warnings()
        .is_empty());

    assert_eq!(
        Compiler::new()
            .add_linter(linters::tag_regex("^(foo|bar)").unwrap())
            .add_source(
                r#"rule test : baz blah { strings: $foo = "foo" condition: $foo }"#
            )
            .unwrap()
            .warnings()
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>(),
        &[r#"warning[invalid_tag]: tag `baz` does not match regex `^(foo|bar)`
 --> line:1:13
  |
1 | rule test : baz blah { strings: $foo = "foo" condition: $foo }
  |             --- tag `baz` does not match regex `^(foo|bar)`"#,
       r#"warning[invalid_tag]: tag `blah` does not match regex `^(foo|bar)`
 --> line:1:17
  |
1 | rule test : baz blah { strings: $foo = "foo" condition: $foo }
  |                 ---- tag `blah` does not match regex `^(foo|bar)`"#,
    ]);

    assert_eq!(
        Compiler::new()
            .add_linter(linters::tag_regex("^(foo|bar)").unwrap().error(true))
            .add_source(
                r#"rule test : baz blah { strings: $foo = "foo" condition: $foo }"#
            )
            .expect_err("expected error")
            .to_string(),
        r#"error[E041]: tag does not match regex `^(foo|bar)`
 --> line:1:13
  |
1 | rule test : baz blah { strings: $foo = "foo" condition: $foo }
  |             ^^^ tag `baz` does not match regex `^(foo|bar)`"#);

    assert!(linters::tag_regex("(AXS|ERS").is_err());
}

#[test]
fn linter_rule_name() {
    assert!(
        Compiler::new()
            .add_linter(linters::rule_name("r_.+").unwrap())
            .add_source(
                r#"rule r_foo { strings: $foo = "foo" condition: $foo }"#
            )
            .unwrap()
            .add_source(
                r#"rule r_bar { strings: $bar = "bar" condition: $bar }"#
            )
            .unwrap()
            .warnings()
            .is_empty()
    );

    assert_eq!(
        Compiler::new()
            .add_linter(linters::rule_name("r_.+").unwrap())
            .add_source(
                r#"rule foo { strings: $foo = "foo" condition: $foo }"#
            )
            .unwrap()
            .warnings()
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>(),
        &[
            r#"warning[invalid_rule_name]: rule name does not match regex `r_.+`
 --> line:1:6
  |
1 | rule foo { strings: $foo = "foo" condition: $foo }
  |      --- this rule name does not match regex `r_.+`"#
        ]
    );

    assert_eq!(
        Compiler::new()
            .add_linter(linters::rule_name("r_.+").unwrap().error(true))
            .add_source(r#"rule foo { condition: true }"#)
            .expect_err("expected error")
            .to_string(),
        "error[E039]: rule name does not match regex `r_.+`
 --> line:1:6
  |
1 | rule foo { condition: true }
  |      ^^^ this rule name does not match regex `r_.+`"
    );

    assert!(linters::rule_name("(AXS|ERS").is_err());
}

#[test]
fn linter_required_metadata() {
    assert!(Compiler::new()
        .add_linter(linters::metadata("author").required(true))
        .add_source(r#"rule r_foo { meta: author = "foo" strings: $foo = "foo" condition: $foo }"#)
        .unwrap()
        .warnings()
        .is_empty());

    assert_eq!(
        Compiler::new()
            .add_linter(linters::metadata("author").required(true))
            .add_source(
                r#"rule foo { strings: $foo = "foo" condition: $foo }"#
            )
            .unwrap()
            .warnings()
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>(),
        &[r#"warning[missing_metadata]: required metadata is missing
 --> line:1:6
  |
1 | rule foo { strings: $foo = "foo" condition: $foo }
  |      --- required metadata `author` not found"#]
    );

    assert_eq!(
        Compiler::new()
            .add_linter(linters::metadata("author").required(true).error(true))
            .add_source(r#"rule foo { condition: true }"#)
            .expect_err("expected error")
            .to_string(),
        "error[E038]: required metadata is missing
 --> line:1:6
  |
1 | rule foo { condition: true }
  |      ^^^ required metadata `author` not found"
    );
}

#[cfg(feature = "test_proto2-module")]
#[test]
fn import_modules() {
    let mut compiler = Compiler::new();
    assert!(
        compiler
            .add_source(
                r#"
            import "test_proto2"
            rule foo {condition: test_proto2.int32_zero == 0}"#
            )
            .unwrap()
            .add_source(
                r#"
            import "test_proto2"
            rule bar {condition: test_proto2.int32_zero == 0}"#
            )
            .is_ok()
    );

    let mut compiler = Compiler::new();
    assert!(
        compiler
            .add_source(
                r#"
            import "test_proto2"
            rule foo {condition: test_proto2.int32_zero == 0}"#
            )
            .unwrap()
            .new_namespace("namespace1")
            .add_source(
                r#"
            import "test_proto2"
            rule bar {condition: test_proto2.int32_zero == 0}"#
            )
            .is_ok()
    );
}

#[cfg(feature = "pe-module")]
#[test]
fn wrong_type() {
    assert_eq!(
        Compiler::new()
            .add_source(
                r#"
            import "pe"
            rule test { condition: pe.is_dll }"#
            )
            .expect_err("expected error")
            .to_string(),
        "error[E002]: wrong type
 --> line:3:36
  |
3 |             rule test { condition: pe.is_dll }
  |                                    ^^^^^^^^^ expression should be `bool`, but it is a function
  |
  = help: you probably meant pe.is_dll()"
    );

    assert_eq!(
        Compiler::new()
            .add_source(
                r#"
            import "pe"
            rule test { condition: pe.sections }"#
            )
            .expect_err("expected error")
            .to_string(),
        "error[E002]: wrong type
 --> line:3:36
  |
3 |             rule test { condition: pe.sections }
  |                                    ^^^^^^^^^^^ expression should be `bool`, but it is an array"
    );

    assert_eq!(
        Compiler::new()
            .add_source(
                r#"
            import "pe"
            rule test { condition: pe.version_info }"#
            )
            .expect_err("expected error")
            .to_string(),
        "error[E002]: wrong type
 --> line:3:36
  |
3 |             rule test { condition: pe.version_info }
  |                                    ^^^^^^^^^^^^^^^ expression should be `bool`, but it is a map"
    );
}

#[test]
fn continue_after_error() {
    let mut compiler = Compiler::new();

    // This rule won't compile because $b is not used.
    assert!(
        compiler
            .add_source(
                r#"
            rule test {
                strings:
                    $a = "foo"
                    $b = "bar"
                condition:
                    $a
            }"#
            )
            .is_err()
    );

    // Adding a rule with the same name after the previous one failed should
    // be ok. Notice that the rule also reuses a pattern that was defined
    // by the rule that failed before.
    assert!(
        compiler
            .add_source(
                r#"
            rule test {
                strings:
                    $a = "foo" 
                condition: 
                    $a 
            }"#
            )
            .is_ok()
    );

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);

    assert_eq!(scanner.scan(b"foo").unwrap().matching_rules().len(), 1);

    // Now do the same test, but with each rule in a different namespace.
    let mut compiler = Compiler::new();
    compiler.new_namespace("namespace1");

    assert!(
        compiler
            .add_source(
                r#"
            rule test {
                strings:
                    $a = "foo"
                    $b = "bar"
                condition:
                    $a
            }"#
            )
            .is_err()
    );

    compiler.new_namespace("namespace2");

    assert!(
        compiler
            .add_source(
                r#"
            rule test {
                strings:
                    $a = "foo" 
                condition: 
                    $a 
            }"#
            )
            .is_ok()
    );

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);

    assert_eq!(scanner.scan(b"foo").unwrap().matching_rules().len(), 1);
}

#[test]
fn conflicting_identifiers_error() {
    assert_eq!(
        Compiler::new()
            .define_global("foo", 1)
            .unwrap()
            .add_source("rule foo  {condition: true}")
            .unwrap_err()
            .to_string(),
        "error[E013]: rule `foo` conflicts with an existing identifier
 --> line:1:6
  |
1 | rule foo  {condition: true}
  |      ^^^ identifier already in use by a module or global variable"
    );
}

#[test]
fn duplicate_rule_error() {
    assert_eq!(
        Compiler::new()
            .add_source("rule foo : first {condition: true}")
            .unwrap()
            .add_source("rule foo : second {condition: true}")
            .unwrap_err()
            .to_string(),
        "error[E012]: duplicate rule `foo`
 --> line:1:6
  |
1 | rule foo : second {condition: true}
  |      ^^^ duplicate declaration of `foo`
  |
 ::: line:1:6
  |
1 | rule foo : first {condition: true}
  |      --- `foo` declared here for the first time"
    );
}

#[cfg(feature = "constant-folding")]
#[test]
fn number_out_of_range_error() {
    assert_eq!(
        Compiler::new()
            .add_source(
                "rule test {
condition:
  	9223372036854775807 + 1000000000 == 0
}"
            )
            .unwrap_err()
            .to_string(),
        "error[E007]: number out of range
 --> line:3:4
  |
3 |    9223372036854775807 + 1000000000 == 0
  |    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this number is out of the allowed range [-9223372036854775808-9223372036854775807]"
    );
}

#[test]
fn utf8_errors() {
    let mut src =
        "rule test {condition: true}".to_string().as_bytes().to_vec();

    // Insert invalid UTF-8 in the code.
    src.insert(4, 0xff);

    let mut compiler = Compiler::new();

    let err = compiler
        .add_source(src.as_slice())
        .expect_err("expected error")
        .to_string();

    assert_eq!(
        err,
        "error[E032]: invalid UTF-8
 --> line:1:5
  |
1 | rule� test {condition: true}
  |     ^ invalid UTF-8 character"
    );

    assert_eq!(
        compiler.errors.first().expect("expected error").to_string(),
        err
    );
}

#[test]
fn errors_serialization() {
    let err = Compiler::new()
        .add_source(
            SourceCode::from("rule test {condition: foo}")
                .with_origin("test.yar"),
        )
        .err()
        .unwrap();

    let json_error = serde_json::to_string(&err).unwrap();

    let expected = json!({
        "type": "UnknownIdentifier",
        "code": "E009",
        "title": "unknown identifier `foo`",
        "line": 1,
        "column": 23,
        "labels":[
            {
                "level": "error",
                "code_origin": "test.yar",
                "line": 1,
                "column": 23,
                "span": { "start": 22, "end": 25 },
                "text": "this identifier has not been declared"
            }
        ],
        "footers": [],
        "text": r#"error[E009]: unknown identifier `foo`
 --> test.yar:1:23
  |
1 | rule test {condition: foo}
  |                       ^^^ this identifier has not been declared"#
    });

    assert_eq!(json_error, expected.to_string());
}

#[test]
fn test_includes() {
    let mut compiler = Compiler::new();

    compiler
        // this directory contains the included.yar file
        .add_include_dir("src/compiler/tests/testdata/includes")
        .add_source(r#"include "included_ok.yar""#)
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);

    assert_eq!(scanner.scan(b"").unwrap().matching_rules().len(), 1);
}

#[test]
fn test_circular_includes() {
    let mut compiler = Compiler::new();

    let err = compiler
        // this directory contains the included.yar file
        .add_include_dir("src/compiler/tests/testdata/includes")
        .add_source(r#"include "included_circular.yar""#)
        .unwrap_err()
        .to_string();

    assert!(err.contains(r#"error[E046]: circular include dependencies"#));

    #[cfg(target_family = "unix")]
    assert!(err.contains(
        r"src/compiler/tests/testdata/includes/included_circular.yar"
    ));

    #[cfg(target_family = "windows")]
    assert!(err.contains(
        r#"src\compiler\tests\testdata\includes\included_circular.yar"#
    ));
}

#[test]
fn test_relative_includes() {
    let mut compiler = Compiler::new();

    compiler
        // this directory contains the included.yar file
        .add_include_dir("src/compiler/tests/testdata/includes")
        .add_source(r#"include "included_relative.yar""#)
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);

    assert_eq!(scanner.scan(b"").unwrap().matching_rules().len(), 1);
}

#[test]
fn test_disable_includes() {
    let mut compiler = Compiler::new();

    compiler
        .enable_includes(false)
        .add_include_dir("src/compiler/tests/testdata/includes");

    assert_eq!(
        compiler
            .add_source(r#"include "included_ok.yar""#)
            .unwrap_err()
            .to_string(),
        r#"error[E044]: include statements not allowed
 --> line:1:1
  |
1 | include "included_ok.yar"
  | ^^^^^^^^^^^^^^^^^^^^^^^^^ includes are disabled for this compilation"#
    );
}

#[test]
fn test_switch_warnings() {
    let mut compiler = Compiler::new();

    compiler
        .switch_warning("invariant_expr", false)
        .unwrap()
        .add_source(
            r#"
            rule test {
                condition: true
            }
            "#,
        )
        .unwrap();

    assert_eq!(compiler.warnings().len(), 0);
}

#[test]
fn test_switch_all_warnings() {
    let mut compiler = Compiler::new();

    compiler
        .switch_all_warnings(false)
        .add_source(
            r#"
            rule test {
                condition: true
            }
            "#,
        )
        .unwrap();

    assert_eq!(compiler.warnings().len(), 0);
}

#[test]
fn test_max_warnings() {
    let mut compiler = Compiler::new();

    compiler
        .max_warnings(1)
        .add_source(
            r#"
            rule test1 {
                condition: true
            }
            rule test2 {
                condition: true
            }
            "#,
        )
        .unwrap();

    assert_eq!(compiler.warnings().len(), 1);
}

#[test]
fn test_errors() {
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/compiler/tests/testdata/errors/*.in")
        .unwrap()
        .flatten()
    {
        // Path to the .in file.
        let in_path = entry.into_path();

        println!("{in_path:?}");

        // Path to the .out file.
        let out_path = in_path.with_extension("out");

        let mut src = String::new();

        let rules = fs::read_to_string(&in_path).expect("unable to read");

        // If the `constant-folding` feature is not enabled ignore files
        // starting with "// constant-folding required".
        #[cfg(not(feature = "constant-folding"))]
        if rules.starts_with("// constant-folding required") {
            continue;
        }

        // If the `test_proto2-module` feature is not enabled ignore files
        // starting with "// test_proto2-module required".
        #[cfg(not(feature = "test_proto2-module"))]
        if rules.starts_with("// test_proto2-module required") {
            continue;
        }

        src.push_str(rules.as_str());

        let err = compile(src.as_str()).expect_err(
            format!("file {in_path:?} should have failed").as_str(),
        );

        let mut output_file = mint.new_goldenfile(out_path).unwrap();

        output_file
            .write_all(err.to_string().as_bytes())
            .expect("unable to write")
    }
}

#[test]
fn test_warnings() {
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/compiler/tests/testdata/warnings/*.in")
        .unwrap()
        .flatten()
    {
        // Path to the .in file.
        let in_path = entry.into_path();

        println!("{in_path:?}");

        // Path to the .out file.
        let out_path = in_path.with_extension("out");

        let mut src = String::new();
        let rules = fs::read_to_string(&in_path).expect("unable to read");

        // If the `constant-folding` feature is not enabled ignore files
        // starting with "// constant-folding required".
        #[cfg(not(feature = "constant-folding"))]
        if rules.starts_with("// constant-folding required") {
            continue;
        }

        // If the `test_proto2-module` feature is not enabled ignore files
        // starting with "// test_proto2-module required".
        #[cfg(not(feature = "test_proto2-module"))]
        if rules.starts_with("// test_proto2-module required") {
            continue;
        }

        let mut compiler = Compiler::new();

        src.push_str(rules.as_str());

        compiler.ignore_module("unsupported_module");
        compiler.add_source(src.as_str()).unwrap();

        let mut output_file = mint.new_goldenfile(out_path).unwrap();

        for w in compiler.warnings() {
            let mut s = w.to_string();
            s.push('\n');
            output_file.write_all(s.as_bytes()).expect("unable to write");
        }
    }
}

fn check_filesize_bound(
    condition: &str,
    matching_sizes: &[usize],
    non_matching_sizes: &[usize],
) {
    let source = format!(
        r#"
        rule test {{
            strings:
                $a = "foo"
            condition:
                $a and ({})
        }}
        "#,
        condition
    );
    let rules = compile(source.as_str()).unwrap();

    for &size in matching_sizes {
        let mut data = vec![b' '; size];
        if size >= 3 {
            data[0..3].copy_from_slice(b"foo");
        }
        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(&data).unwrap();
        assert_eq!(
            results.matching_rules().len(),
            1,
            "Expected match for condition '{}' with size {}",
            condition,
            size
        );
    }

    for &size in non_matching_sizes {
        let mut data = vec![b' '; size];
        if size >= 3 {
            data[0..3].copy_from_slice(b"foo");
        }
        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(&data).unwrap();
        assert_eq!(
            results.matching_rules().len(),
            0,
            "Expected NO match for condition '{}' with size {}",
            condition,
            size
        );
    }
}

#[test]
fn test_filesize_bounds() {
    // 1. filesize > 10 (Excluded start 10)
    check_filesize_bound("filesize > 10", &[11, 20], &[10, 9, 3]);

    // 2. filesize >= 10 (Included start 10)
    check_filesize_bound("filesize >= 10", &[10, 11, 20], &[9, 3]);

    // 3. filesize < 10 (Excluded end 10)
    check_filesize_bound("filesize < 10", &[9, 3], &[10, 11]);

    // 4. filesize <= 10 (Included end 10)
    check_filesize_bound("filesize <= 10", &[10, 9, 3], &[11, 20]);

    // 5. 10 < filesize (Excluded start 10, reversed)
    check_filesize_bound("10 < filesize", &[11, 20], &[10, 9, 3]);

    // 6. 10 <= filesize (Included start 10, reversed)
    check_filesize_bound("10 <= filesize", &[10, 11, 20], &[9, 3]);

    // 7. 10 > filesize (Excluded end 10, reversed)
    check_filesize_bound("10 > filesize", &[9, 3], &[10, 11]);

    // 8. 10 >= filesize (Included end 10, reversed)
    check_filesize_bound("10 >= filesize", &[10, 9, 3], &[11, 20]);

    // 9. filesize > 10 and filesize < 20
    check_filesize_bound(
        "filesize > 10 and filesize < 20",
        &[11, 15, 19],
        &[10, 20, 21, 3],
    );

    // 10. max_start merging: (Included, Included) with new > current
    check_filesize_bound(
        "filesize >= 10 and filesize >= 20",
        &[20, 25],
        &[19, 10, 9, 3],
    );

    // 11. max_start merging: (Included, Excluded) with new >= current
    check_filesize_bound(
        "filesize >= 10 and filesize > 10",
        &[11, 15],
        &[10, 9, 3],
    );
    check_filesize_bound(
        "filesize >= 10 and filesize > 20",
        &[21, 25],
        &[20, 19, 10, 3],
    );

    // 12. max_start merging: (Excluded, Included) with new > current
    check_filesize_bound(
        "filesize > 10 and filesize >= 20",
        &[20, 25],
        &[19, 10, 9, 3],
    );

    // 13. max_start merging: (Excluded, Excluded) with new > current
    check_filesize_bound(
        "filesize > 10 and filesize > 20",
        &[21, 25],
        &[20, 10, 9, 3],
    );

    // 14. min_end merging: (Included, Included) with new < current
    check_filesize_bound(
        "filesize <= 100 and filesize <= 90",
        &[90, 85, 3],
        &[91, 100],
    );

    // 15. min_end merging: (Included, Excluded) with new <= current
    check_filesize_bound(
        "filesize <= 100 and filesize < 100",
        &[99, 90, 3],
        &[100, 101],
    );
    check_filesize_bound(
        "filesize <= 100 and filesize < 90",
        &[89, 80, 3],
        &[90, 100],
    );

    // 16. min_end merging: (Excluded, Included) with new < current
    check_filesize_bound(
        "filesize < 100 and filesize <= 90",
        &[90, 85, 3],
        &[91, 100],
    );

    // 17. min_end merging: (Excluded, Excluded) with new < current
    check_filesize_bound(
        "filesize < 100 and filesize < 90",
        &[89, 80, 3],
        &[90, 100],
    );

    // 18. float filesize bounds
    check_filesize_bound("filesize > 10.5", &[11, 20], &[10, 9, 3]);
    check_filesize_bound("filesize >= 10.5", &[11, 20], &[10, 9, 3]);
    check_filesize_bound("filesize < 10.5", &[10, 9, 3], &[11, 20]);
    check_filesize_bound("filesize <= 10.5", &[10, 9, 3], &[11, 20]);
    check_filesize_bound("10.5 < filesize", &[11, 20], &[10, 9, 3]);
    check_filesize_bound("10.5 > filesize", &[10, 9, 3], &[11, 20]);
}

fn check_header_constraint(
    condition: &str,
    matching_headers: &[&[u8]],
    non_matching_headers: &[&[u8]],
) {
    let source = format!(
        r#"
        rule test {{
            strings:
                $a = "foo"
            condition:
                $a and ({})
        }}
        "#,
        condition
    );
    let rules = compile(source.as_str()).unwrap();

    for &header in matching_headers {
        let mut data = header.to_vec();
        if data.len() < 3 {
            data.extend(vec![b' '; 3 - data.len()]);
        }
        data.extend(b"foo");
        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(&data).unwrap();
        assert_eq!(
            results.matching_rules().len(),
            1,
            "Expected match for header condition '{}' with prefix {:?}",
            condition,
            header
        );
    }

    for &header in non_matching_headers {
        let mut data = header.to_vec();
        if data.len() < 3 {
            data.extend(vec![b' '; 3 - data.len()]);
        }
        data.extend(b"foo");
        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(&data).unwrap();
        assert_eq!(
            results.matching_rules().len(),
            0,
            "Expected NO match for header condition '{}' with prefix {:?}",
            condition,
            header
        );
    }
}

#[test]
fn test_header_constraints() {
    // 1. Constrained
    check_header_constraint(
        "uint32(0) == 0x464c457f",
        &[b"\x7FELF"],
        &[b"MZ\x00\x00"],
    );

    // 2. Unsatisfiable
    check_header_constraint(
        "uint8(0) == 1 and uint8(0) == 2",
        &[],
        &[b"\x01", b"\x02", b"\x03"],
    );
}

#[test]
fn test_rules_warnings() {
    let mut compiler = Compiler::new();
    compiler
        .add_source(
            r#"
            import "math"
            import "math"
            rule test { condition: true }
            "#,
        )
        .unwrap();
    let rules = compiler.build();
    assert!(!rules.warnings().is_empty());
}

#[test]
fn test_rules_debug() {
    let mut compiler = Compiler::new();
    compiler.add_source("rule test { condition: true }").unwrap();
    let rules = compiler.build();

    let debug_str = format!("{:?}", rules);
    assert!(debug_str.contains("RuleId(0)"));
    assert!(debug_str.contains("name: test"));
}

#[test]
fn test_rules_serialization() {
    let mut compiler = Compiler::new();
    compiler.add_source("rule test { condition: true }").unwrap();
    let rules = compiler.build();

    let serialized = rules.serialize().unwrap();
    let deserialized = Rules::deserialize_from(&serialized[..]).unwrap();
    assert_eq!(deserialized.iter().len(), 1);

    let mut iter = deserialized.iter();
    assert_eq!(iter.len(), 1);
    let r = iter.next().unwrap();
    assert_eq!(r.identifier(), "test");
    assert!(iter.next().is_none());
}

#[test]
fn test_rules_matches_many() {
    let mut compiler = Compiler::new();
    compiler
        .define_global("str_foo", "foo")
        .unwrap()
        .add_source(
            r#"
            rule test {
                condition:
                    str_foo matches /ba[rs]/ or str_foo matches /ba[zt]/
            }
            "#,
        )
        .unwrap();
    let rules = compiler.build();
    // Scan using these rules to trigger get_regex_set at scan time
    let mut scanner = Scanner::new(&rules);
    scanner.set_global("str_foo", "bar").unwrap();
    let scan_results = scanner.scan(&[]).unwrap();
    assert_eq!(scan_results.matching_rules().len(), 1);
}

#[test]
fn test_var_stack_overflow() {
    let mut compiler = Compiler::new();
    let vars =
        (0..2050).map(|i| format!("v{i}=0")).collect::<Vec<_>>().join(",");
    let rule = format!("rule test {{ condition: with {vars} : ( true ) }}");
    assert!(compiler.add_source(rule.as_str()).is_err());
}

#[test]
fn test_condition_too_large() {
    use crate::errors::CompileError;

    let mut compiler = Compiler::new();
    compiler.add_source("rule ok_before { condition: true }").unwrap();

    let mut huge = String::from("rule massive { condition: filesize > 0");
    for _ in 0..25_000 {
        huge.push_str(" and filesize > 0");
    }
    huge.push('}');

    let err = compiler.add_source(huge.as_str()).unwrap_err();
    assert!(matches!(err, CompileError::ConditionTooLarge(_)));

    // Two rules that each fit under MAX_FUNC_INSTRS alone, but exceed
    // MAX_FUNC_INSTRS together, should both compile by splitting into
    // separate WASM functions (issue #828).
    let large_rule = |name: &str| {
        format!(
            "rule {name} {{ condition: filesize >= 0{} }}\n",
            " and filesize >= 0".repeat(6000)
        )
    };
    compiler.add_source(large_rule("large_a").as_str()).unwrap();
    compiler.add_source(large_rule("large_b").as_str()).unwrap();

    compiler.add_source("rule ok_after { condition: true }").unwrap();
    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(&[]).unwrap();
    assert_eq!(results.matching_rules().len(), 4);
}

#[test]
fn test_unicode_whitespace() {
    // Space separator characters (including U+1680 and U+3000) must be treated
    // as valid whitespace, and rendering errors on lines containing them must
    // not panic.
    for ws in ['\u{3000}', '\u{1680}'] {
        let rule = format!("rule test {{         {ws}condition: true }}");
        assert!(compile(rule.as_str()).is_ok());

        let hex_rule = format!(
            "rule test {{ strings: $a = {{ AA {ws} BB }} condition: $a }}"
        );
        assert!(compile(hex_rule.as_str()).is_ok());

        let invalid_rule = format!("rule test {{         {ws}invalid }}");
        let err = compile(invalid_rule.as_str()).unwrap_err();
        let _ = err.to_string();
    }

    // Other `char::is_whitespace` characters not accepted as YARA whitespace
    // must produce clean syntax errors whose formatted reports do not panic on
    // UTF-8 char boundaries.
    for ws in ['\u{0085}', '\u{2028}', '\u{2029}'] {
        let rule = format!("rule test {{         {ws}condition: true }}");
        let err = compile(rule.as_str()).unwrap_err();
        let _ = err.to_string();

        let hex_rule = format!(
            "rule test {{ strings: $a = {{ AA {ws} BB }} condition: $a }}"
        );
        let err = compile(hex_rule.as_str()).unwrap_err();
        let _ = err.to_string();
    }
}

#[test]
fn test_var_undef_bitmap_addressing() {
    // On a 1-byte input, `v8 = uint8(1)` is undefined while `v64 = uint8(0)`
    // is defined. Variables 8 and 64 must not share the same undef bit in
    // WASM memory, otherwise `v64` clears `v8`'s undef flag.
    let vars = (0..=64)
        .map(|i| match i {
            8 => "v8 = uint8(1)".to_string(),
            64 => "v64 = uint8(0)".to_string(),
            _ => format!("v{i} = 0"),
        })
        .collect::<Vec<_>>()
        .join(", ");

    let rule =
        format!("rule test {{ condition: with {vars} : ( defined v8 ) }}");

    let rules = compile(rule.as_str()).unwrap();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(b"\x01").unwrap();
    assert_eq!(results.matching_rules().len(), 0);
}

#[test]
fn test_unicode_word_boundary() {
    for pat in [
        r"/(?u)\b{start-half}abc/",
        r"/(?u)abc\b{end-half}/",
        r"/(?u:\b)abc/",
        r"/(?u:\B)abc/",
        r"/(?u:\b{start})abc/",
        r"/(?u:\b{end})abc/",
        r"/(?u:\b{start-half})abc/",
        r"/(?u:\b{end-half})abc/",
    ] {
        let rule =
            format!("rule test {{ strings: $a = {pat} condition: $a }}");
        let err = compile(rule.as_str()).unwrap_err();
        assert!(
            err.to_string().contains(
                "this is unsupported in Unicode regular expressions"
            )
        );
    }
}

#[test]
fn test_unicode_class_too_large() {
    for pat in [r"/(?u)\w+abc/", r"/(?u)\p{L}+abc/"] {
        let rule =
            format!("rule test {{ strings: $a = {pat} condition: $a }}");
        let err = compile(rule.as_str()).unwrap_err();
        assert!(err.to_string().contains("regexp is too large"));
    }
}

#[test]
fn test_best_atom_past_u16_max() {
    // Wide literal: 32,769 `'a'`s expand to 65,538 bytes in UTF-16LE before
    // `"1234"`.
    let wide_prefix = "a".repeat(32769);
    let wide_rule = format!(
        r#"rule test {{ strings: $a = "{wide_prefix}1234" wide condition: $a }}"#
    );
    let rules = compile(wide_rule.as_str()).unwrap();
    let mut scanner = Scanner::new(&rules);

    let matching_wide: Vec<u8> =
        format!("{wide_prefix}1234").bytes().flat_map(|b| [b, 0]).collect();
    let non_matching_wide: Vec<u8> =
        format!("{wide_prefix}1235").bytes().flat_map(|b| [b, 0]).collect();

    assert_eq!(
        scanner.scan(&matching_wide).unwrap().matching_rules().len(),
        1
    );
    assert_eq!(
        scanner.scan(&non_matching_wide).unwrap().matching_rules().len(),
        0
    );

    // Narrow literal: 65,536 `'a'`s followed by `"1234"`.
    let ascii_prefix = "a".repeat(65536);
    let ascii_rule = format!(
        r#"rule test {{ strings: $a = "{ascii_prefix}1234" condition: $a }}"#
    );
    let rules = compile(ascii_rule.as_str()).unwrap();
    let mut scanner = Scanner::new(&rules);

    let matching_ascii = format!("{ascii_prefix}1234");
    let non_matching_ascii = format!("{ascii_prefix}1235");

    assert_eq!(
        scanner
            .scan(matching_ascii.as_bytes())
            .unwrap()
            .matching_rules()
            .len(),
        1
    );
    assert_eq!(
        scanner
            .scan(non_matching_ascii.as_bytes())
            .unwrap()
            .matching_rules()
            .len(),
        0
    );
}

#[test]
#[cfg(feature = "fast-regexp")]
fn test_fastvm_pattern_too_large() {
    // 65,535-byte (`u16::MAX`) literal and masked-literal pieces fit in FastVM.
    let rule_lit_ok = format!(
        "rule test {{ strings: $a = /{}.{{1,2}}b/ condition: $a }}",
        "a".repeat(65535)
    );
    assert!(compile(rule_lit_ok.as_str()).is_ok());

    let rule_masked_ok = format!(
        "rule test {{ strings: $a = /[Aa]{}.{{1,2}}b/ condition: $a }}",
        "a".repeat(65534)
    );
    assert!(compile(rule_masked_ok.as_str()).is_ok());

    // 65,536-byte (`u16::MAX + 1`) literal, masked-literal, and alternation
    // pieces exceed `u16::MAX` and must fail with `Error::TooLarge` rather than
    // panicking.
    for pat in [
        format!("/{}.{{1,2}}b/", "a".repeat(65536)),
        format!("/[Aa]{}.{{1,2}}b/", "a".repeat(65535)),
        format!("/({}|b)1234/", "a".repeat(65535)),
        format!("/({}|b)1234/", "a".repeat(65536)),
    ] {
        let rule =
            format!("rule test {{ strings: $a = {pat} condition: $a }}");
        let err = compile(rule.as_str()).unwrap_err();
        assert!(err.to_string().contains("regexp is too large"));
    }
}

#[test]
fn test_fastvm_wide_jump_bck_underflow() {
    // In all three cases below, FastVM extracts the wide atom
    // `"1\x002\x003\x004\x00"` (`"1234"` in UTF-16LE) and verifies the prefix
    // before `"1234"` backwards via `FastVM::jump_bck`. In `wide` mode each
    // character requires 2 bytes (`step = 2`), so when only 1 byte precedes the
    // jump in the scanned data, no wide character can fit before the jump and
    // `jump_bck` must not subtract `step` (2) from `1` and underflow `usize`.

    // Case 1: Backward jump followed by an alternation (`(ab|cd)`), which
    // takes the byte-by-byte loop in `jump_bck`. Scanning
    // `b"x1\x002\x003\x004\x00"` leaves only 1 byte (`b"x"`) before the atom.
    let rules = compile(
        r#"rule test { strings: $a = /(ab|cd).{0,2}1234/ wide condition: $a }"#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    assert_eq!(
        scanner.scan(b"x1\x002\x003\x004\x00").unwrap().matching_rules().len(),
        0
    );

    // Valid wide matches with 0, 1, and 2 wide characters skipped by `.{0,2}`.
    assert_eq!(
        scanner
            .scan(b"a\x00b\x001\x002\x003\x004\x00")
            .unwrap()
            .matching_rules()
            .len(),
        1
    );
    assert_eq!(
        scanner
            .scan(b"a\x00b\x00x\x001\x002\x003\x004\x00")
            .unwrap()
            .matching_rules()
            .len(),
        1
    );
    assert_eq!(
        scanner
            .scan(b"c\x00d\x00x\x00y\x001\x002\x003\x004\x00")
            .unwrap()
            .matching_rules()
            .len(),
        1
    );

    // 3 wide characters between `"cd"` and `"1234"` exceeds `.{0,2}`.
    assert_eq!(
        scanner
            .scan(b"c\x00d\x00x\x00y\x00z\x001\x002\x003\x004\x00")
            .unwrap()
            .matching_rules()
            .len(),
        0
    );

    // Case 2: Backward jump followed by a literal (`ab`), which takes the
    // `memrchr` fast path in `jump_bck` looking for `'b'`. Scanning
    // `b"b1\x002\x003\x004\x00"` finds `'b'` in the single byte before the
    // atom, where a 2-byte wide character (`"b\x00"`) cannot fit.
    let rules = compile(
        r#"rule test { strings: $a = /ab.{0,2}1234/ wide condition: $a }"#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    assert_eq!(
        scanner.scan(b"b1\x002\x003\x004\x00").unwrap().matching_rules().len(),
        0
    );
    assert_eq!(
        scanner
            .scan(b"a\x00b\x00x\x001\x002\x003\x004\x00")
            .unwrap()
            .matching_rules()
            .len(),
        1
    );

    // Case 3: Non-zero `position` when entering `jump_bck`. Matching `(xf|gh)`
    // backwards against `"x\x00f\x00"` advances `position` to 4, leaving 1 byte
    // (`b"x"`) in `b"xx\x00f\x001\x002\x003\x004\x00"`. `jump_bck` must ignore
    // that single byte rather than moving `position` from 4 back to 3.
    let rules = compile(
        r#"rule test { strings: $a = /(ab|xf).{0,2}(xf|gh)1234/ wide condition: $a }"#,
    )
    .unwrap();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(
        scanner
            .scan(b"xx\x00f\x001\x002\x003\x004\x00")
            .unwrap()
            .matching_rules()
            .len(),
        0
    );
    assert_eq!(
        scanner
            .scan(b"a\x00b\x00x\x00y\x00g\x00h\x001\x002\x003\x004\x00")
            .unwrap()
            .matching_rules()
            .len(),
        1
    );
}

#[test]
fn test_wide_regexp_atom_backtrack_overflow() {
    let p32764 = "a".repeat(32764);
    let p32767 = "a".repeat(32767);
    let p32768 = "a".repeat(32768);

    // FastVM keeps the intra-literal offset in `atom.backtrack` (`32,764`
    // narrow -> `65,528` wide), whereas Thompson's compiler (`not(fast-regexp)`)
    // folds the intra-literal offset into `code_loc` and resets `backtrack` to 0.
    let expected_backtrack =
        if cfg!(feature = "fast-regexp") { 65528 } else { 0 };

    // `"1234"` right at the end of the first 32 KiB (`32764..32768`) is
    // selected with narrow `backtrack = 32,764` (`65,528` in wide mode).
    let rules_32764 = compile(
        format!(
            "rule test {{ strings: $a = /{p32764}1234.{{1,2}}b/ wide condition: $a }}"
        )
        .as_str(),
    )
    .unwrap();
    assert_eq!(rules_32764.atoms().len(), 1);
    assert_eq!(rules_32764.atoms()[0].as_slice(), b"1\x002\x003\x004\x00");
    assert_eq!(rules_32764.atoms()[0].backtrack(), expected_backtrack);

    // `"1234"` straddling the 32 KiB boundary (`32767..32771`): only `"aaa1"`
    // (`32764..32768`) lies within the first 32 KiB (`backtrack = 65,528`).
    let rules_32767 = compile(
        format!(
            "rule test {{ strings: $a = /{p32767}1234.{{1,2}}b/ wide condition: $a }}"
        )
        .as_str(),
    )
    .unwrap();
    assert_eq!(rules_32767.atoms().len(), 1);
    assert_eq!(rules_32767.atoms()[0].as_slice(), b"a\x00a\x00a\x001\x00");
    assert_eq!(rules_32767.atoms()[0].backtrack(), expected_backtrack);

    // High-quality bytes (`"1234"`) past the first 32 KiB (`32,768` bytes):
    // `best_range_in_bytes` and `best_range_in_masked_bytes` consider only the
    // first 32 KiB so `backtrack <= 32,767` and `Atom::make_wide` never
    // overflows `u16`.
    let rules_32768 = compile(
        format!(
            "rule test {{ strings: $a = /{p32768}1234.{{1,2}}b/ wide condition: $a }}"
        )
        .as_str(),
    )
    .unwrap();
    assert_eq!(rules_32768.atoms().len(), 1);
    assert_eq!(rules_32768.atoms()[0].as_slice(), b"a\x00a\x00a\x00a\x00");
    assert_eq!(rules_32768.atoms()[0].backtrack(), 0);

    for rule in [
        format!(
            "rule test {{ strings: $a = /{p32768}1234.{{1,2}}b/ wide condition: $a }}"
        ),
        format!(
            "rule test {{ strings: $a = /{p32768}1234.{{1,2}}b/ wide ascii condition: $a }}"
        ),
        format!(
            "rule test {{ strings: $a = /[Aa]{p32767}1234.{{1,2}}b/ wide condition: $a }}"
        ),
        // Exercises both `RegexpChainHead` and `RegexpChainTail` when `/s`
        // causes `.{300}` to split the regexp into chained sub-patterns.
        format!(
            "rule test {{ strings: $a = /{p32768}1234.{{1,2}}b.{{300}}{p32768}5678.{{1,2}}d/s wide condition: $a }}"
        ),
    ] {
        let rules = compile(rule.as_str()).unwrap();
        let mut scanner = Scanner::new(&rules);
        // Verify that a suffix without the 32,768-char prefix does not match
        // (previously release builds wrapped `backtrack` modulo 65,536 to 0).
        assert_eq!(
            scanner
                .scan(b"1\x002\x003\x004\x00x\x00b\x00")
                .unwrap()
                .matching_rules()
                .len(),
            0
        );
    }
}

#[test]
fn test_hex_large_and_coalesced_jumps() {
    // 1. Large fixed-size jumps (`[4294967295]`) must compile without
    //    materializing ~8 GiB of zero/mask bytes in `LiteralWithMask`, both
    //    when sub-patterns are long enough to chain (`{ 01 02 ... 03 04 }`)
    //    and when a 1-byte sub-pattern prevents chaining (`{ 01 ... 02 }`).
    for pat in [
        "{ 01 [4294967295] 02 }",
        "{ 01 02 [4294967295] 03 04 }",
        "{ 01 [4294967295] 02 03 }",
        "{ ( 01 [4294967295] 02 | 03 04 ) }",
    ] {
        let rule =
            format!("rule test {{ strings: $a = {pat} condition: $a }}");
        let rules = compile(rule.as_str()).unwrap();
        let mut scanner = Scanner::new(&rules);
        assert_eq!(
            scanner.scan(b"\x01\x02").unwrap().matching_rules().len(),
            0
        );
    }

    // Chained fixed jump `{ 01 02 [5000] 03 04 }` matches across an exact
    // 5,000-byte gap (exceeding the 4,096-byte regexp VM scan limit), and does
    // not match 4,999-byte or 5,001-byte gaps.
    let rules = compile(
        "rule test { strings: $a = { 01 02 [5000] 03 04 } condition: $a }",
    )
    .unwrap();
    let mut scanner = Scanner::new(&rules);
    for (gap_len, expected_matches) in [(4999, 0), (5000, 1), (5001, 0)] {
        let mut buf = vec![0x01, 0x02];
        buf.extend(std::iter::repeat_n(0xff, gap_len));
        buf.extend_from_slice(&[0x03, 0x04]);
        assert_eq!(
            scanner.scan(&buf).unwrap().matching_rules().len(),
            expected_matches
        );
    }

    // 2. Un-split jumps exceeding `u16::MAX` (`65,535`) with a >= 2-byte atom
    //    are compiled for FastVM using `u32` jump operands and must not
    //    truncate `65536` to `0` or `65537` to `1`.
    let rules = compile(
        "rule test { strings: $a = { 01 [65536] 02 03 } condition: $a }",
    )
    .unwrap();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(
        scanner.scan(b"\x01\x02\x03").unwrap().matching_rules().len(),
        0
    );

    let rules = compile(
        "rule test { strings: $a = { 01 [0-65536] 02 03 } condition: $a }",
    )
    .unwrap();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(
        scanner.scan(b"\x01\xff\x02\x03").unwrap().matching_rules().len(),
        1
    );

    let rules = compile(
        "rule test { strings: $a = { 01 [0-65537] 02 03 } condition: $a }",
    )
    .unwrap();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(
        scanner.scan(b"\x01\xff\xff\x02\x03").unwrap().matching_rules().len(),
        1
    );

    // Leading and trailing `JumpExact` in FastVM must check `next_pos <= input.len()`
    // rather than advancing past the input slice bounds.
    for pat in ["/.{10}(ab|cd)/s", "/(ab|cd).{10}/s"] {
        let rule =
            format!("rule test {{ strings: $a = {pat} condition: $a }}");
        let rules = compile(rule.as_str()).unwrap();
        let mut scanner = Scanner::new(&rules);
        assert_eq!(scanner.scan(b"ab").unwrap().matching_rules().len(), 0);
        assert_eq!(
            scanner
                .scan(b"0123456789ab0123456789")
                .unwrap()
                .matching_rules()
                .len(),
            1
        );
    }

    // 3. Consecutive jumps whose coalesced lower or upper bound overflows
    //    `u32::MAX` must fail cleanly with `InvalidPattern` (`E024`).
    for pat in [
        "{ 01 [3000000000] [2000000000] 02 }",
        "{ 01 [0-3000000000] [0-2000000000] 02 }",
        "{ 01 [3000000000-] [2000000000-] 02 }",
        "{ 01 [3000000000] [2000000000] [100] 02 }",
    ] {
        let rule =
            format!("rule test {{ strings: $a = {pat} condition: $a }}");
        let err = compile(rule.as_str()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("jump exceeds maximum allowed bound"), "{msg}");
        assert!(
            msg.contains("consecutive jumps were coalesced into a single one"),
            "{msg}"
        );
    }
}
