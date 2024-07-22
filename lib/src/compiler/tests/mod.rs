use pretty_assertions::assert_eq;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::mem::size_of;

use crate::compiler::{
    SerializationError, SubPattern, Var, VarStack, VariableError,
};
use crate::types::Type;
use crate::{compile, Compiler, Error, Rules, Scanner};

#[test]
fn serialization() {
    assert!(matches!(
        Rules::deserialize([]).err().unwrap(),
        SerializationError::InvalidFormat
    ));

    assert!(matches!(
        Rules::deserialize(b"YARA-X").err().unwrap(),
        SerializationError::InvalidEncoding(_)
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

    assert!(compiler
        .add_source("rule foo {condition: true}")
        .unwrap()
        .add_source("rule bar {condition: foo}")
        .is_ok());

    let mut compiler = Compiler::new();

    // `bar` can't use `foo` because they are in different namespaces, this
    // be a compilation error.
    assert!(compiler
        .add_source("rule foo {condition: true}")
        .unwrap()
        .new_namespace("bar")
        .add_source("rule bar {condition: foo}")
        .is_err());
}

#[test]
fn var_stack() {
    let mut stack = VarStack::new();

    let mut frame1 = stack.new_frame(4);
    let mut frame2 = stack.new_frame(4);

    assert_eq!(
        frame1.new_var(Type::Integer),
        Var { ty: Type::Integer, index: 0 }
    );

    assert_eq!(
        frame1.new_var(Type::String),
        Var { ty: Type::String, index: 1 }
    );

    // The first variable in the frame goes after the first two variables
    // already allocated in the stack.
    assert_eq!(
        frame2.new_var(Type::Integer),
        Var { ty: Type::Integer, index: 4 }
    );

    assert_eq!(
        frame2.new_var(Type::Integer),
        Var { ty: Type::Integer, index: 5 }
    );

    stack.unwind(&frame1);

    assert_eq!(stack.used, 0);
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
}

#[test]
fn globals() {
    let mut compiler = Compiler::new();

    assert_eq!(
        compiler.define_global("#invalid", true).err().unwrap(),
        Error::VariableError(VariableError::InvalidIdentifier(
            "#invalid".to_string()
        ))
    );

    let mut compiler = Compiler::new();

    assert_eq!(
        compiler
            .define_global("a", true)
            .unwrap()
            .define_global("a", false)
            .err()
            .unwrap(),
        Error::VariableError(VariableError::AlreadyExists("a".to_string()))
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
        Error::VariableError(VariableError::InvalidArray)
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_array", json!([1, [2, 3], 4]))
            .unwrap_err(),
        Error::VariableError(VariableError::InvalidArray)
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_array", json!([1, null]))
            .unwrap_err(),
        Error::VariableError(VariableError::InvalidArray)
    );

    assert_eq!(
        Compiler::new()
            .define_global("invalid_array", json!({ "foo": null }))
            .unwrap_err(),
        Error::VariableError(VariableError::UnexpectedNull)
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

#[cfg(feature = "test_proto2-module")]
#[test]
fn import_modules() {
    let mut compiler = Compiler::new();
    assert!(compiler
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
        .is_ok());

    let mut compiler = Compiler::new();
    assert!(compiler
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
        .is_ok());
}

#[test]
fn continue_after_error() {
    let mut compiler = Compiler::new();

    // This rule won't compile because we are using `contains` with an integer.
    assert!(compiler
        .add_source(
            r#"
            rule test {
                condition:
                    for any x in (1,2,3) : ( x contains "foo")
            }"#
        )
        .is_err());

    // Adding a rule with the same name after the previous one failed should
    // be ok.
    assert!(compiler.add_source(r#"rule test { condition: true }"#).is_ok());

    // Now do the same test, but with each rule in a different namespace.
    let mut compiler = Compiler::new();
    compiler.new_namespace("namespace1");

    assert!(compiler
        .add_source(
            r#"
            rule test {
                condition:
                    for any x in (1,2,3) : ( x contains "foo")
            }"#
        )
        .is_err());

    compiler.new_namespace("namespace2");

    assert!(compiler.add_source(r#"rule test { condition: true }"#).is_ok());
}

#[test]
fn errors_2() {
    assert_eq!(
        Compiler::new()
            .define_global("foo", 1)
            .unwrap()
            .add_source("rule foo  {condition: true}")
            .unwrap_err()
            .to_string(),
        "error[E111]: rule `foo` conflicts with an existing identifier
 --> line:1:6
  |
1 | rule foo  {condition: true}
  |      ^^^ identifier already in use by a module or global variable
  |"
    );

    assert_eq!(
        Compiler::new()
            .add_source("rule foo : first {condition: true}")
            .unwrap()
            .add_source("rule foo : second {condition: true}")
            .unwrap_err()
            .to_string(),
        "error[E110]: duplicate rule `foo`
 --> line:1:6
  |
1 | rule foo : first {condition: true}
  |      --- note: `foo` declared here for the first time
  |
 ::: line:1:6
  |
1 | rule foo : second {condition: true}
  |      ^^^ duplicate declaration of `foo`
  |"
    );

    #[cfg(feature = "constant-folding")]
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
        "error[E105]: number out of range
 --> line:3:4
  |
3 |    9223372036854775807 + 1000000000 == 0
  |    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this number is out of the allowed range [-9223372036854775808-9223372036854775807]
  |"
    );
}

// TODO
/*
#[test]
fn utf8_errors() {
    let mut src =
        "rule test {condition: true}".to_string().as_bytes().to_vec();

    // Insert invalid UTF-8 in the code.
    src.insert(4, 0xff);

    assert_eq!(
        Parser::new(src.as_slice().as_bytes())
            .into_ast(src.as_slice())
            .expect_err("expected error")
            .to_string(),
        "error[E017]: invalid UTF-8
 --> line:1:5
  |
1 | rule� test {condition: true}
  |     ^ invalid UTF-8 character
  |"
    );
}
*/

#[test]
fn test_errors() {
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/compiler/tests/testdata/errors/*.in")
        .unwrap()
        .flatten()
    {
        // Path to the .in file.
        let in_path = entry.into_path();

        println!("{:?}", in_path);

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

        src.push_str(rules.as_str());

        let err = compile(src.as_str()).expect_err(
            format!("file {:?} should have failed", in_path).as_str(),
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

        src.push_str(rules.as_str());

        let mut compiler = Compiler::new();

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
