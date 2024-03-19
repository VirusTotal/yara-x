use pretty_assertions::assert_eq;
use serde_json::json;
use std::mem::size_of;

use crate::compiler::{
    SerializationError, SubPattern, Var, VarStack, VariableError,
};
use crate::types::Type;
use crate::{compile, Compiler, Error, Rules, Scanner};

mod errors;
mod warnings;

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
fn unsupported_modules() {
    let mut compiler = Compiler::new();

    compiler
        .ignore_module("foo_module")
        .add_source(
            r#"
            import "foo_module"
            rule ignored { condition: foo_module.some_field == 1 }
            // This rule should match even if the previous one was ignored.
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
