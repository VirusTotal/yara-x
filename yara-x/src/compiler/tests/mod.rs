use pretty_assertions::assert_eq;

use crate::compiler::{SerializationError, Var, VarStack, VariableError};
use crate::types::Type;
use crate::{compile, Compiler, Rules, Scanner};

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
    assert_eq!(scanner.scan(b"foo").num_matching_rules(), 1);
}

#[test]
fn namespaces() {
    // `foo` and `bar` are both in the default namespace, this compiles
    // correctly.
    assert!(Compiler::new()
        .add_source("rule foo {condition: true}")
        .unwrap()
        .add_source("rule bar {condition: foo}")
        .is_ok());

    // `bar` can't use `foo` because they are in different namespaces, this
    // be a compilation error.
    assert!(Compiler::new()
        .add_source("rule foo {condition: true}")
        .unwrap()
        .new_namespace("bar")
        .add_source("rule bar {condition: foo}")
        .is_err());

    assert_eq!(
        Compiler::new()
            .define_global("foo", 1)
            .unwrap()
            .add_source("rule foo  {condition: true}")
            .unwrap_err()
            .to_string(),
        "error: duplicate identifier `foo`
   ╭─[line:1:6]
   │
 1 │ rule foo  {condition: true}
   │      ─┬─  
   │       ╰─── duplicate declaration of `foo`
───╯
"
    );

    assert_eq!(
        Compiler::new()
            .add_source("rule foo : first {condition: true}")
            .unwrap()
            .add_source("rule foo : second {condition: true}")
            .unwrap_err()
            .to_string(),
        "error: duplicate rule `foo`
   ╭─[line:1:6]
   │
 1 │ rule foo : first {condition: true}
   │      ─┬─  
   │       ╰─── `foo` declared here for the first time
   │
   ├─[line:1:6]
   │
 1 │ rule foo : second {condition: true}
   │      ─┬─  
   │       ╰─── duplicate declaration of `foo`
───╯
"
    );
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
fn globals() {
    assert_eq!(
        Compiler::new().define_global("#invalid", true).err().unwrap(),
        VariableError::InvalidIdentifier("#invalid".to_string())
    );

    assert_eq!(
        Compiler::new()
            .define_global("a", true)
            .unwrap()
            .define_global("a", false)
            .err()
            .unwrap(),
        VariableError::AlreadyExists("a".to_string())
    );

    let rules = Compiler::new()
        .define_global("int_1", 1u8)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("int_1", 1u16)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("int_1", 1u32)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("int_1", 1i8)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("int_1", 1i16)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("int_1", 1i32)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("int_1", 1i64)
        .unwrap()
        .add_source("rule foo {condition: int_1 == 1}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("float_1", 1_f32)
        .unwrap()
        .add_source("rule foo {condition: float_1 == 1.0}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("float_1", 1_f64)
        .unwrap()
        .add_source("rule foo {condition: float_1 == 1.0}")
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("str_foo", "foo")
        .unwrap()
        .add_source(r#"rule foo {condition: str_foo == "foo"}"#)
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("bstr_foo", b"\0\0".as_slice())
        .unwrap()
        .add_source(r#"rule foo {condition: bstr_foo == "\0\0"}"#)
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);

    let rules = Compiler::new()
        .define_global("str_foo", "foo".to_string())
        .unwrap()
        .add_source(r#"rule foo {condition: str_foo == "foo"}"#)
        .unwrap()
        .build();

    assert_eq!(Scanner::new(&rules).scan(&[]).num_matching_rules(), 1);
}
