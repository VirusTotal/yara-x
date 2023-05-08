use crate::compiler::{SerializationError, Var, VarStack};
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
