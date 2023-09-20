/*! This module implements the [`Variable`] type.

[`Variable`] is just a wrapper around [`TypeValue`]. Instead of exposing
the internal [`TypeValue`] type in the public API we expose [`Variable`]
instead, decoupling the API from internal implementation details.

API functions like [`crate::Compiler::define_global`] expect Rust types that
implement the [`Into<Variable>`] trait. This module implements the trait for
multiple commonly used types like `bool`, `i64`, `&str`, etc.
 */
use bstr::BString;
use thiserror::Error;

use crate::types::{TypeValue, Value};

/// Represents a YARA variable.
///
/// Functions like [`crate::Compiler::define_global`] expect types that
/// implement [`Into<Variable>`].
pub struct Variable(TypeValue);

/// Errors returned while defining or setting variables.
#[derive(Error, Debug, PartialEq)]
pub enum VariableError {
    #[error("variable `{0}` not declared")]
    Undeclared(String),

    #[error("variable `{0}` already exists")]
    AlreadyExists(String),

    #[error("invalid variable identifier `{0}`")]
    InvalidIdentifier(String),

    #[error(
        "invalid type for `{variable}`, expecting `{expected_type}`, got `{actual_type}"
    )]
    InvalidType {
        variable: String,
        expected_type: String,
        actual_type: String,
    },
}

impl From<bool> for Variable {
    fn from(value: bool) -> Self {
        Variable(TypeValue::Bool(Value::Var(value)))
    }
}

impl From<i64> for Variable {
    fn from(value: i64) -> Self {
        Variable(TypeValue::Integer(Value::Var(value)))
    }
}

impl From<i32> for Variable {
    fn from(value: i32) -> Self {
        Variable(TypeValue::Integer(Value::Var(value.into())))
    }
}

impl From<i16> for Variable {
    fn from(value: i16) -> Self {
        Variable(TypeValue::Integer(Value::Var(value.into())))
    }
}

impl From<i8> for Variable {
    fn from(value: i8) -> Self {
        Variable(TypeValue::Integer(Value::Var(value.into())))
    }
}

impl From<u32> for Variable {
    fn from(value: u32) -> Self {
        Variable(TypeValue::Integer(Value::Var(value.into())))
    }
}

impl From<u16> for Variable {
    fn from(value: u16) -> Self {
        Variable(TypeValue::Integer(Value::Var(value.into())))
    }
}

impl From<u8> for Variable {
    fn from(value: u8) -> Self {
        Variable(TypeValue::Integer(Value::Var(value.into())))
    }
}

impl From<f64> for Variable {
    fn from(value: f64) -> Self {
        Variable(TypeValue::Float(Value::Var(value)))
    }
}

impl From<f32> for Variable {
    fn from(value: f32) -> Self {
        Variable(TypeValue::Float(Value::Var(value.into())))
    }
}

impl From<&str> for Variable {
    fn from(value: &str) -> Self {
        Variable(TypeValue::String(Value::Var(BString::from(value))))
    }
}

impl From<&[u8]> for Variable {
    fn from(value: &[u8]) -> Self {
        Variable(TypeValue::String(Value::Var(BString::from(value))))
    }
}

impl From<String> for Variable {
    fn from(value: String) -> Self {
        Variable(TypeValue::String(Value::Var(BString::from(value))))
    }
}

impl From<Variable> for TypeValue {
    fn from(value: Variable) -> Self {
        value.0
    }
}

/// Returns true if the given identifier is a valid one.
///
/// Valid identifiers are composed of letters, digits, and the underscore (_)
/// character, but they can't start with a digit.
pub fn is_valid_identifier(ident: &str) -> bool {
    let mut chars = ident.chars();

    if let Some(first) = chars.next() {
        // The first character must be a letter or underscore.
        if !first.is_alphabetic() && first != '_' {
            return false;
        }
    } else {
        // No first char, ident is empty.
        return false;
    }

    // The the remaining characters must be letters, numbers, or underscores.
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod test {
    #[test]
    fn is_valid_identifier() {
        // Valid identifiers
        assert!(super::is_valid_identifier("a"));
        assert!(super::is_valid_identifier("_"));
        assert!(super::is_valid_identifier("foo"));
        assert!(super::is_valid_identifier("_foo"));

        // Invalid identifiers
        assert!(!super::is_valid_identifier("123"));
        assert!(!super::is_valid_identifier("1foo"));
        assert!(!super::is_valid_identifier("foo|"));
        assert!(!super::is_valid_identifier("foo.bar"));
    }
}
