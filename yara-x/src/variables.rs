/*! This module implements the [`Variable`] type.

The [`Variable`] is just a wrapper around [`TypeValue`]. Instead of exposing
the internal [`TypeValue`] type in the public API we expose [`Variable`]
instead, decoupling the API from internal implementation details.

API functions like [`crate::Compiler::define_global`] expect Rust types that
implement the [`Into<Variable>`] trait. This module implements the trait for
multiple commonly used types like `bool`, `i64`, `&str`, etc.
 */
use bstr::BString;

use crate::types::TypeValue;

/// Represents a YARA variable.
///
/// Functions like [`crate::Compiler::define_global`] expect types that
/// implement [`Into<Variable>`].
pub struct Variable(TypeValue);

impl From<bool> for Variable {
    fn from(value: bool) -> Self {
        Variable(TypeValue::Bool(Some(value)))
    }
}

impl From<i64> for Variable {
    fn from(value: i64) -> Self {
        Variable(TypeValue::Integer(Some(value)))
    }
}

impl From<i32> for Variable {
    fn from(value: i32) -> Self {
        Variable(TypeValue::Integer(Some(value.into())))
    }
}

impl From<i16> for Variable {
    fn from(value: i16) -> Self {
        Variable(TypeValue::Integer(Some(value.into())))
    }
}

impl From<i8> for Variable {
    fn from(value: i8) -> Self {
        Variable(TypeValue::Integer(Some(value.into())))
    }
}

impl From<u32> for Variable {
    fn from(value: u32) -> Self {
        Variable(TypeValue::Integer(Some(value.into())))
    }
}

impl From<u16> for Variable {
    fn from(value: u16) -> Self {
        Variable(TypeValue::Integer(Some(value.into())))
    }
}

impl From<u8> for Variable {
    fn from(value: u8) -> Self {
        Variable(TypeValue::Integer(Some(value.into())))
    }
}

impl From<f64> for Variable {
    fn from(value: f64) -> Self {
        Variable(TypeValue::Float(Some(value)))
    }
}

impl From<f32> for Variable {
    fn from(value: f32) -> Self {
        Variable(TypeValue::Float(Some(value.into())))
    }
}

impl From<&str> for Variable {
    fn from(value: &str) -> Self {
        Variable(TypeValue::String(Some(BString::from(value))))
    }
}

impl From<&[u8]> for Variable {
    fn from(value: &[u8]) -> Self {
        Variable(TypeValue::String(Some(BString::from(value))))
    }
}

impl From<String> for Variable {
    fn from(value: String) -> Self {
        Variable(TypeValue::String(Some(BString::from(value))))
    }
}

impl From<Variable> for TypeValue {
    fn from(value: Variable) -> Self {
        value.0
    }
}
