use bstr::BString;

use crate::types::TypeValue;

/// A YARA global variable.
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

impl From<f64> for Variable {
    fn from(value: f64) -> Self {
        Variable(TypeValue::Float(Some(value)))
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
