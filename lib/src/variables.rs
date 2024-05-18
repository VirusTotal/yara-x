/*! This module implements the [`Variable`] type.

[`Variable`] is just a wrapper around [`TypeValue`]. Instead of exposing
the internal [`TypeValue`] type in the public API we expose [`Variable`]
instead, decoupling the API from internal implementation details.

API functions like [`crate::Compiler::define_global`] expect Rust types that
implement the [`Into<Variable>`] trait. This module implements the trait for
multiple commonly used types like `bool`, `i64`, `&str`, etc.
 */
use std::rc::Rc;

use bstr::BString;
use thiserror::Error;

use crate::types;
use crate::types::{Array, TypeValue, Value};

/// Represents a YARA variable.
///
/// Functions like [`crate::Compiler::define_global`] expect types that
/// implement [`Into<Variable>`].
pub struct Variable(TypeValue);

/// Errors returned while defining or setting variables.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum VariableError {
    /// The variable has not being defined. Before calling
    /// [`crate::Scanner::set_global`] the variable must be defined with a
    /// call to [`crate::Compiler::define_global`].
    #[error("variable `{0}` not defined")]
    Undefined(String),

    /// A variable with the same name already exists.
    #[error("variable `{0}` already exists")]
    AlreadyExists(String),

    /// The identifier is not valid. Identifiers can only contain alphanumeric
    /// characters and underscores, and can't start with a digit.
    #[error("invalid variable identifier `{0}`")]
    InvalidIdentifier(String),

    /// The value of a variable cannot be null. This may happen when using a
    /// [`serde_json::Value`], as JSON values can be null.
    #[error("null values are not accepted")]
    UnexpectedNull,

    /// Invalid array. Arrays can't be empty, and all items must be non-null
    /// and have the same type.
    #[error("arrays can't be empty and all items must be non-null and the same type")]
    InvalidArray,

    /// Integer value is out of range.
    #[error("integer value is out of range")]
    IntegerOutOfRange,

    /// A variable has been previously defined with a different type. You can
    /// not call [`crate::Scanner::set_global`] and pass a value that don't
    /// match the already defined type.
    #[error(
        "invalid type for `{variable}`, expecting `{expected_type}`, got `{actual_type}"
    )]
    InvalidType {
        /// Variable name.
        variable: String,
        /// Name of the expected type.
        expected_type: String,
        /// Name of the actual type.
        actual_type: String,
    },
}

impl TryFrom<bool> for Variable {
    type Error = VariableError;
    fn try_from(value: bool) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_bool_from(value)))
    }
}

impl TryFrom<i64> for Variable {
    type Error = VariableError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_integer_from(value)))
    }
}

impl TryFrom<i32> for Variable {
    type Error = VariableError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_integer_from(value)))
    }
}

impl TryFrom<i16> for Variable {
    type Error = VariableError;
    fn try_from(value: i16) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_integer_from(value)))
    }
}

impl TryFrom<i8> for Variable {
    type Error = VariableError;
    fn try_from(value: i8) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_integer_from(value)))
    }
}

impl TryFrom<u32> for Variable {
    type Error = VariableError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_integer_from(value)))
    }
}

impl TryFrom<u16> for Variable {
    type Error = VariableError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_integer_from(value)))
    }
}

impl TryFrom<u8> for Variable {
    type Error = VariableError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_integer_from(value)))
    }
}

impl TryFrom<f64> for Variable {
    type Error = VariableError;
    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_float_from(value)))
    }
}

impl TryFrom<f32> for Variable {
    type Error = VariableError;
    fn try_from(value: f32) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_float_from(value)))
    }
}

impl TryFrom<&str> for Variable {
    type Error = VariableError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_string_from(value)))
    }
}

impl TryFrom<&[u8]> for Variable {
    type Error = VariableError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_string_from(value)))
    }
}

impl TryFrom<String> for Variable {
    type Error = VariableError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Variable(TypeValue::var_string_from(value)))
    }
}

impl TryFrom<serde_json::Value> for Variable {
    type Error = VariableError;
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        Variable::try_from(&value)
    }
}

impl TryFrom<&serde_json::Value> for Variable {
    type Error = VariableError;
    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Null => Err(VariableError::UnexpectedNull),
            serde_json::Value::Bool(b) => {
                Ok(Variable(TypeValue::Bool(Value::Var(*b))))
            }
            serde_json::Value::Number(n) => {
                if let Some(n) = n.as_u64() {
                    Ok(Variable(TypeValue::Integer(Value::Var(
                        n.try_into()
                            .map_err(|_| VariableError::IntegerOutOfRange)?,
                    ))))
                } else if let Some(n) = n.as_i64() {
                    Ok(Variable(TypeValue::var_integer_from(n)))
                } else if let Some(n) = n.as_f64() {
                    Ok(Variable(TypeValue::var_float_from(n)))
                } else {
                    unreachable!()
                }
            }
            serde_json::Value::String(s) => {
                Ok(Variable(TypeValue::var_string_from(s)))
            }
            serde_json::Value::Array(values) => {
                let mut array = None;
                // Try to determine the type of the array by looking at the
                // type of the first non-null item.
                for v in values {
                    if v.is_boolean() {
                        array = Some(Array::Bools(Vec::new()));
                        break;
                    } else if v.is_i64() {
                        array = Some(Array::Integers(Vec::new()));
                        break;
                    } else if v.is_f64() {
                        array = Some(Array::Floats(Vec::new()));
                        break;
                    } else if v.is_string() {
                        array = Some(Array::Strings(Vec::new()));
                        break;
                    } else if v.is_object() {
                        array = Some(Array::Structs(Vec::new()));
                        break;
                    } else if v.is_array() {
                        // Arrays can't be nested.
                        return Err(VariableError::InvalidArray);
                    }
                }

                // If the array is empty or all the items are null we can't
                // determine the type of the array, and that's not allowed.
                if array.is_none() {
                    return Err(VariableError::InvalidArray);
                }

                let mut array = array.unwrap();

                match array {
                    Array::Integers(ref mut integers) => {
                        for v in values {
                            match v.as_i64() {
                                Some(v) => {
                                    integers.push(v);
                                }
                                None => {
                                    return Err(VariableError::InvalidArray);
                                }
                            };
                        }
                    }
                    Array::Floats(ref mut floats) => {
                        for v in values {
                            match v.as_f64() {
                                Some(v) => {
                                    floats.push(v);
                                }
                                None => {
                                    return Err(VariableError::InvalidArray);
                                }
                            };
                        }
                    }
                    Array::Bools(ref mut bools) => {
                        for v in values {
                            match v.as_bool() {
                                Some(v) => {
                                    bools.push(v);
                                }
                                None => {
                                    return Err(VariableError::InvalidArray);
                                }
                            };
                        }
                    }
                    Array::Strings(ref mut strings) => {
                        for v in values {
                            match v.as_str() {
                                Some(v) => {
                                    strings.push(BString::from(v).into());
                                }
                                None => {
                                    return Err(VariableError::InvalidArray);
                                }
                            };
                        }
                    }
                    Array::Structs(ref mut structs) => {
                        for v in values {
                            match v.as_object() {
                                Some(v) => {
                                    let mut s = types::Struct::new();
                                    for (key, value) in v {
                                        s.add_field(
                                            key,
                                            TypeValue::from(
                                                Variable::try_from(value)?,
                                            ),
                                        );
                                    }
                                    structs.push(Rc::new(s));
                                }
                                None => {
                                    return Err(VariableError::InvalidArray);
                                }
                            };
                        }
                    }
                }
                Ok(Variable(TypeValue::Array(Rc::new(array))))
            }
            serde_json::Value::Object(obj) => {
                let mut s = types::Struct::new();
                for (key, value) in obj {
                    s.add_field(
                        key,
                        TypeValue::from(Variable::try_from(value)?),
                    );
                }
                Ok(Variable(TypeValue::Struct(Rc::new(s))))
            }
        }
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

    // The remaining characters must be letters, numbers, or underscores.
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
