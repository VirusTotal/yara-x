use std::fmt::{Debug, Display, Formatter};
use std::rc::Rc;

use bstr::ByteSlice;
use bstr::{BStr, BString};
use serde::{Deserialize, Serialize};
use walrus::ValType;

mod array;
mod func;
mod map;
mod structure;

pub use array::*;
pub use func::*;
pub use map::*;
pub use structure::*;

/// The type of a YARA expression or identifier.
#[derive(Clone, Copy, PartialEq)]
pub enum Type {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Regexp,
    Struct,
    Array,
    Map,
    Func,
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Debug for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::Bool => write!(f, "boolean"),
            Self::String => write!(f, "string"),
            Self::Regexp => write!(f, "regexp"),
            Self::Struct => write!(f, "struct"),
            Self::Array => write!(f, "array"),
            Self::Map => write!(f, "map"),
            Self::Func => write!(f, "function"),
        }
    }
}

impl From<Type> for ValType {
    fn from(ty: Type) -> ValType {
        match ty {
            Type::Integer => ValType::I64,
            Type::Float => ValType::F64,
            Type::Bool => ValType::I32,
            Type::String => ValType::I64,
            _ => panic!("can not create WASM primitive type for `{}`", ty),
        }
    }
}

/// Contains information about a value.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Value<T> {
    /// Constant value. The value is known and it can not change at runtime.
    Const(T),
    /// Variable value. The value is known, but it can change at runtime.
    Var(T),
    /// Unknown value.
    Unknown,
}

impl<T> Value<T> {
    /// Returns true if the value is constant.
    ///
    /// A constant value can not change at runtime.
    #[inline]
    pub fn is_const(&self) -> bool {
        matches!(self, Value::Const(_))
    }

    /// Extract the value of type `T` contained inside [`Value`].
    ///
    /// Returns [`Some(T)`] if the value is known or [`None`] if it's unknown.
    pub fn extract(&self) -> Option<&T> {
        match self {
            Value::Const(v) | Value::Var(v) => Some(v),
            Value::Unknown => None,
        }
    }
}

/// A simple wrapper around [`String`] that represents a regular expression.
///
/// The string must be enclosed in slashes (`/`), optionally followed by the
/// `i` or `s` modifiers, or both. Some example of valid strings are:
///
/// ```text
/// /foobar/
/// /foobar/i
/// /foobar/s
/// /foobar/is
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regexp(String);

impl Regexp {
    pub fn new<R: AsRef<str>>(regexp: R) -> Self {
        let regexp = regexp.as_ref();

        assert!(regexp.starts_with('/'));
        assert!(regexp[1..].contains('/'));

        Self(regexp.to_string())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns the portion of the regexp within the starting and ending slashes.
    ///
    /// For example, for `/foobar/` returns `foobar`.
    pub fn naked(&self) -> &str {
        &self.0[1..self.0.rfind('/').unwrap()]
    }

    pub fn case_insensitive(&self) -> bool {
        let modifiers = &self.0[self.0.rfind('/').unwrap()..];
        modifiers.contains('i')
    }

    pub fn dot_matches_new_line(&self) -> bool {
        let modifiers = &self.0[self.0.rfind('/').unwrap()..];
        modifiers.contains('s')
    }
}

/// A [`TypeValue`] contains information about the type, and possibly the
/// value of a YARA expression or identifier.
///
/// In the case of primitive types (integer, float, bool and string), the
/// value can be constant, variable, or unknown. Structs, arrays and maps
/// always have a reference to a [`Struct`], [`Array`] or [`Map`] respectively,
/// but those structures, arrays and maps don't contain actual values at
/// compile time, they only provide details about the type, like for example,
/// which are the fields in a struct, or what's the type of the items in an
/// array.
#[derive(Clone, Serialize, Deserialize)]
pub enum TypeValue {
    Unknown,
    Integer(Value<i64>),
    Float(Value<f64>),
    Bool(Value<bool>),
    String(Value<BString>),
    Regexp(Option<Regexp>),
    Struct(Rc<Struct>),
    Array(Rc<Array>),
    Map(Rc<Map>),

    // A TypeValue that contains a function is not serialized.
    #[serde(skip)]
    Func(Rc<Func>),
}

impl TypeValue {
    pub fn is_const(&self) -> bool {
        match self {
            TypeValue::Unknown => false,
            TypeValue::Integer(value) => value.is_const(),
            TypeValue::Float(value) => value.is_const(),
            TypeValue::Bool(value) => value.is_const(),
            TypeValue::String(value) => value.is_const(),
            TypeValue::Regexp(_) => false,
            TypeValue::Struct(_) => false,
            TypeValue::Array(_) => false,
            TypeValue::Map(_) => false,
            TypeValue::Func(_) => false,
        }
    }

    /// Compares the types of two [`TypeValue`] instances, returning true if
    /// they are equal. The values can differ, only the types are taken into
    /// account.
    ///
    /// Instances of [`TypeValue::Struct`] are equal if both structures have
    /// the same fields and the type of each field matches.
    pub fn eq_type(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Integer(_), Self::Integer(_)) => true,
            (Self::Float(_), Self::Float(_)) => true,
            (Self::String(_), Self::String(_)) => true,
            (Self::Bool(_), Self::Bool(_)) => true,
            (Self::Array(a), Self::Array(b)) => {
                a.deputy().eq_type(&b.deputy())
            }
            (Self::Map(a), Self::Map(b)) => match (a.as_ref(), b.as_ref()) {
                (Map::StringKeys { .. }, Map::StringKeys { .. }) => {
                    a.deputy().eq_type(&b.deputy())
                }
                (Map::IntegerKeys { .. }, Map::IntegerKeys { .. }) => {
                    a.deputy().eq_type(&b.deputy())
                }
                _ => false,
            },
            (Self::Struct(a), Self::Struct(b)) => a.eq(b),
            _ => false,
        }
    }

    pub fn ty(&self) -> Type {
        match self {
            Self::Unknown => Type::Unknown,
            Self::Integer(_) => Type::Integer,
            Self::Float(_) => Type::Float,
            Self::Bool(_) => Type::Bool,
            Self::String(_) => Type::String,
            Self::Regexp(_) => Type::Regexp,
            Self::Map(_) => Type::Map,
            Self::Struct(_) => Type::Struct,
            Self::Array(_) => Type::Array,
            Self::Func(_) => Type::Func,
        }
    }

    pub fn clone_without_value(&self) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::Integer(_) => Self::Integer(Value::Unknown),
            Self::Float(_) => Self::Float(Value::Unknown),
            Self::Bool(_) => Self::Bool(Value::Unknown),
            Self::String(_) => Self::String(Value::Unknown),
            Self::Regexp(_) => Self::Regexp(None),
            Self::Map(v) => Self::Map(v.clone()),
            Self::Struct(v) => Self::Struct(v.clone()),
            Self::Array(v) => Self::Array(v.clone()),
            Self::Func(v) => Self::Func(v.clone()),
        }
    }

    /// Casts a [`TypeValue`] to [`TypeValue::Bool`].
    ///
    /// # Panics
    ///
    /// If the [`TypeValue`] has a type that can't be casted to bool. Only
    /// integers, floats, and strings and bools can be casted to bool.
    pub fn cast_to_bool(&self) -> Self {
        match self {
            Self::Integer(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::Integer(Value::Var(i)) => Self::Bool(Value::Var(*i != 0)),
            Self::Integer(Value::Const(i)) => {
                Self::Bool(Value::Const(*i != 0))
            }

            Self::Float(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::Float(Value::Var(f)) => Self::Bool(Value::Var(*f != 0.0)),
            Self::Float(Value::Const(f)) => {
                Self::Bool(Value::Const(*f != 0.0))
            }

            Self::String(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::String(Value::Var(s)) => Self::Bool(Value::Var(s.len() > 0)),
            Self::String(Value::Const(s)) => {
                Self::Bool(Value::Const(s.len() > 0))
            }

            Self::Bool(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::Bool(Value::Var(b)) => Self::Bool(Value::Var(*b)),
            Self::Bool(Value::Const(b)) => Self::Bool(Value::Const(*b)),

            _ => panic!("can not cast {:?} to bool", self),
        }
    }

    pub fn as_bstr(&self) -> &BStr {
        if let TypeValue::String(v) = self {
            v.extract()
                .expect("TypeValue doesn't have an associated value")
                .as_bstr()
        } else {
            panic!(
                "called `as_bstr` on a TypeValue that is not TypeValue::String, it is: {:?}",
                self
            )
        }
    }

    pub fn as_array(&self) -> Rc<Array> {
        if let TypeValue::Array(array) = self {
            array.clone()
        } else {
            panic!(
                "called `as_array` on a TypeValue that is not TypeValue::Array, it is: {:?}",
                self
            )
        }
    }

    pub fn as_struct(&self) -> Rc<Struct> {
        if let TypeValue::Struct(structure) = self {
            structure.clone()
        } else {
            panic!(
                "called `as_struct` on a TypeValue that is not TypeValue::Struct, it is: {:?}",
                self
            )
        }
    }

    pub fn as_map(&self) -> Rc<Map> {
        if let TypeValue::Map(map) = self {
            map.clone()
        } else {
            panic!(
                "called `as_map` on a TypeValue that is not TypeValue::Map, it is: {:?}",
                self
            )
        }
    }

    pub fn as_func(&self) -> Rc<Func> {
        if let TypeValue::Func(func) = self {
            func.clone()
        } else {
            panic!(
                "called `as_func` on a TypeValue that is not TypeValue::Func, it is: {:?}",
                self
            )
        }
    }

    pub fn as_integer(&self) -> i64 {
        if let TypeValue::Integer(value) = self {
            value
                .extract()
                .cloned()
                .expect("TypeValue doesn't have an associated value")
        } else {
            panic!(
                "called `as_integer` on a TypeValue that is not TypeValue::Integer, it is: {:?}",
                self
            )
        }
    }

    pub fn as_float(&self) -> f64 {
        if let TypeValue::Float(value) = self {
            value
                .extract()
                .cloned()
                .expect("TypeValue doesn't have an associated value")
        } else {
            panic!(
                "called `as_float` on a TypeValue that is not TypeValue::Float, it is: {:?}",
                self
            )
        }
    }

    pub fn as_bool(&self) -> bool {
        if let TypeValue::Bool(value) = self {
            value
                .extract()
                .cloned()
                .expect("TypeValue doesn't have an associated value")
        } else {
            panic!(
                "called `as_bool` on a TypeValue that is not TypeValue::Bool, it is: {:?}",
                self
            )
        }
    }

    pub fn try_as_bool(&self) -> Option<bool> {
        if let TypeValue::Bool(value) = self {
            value.extract().cloned()
        } else {
            None
        }
    }

    pub fn try_as_integer(&self) -> Option<i64> {
        if let TypeValue::Integer(value) = self {
            value.extract().cloned()
        } else {
            None
        }
    }
}

impl Display for TypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Debug for TypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Bool(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "boolean({:?})", v)
                } else {
                    write!(f, "boolean(unknown)")
                }
            }
            Self::Integer(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "integer({:?})", v)
                } else {
                    write!(f, "integer(unknown)")
                }
            }
            Self::Float(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "float({:?})", v)
                } else {
                    write!(f, "float(unknown)")
                }
            }
            Self::String(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "string({:?})", v)
                } else {
                    write!(f, "string(unknown)")
                }
            }
            Self::Regexp(v) => {
                if let Some(v) = v {
                    write!(f, "regexp({:?})", v)
                } else {
                    write!(f, "regexp(unknown)")
                }
            }
            Self::Map(_) => write!(f, "map"),
            Self::Struct(_) => write!(f, "struct"),
            Self::Array(_) => write!(f, "array"),
            Self::Func(_) => write!(f, "function"),
        }
    }
}

#[cfg(test)]
impl PartialEq for TypeValue {
    fn eq(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (Self::Unknown, Self::Unknown) => true,
            (Self::String(lhs), Self::String(rhs)) => lhs == rhs,
            (Self::Bool(lhs), Self::Bool(rhs)) => lhs == rhs,
            (Self::Integer(lhs), Self::Integer(rhs)) => lhs == rhs,
            (Self::Float(lhs), Self::Float(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}
