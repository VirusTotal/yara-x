use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::mem;
use std::mem::Discriminant;
use std::sync::Arc;

use bstr::BString;
use lazy_static::lazy_static;

use crate::ast::TypeHint;
use crate::symbols::SymbolLookup;

/// Type of a YARA expression or identifier.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Type {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Struct,
    // The Array variant contains the discriminant corresponding to the
    // type of each item in the array. This implies that we can't have
    // an array of arrays. Doing so would require an Array variant where
    // the discriminant is the one corresponding to the Array variant
    // itself, creating self-referencing structure where the type of the
    // innermost array can't be expressed.
    Array(Discriminant<Type>),
}

lazy_static! {
    // TYPE_DISCRIMINANTS is a map where keys are type discriminants
    // (i.e: Discriminant<Type>), and values are the corresponding Type.
    //
    // This map allows a quick translation from Array(Discriminant<Type>),
    // to the type corresponding to the items in the array. For this reason
    // the map doesn't include entries for Type::Array or Type::Unknown, as
    // arrays of arrays, and arrays of unknown type are not allowed.
    pub(crate) static ref TYPE_DISCRIMINANTS: HashMap<Discriminant<Type>, Type> = {
        HashMap::from([
            (mem::discriminant(&Type::Integer), Type::Integer),
            (mem::discriminant(&Type::Float), Type::Float),
            (mem::discriminant(&Type::Bool), Type::Bool),
            (mem::discriminant(&Type::String), Type::String),
            (mem::discriminant(&Type::Struct), Type::Struct),
        ])
    };
}

impl Type {
    /// Returns the type of the items in an array.
    ///
    /// If this function is called for a [`Type::Array`] variant the result is
    /// the type of the array items. When called with any other [`Type`] variant
    /// the result is [`None`].
    fn array_items_ty(&self) -> Option<Type> {
        if let Type::Array(discriminant) = self {
            TYPE_DISCRIMINANTS.get(discriminant).cloned()
        } else {
            None
        }
    }
}

/// Value of a YARA expression or identifier.
#[derive(Clone)]
pub enum Value {
    Integer(i64),
    Float(f64),
    Bool(bool),
    String(BString),
    Struct(Arc<dyn SymbolLookup + Send + Sync>),
    Array(Vec<Value>),
}

/// Compares two YARA values.
///
/// They are equal if they have the same type and value. Comparing
/// two structures or arrays causes a panic.
impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bool(this), Self::Bool(other)) => this == other,
            (Self::Integer(this), Self::Integer(other)) => this == other,
            (Self::Float(this), Self::Float(other)) => this == other,
            (Self::String(this), Self::String(other)) => this == other,
            (Self::Struct(_), Self::Struct(_)) => {
                panic!("can't compare two structures")
            }
            (Self::Array(_), Self::Array(_)) => {
                panic!("can't compare two arrays")
            }
            _ => false,
        }
    }
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "Bool({:?})", v),
            Self::Integer(v) => write!(f, "Integer({:?})", v),
            Self::Float(v) => write!(f, "Float({:?})", v),
            Self::String(v) => write!(f, "String({:?})", v),
            Self::Struct(_) => write!(f, "Struct"),
            Self::Array(_) => write!(f, "Array"),
        }
    }
}

impl From<Value> for i64 {
    fn from(value: Value) -> Self {
        if let Value::Integer(value) = value {
            value
        } else {
            panic!("can not convert into i64")
        }
    }
}

impl From<Value> for f64 {
    fn from(value: Value) -> Self {
        if let Value::Float(value) = value {
            value
        } else {
            panic!("can not convert into f64")
        }
    }
}

impl From<Value> for bool {
    fn from(value: Value) -> Self {
        if let Value::Bool(value) = value {
            value
        } else {
            panic!("can not convert into bool")
        }
    }
}

/// A type-value pair, where value is optional
#[derive(Clone, PartialEq)]
pub struct TypeValue(Type, Option<Value>);

impl TypeValue {
    pub fn ty(&self) -> Type {
        self.0
    }
    pub fn value(&self) -> Option<&Value> {
        self.1.as_ref()
    }

    pub fn new_integer(i: i64) -> Self {
        Self(Type::Integer, Some(Value::Integer(i)))
    }

    pub fn new_struct(
        symbol_table: Arc<dyn SymbolLookup + Send + Sync>,
    ) -> Self {
        Self(Type::Struct, Some(Value::Struct(symbol_table)))
    }
}

impl From<&TypeHint> for TypeValue {
    fn from(type_hint: &TypeHint) -> Self {
        match type_hint {
            TypeHint::Bool(v) => Self(Type::Bool, v.map(Value::Bool)),
            TypeHint::Integer(v) => Self(Type::Integer, v.map(Value::Integer)),
            TypeHint::Float(v) => Self(Type::Float, v.map(Value::Float)),
            TypeHint::String(v) => Self(
                Type::String,
                v.as_ref().map(|v| Value::String(v.clone())),
            ),
            _ => unreachable!(),
        }
    }
}

impl AsRef<TypeValue> for TypeValue {
    fn as_ref(&self) -> &TypeValue {
        self
    }
}

impl From<Type> for TypeValue {
    fn from(ty: Type) -> Self {
        match ty {
            Type::Unknown => Self(Type::Unknown, None),
            Type::Integer => Self(Type::Integer, None),
            Type::Float => Self(Type::Float, None),
            Type::Bool => Self(Type::Bool, None),
            Type::String => Self(Type::String, None),
            Type::Struct => Self(Type::Struct, None),
            Type::Array(_) => todo!(),
        }
    }
}

impl From<Option<i64>> for TypeValue {
    #[inline]
    fn from(value: Option<i64>) -> Self {
        TypeValue(Type::Integer, value.map(Value::Integer))
    }
}

impl From<Option<i32>> for TypeValue {
    #[inline]
    fn from(value: Option<i32>) -> Self {
        TypeValue(Type::Integer, value.map(|v| Value::Integer(v as i64)))
    }
}

impl From<Option<u32>> for TypeValue {
    #[inline]
    fn from(value: Option<u32>) -> Self {
        TypeValue(Type::Integer, value.map(|v| Value::Integer(v as i64)))
    }
}

impl From<Option<f64>> for TypeValue {
    #[inline]
    fn from(value: Option<f64>) -> Self {
        TypeValue(Type::Float, value.map(Value::Float))
    }
}

impl From<Option<f32>> for TypeValue {
    #[inline]
    fn from(value: Option<f32>) -> Self {
        TypeValue(Type::Float, value.map(|v| Value::Float(v as f64)))
    }
}

impl From<Option<bool>> for TypeValue {
    #[inline]
    fn from(value: Option<bool>) -> Self {
        TypeValue(Type::Bool, value.map(Value::Bool))
    }
}

impl From<Option<&str>> for TypeValue {
    #[inline]
    fn from(value: Option<&str>) -> Self {
        TypeValue(Type::String, value.map(|v| Value::String(BString::from(v))))
    }
}

impl From<Option<BString>> for TypeValue {
    #[inline]
    fn from(value: Option<BString>) -> Self {
        TypeValue(Type::String, value.map(Value::String))
    }
}

impl From<i64> for TypeValue {
    #[inline]
    fn from(value: i64) -> Self {
        TypeValue(Type::Integer, Some(Value::Integer(value)))
    }
}

impl From<f64> for TypeValue {
    #[inline]
    fn from(value: f64) -> Self {
        TypeValue(Type::Float, Some(Value::Float(value)))
    }
}

impl From<bool> for TypeValue {
    #[inline]
    fn from(value: bool) -> Self {
        TypeValue(Type::Bool, Some(Value::Bool(value)))
    }
}

impl From<BString> for TypeValue {
    #[inline]
    fn from(value: BString) -> Self {
        TypeValue(Type::String, Some(Value::String(value)))
    }
}

impl From<&str> for TypeValue {
    #[inline]
    fn from(value: &str) -> Self {
        TypeValue(Type::String, Some(Value::String(BString::from(value))))
    }
}
