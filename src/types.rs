use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::mem;
use std::mem::Discriminant;
use std::sync::Arc;

use bstr::BString;

use crate::ast::TypeHint;
use crate::symbols::{SymbolIndex, SymbolLookup};

/// Type of a YARA expression or identifier.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Type {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Struct,
    Array(ArrayItemType),
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ArrayItemType {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Struct,
}

/// Value of a YARA expression or identifier.
#[derive(Clone)]
pub enum Value {
    Integer(i64),
    Float(f64),
    Bool(bool),
    String(BString),
    Struct(Arc<dyn SymbolLookup + Send + Sync>),
    Array(Arc<dyn SymbolIndex + Send + Sync>),
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

impl From<ArrayItemType> for Type {
    fn from(array_item_ty: ArrayItemType) -> Self {
        match array_item_ty {
            ArrayItemType::Unknown => Self::Unknown,
            ArrayItemType::Integer => Self::Integer,
            ArrayItemType::Float => Self::Float,
            ArrayItemType::Bool => Self::Bool,
            ArrayItemType::String => Self::String,
            ArrayItemType::Struct => Self::Struct,
        }
    }
}

impl From<Type> for ArrayItemType {
    fn from(ty: Type) -> Self {
        match ty {
            Type::Unknown => Self::Unknown,
            Type::Integer => Self::Integer,
            Type::Float => Self::Float,
            Type::Bool => Self::Bool,
            Type::String => Self::String,
            Type::Struct => Self::Struct,
            Type::Array(_) => panic!("array of arrays are not supported"),
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

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Self::Float(value as f64)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(BString::from(value))
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
