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
