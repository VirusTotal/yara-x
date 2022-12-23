use crate::types::{Struct, Type, TypeValue};
use bstr::BString;
use std::rc::Rc;

pub enum Array {
    Integer(Vec<i64>),
    Float(Vec<f64>),
    Bool(Vec<bool>),
    String(Vec<BString>),
    Struct(Vec<Rc<Struct>>),
}

impl Array {
    pub fn item_type(&self) -> Type {
        match self {
            Array::Integer(_) => Type::Integer,
            Array::Float(_) => Type::Float,
            Array::Bool(_) => Type::Bool,
            Array::String(_) => Type::String,
            Array::Struct(_) => Type::Struct,
        }
    }

    pub fn deputy(&self) -> TypeValue {
        match self {
            Array::Integer(_) => TypeValue::Integer(None),
            Array::Float(_) => TypeValue::Float(None),
            Array::Bool(_) => TypeValue::Bool(None),
            Array::String(_) => TypeValue::String(None),
            Array::Struct(s) => TypeValue::Struct(s.first().unwrap().clone()),
        }
    }

    pub fn as_integer_array(&self) -> &Vec<i64> {
        if let Self::Integer(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_float_array(&self) -> &Vec<f64> {
        if let Self::Float(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_bool_array(&self) -> &Vec<bool> {
        if let Self::Bool(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_string_array(&self) -> &Vec<BString> {
        if let Self::String(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_struct_array(&self) -> &Vec<Rc<Struct>> {
        if let Self::Struct(v) = self {
            v
        } else {
            panic!()
        }
    }
}
