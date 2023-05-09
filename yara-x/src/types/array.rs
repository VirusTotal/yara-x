use crate::types::{Struct, TypeValue};
use bstr::BString;
use std::rc::Rc;

pub enum Array {
    Integers(Vec<i64>),
    Floats(Vec<f64>),
    Bools(Vec<bool>),
    Strings(Vec<BString>),
    Structs(Vec<Rc<Struct>>),
}

impl Array {
    pub fn deputy(&self) -> TypeValue {
        match self {
            Array::Integers(_) => TypeValue::Integer(None),
            Array::Floats(_) => TypeValue::Float(None),
            Array::Bools(_) => TypeValue::Bool(None),
            Array::Strings(_) => TypeValue::String(None),
            Array::Structs(s) => TypeValue::Struct(s.first().unwrap().clone()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        match self {
            Array::Integers(a) => a.len(),
            Array::Floats(a) => a.len(),
            Array::Bools(a) => a.len(),
            Array::Strings(a) => a.len(),
            Array::Structs(a) => a.len(),
        }
    }

    pub fn as_integer_array(&self) -> &Vec<i64> {
        if let Self::Integers(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_float_array(&self) -> &Vec<f64> {
        if let Self::Floats(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_bool_array(&self) -> &Vec<bool> {
        if let Self::Bools(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_string_array(&self) -> &Vec<BString> {
        if let Self::Strings(v) = self {
            v
        } else {
            panic!()
        }
    }

    pub fn as_struct_array(&self) -> &Vec<Rc<Struct>> {
        if let Self::Structs(v) = self {
            v
        } else {
            panic!()
        }
    }
}
