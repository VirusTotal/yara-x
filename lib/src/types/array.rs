use std::cell::OnceCell;
use std::rc::Rc;

use bstr::BString;
use serde::{Deserialize, Serialize};

use crate::symbols::{Symbol, SymbolTable};
use crate::types::{Struct, TypeValue};
use crate::wasm::WasmExport;

#[derive(Serialize, Deserialize)]
pub(crate) enum Array {
    Integers(Vec<i64>),
    Floats(Vec<f64>),
    Bools(Vec<bool>),
    Strings(Vec<Rc<BString>>),
    Structs(Vec<Rc<Struct>>),
}

impl Array {
    #[allow(clippy::declare_interior_mutable_const)]
    const BUILTIN_METHODS: OnceCell<Rc<SymbolTable>> = OnceCell::new();

    pub fn builtin_methods(&self) -> Rc<SymbolTable> {
        #[allow(clippy::borrow_interior_mutable_const)]
        Self::BUILTIN_METHODS
            .get_or_init(|| {
                let mut s = SymbolTable::new();
                for (name, func) in WasmExport::get_methods("Array") {
                    s.insert(name, Symbol::Func(Rc::new(func)));
                }
                Rc::new(s)
            })
            .clone()
    }

    pub fn deputy(&self) -> TypeValue {
        match self {
            Array::Integers(_) => TypeValue::unknown_integer(),
            Array::Floats(_) => TypeValue::unknown_float(),
            Array::Bools(_) => TypeValue::unknown_bool(),
            Array::Strings(_) => TypeValue::unknown_string(),
            Array::Structs(s) => TypeValue::Struct(s.first().unwrap().clone()),
        }
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

    pub fn as_string_array(&self) -> &Vec<Rc<BString>> {
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

    pub fn enum_substructures<F>(&mut self, f: &mut F)
    where
        F: FnMut(&mut Struct),
    {
        if let Self::Structs(v) = self {
            for s in v.iter_mut() {
                Rc::<Struct>::get_mut(s).unwrap().enum_substructures(f);
            }
        }
    }
}
