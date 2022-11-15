use crate::modules::Module;
use bstr::BStr;
use protobuf::reflect::{MessageDescriptor, RuntimeFieldType, RuntimeType};
use std::collections::HashMap;

pub trait SymbolTable {
    fn lookup(&self, ident: &str) -> Option<Symbol>;
}

pub enum Symbol<'a> {
    Integer(Option<i64>),
    Float(Option<f64>),
    String(Option<&'a BStr>),
    Struct(Box<dyn SymbolTable>),
}

impl SymbolTable for &'static HashMap<&str, Module> {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        self.get(ident).map(|module| Symbol::Struct(Box::new(module)))
    }
}

impl SymbolTable for &Module {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        self.descriptor.lookup(ident)
    }
}

impl SymbolTable for MessageDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        // TODO: take into account that the name passed to field_by_name
        // is the actual field name in the proto, but not the field name
        // from the YARA module's perspective, which can be changed with
        // the "name" option.
        let field_type =
            self.field_by_name(ident).map(|d| d.runtime_field_type())?;

        match field_type {
            RuntimeFieldType::Singular(ty) => match ty {
                RuntimeType::I32 => {
                    todo!()
                }
                RuntimeType::I64 => Some(Symbol::Integer(None)),
                RuntimeType::U32 => {
                    todo!()
                }
                RuntimeType::U64 => {
                    todo!()
                }
                RuntimeType::F32 => {
                    todo!()
                }
                RuntimeType::F64 => {
                    todo!()
                }
                RuntimeType::Bool => {
                    todo!()
                }
                RuntimeType::String => {
                    todo!()
                }
                RuntimeType::VecU8 => {
                    todo!()
                }
                RuntimeType::Enum(_) => {
                    todo!()
                }
                RuntimeType::Message(m) => Some(Symbol::Struct(Box::new(m))),
            },
            RuntimeFieldType::Repeated(item_ty) => todo!(),
            RuntimeFieldType::Map(key_ty, val_ty) => todo!(),
        }
    }
}
