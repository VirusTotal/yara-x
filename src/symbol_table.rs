use crate::modules::Module;
use bstr::BString;
use protobuf::reflect::{MessageDescriptor, RuntimeFieldType, RuntimeType};
use std::collections::HashMap;
use std::rc::Rc;

pub trait SymbolLookup {
    fn lookup(&self, ident: &str) -> Option<TypeValue>;
}

#[derive(Clone)]
pub enum TypeValue {
    Integer(Option<i64>),
    Float(Option<f64>),
    String(Option<BString>),
    Struct(Rc<dyn SymbolLookup>),
}

impl SymbolLookup for &'static HashMap<&str, Module> {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
        self.get(ident).map(|module| TypeValue::Struct(Rc::new(module)))
    }
}

impl SymbolLookup for &Module {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
        self.descriptor.lookup(ident)
    }
}

impl SymbolLookup for MessageDescriptor {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
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
                RuntimeType::I64 => Some(TypeValue::Integer(None)),
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
                RuntimeType::Message(m) => Some(TypeValue::Struct(Rc::new(m))),
            },
            RuntimeFieldType::Repeated(item_ty) => todo!(),
            RuntimeFieldType::Map(key_ty, val_ty) => todo!(),
        }
    }
}

pub struct SymbolTable {
    map: HashMap<String, TypeValue>,
}

impl SymbolTable {
    /// Creates a new symbol table.
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    /// Inserts a new symbol into the symbol table.
    ///
    /// If the symbol was already in the table it gets updated and the old
    /// value is returned. If the symbol was not in the table [`None`] is
    /// returned.
    pub fn insert<I>(
        &mut self,
        ident: I,
        symbol: TypeValue,
    ) -> Option<TypeValue>
    where
        I: Into<String>,
    {
        self.map.insert(ident.into(), symbol)
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        SymbolTable::new()
    }
}

impl SymbolLookup for &SymbolTable {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
        self.map.get(ident).cloned()
    }
}
