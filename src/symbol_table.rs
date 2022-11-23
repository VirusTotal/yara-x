use crate::modules::Module;
use bstr::BString;
use protobuf::reflect::{
    EnumDescriptor, MessageDescriptor, RuntimeFieldType, RuntimeType,
};
use protobuf::MessageDyn;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;

pub trait SymbolLookup {
    fn lookup(&self, ident: &str) -> Option<TypeValue>;
}

#[derive(Clone)]
pub enum TypeValue {
    Integer(Option<i64>),
    Float(Option<f64>),
    Bool(Option<bool>),
    String(Option<BString>),
    Struct(Rc<dyn SymbolLookup>),
}

impl Debug for TypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "Bool({:?})", v),
            Self::Integer(v) => write!(f, "Integer({:?})", v),
            Self::Float(v) => write!(f, "Float({:?})", v),
            Self::String(v) => write!(f, "String({:?})", v),
            Self::Struct(_) => write!(f, "Struct"),
        }
    }
}

impl PartialEq for TypeValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bool(this), Self::Bool(other)) => this == other,
            (Self::Integer(this), Self::Integer(other)) => this == other,
            (Self::Float(this), Self::Float(other)) => this == other,
            (Self::String(this), Self::String(other)) => this == other,
            _ => false,
        }
    }
}

impl SymbolLookup for &'static HashMap<&str, Module> {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
        self.get(ident).map(|module| TypeValue::Struct(Rc::new(module)))
    }
}

impl SymbolLookup for Option<TypeValue> {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
        if let Some(TypeValue::Struct(s)) = self {
            s.lookup(ident)
        } else {
            None
        }
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
                RuntimeType::I32 => Some(TypeValue::Integer(None)),
                RuntimeType::I64 => Some(TypeValue::Integer(None)),
                RuntimeType::U32 => Some(TypeValue::Integer(None)),
                RuntimeType::U64 => {
                    todo!()
                }
                RuntimeType::F32 => Some(TypeValue::Float(None)),
                RuntimeType::F64 => Some(TypeValue::Float(None)),
                RuntimeType::Bool => Some(TypeValue::Bool(None)),
                RuntimeType::String => Some(TypeValue::String(None)),
                RuntimeType::VecU8 => Some(TypeValue::String(None)),
                RuntimeType::Enum(e) => Some(TypeValue::Struct(Rc::new(e))),
                RuntimeType::Message(m) => Some(TypeValue::Struct(Rc::new(m))),
            },
            RuntimeFieldType::Repeated(item_ty) => todo!(),
            RuntimeFieldType::Map(key_ty, val_ty) => todo!(),
        }
    }
}

impl SymbolLookup for EnumDescriptor {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
        let descriptor = self.value_by_name(ident)?;
        Some(TypeValue::Integer(Some(descriptor.value() as i64)))
    }
}

impl SymbolLookup for Box<dyn MessageDyn> {
    fn lookup(&self, ident: &str) -> Option<TypeValue> {
        let field_descriptor = self.descriptor_dyn().field_by_name(ident)?;

        match field_descriptor.runtime_field_type() {
            RuntimeFieldType::Singular(ty) => match ty {
                RuntimeType::I32 => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_i32()
                    .map(|v| TypeValue::Integer(Some(v as i64))),
                RuntimeType::I64 => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_i64()
                    .map(|v| TypeValue::Integer(Some(v))),
                RuntimeType::U32 => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_u32()
                    .map(|v| TypeValue::Integer(Some(v as i64))),
                RuntimeType::U64 => {
                    todo!()
                }
                RuntimeType::F32 => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_f32()
                    .map(|v| TypeValue::Float(Some(v as f64))),
                RuntimeType::F64 => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_f64()
                    .map(|v| TypeValue::Float(Some(v))),
                RuntimeType::Bool => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_bool()
                    .map(|v| TypeValue::Bool(Some(v))),
                RuntimeType::String => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_str()
                    .map(|v| TypeValue::String(Some(BString::from(v)))),
                RuntimeType::VecU8 => field_descriptor
                    .get_singular(self.as_ref())?
                    .to_str()
                    .map(|v| TypeValue::String(Some(BString::from(v)))),
                RuntimeType::Enum(e) => Some(TypeValue::Struct(Rc::new(e))),
                RuntimeType::Message(m) => Some(TypeValue::Struct(Rc::new(m))),
            },
            RuntimeFieldType::Repeated(_) => {
                todo!()
            }
            RuntimeFieldType::Map(_, _) => {
                todo!()
            }
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

#[cfg(test)]
mod tests {
    use crate::modules;
    use crate::symbol_table::{SymbolLookup, TypeValue};
    use bstr::BString;
    use pretty_assertions::assert_eq;
    use protobuf::Message;
    use protobuf::MessageFull;

    #[test]
    #[cfg(feature = "test_proto2-module")]
    fn message_dyn_lookup() {
        let mut proto = modules::protos::test_proto2::Test::new();

        proto.int32_field = Some(32);
        proto.int64_field = Some(64);
        proto.string_field = Some("foo".to_string());

        let mut buf = Vec::new();
        proto.write_to_vec(&mut buf).unwrap();

        let message_dyn = modules::protos::test_proto2::Test::descriptor()
            .parse_from_bytes(buf.as_slice())
            .unwrap();

        assert_eq!(
            message_dyn.lookup("int32_field"),
            Some(TypeValue::Integer(Some(32)))
        );

        assert_eq!(
            message_dyn.lookup("int64_field"),
            Some(TypeValue::Integer(Some(64)))
        );

        assert_eq!(
            message_dyn.lookup("string_field"),
            Some(TypeValue::String(Some(BString::from("foo"))))
        );

        assert_eq!(
            message_dyn.lookup("enum").lookup("ENUM_ITEM_1"),
            Some(TypeValue::Integer(Some(1)))
        );
    }
}
