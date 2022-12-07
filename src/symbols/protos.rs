use std::rc::Rc;

use protobuf::reflect::{
    EnumDescriptor, FieldDescriptor, MessageDescriptor, RuntimeFieldType,
    RuntimeType,
};

use protobuf::MessageDyn;

use crate::symbols::Symbol;
use crate::symbols::SymbolIndex;
use crate::symbols::SymbolLookup;
use crate::symbols::SymbolValue;
use crate::types::Type;
use crate::types::Value;

pub struct ProtoMessage {
    msg: Rc<dyn MessageDyn>,
}

impl ProtoMessage {
    pub(crate) fn new(msg: Rc<dyn MessageDyn>) -> Self {
        Self { msg }
    }

    pub(crate) fn descriptor_dyn(&self) -> MessageDescriptor {
        self.msg.descriptor_dyn()
    }
}

impl<'a> SymbolLookup<'a> for ProtoMessage {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        let message_descriptor = self.msg.descriptor_dyn();
        if let Some(field) = message_descriptor.field_by_name(ident) {
            match field.runtime_field_type() {
                RuntimeFieldType::Singular(ty) => match ty {
                    RuntimeType::I32 => {
                        let value = field
                            .get_singular(self.msg.as_ref())
                            .and_then(|v| v.to_i32())
                            .map(Value::from)
                            .unwrap_or(Value::Unknown);
                        Some(Symbol::new(
                            Type::Integer,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::I64 => {
                        let value = field
                            .get_singular(self.msg.as_ref())
                            .and_then(|v| v.to_i64())
                            .map(Value::from)
                            .unwrap_or(Value::Unknown);
                        Some(Symbol::new(
                            Type::Integer,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::U32 => {
                        let value = field
                            .get_singular(self.msg.as_ref())
                            .and_then(|v| v.to_u32())
                            .map(Value::from)
                            .unwrap_or(Value::Unknown);
                        Some(Symbol::new(
                            Type::Integer,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::U64 => {
                        todo!()
                    }
                    RuntimeType::F32 => {
                        let value = field
                            .get_singular(self.msg.as_ref())
                            .and_then(|v| v.to_f32())
                            .map(Value::from)
                            .unwrap_or(Value::Unknown);
                        Some(Symbol::new(
                            Type::Float,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::F64 => {
                        let value = field
                            .get_singular(self.msg.as_ref())
                            .and_then(|v| v.to_f64())
                            .map(Value::from)
                            .unwrap_or(Value::Unknown);
                        Some(Symbol::new(
                            Type::Float,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::Bool => {
                        let value = field
                            .get_singular(self.msg.as_ref())
                            .and_then(|v| v.to_bool())
                            .map(Value::from)
                            .unwrap_or(Value::Unknown);
                        Some(Symbol::new(
                            Type::Bool,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::Enum(_) => {
                        let value = field
                            .get_singular(self.msg.as_ref())
                            .and_then(|v| v.to_enum_value())
                            .map(Value::from)
                            .unwrap_or(Value::Unknown);
                        Some(Symbol::new(
                            Type::Integer,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::String | RuntimeType::VecU8 => {
                        let value = if let Some(v) =
                            field.get_singular(self.msg.as_ref())
                        {
                            v.to_str()
                                .map(Value::from)
                                .unwrap_or(Value::Unknown)
                        } else {
                            Value::Unknown
                        };
                        Some(Symbol::new(
                            Type::String,
                            SymbolValue::Value(value),
                        ))
                    }
                    RuntimeType::Message(_) => {
                        Some(Symbol::new_struct(Rc::new(ProtoMessage {
                            msg: field
                                .get_message(self.msg.as_ref())
                                .clone_box()
                                .into(),
                        })))
                    }
                },
                RuntimeFieldType::Repeated(_) => {
                    Some(Symbol::new_array(Rc::new(ProtoRepeatedField {
                        msg: self.msg.clone(),
                        field_descriptor: field,
                    })))
                }
                RuntimeFieldType::Map(_, _) => {
                    todo!()
                }
            }
        } else {
            // If the message doesn't have a field with the requested name,
            // let's look if there's a nested enum that has that name.
            message_descriptor
                .nested_enums()
                .find(|e| e.name() == ident)
                .map(|nested_enum| Symbol::new_struct(Rc::new(nested_enum)))
        }
    }
}

pub struct ProtoRepeatedField {
    msg: Rc<dyn MessageDyn>,
    field_descriptor: FieldDescriptor,
}

impl<'a> SymbolIndex<'a> for ProtoRepeatedField {
    fn index(&self, index: usize) -> Option<Symbol<'a>> {
        let item =
            self.field_descriptor.get_repeated(self.msg.as_ref()).get(index);

        match self.field_descriptor.runtime_field_type() {
            RuntimeFieldType::Singular(ty) => match ty {
                RuntimeType::I32 => {}
                RuntimeType::I64 => {}
                RuntimeType::U32 => {}
                RuntimeType::U64 => {}
                RuntimeType::F32 => {}
                RuntimeType::F64 => {}
                RuntimeType::Bool => {}
                RuntimeType::String => {}
                RuntimeType::VecU8 => {}
                RuntimeType::Enum(_) => {}
                RuntimeType::Message(_) => {
                    return Some(Symbol::new_struct(Rc::new(ProtoMessage {
                        msg: item.to_message().unwrap().clone_box().into(),
                    })))
                }
            },
            RuntimeFieldType::Repeated(_) => {}
            RuntimeFieldType::Map(_, _) => {}
        }

        todo!()
    }

    fn item_type(&self) -> Type {
        match self.field_descriptor.runtime_field_type() {
            RuntimeFieldType::Singular(ty) => match ty {
                RuntimeType::I32 => Type::Integer,
                RuntimeType::I64 => Type::Integer,
                RuntimeType::U32 => Type::Integer,
                RuntimeType::U64 => Type::Integer,
                RuntimeType::F32 => Type::Float,
                RuntimeType::F64 => Type::Float,
                RuntimeType::Bool => Type::Bool,
                RuntimeType::String => Type::String,
                RuntimeType::VecU8 => Type::String,
                RuntimeType::Enum(_) => Type::Integer,
                RuntimeType::Message(_) => Type::Struct,
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

/// [`EnumDescriptor`] also implements [`SymbolLookup`].
impl<'a> SymbolLookup<'a> for EnumDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        let descriptor = self.value_by_name(ident)?;
        Some(Symbol::new_integer(descriptor.value() as i64))
    }
}

impl<'a> SymbolIndex<'a> for FieldDescriptor {
    fn index(&self, _index: usize) -> Option<Symbol<'a>> {
        None
    }

    fn item_type(&self) -> Type {
        todo!()
    }
}

/// Implements [`SymbolLookup`] for [`MessageDescriptor`].
///
/// A [`MessageDescriptor`] describes the structure of a protobuf message. By
/// implementing the [`SymbolLookup`] trait, a protobuf message descriptor
/// can be wrapped in a [`Symbol`] of type [`Type::Struct`] and added to a
/// symbol table.
///
/// When symbols are looked up in a protobuf message descriptor only the type
/// will be returned. Values will be [`None`] in all cases, as the descriptor
/// is not an instance of the protobuf message, only a description of it.
/// Therefore it doesn't have associated data.
impl<'a> SymbolLookup<'a> for MessageDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        // TODO: take into account that the name passed to field_by_name
        // is the actual field name in the proto, but not the field name
        // from the YARA module's perspective, which can be changed with
        // the "name" option.

        if let Some(field) = self.field_by_name(ident) {
            match field.runtime_field_type() {
                RuntimeFieldType::Singular(ty) => {
                    Some(runtime_type_to_symbol(ty))
                }
                RuntimeFieldType::Repeated(ty) => {
                    Some(Symbol::new_array(Rc::new(field)))
                }
                RuntimeFieldType::Map(_, _) => {
                    todo!()
                }
            }
        } else {
            // If the message doesn't have a field with the requested name,
            // let's look if there's a nested enum that has that name.
            self.nested_enums()
                .find(|e| e.name() == ident)
                .map(|nested_enum| Symbol::new_struct(Rc::new(nested_enum)))
        }
    }
}

fn runtime_type_to_type(rt: RuntimeType) -> Type {
    match rt {
        RuntimeType::U64 => {
            todo!()
        }
        RuntimeType::I32
        | RuntimeType::I64
        | RuntimeType::U32
        | RuntimeType::Enum(_) => Type::Integer,
        RuntimeType::F32 | RuntimeType::F64 => Type::Float,
        RuntimeType::Bool => Type::Bool,
        RuntimeType::String | RuntimeType::VecU8 => Type::String,
        RuntimeType::Message(_) => Type::Struct,
    }
}

fn runtime_type_to_symbol<'a>(rt: RuntimeType) -> Symbol<'a> {
    match rt {
        RuntimeType::U64 => {
            todo!()
        }
        RuntimeType::I32
        | RuntimeType::I64
        | RuntimeType::U32
        | RuntimeType::Enum(_) => Type::Integer.into(),
        RuntimeType::F32 | RuntimeType::F64 => Type::Float.into(),
        RuntimeType::Bool => Type::Bool.into(),
        RuntimeType::String | RuntimeType::VecU8 => Type::String.into(),
        RuntimeType::Message(m) => Symbol::new_struct(Rc::new(m)),
    }
}
