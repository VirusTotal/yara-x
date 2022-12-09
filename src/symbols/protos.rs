use std::rc::Rc;

use protobuf::reflect::{
    EnumDescriptor, FieldDescriptor, MessageDescriptor, ReflectValueRef,
    RuntimeFieldType, RuntimeType,
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
                RuntimeFieldType::Singular(ty) => {
                    let value = field.get_singular(self.msg.as_ref());
                    match ty {
                        RuntimeType::I32 => {
                            let value = value
                                .and_then(|v| v.to_i32())
                                .map(Value::from)
                                .unwrap_or(Value::Unknown);
                            Some(Symbol::new(
                                Type::Integer,
                                SymbolValue::Value(value),
                            ))
                        }
                        RuntimeType::I64 => {
                            let value = value
                                .and_then(|v| v.to_i64())
                                .map(Value::from)
                                .unwrap_or(Value::Unknown);
                            Some(Symbol::new(
                                Type::Integer,
                                SymbolValue::Value(value),
                            ))
                        }
                        RuntimeType::U32 => {
                            let value = value
                                .and_then(|v| v.to_u32())
                                .map(Value::from)
                                .unwrap_or(Value::Unknown);
                            Some(Symbol::new(
                                Type::Integer,
                                SymbolValue::Value(value),
                            ))
                        }
                        RuntimeType::U64 => todo!(),
                        RuntimeType::F32 => {
                            let value = value
                                .and_then(|v| v.to_f32())
                                .map(Value::from)
                                .unwrap_or(Value::Unknown);
                            Some(Symbol::new(
                                Type::Float,
                                SymbolValue::Value(value),
                            ))
                        }
                        RuntimeType::F64 => {
                            let value = value
                                .and_then(|v| v.to_f64())
                                .map(Value::from)
                                .unwrap_or(Value::Unknown);
                            Some(Symbol::new(
                                Type::Float,
                                SymbolValue::Value(value),
                            ))
                        }
                        RuntimeType::Bool => {
                            let value = value
                                .and_then(|v| v.to_bool())
                                .map(Value::from)
                                .unwrap_or(Value::Unknown);
                            Some(Symbol::new(
                                Type::Float,
                                SymbolValue::Value(value),
                            ))
                        }
                        RuntimeType::Enum(_) => {
                            let value = value
                                .and_then(|v| v.to_enum_value())
                                .map(Value::from)
                                .unwrap_or(Value::Unknown);
                            Some(Symbol::new(
                                Type::String,
                                SymbolValue::Value(value),
                            ))
                        }
                        RuntimeType::String | RuntimeType::VecU8 => {
                            let value = if let Some(value_ref) = value {
                                value_ref
                                    .to_str()
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
                        RuntimeType::Message(message_descriptor) => {
                            if let Some(value_ref) = value {
                                Some(Symbol::new_struct(Rc::new(
                                    ProtoMessage {
                                        msg: value_ref
                                            .to_message()
                                            .unwrap()
                                            .clone_box()
                                            .into(),
                                    },
                                )))
                            } else {
                                Some(Symbol::new_struct(Rc::new(
                                    message_descriptor,
                                )))
                            }
                        }
                    }
                }
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
        let msg = self.msg.as_ref();
        let item = self.field_descriptor.get_repeated(msg).get(index);
        to_symbol(item.get_type(), Some(item))
    }

    fn item_type(&self) -> Type {
        self.field_descriptor.item_type()
    }
}

fn to_symbol<'a>(
    ty: RuntimeType,
    value: Option<ReflectValueRef>,
) -> Option<Symbol<'a>> {
    match ty {
        RuntimeType::I32 => {
            let value = value
                .and_then(|v| v.to_i32())
                .map(Value::from)
                .unwrap_or(Value::Unknown);
            Some(Symbol::new(Type::Integer, SymbolValue::Value(value)))
        }
        RuntimeType::I64 => {
            let value = value
                .and_then(|v| v.to_i64())
                .map(Value::from)
                .unwrap_or(Value::Unknown);
            Some(Symbol::new(Type::Integer, SymbolValue::Value(value)))
        }
        RuntimeType::U32 => {
            let value = value
                .and_then(|v| v.to_u32())
                .map(Value::from)
                .unwrap_or(Value::Unknown);
            Some(Symbol::new(Type::Integer, SymbolValue::Value(value)))
        }
        RuntimeType::U64 => todo!(),
        RuntimeType::F32 => {
            let value = value
                .and_then(|v| v.to_f32())
                .map(Value::from)
                .unwrap_or(Value::Unknown);
            Some(Symbol::new(Type::Float, SymbolValue::Value(value)))
        }
        RuntimeType::F64 => {
            let value = value
                .and_then(|v| v.to_f64())
                .map(Value::from)
                .unwrap_or(Value::Unknown);
            Some(Symbol::new(Type::Float, SymbolValue::Value(value)))
        }
        RuntimeType::Bool => {
            let value = value
                .and_then(|v| v.to_bool())
                .map(Value::from)
                .unwrap_or(Value::Unknown);
            Some(Symbol::new(Type::Float, SymbolValue::Value(value)))
        }
        RuntimeType::Enum(_) => {
            let value = value
                .and_then(|v| v.to_enum_value())
                .map(Value::from)
                .unwrap_or(Value::Unknown);
            Some(Symbol::new(Type::String, SymbolValue::Value(value)))
        }
        RuntimeType::String | RuntimeType::VecU8 => {
            let value = if let Some(value_ref) = value {
                value_ref.to_str().map(Value::from).unwrap_or(Value::Unknown)
            } else {
                Value::Unknown
            };
            Some(Symbol::new(Type::String, SymbolValue::Value(value)))
        }
        RuntimeType::Message(message_descriptor) => {
            if let Some(value_ref) = value {
                Some(Symbol::new_struct(Rc::new(ProtoMessage {
                    msg: value_ref.to_message().unwrap().clone_box().into(),
                })))
            } else {
                Some(Symbol::new_struct(Rc::new(message_descriptor)))
            }
        }
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
                RuntimeFieldType::Singular(ty) => to_symbol(ty, None),
                RuntimeFieldType::Repeated(_) => {
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
        match self.runtime_field_type() {
            RuntimeFieldType::Repeated(ty) => match ty {
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
            _ => unreachable!(),
        }
    }
}
