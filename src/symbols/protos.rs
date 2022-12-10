use std::pin::Pin;
use std::rc::Rc;

use lazy_static::__Deref;
use protobuf::reflect::{
    EnumDescriptor, FieldDescriptor, MessageDescriptor, MessageRef,
    ReflectValueRef, RuntimeFieldType, RuntimeType,
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

    fn message_dyn<'a>(&self) -> &'a dyn MessageDyn {
        unsafe {
            let ptr: *const dyn MessageDyn = self.msg.as_ref();
            ptr.as_ref().unwrap()
        }
    }
}

impl<'a> SymbolLookup<'a> for ProtoMessage {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        lookup_impl(
            ident,
            &self.msg.descriptor_dyn(),
            Some(self.message_dyn()),
        )
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
/// will be returned. Values will be unknown in all cases, as the descriptor
/// is not an instance of the protobuf message, only a description of it.
/// Therefore it doesn't have associated data.
impl<'a> SymbolLookup<'a> for MessageDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        lookup_impl(ident, self, None)
    }
}

/// [`EnumDescriptor`] also implements [`SymbolLookup`].
impl<'a> SymbolLookup<'a> for EnumDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        let descriptor = self.value_by_name(ident)?;
        Some(Symbol::new_integer(descriptor.value() as i64))
    }
}

struct ProtoMessageRef<'a> {
    message_ref: Pin<Box<MessageRef<'a>>>,
}

impl<'a> ProtoMessageRef<'a> {
    fn new(m: MessageRef<'a>) -> Self {
        Self { message_ref: Pin::new(Box::new(m)) }
    }

    fn message_dyn(&self) -> &'a dyn MessageDyn {
        unsafe {
            let ptr: *const dyn MessageDyn = self.message_ref.deref().deref();
            ptr.as_ref().unwrap()
        }
    }
}

impl<'a> SymbolLookup<'a> for ProtoMessageRef<'a> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        lookup_impl(
            ident,
            &self.message_ref.descriptor_dyn(),
            Some(self.message_dyn()),
        )
    }
}

pub struct ProtoRepeatedField<'a> {
    message: &'a dyn MessageDyn,
    field_descriptor: FieldDescriptor,
}

impl<'a> SymbolIndex<'a, usize> for ProtoRepeatedField<'a> {
    fn index(&self, index: usize) -> Option<Symbol<'a>> {
        let field = self.field_descriptor.get_repeated(self.message);
        let item = field.get(index);
        symbol_from_type_value(item.get_type(), Some(item))
    }

    fn item_type(&self) -> Type {
        <FieldDescriptor as SymbolIndex<'_, usize>>::item_type(
            &self.field_descriptor,
        )
    }

    fn item_value(&self) -> SymbolValue<'a> {
        todo!();
    }
}

fn lookup_impl<'a>(
    ident: &str,
    message_descriptor: &MessageDescriptor,
    message: Option<&'a dyn MessageDyn>,
) -> Option<Symbol<'a>> {
    // TODO: take into account that the name passed to field_by_name
    // is the actual field name in the proto, but not the field name
    // from the YARA module's perspective, which can be changed with
    // the "name" option.
    if let Some(field_descriptor) = message_descriptor.field_by_name(ident) {
        match field_descriptor.runtime_field_type() {
            RuntimeFieldType::Singular(ty) => {
                let value = if let Some(message) = message {
                    field_descriptor.get_singular(message)
                } else {
                    None
                };
                symbol_from_type_value(ty, value)
            }
            RuntimeFieldType::Repeated(_) => {
                let symbol = if let Some(message) = message {
                    Symbol::new_array(Rc::new(ProtoRepeatedField {
                        message,
                        field_descriptor,
                    }))
                } else {
                    Symbol::new_array(Rc::new(field_descriptor))
                };
                Some(symbol)
            }
            RuntimeFieldType::Map(_, _) => {
                let symbol = if let Some(message) = message {
                    todo!()
                } else {
                    Symbol::new_map(Rc::new(field_descriptor))
                };
                Some(symbol)
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

fn symbol_from_type_value(
    ty: RuntimeType,
    value: Option<ReflectValueRef>,
) -> Option<Symbol> {
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
            if let Some(value) = value {
                let message = value.to_message().unwrap();
                Some(Symbol::new_struct(Rc::new(ProtoMessageRef::new(
                    message,
                ))))
            } else {
                Some(Symbol::new_struct(Rc::new(message_descriptor)))
            }
        }
    }
}

impl<'a, T> SymbolIndex<'a, T> for FieldDescriptor {
    fn index(&self, _index: T) -> Option<Symbol<'a>> {
        None
    }
    fn item_type(&self) -> Type {
        match self.runtime_field_type() {
            RuntimeFieldType::Repeated(ty) | RuntimeFieldType::Map(_, ty) => {
                match ty {
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
                }
            }
            _ => unreachable!(),
        }
    }

    fn item_value(&self) -> SymbolValue<'a> {
        match self.runtime_field_type() {
            RuntimeFieldType::Repeated(ty) | RuntimeFieldType::Map(_, ty) => {
                match ty {
                    RuntimeType::I32 => SymbolValue::Value(Value::Unknown),
                    RuntimeType::I64 => SymbolValue::Value(Value::Unknown),
                    RuntimeType::U32 => SymbolValue::Value(Value::Unknown),
                    RuntimeType::U64 => SymbolValue::Value(Value::Unknown),
                    RuntimeType::F32 => SymbolValue::Value(Value::Unknown),
                    RuntimeType::F64 => SymbolValue::Value(Value::Unknown),
                    RuntimeType::Bool => SymbolValue::Value(Value::Unknown),
                    RuntimeType::String => SymbolValue::Value(Value::Unknown),
                    RuntimeType::VecU8 => SymbolValue::Value(Value::Unknown),
                    RuntimeType::Enum(_) => SymbolValue::Value(Value::Unknown),
                    RuntimeType::Message(message_descriptor) => {
                        SymbolValue::Struct(Rc::new(message_descriptor))
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}
