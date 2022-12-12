use std::fmt::Display;
use std::ops::Deref;

use crate::ast::Type;
use bstr::BString;
use protobuf::reflect::{
    MessageDescriptor, ReflectRepeatedRef, ReflectValueRef, RuntimeFieldType,
    RuntimeType,
};
use protobuf::MessageDyn;
use rustc_hash::FxHashMap;

/// Type and value of a structure field.
pub enum RuntimeTypeAndValue {
    Integer(Option<i64>),
    Float(Option<f64>),
    Bool(Option<bool>),
    String(Option<BString>),
    Struct(RuntimeStruct),
    Array(RuntimeArray),
}

pub enum RuntimeArray {
    Integer(Vec<i64>),
    Float(Vec<f64>),
    Bool(Vec<bool>),
    String(Vec<BString>),
    Struct(Vec<RuntimeStruct>),
}

pub struct RuntimeStructField {
    // Field name.
    pub name: String,
    // For structures derived from a protobuf this contains the field number
    // specified in the .proto file. For other structures this is the same as
    // index.
    pub number: i32,
    // Index that occupies the field in the structure it belongs to.
    pub index: usize,
    // Field type and value.
    pub type_value: RuntimeTypeAndValue,
}

impl RuntimeStructField {
    fn ty(&self) -> Type {
        match self.type_value {
            RuntimeTypeAndValue::Integer(_) => Type::Integer,
            RuntimeTypeAndValue::Float(_) => Type::Float,
            RuntimeTypeAndValue::Bool(_) => Type::Bool,
            RuntimeTypeAndValue::String(_) => Type::String,
            RuntimeTypeAndValue::Struct(_) => Type::Struct,
            RuntimeTypeAndValue::Array(_) => Type::Array,
        }
    }
}

pub struct RuntimeStruct {
    // Fields in this structure. The index of each field is the index that it
    // has in this vector. Fields are sorted by field number, which means that
    // for protobuf-derived structures the order of the fields  doesn't depend
    // on the order in which they appear in the source .proto file.
    fields: Vec<RuntimeStructField>,
    // Map where keys are field names and values are their corresponding index
    // in the `fields` vector.
    field_index: FxHashMap<String, usize>,
}

/*
impl<'a> SymbolLookup<'a> for RuntimeStruct {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        let field = self.field_by_name(ident)?;

        Symbol::new(field.ty())
    }
}
*/

impl RuntimeStruct {
    #[inline]
    pub fn field_by_index(&self, index: usize) -> Option<&RuntimeStructField> {
        self.fields.get(index)
    }

    #[inline]
    pub fn field_by_name(&self, name: &str) -> Option<&RuntimeStructField> {
        let index = self.field_index.get(name)?;
        self.field_by_index(*index)
    }

    #[inline]
    pub fn from_proto(msg: Box<dyn MessageDyn>) -> Self {
        Self::from_proto_message(&msg.descriptor_dyn(), Some(msg.deref()))
    }

    /// Creates a [`RuntimeStruct`] from a protobuf message.
    ///
    /// Receives the [`MessageDescriptor`] corresponding to the protobuf
    /// message, and optionally, an instance of that message with actual
    /// data as a [`MessageDyn`]. The structure returned will have the
    /// fields described by the message descriptor, and the value of each
    /// field will be extracted from the message instance, if provided.
    ///
    /// If a [`MessageDyn`] is not provided the value of each field will
    /// be [`None`].
    ///
    /// # Panics
    ///
    /// If [`MessageDyn`] doesn't represent a message that corresponds to
    /// the given [`MessageDescriptor`].
    pub fn from_proto_message(
        msg_descriptor: &MessageDescriptor,
        msg: Option<&dyn MessageDyn>,
    ) -> Self {
        let mut fields = Vec::new();

        for fd in msg_descriptor.fields() {
            let field_ty = fd.runtime_field_type();
            let number = fd.number();
            let name = fd.name().to_owned();
            let value = match field_ty {
                RuntimeFieldType::Singular(ty) => {
                    if let Some(msg) = msg {
                        Self::new_value(ty, fd.get_singular(msg))
                    } else {
                        Self::new_value(ty, None)
                    }
                }
                RuntimeFieldType::Repeated(ty) => {
                    if let Some(msg) = msg {
                        Self::new_array(ty, Some(fd.get_repeated(msg)))
                    } else {
                        Self::new_array(ty, None)
                    }
                }
                RuntimeFieldType::Map(_, _) => {
                    todo!()
                }
            };

            fields.push(RuntimeStructField {
                // Index is initially zero, will be adjusted later.
                index: 0,
                type_value: value,
                number,
                name,
            });
        }

        // Sort fields by field number ascending.
        fields.sort_by(|a, b| a.number.cmp(&b.number));

        // Update index numbers, so that each field has an index that
        // corresponds to its position in the vector. Also create the
        // map that correlates field names to field indexes.
        let mut field_index = FxHashMap::default();

        for (index, field) in fields.iter_mut().enumerate() {
            field.index = index;
            field_index.insert(field.name.clone(), index);
        }

        Self { fields, field_index }
    }

    fn new_value(
        ty: RuntimeType,
        value: Option<ReflectValueRef>,
    ) -> RuntimeTypeAndValue {
        match ty {
            RuntimeType::I32 => RuntimeTypeAndValue::Integer(
                value.map(|value| value.to_i32().unwrap() as i64),
            ),
            RuntimeType::I64 => RuntimeTypeAndValue::Integer(
                value.map(|value| value.to_i64().unwrap()),
            ),
            RuntimeType::U32 => RuntimeTypeAndValue::Integer(
                value.map(|value| value.to_u32().unwrap() as i64),
            ),
            RuntimeType::U64 => {
                todo!()
            }
            RuntimeType::F32 => RuntimeTypeAndValue::Float(
                value.map(|value| value.to_f32().unwrap() as f64),
            ),
            RuntimeType::F64 => RuntimeTypeAndValue::Float(
                value.map(|value| value.to_f64().unwrap()),
            ),
            RuntimeType::Bool => RuntimeTypeAndValue::Bool(
                value.map(|value| value.to_bool().unwrap()),
            ),
            RuntimeType::String => RuntimeTypeAndValue::String(
                value.map(|value| BString::from(value.to_str().unwrap())),
            ),
            RuntimeType::VecU8 => RuntimeTypeAndValue::String(
                value.map(|value| BString::from(value.to_bytes().unwrap())),
            ),
            RuntimeType::Enum(_) => RuntimeTypeAndValue::Integer(
                value.map(|value| value.to_enum_value().unwrap() as i64),
            ),
            RuntimeType::Message(msg_descriptor) => {
                let value = if let Some(value) = value {
                    if let ReflectValueRef::Message(msg) = value {
                        RuntimeStruct::from_proto_message(
                            &msg_descriptor,
                            Some(msg.deref()),
                        )
                    } else {
                        unreachable!()
                    }
                } else {
                    Self::from_proto_message(&msg_descriptor, None)
                };
                RuntimeTypeAndValue::Struct(value)
            }
        }
    }

    fn new_array(
        ty: RuntimeType,
        repeated: Option<ReflectRepeatedRef>,
    ) -> RuntimeTypeAndValue {
        let array = match ty {
            RuntimeType::I32 => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Integer(
                        repeated
                            .into_iter()
                            .map(|value| value.to_i32().unwrap() as i64)
                            .collect(),
                    )
                } else {
                    RuntimeArray::Integer(vec![])
                }
            }
            RuntimeType::I64 => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Integer(
                        repeated
                            .into_iter()
                            .map(|value| value.to_i64().unwrap())
                            .collect(),
                    )
                } else {
                    RuntimeArray::Integer(vec![])
                }
            }
            RuntimeType::U32 => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Integer(
                        repeated
                            .into_iter()
                            .map(|value| value.to_u32().unwrap() as i64)
                            .collect(),
                    )
                } else {
                    RuntimeArray::Integer(vec![])
                }
            }
            RuntimeType::U64 => {
                todo!()
            }
            RuntimeType::F32 => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Float(
                        repeated
                            .into_iter()
                            .map(|value| value.to_f32().unwrap() as f64)
                            .collect(),
                    )
                } else {
                    RuntimeArray::Float(vec![])
                }
            }
            RuntimeType::F64 => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Float(
                        repeated
                            .into_iter()
                            .map(|value| value.to_f64().unwrap())
                            .collect(),
                    )
                } else {
                    RuntimeArray::Float(vec![])
                }
            }
            RuntimeType::Bool => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Bool(
                        repeated
                            .into_iter()
                            .map(|value| value.to_bool().unwrap())
                            .collect(),
                    )
                } else {
                    RuntimeArray::Bool(vec![])
                }
            }
            RuntimeType::String => {
                if let Some(repeated) = repeated {
                    RuntimeArray::String(
                        repeated
                            .into_iter()
                            .map(|value| {
                                BString::from(value.to_str().unwrap())
                            })
                            .collect(),
                    )
                } else {
                    RuntimeArray::String(vec![])
                }
            }
            RuntimeType::VecU8 => {
                if let Some(repeated) = repeated {
                    RuntimeArray::String(
                        repeated
                            .into_iter()
                            .map(|value| {
                                BString::from(value.to_bytes().unwrap())
                            })
                            .collect(),
                    )
                } else {
                    RuntimeArray::String(vec![])
                }
            }
            RuntimeType::Enum(_) => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Integer(
                        repeated
                            .into_iter()
                            .map(|value| value.to_enum_value().unwrap() as i64)
                            .collect(),
                    )
                } else {
                    RuntimeArray::Integer(vec![])
                }
            }
            RuntimeType::Message(msg_descriptor) => {
                if let Some(repeated) = repeated {
                    RuntimeArray::Struct(
                        repeated
                            .into_iter()
                            .map(|value| {
                                if let ReflectValueRef::Message(m) = value {
                                    RuntimeStruct::from_proto_message(
                                        &msg_descriptor,
                                        Some(m.deref()),
                                    )
                                } else {
                                    unreachable!()
                                }
                            })
                            .collect(),
                    )
                } else {
                    RuntimeArray::Struct(vec![
                        RuntimeStruct::from_proto_message(
                            &msg_descriptor,
                            None,
                        ),
                    ])
                }
            }
        };

        RuntimeTypeAndValue::Array(array)
    }
}
