use std::ops::Deref;
use std::rc::Rc;

use crate::ast::Type;
use crate::symbols::{Symbol, SymbolLookup};
use bstr::{BStr, BString, ByteSlice};
use protobuf::reflect::{
    MessageDescriptor, ReflectMapRef, ReflectRepeatedRef, ReflectValueRef,
    RuntimeFieldType, RuntimeType,
};
use protobuf::MessageDyn;
use rustc_hash::FxHashMap;

/// Type and value of a structure field.
#[derive(Clone)]
pub enum RuntimeValue {
    Integer(Option<i64>),
    Float(Option<f64>),
    Bool(Option<bool>),
    String(Option<BString>),
    Struct(Rc<RuntimeStruct>),
    Array(Rc<RuntimeArray>),
    Map(Rc<RuntimeMap>),
}

impl From<Type> for RuntimeValue {
    fn from(ty: Type) -> Self {
        match ty {
            Type::Integer => RuntimeValue::Integer(None),
            Type::Float => RuntimeValue::Float(None),
            Type::Bool => RuntimeValue::Bool(None),
            Type::String => RuntimeValue::String(None),
            _ => {
                panic!("can not create RuntimeTypeAndValue from type `{}`", ty)
            }
        }
    }
}

impl RuntimeValue {
    pub fn ty(&self) -> Type {
        match &self {
            RuntimeValue::Integer(_) => Type::Integer,
            RuntimeValue::Float(_) => Type::Float,
            RuntimeValue::Bool(_) => Type::Bool,
            RuntimeValue::String(_) => Type::String,
            RuntimeValue::Struct(_) => Type::Struct,
            RuntimeValue::Array(_) => Type::Array,
            RuntimeValue::Map(_) => Type::Map,
        }
    }

    pub fn as_bstr(&self) -> Option<&BStr> {
        if let RuntimeValue::String(v) = self {
            v.as_ref().map(|v| v.as_bstr())
        } else {
            panic!()
        }
    }
}

pub enum RuntimeArray {
    Integer(Vec<i64>),
    Float(Vec<f64>),
    Bool(Vec<bool>),
    String(Vec<BString>),
    Struct(Vec<Rc<RuntimeStruct>>),
}

impl RuntimeArray {
    pub fn item_type(&self) -> Type {
        match self {
            RuntimeArray::Integer(_) => Type::Integer,
            RuntimeArray::Float(_) => Type::Float,
            RuntimeArray::Bool(_) => Type::Bool,
            RuntimeArray::String(_) => Type::String,
            RuntimeArray::Struct(_) => Type::Struct,
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

    pub fn as_struct_array(&self) -> &Vec<Rc<RuntimeStruct>> {
        if let Self::Struct(v) = self {
            v
        } else {
            panic!()
        }
    }
}

pub enum RuntimeMap {
    /// A map that has integer keys.
    IntegerKeys {
        // The deputy value is one that acts as a representative of the values
        // stored in the map. This value only contains type information, not
        // actual data. For example, if the value is an integer it will be
        // RuntimeValue::Integer(None), if it is a structure, it will have the
        // same fields than actual structures stored in the map, but those
        // fields will contain no data. The deputy value is optional because
        // it is present only at compile time, when the `map` field is an
        // empty map.
        deputy: Option<RuntimeValue>,
        map: FxHashMap<i64, RuntimeValue>,
    },
    /// A map that has string keys.
    StringKeys {
        deputy: Option<RuntimeValue>,
        map: FxHashMap<BString, RuntimeValue>,
    },
}

pub struct RuntimeStructField {
    // Field name.
    pub name: String,
    // For structures derived from a protobuf this contains the field number
    // specified in the .proto file. For other structures this is set to 0.
    pub number: u64,
    // Index that occupies the field in the structure it belongs to.
    pub index: i32,
    // Field type and value.
    pub value: RuntimeValue,
}

impl RuntimeStructField {
    fn ty(&self) -> Type {
        match self.value {
            RuntimeValue::Integer(_) => Type::Integer,
            RuntimeValue::Float(_) => Type::Float,
            RuntimeValue::Bool(_) => Type::Bool,
            RuntimeValue::String(_) => Type::String,
            RuntimeValue::Struct(_) => Type::Struct,
            RuntimeValue::Array(_) => Type::Array,
            RuntimeValue::Map(_) => Type::Map,
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

impl SymbolLookup for RuntimeStruct {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        let field = self.field_by_name(ident)?;
        let mut symbol = Symbol::new(field.ty(), field.value.clone());
        symbol.set_field_index(field.index);
        Some(symbol)
    }
}

impl RuntimeStruct {
    pub fn new() -> Self {
        Self { fields: Vec::new(), field_index: FxHashMap::default() }
    }

    pub fn insert(&mut self, name: &str, value: RuntimeValue) -> &mut Self {
        let index = self.fields.len();
        self.fields.push(RuntimeStructField {
            value,
            name: name.to_owned(),
            number: 0,
            index: index as i32,
        });
        self.field_index.insert(name.to_owned(), index);
        self
    }

    #[inline]
    pub fn field_by_index(&self, index: usize) -> Option<&RuntimeStructField> {
        self.fields.get(index)
    }

    #[inline]
    pub fn field_by_name(&self, name: &str) -> Option<&RuntimeStructField> {
        let index = self.field_index.get(name)?;
        self.field_by_index(*index)
    }

    /// Creates a [`RuntimeStruct`] from a protobuf message.
    ///
    /// See [`Self::from_proto_descriptor_and_msg`] for details.
    #[inline]
    pub fn from_proto_msg(
        msg: Box<dyn MessageDyn>,
        generate_fields_for_enums: bool,
    ) -> Self {
        Self::from_proto_descriptor_and_msg(
            &msg.descriptor_dyn(),
            Some(msg.deref()),
            generate_fields_for_enums,
        )
    }

    /// Creates a [`RuntimeStruct`] from a protobuf message descriptor.
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
    /// The `generate_fields_for_enums` controls whether the enums defined
    /// by the proto will be included as fields in the structure. Enums
    /// are required at compile time, so that the compiler can lookup the
    /// enums by name and resolve their values, but at scan time enums are
    /// not necessary because their values are already embedded in the code.
    /// The scanner never asks for an enum by field index.
    ///
    /// # Panics
    ///
    /// If [`MessageDyn`] doesn't represent a message that corresponds to
    /// the given [`MessageDescriptor`].
    pub fn from_proto_descriptor_and_msg(
        msg_descriptor: &MessageDescriptor,
        msg: Option<&dyn MessageDyn>,
        generate_fields_for_enums: bool,
    ) -> Self {
        let mut fields = Vec::new();

        for fd in msg_descriptor.fields() {
            let field_ty = fd.runtime_field_type();
            let number = fd.number() as u64;
            let name = fd.name().to_owned();
            let value = match field_ty {
                RuntimeFieldType::Singular(ty) => {
                    if let Some(msg) = msg {
                        Self::new_value(
                            &ty,
                            fd.get_singular(msg),
                            generate_fields_for_enums,
                        )
                    } else {
                        Self::new_value(&ty, None, generate_fields_for_enums)
                    }
                }
                RuntimeFieldType::Repeated(ty) => {
                    if let Some(msg) = msg {
                        Self::new_array(
                            &ty,
                            Some(fd.get_repeated(msg)),
                            generate_fields_for_enums,
                        )
                    } else {
                        Self::new_array(&ty, None, generate_fields_for_enums)
                    }
                }
                RuntimeFieldType::Map(key_ty, value_ty) => {
                    if let Some(msg) = msg {
                        Self::new_map(
                            &key_ty,
                            &value_ty,
                            Some(fd.get_map(msg)),
                            generate_fields_for_enums,
                        )
                    } else {
                        Self::new_map(
                            &key_ty,
                            &value_ty,
                            None,
                            generate_fields_for_enums,
                        )
                    }
                }
            };

            fields.push(RuntimeStructField {
                // Index is initially zero, will be adjusted later.
                index: 0,
                value,
                number,
                name,
            });
        }

        // Sort fields by field numbers specified in the proto.
        fields.sort_by(|a, b| a.number.cmp(&b.number));

        if generate_fields_for_enums {
            // Enums declared inside a message are treated as a nested structure
            // where each field is an enum item, and each field has a constant
            // value.
            for enum_ in msg_descriptor.nested_enums() {
                let mut enum_struct = RuntimeStruct::new();

                for item in enum_.values() {
                    enum_struct.insert(
                        item.name(),
                        RuntimeValue::Integer(Some(item.value() as i64)),
                    );
                }

                fields.push(RuntimeStructField {
                    index: fields.len() as i32,
                    value: RuntimeValue::Struct(Rc::new(enum_struct)),
                    number: 0,
                    name: enum_.name().to_owned(),
                })
            }
        }

        // Update index numbers, so that each field has an index that
        // corresponds to its position in the vector. Also create the
        // map that correlates field names to field indexes.
        let mut field_index = FxHashMap::default();

        for (index, field) in fields.iter_mut().enumerate() {
            field.index = index as i32;
            field_index.insert(field.name.clone(), index);
        }

        Self { fields, field_index }
    }

    fn new_value(
        ty: &RuntimeType,
        value: Option<ReflectValueRef>,
        enum_as_fields: bool,
    ) -> RuntimeValue {
        match ty {
            RuntimeType::I32 => {
                RuntimeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::I64 => {
                RuntimeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::U32 => {
                RuntimeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::U64 => {
                RuntimeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::F32 => RuntimeValue::Float(
                value.map(|value| value.to_f32().unwrap() as f64),
            ),
            RuntimeType::F64 => {
                RuntimeValue::Float(value.map(|value| value.to_f64().unwrap()))
            }
            RuntimeType::Bool => {
                RuntimeValue::Bool(value.map(|value| value.to_bool().unwrap()))
            }
            RuntimeType::String => RuntimeValue::String(
                value.map(|value| BString::from(value.to_str().unwrap())),
            ),
            RuntimeType::VecU8 => RuntimeValue::String(
                value.map(|value| BString::from(value.to_bytes().unwrap())),
            ),
            RuntimeType::Enum(_) => RuntimeValue::Integer(
                value.map(|value| value.to_enum_value().unwrap() as i64),
            ),
            RuntimeType::Message(msg_descriptor) => {
                let structure = if let Some(value) = value {
                    Self::from_proto_descriptor_and_value(
                        msg_descriptor,
                        value,
                        enum_as_fields,
                    )
                } else {
                    Self::from_proto_descriptor_and_msg(
                        msg_descriptor,
                        None,
                        enum_as_fields,
                    )
                };
                RuntimeValue::Struct(Rc::new(structure))
            }
        }
    }

    fn new_array(
        ty: &RuntimeType,
        repeated: Option<ReflectRepeatedRef>,
        enum_as_fields: bool,
    ) -> RuntimeValue {
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
                                Rc::new(Self::from_proto_descriptor_and_value(
                                    msg_descriptor,
                                    value,
                                    enum_as_fields,
                                ))
                            })
                            .collect(),
                    )
                } else {
                    RuntimeArray::Struct(vec![Rc::new(
                        RuntimeStruct::from_proto_descriptor_and_msg(
                            msg_descriptor,
                            None,
                            enum_as_fields,
                        ),
                    )])
                }
            }
        };

        RuntimeValue::Array(Rc::new(array))
    }

    fn new_map(
        key_ty: &RuntimeType,
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
    ) -> RuntimeValue {
        let map = match key_ty {
            RuntimeType::String => {
                Self::new_map_with_string_key(value_ty, map, enum_as_fields)
            }
            RuntimeType::I32
            | RuntimeType::I64
            | RuntimeType::U32
            | RuntimeType::U64 => {
                Self::new_map_with_integer_key(value_ty, map, enum_as_fields)
            }
            _ => unreachable!(),
        };

        RuntimeValue::Map(Rc::new(map))
    }

    fn new_map_with_integer_key(
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
    ) -> RuntimeMap {
        if let Some(map) = map {
            let mut result = FxHashMap::default();
            for (key, value) in map.into_iter() {
                result.insert(
                    Self::value_as_i64(key),
                    Self::new_value(value_ty, Some(value), enum_as_fields),
                );
            }
            RuntimeMap::IntegerKeys { deputy: None, map: result }
        } else {
            RuntimeMap::IntegerKeys {
                deputy: Some(Self::new_value(value_ty, None, enum_as_fields)),
                map: Default::default(),
            }
        }
    }

    fn new_map_with_string_key(
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
    ) -> RuntimeMap {
        if let Some(map) = map {
            let mut result = FxHashMap::default();
            for (key, value) in map.into_iter() {
                result.insert(
                    BString::from(Self::value_as_str(key)),
                    Self::new_value(value_ty, Some(value), enum_as_fields),
                );
            }
            RuntimeMap::StringKeys { deputy: None, map: result }
        } else {
            RuntimeMap::StringKeys {
                deputy: Some(Self::new_value(value_ty, None, enum_as_fields)),
                map: Default::default(),
            }
        }
    }

    fn from_proto_descriptor_and_value(
        msg_descriptor: &MessageDescriptor,
        value: ReflectValueRef,
        enum_as_fields: bool,
    ) -> RuntimeStruct {
        if let ReflectValueRef::Message(m) = value {
            RuntimeStruct::from_proto_descriptor_and_msg(
                msg_descriptor,
                Some(m.deref()),
                enum_as_fields,
            )
        } else {
            unreachable!()
        }
    }

    fn value_as_i64(value: ReflectValueRef) -> i64 {
        match value {
            ReflectValueRef::U32(v) => v as i64,
            ReflectValueRef::U64(v) => v as i64,
            ReflectValueRef::I32(v) => v as i64,
            ReflectValueRef::I64(v) => v,
            _ => panic!(),
        }
    }

    fn value_as_str(value: ReflectValueRef) -> &str {
        match value {
            ReflectValueRef::String(v) => v,
            _ => panic!(),
        }
    }
}
