use bstr::BString;
use std::ops::Deref;
use std::rc::Rc;

use protobuf::reflect::{
    EnumDescriptor, FieldDescriptor, MessageDescriptor, ReflectMapRef,
    ReflectRepeatedRef, ReflectValueRef, RuntimeFieldType, RuntimeType,
};
use protobuf::MessageDyn;
use rustc_hash::FxHashMap;
use yara_proto::exts::enum_options as yara_enum_options;
use yara_proto::exts::field_options as yara_field_options;
use yara_proto::exts::module_options as yara_module_options;

use crate::symbols::{Location, Symbol, SymbolLookup};
use crate::types::{Array, Map, TypeValue};

/// A field in a [`Struct`].
pub struct StructField {
    /// Field name.
    pub name: String,
    /// For structures derived from a protobuf this contains the field number
    /// specified in the .proto file. For other structures this is set to 0.
    pub number: u64,
    /// Index that occupies the field in the structure it belongs to.
    pub index: i32,
    /// Field type and value.
    pub type_value: TypeValue,
}

/// A dynamic structure with one or more fields.
///
/// These structures are used during the compilation of YARA rules and the
/// evaluation of conditions. Fields can be of any of the primitive types like
/// integers, floats or strings, or more complex types like maps, arrays and
/// other structures.
///
/// There's usually a top-level struct that represents the global scope in
/// YARA, where each field represents a variable or a YARA module. Each module
/// is also represented by one of these structures.
///
/// The structures that represent a YARA module are created from the protobuf
/// associated to that module. Functions [`Struct::from_proto_msg`] and
/// [`Struct::from_proto_descriptor_and_msg`] are used for that purpose.
pub struct Struct {
    /// Fields in this structure. The index of each field is the index that it
    /// has in this vector. Fields are sorted by field number, which means that
    /// for protobuf-derived structures the order of the fields  doesn't depend
    /// on the order in which they appear in the source .proto file. For
    /// structures that are not created from a protobuf, the order of fields is
    /// the order in which they were inserted.
    fields: Vec<StructField>,
    /// Map where keys are field names and values are their corresponding index
    /// in the `fields` vector.
    field_index: FxHashMap<String, usize>,
}

impl SymbolLookup for Struct {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        let field = self.field_by_name(ident)?;
        let mut symbol = Symbol::new(field.type_value.clone());
        symbol.location = Location::FieldIndex(field.index);
        Some(symbol)
    }
}

impl Struct {
    pub fn new() -> Self {
        Self { fields: Vec::new(), field_index: FxHashMap::default() }
    }

    pub fn insert(&mut self, name: &str, value: TypeValue) -> &mut Self {
        let index = self.fields.len();
        self.fields.push(StructField {
            type_value: value,
            name: name.to_owned(),
            number: 0,
            index: index as i32,
        });
        self.field_index.insert(name.to_owned(), index);
        self
    }

    #[inline]
    pub fn field_by_index(&self, index: usize) -> Option<&StructField> {
        self.fields.get(index)
    }

    #[inline]
    pub fn field_by_name(&self, name: &str) -> Option<&StructField> {
        let index = self.field_index.get(name)?;
        self.field_by_index(*index)
    }

    /// Creates a [`Struct`] from a protobuf message.
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

    /// Creates a [`Struct`] from a protobuf message descriptor.
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
    /// by the proto will be included as fields in the structure. Enums are
    /// required only at compile time, so that the compiler can lookup the
    /// enums by name and resolve their values, but at scan time enums are
    /// not necessary because their values are already embedded in the code.
    /// The scanner never asks for an enum by field index.
    ///
    /// Also notice that a .proto file can define enums at the top level,
    /// outside of any message. Those enums will be handled as if they were
    /// defined inside of the module's root message, in other words, if you
    /// have this proto that defines a YARA module...
    ///
    /// ```text
    /// message MyMessage {
    ///   enum SomeEnum {
    ///     FOO = 0;
    ///     BAR = 1;
    /// }
    ///
    /// enum SomeOtherEnum {
    ///    BAZ = 0;
    ///    QUX = 1;
    /// }
    /// ```
    ///
    /// If `MyMessage` is the root message for the module, both `SomeEnum`
    /// and `SomeOtherEnum` will be included as fields of the [`Struct`]
    /// created for `MyMessage`.
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
            // The field should be ignored if it was annotated with:
            // [(yara.field_options).ignore = true]
            if Self::ignore_field(&fd) {
                continue;
            }

            let field_ty = fd.runtime_field_type();
            let number = fd.number() as u64;
            let name = Self::field_name(&fd);

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

            fields.push(StructField {
                // Index is initially zero, will be adjusted later.
                index: 0,
                type_value: value,
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
            let enums = msg_descriptor.nested_enums();

            // If the message is the module's root message, the enums that are
            // declared in the file outside of any structures are also added as
            // fields of this structure.
            let enums: Box<dyn Iterator<Item = EnumDescriptor>> =
                if Self::is_root_msg(msg_descriptor) {
                    Box::new(
                        enums.chain(msg_descriptor.file_descriptor().enums()),
                    )
                } else {
                    Box::new(enums)
                };

            for enum_ in enums {
                let mut enum_struct = Struct::new();

                for item in enum_.values() {
                    enum_struct.insert(
                        item.name(),
                        TypeValue::Integer(Some(item.value() as i64)),
                    );
                }

                fields.push(StructField {
                    index: fields.len() as i32,
                    type_value: TypeValue::Struct(Rc::new(enum_struct)),
                    number: 0,
                    name: Self::enum_name(&enum_),
                })
            }
        }

        // Update index numbers, so that each field has an index that
        // corresponds to its position in the vector. Also create the
        // map that correlates field names to field indexes.
        let mut field_index = FxHashMap::default();

        for (index, field) in fields.iter_mut().enumerate() {
            field.index = index as i32;
            if field_index.insert(field.name.clone(), index).is_some() {
                panic!(
                    "duplicate field name `{}` in `{}`",
                    field.name,
                    msg_descriptor.name()
                )
            }
        }

        Self { fields, field_index }
    }

    /// Returns true if the given message is the YARA module's root message.
    fn is_root_msg(msg_descriptor: &MessageDescriptor) -> bool {
        let file_descriptor = msg_descriptor.file_descriptor();
        if let Some(module_options) =
            yara_module_options.get(&file_descriptor.proto().options)
        {
            module_options.root_message.unwrap() == msg_descriptor.name()
        } else {
            false
        }
    }

    /// Given a [`EnumDescriptor`] returns the name that this enum will
    /// have in YARA..
    ///
    /// By default, the name of the enum will be the same one that it has in
    /// the protobuf definition. However, the name can be set to something
    /// different by using an annotation in the .proto file, like this:
    ///
    /// ```text
    /// enum Enumeration {
    ///   option (yara.enum_options).name = "my_enum";
    ///   ITEM_0 = 0;
    ///   ITEM_1 = 1;
    /// }
    /// ```
    ///
    /// Here the enum will be named `my_enum` instead of `Enumeration`.
    fn enum_name(enum_descriptor: &EnumDescriptor) -> String {
        if let Some(enum_options) =
            yara_enum_options.get(&enum_descriptor.proto().options)
        {
            enum_options
                .name
                .unwrap_or_else(|| enum_descriptor.name().to_owned())
        } else {
            enum_descriptor.name().to_owned()
        }
    }

    /// Given a [`FieldDescriptor`] returns the name that this field will
    /// have in the corresponding [`Struct`].
    ///
    /// By default, the name of the field will be the same one that it has in
    /// the protobuf definition. However, the name can be set to something
    /// different by using an annotation in the .proto file, like this:
    ///
    /// ```text
    /// int64 foo = 1 [(yara.field_options).name = "bar"];
    /// ```
    ///
    /// Here the `foo` field will be named `bar` when the protobuf is converted
    /// into a [`Struct`].
    fn field_name(field_descriptor: &FieldDescriptor) -> String {
        if let Some(field_options) =
            yara_field_options.get(&field_descriptor.proto().options)
        {
            field_options
                .name
                .unwrap_or_else(|| field_descriptor.name().to_owned())
        } else {
            field_descriptor.name().to_owned()
        }
    }

    /// Given a [`FieldDescriptor`] returns `true` if the field should be
    /// ignored by YARA.
    ///
    /// Fields that should be ignored are those annotated in the protobuf
    /// definition as follows:
    ///
    /// ```text
    /// int64 foo = 1 [(yara.field_options).ignore = true];
    /// ```
    ///
    fn ignore_field(field_descriptor: &FieldDescriptor) -> bool {
        if let Some(field_options) =
            yara_field_options.get(&field_descriptor.proto().options)
        {
            field_options.ignore.unwrap_or(false)
        } else {
            false
        }
    }

    fn new_value(
        ty: &RuntimeType,
        value: Option<ReflectValueRef>,
        enum_as_fields: bool,
    ) -> TypeValue {
        match ty {
            RuntimeType::I32 => {
                TypeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::I64 => {
                TypeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::U32 => {
                TypeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::U64 => {
                TypeValue::Integer(value.map(Self::value_as_i64))
            }
            RuntimeType::F32 => TypeValue::Float(
                value.map(|value| value.to_f32().unwrap() as f64),
            ),
            RuntimeType::F64 => {
                TypeValue::Float(value.map(|value| value.to_f64().unwrap()))
            }
            RuntimeType::Bool => {
                TypeValue::Bool(value.map(|value| value.to_bool().unwrap()))
            }
            RuntimeType::String => TypeValue::String(
                value.map(|value| BString::from(value.to_str().unwrap())),
            ),
            RuntimeType::VecU8 => TypeValue::String(
                value.map(|value| BString::from(value.to_bytes().unwrap())),
            ),
            RuntimeType::Enum(_) => TypeValue::Integer(
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
                TypeValue::Struct(Rc::new(structure))
            }
        }
    }

    fn new_array(
        ty: &RuntimeType,
        repeated: Option<ReflectRepeatedRef>,
        enum_as_fields: bool,
    ) -> TypeValue {
        let array = match ty {
            RuntimeType::I32 => {
                if let Some(repeated) = repeated {
                    Array::Integers(
                        repeated
                            .into_iter()
                            .map(|value| value.to_i32().unwrap() as i64)
                            .collect(),
                    )
                } else {
                    Array::Integers(vec![])
                }
            }
            RuntimeType::I64 => {
                if let Some(repeated) = repeated {
                    Array::Integers(
                        repeated
                            .into_iter()
                            .map(|value| value.to_i64().unwrap())
                            .collect(),
                    )
                } else {
                    Array::Integers(vec![])
                }
            }
            RuntimeType::U32 => {
                if let Some(repeated) = repeated {
                    Array::Integers(
                        repeated
                            .into_iter()
                            .map(|value| value.to_u32().unwrap() as i64)
                            .collect(),
                    )
                } else {
                    Array::Integers(vec![])
                }
            }
            RuntimeType::U64 => {
                todo!()
            }
            RuntimeType::F32 => {
                if let Some(repeated) = repeated {
                    Array::Floats(
                        repeated
                            .into_iter()
                            .map(|value| value.to_f32().unwrap() as f64)
                            .collect(),
                    )
                } else {
                    Array::Floats(vec![])
                }
            }
            RuntimeType::F64 => {
                if let Some(repeated) = repeated {
                    Array::Floats(
                        repeated
                            .into_iter()
                            .map(|value| value.to_f64().unwrap())
                            .collect(),
                    )
                } else {
                    Array::Floats(vec![])
                }
            }
            RuntimeType::Bool => {
                if let Some(repeated) = repeated {
                    Array::Bools(
                        repeated
                            .into_iter()
                            .map(|value| value.to_bool().unwrap())
                            .collect(),
                    )
                } else {
                    Array::Bools(vec![])
                }
            }
            RuntimeType::String => {
                if let Some(repeated) = repeated {
                    Array::Strings(
                        repeated
                            .into_iter()
                            .map(|value| {
                                BString::from(value.to_str().unwrap())
                            })
                            .collect(),
                    )
                } else {
                    Array::Strings(vec![])
                }
            }
            RuntimeType::VecU8 => {
                if let Some(repeated) = repeated {
                    Array::Strings(
                        repeated
                            .into_iter()
                            .map(|value| {
                                BString::from(value.to_bytes().unwrap())
                            })
                            .collect(),
                    )
                } else {
                    Array::Strings(vec![])
                }
            }
            RuntimeType::Enum(_) => {
                if let Some(repeated) = repeated {
                    Array::Integers(
                        repeated
                            .into_iter()
                            .map(|value| value.to_enum_value().unwrap() as i64)
                            .collect(),
                    )
                } else {
                    Array::Integers(vec![])
                }
            }
            RuntimeType::Message(msg_descriptor) => {
                if let Some(repeated) = repeated {
                    Array::Structs(
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
                    Array::Structs(vec![Rc::new(
                        Struct::from_proto_descriptor_and_msg(
                            msg_descriptor,
                            None,
                            enum_as_fields,
                        ),
                    )])
                }
            }
        };

        TypeValue::Array(Rc::new(array))
    }

    fn new_map(
        key_ty: &RuntimeType,
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
    ) -> TypeValue {
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

        TypeValue::Map(Rc::new(map))
    }

    fn new_map_with_integer_key(
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
    ) -> Map {
        if let Some(map) = map {
            let mut result = FxHashMap::default();
            for (key, value) in map.into_iter() {
                result.insert(
                    Self::value_as_i64(key),
                    Self::new_value(value_ty, Some(value), enum_as_fields),
                );
            }
            Map::IntegerKeys { deputy: None, map: result }
        } else {
            Map::IntegerKeys {
                deputy: Some(Self::new_value(value_ty, None, enum_as_fields)),
                map: Default::default(),
            }
        }
    }

    fn new_map_with_string_key(
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
    ) -> Map {
        if let Some(map) = map {
            let mut result = FxHashMap::default();
            for (key, value) in map.into_iter() {
                result.insert(
                    BString::from(Self::value_as_str(key)),
                    Self::new_value(value_ty, Some(value), enum_as_fields),
                );
            }
            Map::StringKeys { deputy: None, map: result }
        } else {
            Map::StringKeys {
                deputy: Some(Self::new_value(value_ty, None, enum_as_fields)),
                map: Default::default(),
            }
        }
    }

    fn from_proto_descriptor_and_value(
        msg_descriptor: &MessageDescriptor,
        value: ReflectValueRef,
        enum_as_fields: bool,
    ) -> Struct {
        if let ReflectValueRef::Message(m) = value {
            Struct::from_proto_descriptor_and_msg(
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
