use std::iter;
use std::ops::Deref;
use std::rc::Rc;

use bstr::BString;
use indexmap::{IndexMap, IndexSet};
use itertools::Itertools;
use protobuf::reflect::{
    EnumDescriptor, FieldDescriptor, MessageDescriptor, ReflectMapRef,
    ReflectRepeatedRef, ReflectValueRef, RuntimeFieldType, RuntimeType,
};
use protobuf::reflect::{EnumValueDescriptor, Syntax};
use protobuf::{MessageDyn, MessageField};
use serde::{Deserialize, Serialize};

use crate::modules::protos::yara as protos;
use crate::modules::protos::yara::enum_value_options::Value as EnumValue;
use crate::modules::protos::yara::exts::{
    enum_options, enum_value, field_options, message_options, module_options,
};
use crate::modules::Module;
use crate::symbols::{Symbol, SymbolLookup};
use crate::types::{Array, Map, StringConstraint, TypeValue};
use crate::wasm::WasmExport;

/// Each of the entries in an Access Control List (ACL)
///
/// When defining the structure of a module in a `.proto` file, you can specify
/// that certain fields are accessible only when one or more features are
/// enabled in the compiler with using [`crate::Compiler::enable_feature`]. For
/// example, the field ``requires_foo_and_bar` in the snippet below has an ACL
/// indicating that the field can be accessed only if features "foo" and "bar"
/// are enabled in the compiler.
///
/// ```protobuf
/// optional uint64 requires_foo_and_bar = 500 [
///   (yara.field_options) = {
///     acl: [
///       {
///         accept_if: "foo",
///         error_title: "foo is required",
///         error_label: "this field was used without foo"
///       },
///       {
///         accept_if: "bar",
///         error_title: "bar is required",
///         error_label: "this field was used without bar"
///       }
///     ]
///   }
/// ];
/// ```
///
/// If some of the required features are not enabled, using this field in
/// a YARA rule will cause an error while compiling the rules. The error
/// looks like:
///
/// ```text
/// error[E034]: foo is required
///  --> line:5:29
///   |
/// 5 |  test_proto2.requires_foo_and_bar == 0
///   |              ^^^^^^^^^^^^^^^^^^^^ this field was used without foo
///   |
/// ```
///
/// Notice that both the title and label in the error message are defined
/// in the .proto file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AclEntry {
    pub error_title: String,
    pub error_label: String,
    pub accept_if: Vec<String>,
    pub reject_if: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DeprecationNotice {
    pub text: String,
    pub help: Option<String>,
    pub replacement: Option<String>,
}

impl From<MessageField<protos::DeprecationNotice>> for DeprecationNotice {
    fn from(value: MessageField<protos::DeprecationNotice>) -> Self {
        Self {
            text: value.text.clone().expect("the `text` field is required"),
            help: value.help.clone(),
            replacement: value.replacement.clone(),
        }
    }
}

/// A field in a [`Struct`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StructField {
    /// For structures derived from a protobuf this contains the field number
    /// specified in the .proto file. For other structures this is set to 0.
    pub number: u64,
    /// Field type and value.
    pub type_value: TypeValue,
    /// Access control list (ACL) for accessing this struct field.
    pub acl: Option<Vec<AclEntry>>,
    /// Deprecation notice that must be shown when the field is used in a
    /// rule. This is `None` for non-deprecated fields.
    pub deprecation_notice: Option<DeprecationNotice>,
}

/// A dynamic structure with one or more fields.
///
/// These structures are used during the compilation of YARA rules and the
/// evaluation of conditions. Fields can be any of the primitive types like
/// integers, floats or strings, or more complex types like maps, arrays and
/// other structures.
///
/// There's usually a top-level struct that represents the global scope in
/// YARA, where each field represents a variable or a YARA module. Each module
/// is also represented by one of these structures.
///
/// The structures that represent a YARA module are created from the protobuf
/// associated to that module. Function [`Struct::from_proto_descriptor_and_msg`]
/// is used for that purpose.
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct Struct {
    /// Fields in this structure.
    ///
    /// An `IndexMap` is used instead of a `HashMap` because we want to be
    /// able to maintain the field insertion order and retrieve fields
    /// according to this order. For protobuf-derived structures fields
    /// are inserted in the order determined by their tag numbers, the
    /// order in which they appear in the .proto source file is
    /// irrelevant.
    fields: IndexMap<String, StructField>,
    /// True if this is the root structure. The root structure is the top-level
    /// structure that contains global variables and modules.
    is_root: bool,
    /// The name of the protobuf type this enum was crated from. If the enum
    /// was not created from a protobuf type, this is `None`.
    protobuf_type_name: Option<String>,
}

impl SymbolLookup for Struct {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        let (field, index) = self.field_and_index_by_name(ident)?;
        Some(Symbol::Field {
            index,
            is_root: self.is_root,
            type_value: field.type_value.clone(),
            acl: field.acl.clone(),
            deprecation_notice: field.deprecation_notice.clone(),
        })
    }
}

impl Struct {
    /// Creates a new, empty struct.
    pub fn new() -> Self {
        Self {
            fields: IndexMap::new(),
            is_root: false,
            protobuf_type_name: None,
        }
    }

    /// Makes this the root structure.
    pub fn make_root(mut self) -> Self {
        self.is_root = true;
        self
    }

    /// Returns the protobuf type this enum was created from, if any.
    pub fn protobuf_type_name(&self) -> Option<&str> {
        self.protobuf_type_name.as_deref()
    }

    /// Adds a new field to the structure.
    ///
    /// The field name may be a dot-separated sequence of field names, like
    /// "foo.bar.baz". In such cases the field named "foo" must be another
    /// structure with a field named "bar", which is also a structure where
    /// the field "baz" will be finally inserted. If some of the intermediate
    /// structure fields don't exist, they will be created.
    ///
    /// If the final field was not present in the structure, it is added and
    /// the function returns `None`. If it was already present, it is replaced
    /// with the new field and the function returns `Some(StructField)` with
    /// the previous field.
    ///
    /// # Panics
    ///
    /// If the name is a dot-separated sequence of field names but some of
    /// the intermediate fields is not a structure. For example if field
    /// name is "foo.bar.baz" but either "foo" or "bar" is not a structure.
    ///
    /// If there is some [`Rc`] or [`Weak`] pointer pointing to any of the
    /// intermediate structures (e.g: the structures in the "foo" and "bar"
    /// fields).
    pub fn add_field<N: Into<String>>(
        &mut self,
        name: N,
        value: TypeValue,
    ) -> Option<StructField> {
        let name = name.into();
        if let Some(dot) = name.find('.') {
            // Get existing field or create a new one of type struct.
            let field = self
                .field_entry_by_name(name[0..dot].to_owned())
                .or_insert_with(|| StructField {
                    type_value: TypeValue::Struct(Rc::new(Struct::new())),
                    number: 0,
                    acl: None,
                    deprecation_notice: None,
                });

            if let TypeValue::Struct(ref mut s) = field.type_value {
                let s = Rc::<Struct>::get_mut(s).unwrap_or_else(|| {
                    panic!(
                        "`add_field` was called while an `Rc` or `Weak` pointer points to field `{}`",
                        (&name[0..dot])
                    )
                });

                s.add_field(&name[dot + 1..], value)
            } else {
                panic!("field `{}` is not a struct", &name[0..dot])
            }
        } else {
            self.fields.insert(
                name,
                StructField {
                    type_value: value,
                    number: 0,
                    acl: None,
                    deprecation_notice: None,
                },
            )
        }
    }

    /// Adds new fields to the structure corresponding to the values in the
    /// given enum.
    fn add_enum_fields(&mut self, enum_descriptor: &EnumDescriptor) {
        let mut enclosing_msg = enum_descriptor.enclosing_message();
        let mut path = Vec::new();

        if !Self::enum_is_inline(enum_descriptor) {
            path.push(Self::enum_name(enum_descriptor));
        }

        while let Some(msg) = enclosing_msg {
            if !Self::is_module_root(&msg) {
                path.push(Self::message_name(&msg));
            }
            enclosing_msg = msg.enclosing_message()
        }

        let path = path.iter().rev().join(".");

        for item in enum_descriptor.values() {
            let field_name = if path.is_empty() {
                item.name().to_owned()
            } else {
                format!("{}.{}", path, item.name())
            };
            self.add_field(field_name, Self::enum_value(&item).into());
        }
    }

    /// Returns true if the structure have a field with the given name.
    #[inline]
    pub fn has_field(&self, name: &str) -> bool {
        self.field_by_name(name).is_some()
    }

    /// Get a field by index.
    #[inline]
    pub fn field_by_index(&self, index: usize) -> Option<&StructField> {
        self.fields.get_index(index).map(|(_, v)| v)
    }

    /// Get a field by name.
    #[inline]
    pub fn field_by_name(&self, name: &str) -> Option<&StructField> {
        self.fields.get(name)
    }

    /// Get a field and its corresponding index by name.
    #[inline]
    pub fn field_and_index_by_name(
        &self,
        name: &str,
    ) -> Option<(&StructField, usize)> {
        self.fields.get_full(name).map(|(index, _, field)| (field, index))
    }

    /// Get a mutable field by name.
    #[inline]
    pub fn field_by_name_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut StructField> {
        self.fields.get_mut(name)
    }

    /// Get the entry corresponding to the field with the give name, for
    /// insertion and/or in-place manipulation.
    #[inline]
    pub fn field_entry_by_name(
        &mut self,
        name: String,
    ) -> indexmap::map::Entry<'_, String, StructField> {
        self.fields.entry(name)
    }

    /// Calls `f` with all the structures contained in the current one.
    /// The first call to `f` is for the current structure itself.
    pub fn enum_substructures<F>(&mut self, f: &mut F)
    where
        F: FnMut(&mut Struct),
    {
        f(self);
        for field in self.fields.values_mut() {
            match &mut field.type_value {
                TypeValue::Struct(s) => {
                    Rc::<Struct>::get_mut(s).unwrap().enum_substructures(f);
                }
                TypeValue::Array(a) => {
                    Rc::<Array>::get_mut(a).unwrap().enum_substructures(f);
                }
                _ => {}
            }
        }
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
    /// required only at compile time, so that the compiler can look up the
    /// enums by name and resolve their values, but at scan time enums are
    /// not necessary because their values are already embedded in the code.
    /// The scanner never asks for an enum by field index.
    ///
    /// Also notice that a .proto file can define enums at the top level,
    /// outside any message. Those enums will be handled as if they were
    /// defined inside the module's root message, in other words, if you
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
    ) -> Rc<Self> {
        let syntax = msg_descriptor.file_descriptor().syntax();
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

            let mut value = match field_ty {
                RuntimeFieldType::Singular(ty) => Self::new_value(
                    &ty,
                    msg.and_then(|msg| fd.get_singular(msg)),
                    generate_fields_for_enums,
                    syntax,
                ),
                RuntimeFieldType::Repeated(ty) => Self::new_array(
                    &ty,
                    msg.map(|msg| fd.get_repeated(msg)),
                    generate_fields_for_enums,
                ),
                RuntimeFieldType::Map(key_ty, value_ty) => Self::new_map(
                    &key_ty,
                    &value_ty,
                    msg.map(|msg| fd.get_map(msg)),
                    generate_fields_for_enums,
                    syntax,
                ),
            };

            if Self::lowercase(&fd) {
                if let TypeValue::String { constraints, .. } = &mut value {
                    constraints
                        .get_or_insert_default()
                        .push(StringConstraint::Lowercase);
                } else {
                    panic!(
                        "`lowercase = true` in non-string field: {}",
                        fd.full_name()
                    )
                }
            }

            fields.push((
                name,
                StructField {
                    // Index is initially zero, will be adjusted later.
                    type_value: value,
                    acl: Self::acl(&fd),
                    deprecation_notice: Self::deprecation_notice(&fd),
                    number,
                },
            ));
        }

        // Sort fields by field numbers specified in the proto.
        fields.sort_by(|a, b| a.1.number.cmp(&b.1.number));

        // Insert the fields in a map, checking for duplicate fields.
        let mut field_index = IndexMap::new();

        for (name, field) in fields {
            if field_index.insert(name, field).is_some() {
                panic!(
                    "duplicate field name in message `{}`",
                    msg_descriptor.name()
                )
            }
        }

        let mut new_struct = Self {
            fields: field_index,
            is_root: false,
            protobuf_type_name: Some(msg_descriptor.full_name().to_string()),
        };

        if generate_fields_for_enums && Self::is_module_root(msg_descriptor) {
            let mut enums = IndexSet::new();

            // Any enum declared or used by the module's root message is added.
            Self::nested_enums(msg_descriptor, &mut |enum_| {
                enums.insert(enum_);
            });

            // Also add the enums that are declared in the file outside any
            // structures.
            for enum_ in msg_descriptor.file_descriptor().enums() {
                enums.insert(enum_);
            }

            for enum_ in &enums {
                new_struct.add_enum_fields(enum_);
            }
        }

        Rc::new(new_struct)
    }

    /// Returns true if the given message is the YARA module's root message.
    fn is_module_root(msg_descriptor: &MessageDescriptor) -> bool {
        let file_descriptor = msg_descriptor.file_descriptor();
        if let Some(options) =
            module_options.get(&file_descriptor.proto().options)
        {
            options.root_message.unwrap() == msg_descriptor.full_name()
        } else {
            false
        }
    }

    /// Calls `f` for every enum type used or declared by a protobuf message,
    /// both directly (enums declared inside the message, or fields of type
    /// enum declared in the message), or indirectly (fields of message type
    /// that use or declare some enum type).
    fn nested_enums<F>(msg_descriptor: &MessageDescriptor, f: &mut F)
    where
        F: FnMut(EnumDescriptor),
    {
        for e in msg_descriptor.nested_enums() {
            f(e);
        }
        for fd in msg_descriptor.fields() {
            if Self::ignore_field(&fd) {
                continue;
            }
            match fd.runtime_field_type() {
                RuntimeFieldType::Singular(RuntimeType::Enum(e)) => f(e),
                RuntimeFieldType::Repeated(RuntimeType::Enum(e)) => f(e),
                RuntimeFieldType::Singular(RuntimeType::Message(m)) => {
                    if m.full_name() == msg_descriptor.full_name() {
                        panic!("recursive protobuf type: {}", m.full_name())
                    }
                    Self::nested_enums(&m, f);
                }
                RuntimeFieldType::Repeated(RuntimeType::Message(m)) => {
                    if m.full_name() == msg_descriptor.full_name() {
                        panic!("recursive protobuf type: {}", m.full_name())
                    }
                    Self::nested_enums(&m, f);
                }
                _ => {}
            }
        }
    }

    /// Given a [`MessageDescriptor`] returns the name that the corresponding
    /// structure will have in YARA.
    ///
    /// By default, the name of the structure will be the same one that it has
    /// in the protobuf definition. However, the name can be set to something
    /// different by using an annotation in the .proto file, like this:
    ///
    /// ```text
    /// message Foo {
    ///  option (yara.message_options).name = "Bar";
    /// }
    ///
    /// ```
    ///
    /// Here the `Foo` structure will be named `Bar` when the protobuf is
    /// converted into a [`Struct`].
    fn message_name(msg_descriptor: &MessageDescriptor) -> String {
        message_options
            .get(&msg_descriptor.proto().options)
            .and_then(|options| options.name)
            .unwrap_or_else(|| msg_descriptor.name().to_owned())
    }

    /// Given a [`EnumDescriptor`] returns the name that this enum will
    /// have in YARA.
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
        enum_options
            .get(&enum_descriptor.proto().options)
            .and_then(|options| options.name)
            .unwrap_or_else(|| enum_descriptor.name().to_owned())
    }

    /// Given a [`EnumDescriptor`] returns whether this enum is declared as
    /// inline.
    ///
    /// Inline enums are those whose fields are added directly to the parent
    /// struct, no new structs are created for accommodating the enum fields.
    ///
    /// For example, consider this non-inline enum:
    ///
    /// ```text
    /// enum MyEnum {
    ///   ITEM_0 = 0;
    ///   ITEM_1 = 1;
    /// }
    /// ```
    ///
    /// Fields like `ITEM_0` and `ITEM_1` will appear under a struct named
    /// `MyEnum`. If the enum is declared at the module level, it will be
    /// accessed like this:  `module_name.MyEnum.ITEM_0`.
    ///
    /// Now consider the inline variant:
    ///
    /// ```text
    /// enum MyEnum {
    ///   option (yara.enum_options).inline = true;
    ///   ITEM_0 = 0;
    ///   ITEM_1 = 1;
    /// }
    /// ```
    ///
    /// The fields in this enum will be used like `module_name.ITEM_0`, items
    /// in the enum are added directly as fields of the module, or the struct
    /// that contains the enum.
    fn enum_is_inline(enum_descriptor: &EnumDescriptor) -> bool {
        enum_options
            .get(&enum_descriptor.proto().options)
            .and_then(|options| options.inline)
            .unwrap_or(false)
    }

    /// Given a [`EnumValueDescriptor`] returns the value associated to that
    /// enum item.
    ///
    /// The value for each item in an enum can be specified in two ways: by
    /// means of the tag number, or by using a special option. Let's see an
    /// example of the first case:
    ///
    /// ```text
    /// enum MyEnum {
    ///   ITEM_0 = 0;
    ///   ITEM_1 = 1;
    /// }
    /// ```
    ///
    /// In this enum the value of `ITEM_0` is 0 and the value of `ITEM_1` is 1.
    /// The tag number associated to each item determines its value. However,
    /// this approach has one limitation, tag number are of type `i32` and
    /// therefore they are limited to the range `-2147483648,2147483647`. For
    /// larger values you need to use the second approach:
    ///
    /// ```text
    /// enum MyEnum {
    ///   ITEM_0 = 0  [(yara.enum_value).i64 = 0x7fffffffffff];
    ///   ITEM_1 = 1  [(yara.enum_value).i64 = -1];;
    /// }
    /// ```
    ///
    /// In this other case tag number are maintained because they are required
    /// in every protobuf enum, however, the value associated to each item is
    /// not determined by the field number, but by the `(yara.enum_value).i64`
    /// option.
    ///
    /// By using `(yara.enum_value).f64` you can specify a float value. For
    /// instance:
    ///
    /// enum Constants {
    ///   PI = 0  [(yara.enum_value).f64 = 3.141592];
    ///   TAU = 1  [(yara.enum_value).i64 = 6.283186];
    /// }
    ///
    /// What this function returns is the value associated to an enum item,
    /// returning the value set via the `(yara.enum_value).i64` option, if any,
    /// or the tag number.
    pub(crate) fn enum_value(
        enum_value_descriptor: &EnumValueDescriptor,
    ) -> EnumValue {
        enum_value
            .get(&enum_value_descriptor.proto().options)
            .and_then(|options| options.value)
            .unwrap_or_else(|| {
                EnumValue::I64(enum_value_descriptor.value() as i64)
            })
    }

    /// Returns an iterator over the fields of this structure.
    ///
    /// The returned values are tuples where the first value is the name of the
    /// field and the second one is a reference to [`StructField`] describing
    /// the field.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&str, &StructField)> {
        self.fields.iter().map(move |(name, field)| (name.as_str(), field))
    }

    /// Similar to [`Struct::enum_value`], but returns the enum value as an `i64`
    /// or `None` if it isn't an `i64`.
    pub(crate) fn enum_value_i64(
        enum_value_descriptor: &EnumValueDescriptor,
    ) -> Option<i64> {
        match Self::enum_value(enum_value_descriptor) {
            EnumValue::I64(i) => Some(i),
            EnumValue::F64(_) => None,
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
        field_options
            .get(&field_descriptor.proto().options)
            .and_then(|options| options.name)
            .unwrap_or_else(|| field_descriptor.name().to_owned())
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
    fn ignore_field(field_descriptor: &FieldDescriptor) -> bool {
        field_options
            .get(&field_descriptor.proto().options)
            .and_then(|options| options.ignore)
            .unwrap_or(false)
    }

    /// Given a [`FieldDescriptor`] returns `true` if the field is a lowercase
    /// string
    ///
    /// Lowercase strings are annotated in the protobuf definition as follows:
    ///
    /// ```text
    /// string foo = 1 [(yara.field_options).lowercase = true];
    /// ```
    fn lowercase(field_descriptor: &FieldDescriptor) -> bool {
        field_options
            .get(&field_descriptor.proto().options)
            .and_then(|options| options.lowercase)
            .unwrap_or(false)
    }

    /// Given a [`FieldDescriptor`] returns the information that must be
    /// shown if the field is deprecated.
    ///
    /// ```text
    /// string foo = 1 [(yara.field_options).deprecation_notice = {
    ///    text: "`bar` is deprecated",
    ///    replacement: "baz",
    /// }];
    /// ```
    fn deprecation_notice(
        field_descriptor: &FieldDescriptor,
    ) -> Option<DeprecationNotice> {
        field_options
            .get(&field_descriptor.proto().options)
            .filter(|options| options.deprecation_notice.is_some())
            .map(|options| options.deprecation_notice.into())
    }

    /// Given a [`FieldDescriptor`] returns the Access Control List (ACL)
    /// associated to that field.
    ///
    /// See [`AclEntry`] for details.
    fn acl(field_descriptor: &FieldDescriptor) -> Option<Vec<AclEntry>> {
        field_options
            .get(&field_descriptor.proto().options)
            .map(|options| options.acl)
            .filter(|acl| !acl.is_empty())
            .map(|acl| {
                acl.into_iter()
                    .map(|entry| AclEntry {
                        accept_if: entry.accept_if,
                        reject_if: entry.reject_if,
                        error_title: entry
                            .error_title
                            .expect("the `error_title` field is required"),
                        error_label: entry
                            .error_label
                            .expect("the `error_label` field is required"),
                    })
                    .collect()
            })
    }

    /// Given a protobuf type and value returns a [`TypeValue`].
    ///
    /// For proto2, if `value` is `None`, the resulting [`TypeValue`] will
    /// contain type information only, but not values. For proto3, `None`
    /// values will be translated to the default value for the type (i.e:
    /// 0, false, empty strings).
    ///
    /// This is because in proto3, when a field is missing in the serialized
    /// data, we can't know whether it's because the field was left
    /// uninitialized or because it was initialized with its default value.
    /// In both cases the result is that the field is not included in the
    /// serialized data. For that reason we can't assume that a missing
    /// field can be translated to an undefined field in YARA. An integer
    /// field that is missing from the serialized data could be simply
    /// because its value was set to 0.
    ///
    /// In proto2 in the other hand, initialized fields are always present in
    /// the serialized data, regardless of their values. So we can distinguish
    /// a default value (like 0) from an uninitialized value, and handle the
    /// latter undefined values in YARA.
    fn new_value(
        ty: &RuntimeType,
        value: Option<ReflectValueRef>,
        enum_as_fields: bool,
        syntax: Syntax,
    ) -> TypeValue {
        match ty {
            RuntimeType::I32
            | RuntimeType::I64
            | RuntimeType::U32
            | RuntimeType::U64
            | RuntimeType::Enum(_) => {
                if let Some(v) = value {
                    TypeValue::var_integer_from(Self::value_as_i64(v))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::var_integer_from(0)
                } else {
                    TypeValue::unknown_integer()
                }
            }
            RuntimeType::F32 | RuntimeType::F64 => {
                if let Some(v) = value {
                    TypeValue::var_float_from(Self::value_as_f64(v))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::var_float_from(0_f64)
                } else {
                    TypeValue::unknown_float()
                }
            }
            RuntimeType::Bool => {
                if let Some(v) = value {
                    TypeValue::var_bool_from(Self::value_as_bool(v))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::var_bool_from(false)
                } else {
                    TypeValue::unknown_bool()
                }
            }
            RuntimeType::String | RuntimeType::VecU8 => {
                if let Some(v) = value {
                    TypeValue::var_string_from(Self::value_as_string(v))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::var_string_from(b"")
                } else {
                    TypeValue::unknown_string()
                }
            }
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
                TypeValue::Struct(structure)
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
                                Rc::new(BString::from(value.to_str().unwrap()))
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
                                Rc::new(BString::from(
                                    value.to_bytes().unwrap(),
                                ))
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
                                Self::from_proto_descriptor_and_value(
                                    msg_descriptor,
                                    value,
                                    enum_as_fields,
                                )
                            })
                            .collect(),
                    )
                } else {
                    Array::Structs(vec![
                        Struct::from_proto_descriptor_and_msg(
                            msg_descriptor,
                            None,
                            enum_as_fields,
                        ),
                    ])
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
        syntax: Syntax,
    ) -> TypeValue {
        let map = match key_ty {
            RuntimeType::String => Self::new_map_with_string_key(
                value_ty,
                map,
                enum_as_fields,
                syntax,
            ),
            RuntimeType::I32
            | RuntimeType::I64
            | RuntimeType::U32
            | RuntimeType::U64 => Self::new_map_with_integer_key(
                value_ty,
                map,
                enum_as_fields,
                syntax,
            ),
            ty => {
                panic!("maps in YARA can't have keys of type `{ty}`");
            }
        };

        TypeValue::Map(Rc::new(map))
    }

    fn new_map_with_integer_key(
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
        syntax: Syntax,
    ) -> Map {
        if let Some(map) = map {
            let mut result = IndexMap::default();
            for (key, value) in map.into_iter() {
                result.insert(
                    Self::value_as_i64(key),
                    Self::new_value(
                        value_ty,
                        Some(value),
                        enum_as_fields,
                        syntax,
                    ),
                );
            }
            Map::IntegerKeys { deputy: None, map: result }
        } else {
            Map::IntegerKeys {
                deputy: Some(Self::new_value(
                    value_ty,
                    None,
                    enum_as_fields,
                    syntax,
                )),
                map: Default::default(),
            }
        }
    }

    fn new_map_with_string_key(
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
        syntax: Syntax,
    ) -> Map {
        if let Some(map) = map {
            let mut result = IndexMap::default();
            for (key, value) in map.into_iter() {
                result.insert(
                    BString::from(Self::value_as_string(key)),
                    Self::new_value(
                        value_ty,
                        Some(value),
                        enum_as_fields,
                        syntax,
                    ),
                );
            }
            Map::StringKeys { deputy: None, map: result }
        } else {
            Map::StringKeys {
                deputy: Some(Self::new_value(
                    value_ty,
                    None,
                    enum_as_fields,
                    syntax,
                )),
                map: Default::default(),
            }
        }
    }

    fn from_proto_descriptor_and_value(
        msg_descriptor: &MessageDescriptor,
        value: ReflectValueRef,
        enum_as_fields: bool,
    ) -> Rc<Self> {
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
            ReflectValueRef::Enum(_, v) => v as i64,
            _ => panic!(),
        }
    }

    fn value_as_f64(value: ReflectValueRef) -> f64 {
        match value {
            ReflectValueRef::F64(v) => v,
            ReflectValueRef::F32(v) => v as f64,
            _ => panic!(),
        }
    }

    fn value_as_bool(value: ReflectValueRef) -> bool {
        match value {
            ReflectValueRef::Bool(v) => v,
            _ => panic!(),
        }
    }

    fn value_as_string(value: ReflectValueRef<'_>) -> &[u8] {
        match value {
            ReflectValueRef::String(v) => v.as_bytes(),
            ReflectValueRef::Bytes(v) => v,
            _ => panic!(),
        }
    }
}

impl PartialEq for Struct {
    /// Compares two structs for equality.
    ///
    /// Structs are equal if they have the same number of fields, fields have
    /// the same names and types, and appear in the same order. Field values
    /// are not taken into account.
    fn eq(&self, other: &Self) -> bool {
        // Both structs must have the same number of fields.
        if self.fields.len() != other.fields.len() {
            return false;
        }
        for (a, b) in iter::zip(&self.fields, &other.fields) {
            // Field names must match.
            if a.0 != b.0 {
                return false;
            };
            // Field types must match.
            if !a.1.type_value.eq_type(&b.1.type_value) {
                return false;
            }
        }
        true
    }
}

impl From<&Module> for Rc<Struct> {
    /// Creates a `Rc<Struct>` from a [`Module`] definition.
    fn from(module: &Module) -> Self {
        // Create the structure that describes the module.
        let mut module_struct = Struct::from_proto_descriptor_and_msg(
            &module.root_struct_descriptor,
            None,
            true,
        );

        // Get a mutable reference for the module's structure. This is
        // possible because there's only one Rc pointing to the structure,
        // otherwise the `.unwrap()` panics.
        let module_struct_mut =
            Rc::<Struct>::get_mut(&mut module_struct).unwrap();

        // If the YARA module has an associated Rust module, check if it
        // exports some function and add it to the structure.
        if let Some(rust_module_name) = module.rust_module_name {
            let functions = WasmExport::get_functions(|export| {
                export.public
                    && export.rust_module_path.ends_with(rust_module_name)
                    && export.method_of.is_none()
            })
            .into_iter()
            .sorted_by_key(|(name, _)| *name);

            for (name, func) in functions {
                let func = TypeValue::Func(Rc::new(func));
                if module_struct_mut.add_field(name, func).is_some() {
                    panic!(
                        "function `{name}` has the same name than a field in `{rust_module_name}`",
                    )
                };
            }
        }

        // Iterate over all substructures of the module's main structure and
        // add any methods defined for them.
        module_struct_mut.enum_substructures(&mut |sub_struct| {
            let methods = sub_struct.protobuf_type_name().map(WasmExport::get_methods);
            if let Some(methods) = methods {
                for (name, func) in methods {
                    let func = TypeValue::Func(Rc::new(func));
                    if sub_struct.add_field(name, func).is_some() {
                        panic!(
                            "method `{name}` has the same name than a field in `{}`",
                            sub_struct.protobuf_type_name().unwrap(),
                        )
                    };
                }
            }
        });

        module_struct
    }
}

#[cfg(test)]
mod tests {
    use super::Struct;
    use crate::types::{Array, Type, TypeValue};
    use std::rc::Rc;

    #[test]
    fn test_struct() {
        let mut root = Struct::default();
        let foo = Struct::default();

        root.add_field("foo", TypeValue::Struct(Rc::new(foo)));
        root.add_field("bar", TypeValue::var_integer_from(1));

        let field1 = root.field_by_name("foo").unwrap();
        let field2 = root.field_by_index(0).unwrap();

        assert_eq!(field1.type_value.ty(), Type::Struct);
        assert_eq!(field1.type_value.ty(), field2.type_value.ty());

        root.add_field("foo.bar", TypeValue::var_integer_from(1));
    }
    #[test]
    fn test_proto_struct() {
        use protobuf::MessageFull;

        use crate::modules::protos::test_proto2::TestProto2;

        let mut structure = Struct::from_proto_descriptor_and_msg(
            &TestProto2::descriptor(),
            None,
            true,
        );

        let structure = Rc::<Struct>::get_mut(&mut structure).unwrap();

        let mut names = Vec::new();

        structure.enum_substructures(&mut |s| {
            names.push(s.protobuf_type_name().map(|n| n.to_string()));
            println!("{s:?}\n\n")
        });

        assert_eq!(
            vec![
                Some("test_proto2.TestProto2".to_string()),
                Some("test_proto2.NestedProto2".to_string()),
                Some("test_proto2.NestedProto2".to_string()),
                None,
                None,
                None,
                None,
                None,
            ],
            names
        );
    }

    #[test]
    fn struct_eq() {
        let mut sub: Struct = Struct::default();

        sub.add_field("integer", TypeValue::unknown_integer());
        sub.add_field("string", TypeValue::unknown_string());
        sub.add_field("boolean", TypeValue::unknown_bool());

        let sub = Rc::new(sub);

        let mut a = Struct::default();
        let mut b = Struct::default();

        a.add_field("boolean", TypeValue::var_bool_from(true));
        a.add_field("integer", TypeValue::var_integer_from(1));
        a.add_field("structure", TypeValue::Struct(sub.clone()));
        a.add_field(
            "floats_array",
            TypeValue::Array(Rc::new(Array::Floats(vec![]))),
        );

        // At this point a != b because b is still empty.
        assert_ne!(a, b);

        b.add_field("boolean", TypeValue::var_bool_from(false));
        b.add_field("integer", TypeValue::var_integer_from(1));
        b.add_field("structure", TypeValue::Struct(sub));
        b.add_field(
            "floats_array",
            TypeValue::Array(Rc::new(Array::Floats(vec![]))),
        );

        // At this point a == b.
        assert_eq!(a, b);

        a.add_field("foo", TypeValue::var_bool_from(false));
        b.add_field("foo", TypeValue::unknown_integer());

        // At this point a != b again because field "foo" have a different type
        // on each structure.
        assert_ne!(a, b);
    }
}
