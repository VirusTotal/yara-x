use std::cell::RefCell;
use std::iter;
use std::ops::Deref;
use std::rc::Rc;

use crate::modules::RegisteredModule;
use crate::modules::protos::yara as protos;
use crate::modules::protos::yara::enum_value_options::Value as EnumValue;
use crate::modules::protos::yara::exts::{
    enum_options, enum_value, field_options, message_options, module_options,
};
use crate::symbols::{Symbol, SymbolLookup};
use crate::types::{Array, Map, StringConstraint, TypeValue, Value};
use crate::wasm::WasmExport;
use bstr::BString;
use indexmap::{IndexMap, IndexSet};
use itertools::Itertools;
use protobuf::reflect::{
    EnumDescriptor, FieldDescriptor, MessageDescriptor, ReflectMapRef,
    ReflectRepeatedRef, ReflectValueRef, RuntimeFieldType, RuntimeType,
};
use protobuf::reflect::{EnumValueDescriptor, Syntax};
use protobuf::{MessageDyn, MessageField};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

/// Wrapper around [`Rc<BString>`] used to deduplicate string values in a
/// [`FxHashSet`] when converting protobuf messages into [`Struct`] instances.
///
/// Implementing [`std::borrow::Borrow<[u8]>`] with matching [`PartialEq`],
/// [`Eq`], and [`std::hash::Hash`] implementations allows looking up existing
/// [`Rc<BString>`] instances directly by `&[u8]` (`pool.get(bytes)`) without
/// allocating a new [`BString`] on cache hits or tying the pool to the
/// lifetime of borrowed protobuf slices.
#[derive(Eq)]
struct InternedString(Rc<BString>);

impl PartialEq for InternedString {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl std::hash::Hash for InternedString {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_slice().hash(state);
    }
}

impl std::borrow::Borrow<[u8]> for InternedString {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// An entry in a field's Access Control List (ACL).
///
/// When defining the structure of a module in a `.proto` file, fields can be
/// assigned an ACL (`acl`) containing one or more `AclEntry` items. Access to
/// a structure field during YARA rule compilation is evaluated against the set
/// of features enabled in the compiler via [`crate::Compiler::enable_feature`].
///
/// # Evaluation Rules
///
/// - All `AclEntry` items in a field's `acl` vector are evaluated sequentially
///   in order. Every single entry must be satisfied for the field to be
///   accessible. Evaluation stops at the first failing entry, which immediately
///   triggers a compilation error using that entry's `error_title` and
///   `error_label`.
///
/// - An `accept_if` list contains feature names. An entry is accepted if
///   `accept_if` is empty, or if at least one (ANY) of the listed features is
///   enabled in the compiler. For example, `accept_if: ["foo", "bar"]` means
///   the field is accepted if either "foo" or "bar" is enabled.
///
/// - A `reject_if` list contains feature names. An entry is rejected if at
///   least one (ANY) of the listed features is enabled in the compiler. If any
///   feature in `reject_if` is enabled, access is denied regardless of
///   `accept_if`. For example, `reject_if: ["legacy", "deprecated"]` denies
///   access if either `"legacy"` or `"deprecated"` is enabled.
///
/// # Protobuf Example
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
/// If some of the required conditions are not met, using this field in a YARA
/// rule causes a compilation error like:
///
/// ```text
/// error[E034]: foo is required
///  --> line:5:29
///   |
/// 5 |  test_proto2.requires_foo_and_bar == 0
///   |              ^^^^^^^^^^^^^^^^^^^^ this field was used without foo
///   |
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AclEntry {
    /// Title of the compilation error raised if this ACL entry fails.
    pub error_title: String,
    /// Label pointing to the code location in the error report if this ACL
    /// entry fails.
    pub error_label: String,
    /// Features that grant access. At least one feature in this list must be
    /// enabled (logical OR). If empty, access is accepted by default.
    pub accept_if: Vec<String>,
    /// Features that deny access. If any feature in this list is enabled
    /// (logical OR), access is rejected.
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

/// Compile-time metadata associated with a field in a [`Struct`].
///
/// This metadata is stored in [`Struct::field_meta`] and shared across all
/// [`Struct`] instances created from the same protobuf [`MessageDescriptor`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct StructFieldMeta {
    /// Access control list (ACL) for accessing this struct field.
    #[serde(skip)]
    pub acl: Option<Vec<AclEntry>>,
    /// Deprecation notice that must be shown when the field is used in a
    /// rule. This is `None` for non-deprecated fields.
    #[serde(skip)]
    pub deprecation_notice: Option<DeprecationNotice>,
    /// Description of the field extracted from the .proto file.
    #[serde(skip)]
    pub doc: Option<&'static str>,
}

/// A field in a [`Struct`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StructField {
    /// Field type and value.
    type_value: TypeValue,
}

impl StructField {
    /// Returns a reference to the [`TypeValue`] of this field.
    #[inline]
    pub fn type_value(&self) -> &TypeValue {
        &self.type_value
    }

    /// Returns a mutable reference to the [`TypeValue`] of this field.
    #[inline]
    pub fn type_value_mut(&mut self) -> &mut TypeValue {
        &mut self.type_value
    }
}

/// Pre-computed schema for a single protobuf field within a [`ProtoStructSchema`].
struct ProtoFieldSchema {
    /// Protobuf reflection descriptor for this field.
    descriptor: FieldDescriptor,
    /// True if the field was annotated with `[(yara.field_options).lowercase = true]`.
    lowercase: bool,
}

/// Pre-computed schema for a protobuf [`MessageDescriptor`].
///
/// Converting a protobuf message into a [`Struct`] requires inspecting the
/// message's [`FieldDescriptor`]s, parsing custom `(yara.field_options)`
/// extensions (such as `ignore`, `name`, `lowercase`, `acl`, and
/// `deprecation_notice`), sorting fields by their protobuf tag number, and
/// building an [`IndexMap`] that maps field names to their index and metadata.
///
/// Because a single scan can instantiate tens of thousands of [`Struct`]s from
/// the same [`MessageDescriptor`] (for example, `dotnet.Class`, `dotnet.Method`,
/// and `dotnet.Param`), doing this work on every [`Struct`] creation would be
/// very expensive in both CPU and memory. Instead, `ProtoStructSchema` computes
/// this information once per [`MessageDescriptor`] and caches it in the
/// thread-local `PROTO_STRUCT_SCHEMAS` map so that all [`Struct`] instances of
/// the same protobuf message type share the same
/// `Rc<IndexMap<String, StructFieldMeta>>`.
struct ProtoStructSchema {
    /// Protobuf syntax version (`proto2` or `proto3`) of the file defining the message.
    syntax: Syntax,
    /// Shared map from field name to [`StructFieldMeta`], ordered by protobuf tag number.
    field_meta: Rc<IndexMap<String, StructFieldMeta>>,
    /// Per-field descriptors and options in the same order as `field_meta`.
    fields: Vec<ProtoFieldSchema>,
}

thread_local! {
    static PROTO_STRUCT_SCHEMAS: RefCell<FxHashMap<MessageDescriptor, Rc<ProtoStructSchema>>> =
        RefCell::new(FxHashMap::default());
    static EMPTY_ARRAY_INTEGERS: Rc<Array> = Rc::new(Array::Integers(vec![]));
    static EMPTY_ARRAY_FLOATS: Rc<Array> = Rc::new(Array::Floats(vec![]));
    static EMPTY_ARRAY_BOOLS: Rc<Array> = Rc::new(Array::Bools(vec![]));
    static EMPTY_ARRAY_STRINGS: Rc<Array> = Rc::new(Array::Strings(vec![]));
    static EMPTY_ARRAY_STRUCTS: Rc<Array> = Rc::new(Array::Structs(vec![]));
}

impl ProtoStructSchema {
    /// Returns the cached [`ProtoStructSchema`] for `msg_descriptor`, computing
    /// and caching it on first access in the current thread.
    fn get_or_init(msg_descriptor: &MessageDescriptor) -> Rc<Self> {
        PROTO_STRUCT_SCHEMAS.with(|cache| {
            if let Some(schema) = cache.borrow().get(msg_descriptor) {
                return Rc::clone(schema);
            }
            let schema = Rc::new(Self::from_descriptor(msg_descriptor));
            cache
                .borrow_mut()
                .insert(msg_descriptor.clone(), Rc::clone(&schema));
            schema
        })
    }

    /// Builds a [`ProtoStructSchema`] from `msg_descriptor`.
    fn from_descriptor(msg_descriptor: &MessageDescriptor) -> Self {
        let syntax = msg_descriptor.file_descriptor().syntax();
        let proto_fields = msg_descriptor.fields();
        let mut temp_fields = Vec::new();

        for fd in proto_fields {
            let options = field_options.get(&fd.proto().options);
            // The field should be ignored if it was annotated with:
            // [(yara.field_options).ignore = true]
            if options.as_ref().and_then(|o| o.ignore).unwrap_or(false) {
                continue;
            }
            let lowercase =
                options.as_ref().and_then(|o| o.lowercase).unwrap_or(false);
            let name = options
                .and_then(|o| o.name)
                .unwrap_or_else(|| fd.name().to_owned());
            let number = fd.number() as u64;
            temp_fields.push((
                number,
                name,
                ProtoFieldSchema { descriptor: fd, lowercase },
            ));
        }

        // Sort fields by field numbers specified in the proto.
        temp_fields.sort_by_key(|(number, _, _)| *number);

        let mut field_meta = IndexMap::with_capacity(temp_fields.len());
        let mut fields = Vec::with_capacity(temp_fields.len());

        for (number, name, field_schema) in temp_fields {
            let acl = Struct::acl(&field_schema.descriptor);
            let deprecation_notice =
                Struct::deprecation_notice(&field_schema.descriptor);
            let doc = Struct::field_doc(msg_descriptor.full_name(), number);
            let meta = StructFieldMeta { acl, deprecation_notice, doc };
            if field_meta.insert(name, meta).is_some() {
                panic!(
                    "duplicate field name in message `{}`",
                    msg_descriptor.name()
                )
            }
            fields.push(field_schema);
        }

        Self { syntax, field_meta: Rc::new(field_meta), fields }
    }
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
    /// Field metadata keyed by field name in insertion order. The index of each
    /// entry in this `IndexMap` corresponds to its [`StructField`] in `fields`.
    ///
    /// Wrapped in [`Rc`] so that all [`Struct`] instances created from the
    /// same protobuf [`MessageDescriptor`] share a single [`IndexMap`]
    /// instead of duplicating field names, metadata, and hash tables per
    /// instance.
    field_meta: Rc<IndexMap<String, StructFieldMeta>>,
    /// Fields in this structure, ordered by their index in `field_meta`.
    /// For protobuf-derived structures fields are inserted in the order
    /// determined by their tag numbers, the order in which they appear in
    /// the .proto source file is irrelevant.
    fields: Vec<StructField>,
    /// The name of the protobuf type this struct was created from. If the struct
    /// was not created from a protobuf type (or was created at scan time where
    /// the type name is not needed), this is `None`.
    protobuf_type_name: Option<String>,
    /// True if this is the root structure. The root structure is the top-level
    /// structure that contains global variables and modules.
    is_root: bool,
    /// True if this structure is representing an enum.
    is_enum: bool,
}

impl SymbolLookup for Struct {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        let (index, _, meta) = self.field_meta.get_full(ident)?;
        let field = self.fields.get(index)?;
        Some(Symbol::Field {
            index,
            is_root: self.is_root,
            type_value: field.type_value.clone(),
            acl: meta.acl.clone(),
            deprecation_notice: meta.deprecation_notice.clone(),
        })
    }
}

impl Struct {
    /// Creates a new, empty struct.
    pub fn new() -> Self {
        Self {
            field_meta: Rc::new(IndexMap::new()),
            fields: Vec::new(),
            is_root: false,
            protobuf_type_name: None,
            is_enum: false,
        }
    }

    /// Makes this the root structure.
    pub fn make_root(mut self) -> Self {
        self.is_root = true;
        self
    }

    /// Returns true if this structure represents an enum.
    #[inline]
    pub fn is_enum(&self) -> bool {
        self.is_enum
    }

    /// Returns the protobuf type this struct was created from, if any.
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
            let prefix = &name[0..dot];
            // Get existing field or create a new one of type struct.
            let field = self.get_or_insert_struct_field(prefix);

            if let TypeValue::Struct(ref mut s) = field.type_value {
                let s = Rc::<Struct>::get_mut(s).unwrap_or_else(|| {
                    panic!(
                        "`add_field` was called while an `Rc` or `Weak` pointer points to field `{}`",
                        prefix
                    )
                });

                s.add_field(&name[dot + 1..], value)
            } else {
                panic!("field `{}` is not a struct", prefix)
            }
        } else {
            let new_field = StructField { type_value: value };
            if let Some(index) = self.field_meta.get_index_of(name.as_str()) {
                Some(std::mem::replace(&mut self.fields[index], new_field))
            } else {
                Rc::make_mut(&mut self.field_meta)
                    .insert(name, StructFieldMeta::default());
                self.fields.push(new_field);
                None
            }
        }
    }

    fn get_or_insert_struct_field(&mut self, name: &str) -> &mut StructField {
        if let Some(index) = self.field_meta.get_index_of(name) {
            &mut self.fields[index]
        } else {
            let (index, _) = Rc::make_mut(&mut self.field_meta)
                .insert_full(name.to_owned(), StructFieldMeta::default());
            self.fields.push(StructField {
                type_value: TypeValue::Struct(Rc::new(Struct::new())),
            });
            &mut self.fields[index]
        }
    }

    /// Adds new fields to the structure corresponding to the values in the
    /// given enum.
    fn add_enum_fields(&mut self, enum_descriptor: &EnumDescriptor) {
        let mut enclosing_msg = enum_descriptor.enclosing_message();
        let mut path = Vec::new();

        let is_inline = Self::enum_is_inline(enum_descriptor);
        if !is_inline {
            path.push(Self::enum_name(enum_descriptor));
        }

        while let Some(msg) = enclosing_msg {
            if !Self::is_module_root(&msg) {
                path.push(Self::message_name(&msg));
            }
            enclosing_msg = msg.enclosing_message()
        }

        let path = path.iter().rev().join(".");

        if !is_inline {
            let enum_struct = self.get_or_create_struct(&path);
            enum_struct.is_enum = true;
            for item in enum_descriptor.values() {
                enum_struct
                    .add_field(item.name(), Self::enum_value(&item).into());
            }
        } else {
            for item in enum_descriptor.values() {
                let field_name = if path.is_empty() {
                    item.name().to_owned()
                } else {
                    format!("{}.{}", path, item.name())
                };
                self.add_field(field_name, Self::enum_value(&item).into());
            }
        }
    }

    fn get_or_create_struct(&mut self, path: &str) -> &mut Struct {
        if let Some(dot) = path.find('.') {
            let target = &path[0..dot];
            let field = self.get_or_insert_struct_field(target);

            if let TypeValue::Struct(ref mut s) = field.type_value {
                let s = Rc::<Struct>::get_mut(s).unwrap_or_else(|| {
                    panic!(
                        "`get_or_create_struct` was called while an `Rc` or `Weak` pointer points to field `{}`",
                        target
                    )
                });
                s.get_or_create_struct(&path[dot + 1..])
            } else {
                panic!("field `{}` is not a struct", target)
            }
        } else {
            let field = self.get_or_insert_struct_field(path);

            if let TypeValue::Struct(ref mut s) = field.type_value {
                Rc::<Struct>::get_mut(s).unwrap_or_else(|| {
                    panic!(
                        "`get_or_create_struct` was called while an `Rc` or `Weak` pointer points to field `{}`",
                        path
                    )
                })
            } else {
                panic!("field `{}` is not a struct", path)
            }
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
        self.fields.get(index)
    }

    /// Get a field by name.
    #[inline]
    pub fn field_by_name(&self, name: &str) -> Option<&StructField> {
        let index = self.field_meta.get_index_of(name)?;
        self.fields.get(index)
    }

    /// Get a mutable field by name.
    #[inline]
    pub fn field_by_name_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut StructField> {
        let index = self.field_meta.get_index_of(name)?;
        self.fields.get_mut(index)
    }

    /// Calls `f` with all the structures contained in the current one.
    /// The first call to `f` is for the current structure itself.
    pub fn enum_substructures<F>(&mut self, f: &mut F)
    where
        F: FnMut(&mut Struct),
    {
        f(self);
        for field in &mut self.fields {
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
    /// by the proto will be included in the structure. These are required
    /// only at compile time, or when constant folding is disabled.
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
        generate_compile_time_fields: bool,
    ) -> Rc<Self> {
        let mut string_pool = FxHashSet::default();
        Self::from_proto_descriptor_and_msg_with_pool(
            msg_descriptor,
            msg,
            generate_fields_for_enums,
            generate_compile_time_fields,
            &mut string_pool,
        )
    }

    fn from_proto_descriptor_and_msg_with_pool(
        msg_descriptor: &MessageDescriptor,
        msg: Option<&dyn MessageDyn>,
        generate_fields_for_enums: bool,
        generate_compile_time_fields: bool,
        string_pool: &mut FxHashSet<InternedString>,
    ) -> Rc<Self> {
        let schema = ProtoStructSchema::get_or_init(msg_descriptor);
        let syntax = schema.syntax;
        let mut fields = Vec::with_capacity(schema.fields.len());

        for field_schema in &schema.fields {
            let fd = &field_schema.descriptor;
            let field_ty = fd.runtime_field_type();

            let mut value = match field_ty {
                RuntimeFieldType::Singular(ty) => Self::new_value(
                    &ty,
                    msg.and_then(|msg| fd.get_singular(msg)),
                    generate_fields_for_enums,
                    generate_compile_time_fields,
                    syntax,
                    string_pool,
                ),
                RuntimeFieldType::Repeated(ty) => Self::new_array(
                    &ty,
                    msg.map(|msg| fd.get_repeated(msg)),
                    generate_fields_for_enums,
                    generate_compile_time_fields,
                    string_pool,
                ),
                RuntimeFieldType::Map(key_ty, value_ty) => Self::new_map(
                    &key_ty,
                    &value_ty,
                    msg.map(|msg| fd.get_map(msg)),
                    generate_fields_for_enums,
                    generate_compile_time_fields,
                    syntax,
                    string_pool,
                ),
            };

            if field_schema.lowercase {
                if let TypeValue::String { constraints, .. } = &mut value {
                    if generate_compile_time_fields {
                        *constraints = Some(vec![StringConstraint::Lowercase]);
                    }
                } else {
                    panic!(
                        "`lowercase = true` in non-string field: {}",
                        fd.full_name()
                    )
                }
            }

            fields.push(StructField { type_value: value });
        }

        let mut new_struct = Self {
            field_meta: Rc::clone(&schema.field_meta),
            fields,
            is_root: false,
            protobuf_type_name: if generate_compile_time_fields {
                Some(msg_descriptor.full_name().to_string())
            } else {
                None
            },
            is_enum: false,
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

    #[inline]
    fn intern_string(
        pool: &mut FxHashSet<InternedString>,
        bytes: &[u8],
    ) -> Rc<BString> {
        if let Some(entry) = pool.get(bytes) {
            return Rc::clone(&entry.0);
        }
        let rc = Rc::new(BString::from(bytes));
        pool.insert(InternedString(Rc::clone(&rc)));
        rc
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
    /// The returned values are tuples with the field name, a reference to
    /// [`StructField`] describing the field's type and value, and a reference
    /// to [`StructFieldMeta`] with the field's metadata.
    pub(crate) fn fields(
        &self,
    ) -> impl Iterator<Item = (&str, &StructField, &StructFieldMeta)> {
        iter::zip(&*self.field_meta, &self.fields)
            .map(|((name, meta), field)| (name.as_str(), field, meta))
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

    fn field_doc(msg_name: &str, field_number: u64) -> Option<&'static str> {
        use crate::modules::field_docs::FIELD_DOCS;
        let idx = FIELD_DOCS
            .binary_search_by(|&(name, number, _)| match name.cmp(msg_name) {
                std::cmp::Ordering::Equal => number.cmp(&field_number),
                ord => ord,
            })
            .ok()?;
        Some(FIELD_DOCS[idx].2)
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
        generate_compile_time_fields: bool,
        syntax: Syntax,
        string_pool: &mut FxHashSet<InternedString>,
    ) -> TypeValue {
        match ty {
            RuntimeType::U64 => {
                if let Some(v) = value {
                    TypeValue::var_unsigned_integer_from(Self::value_as_u64(v))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::var_unsigned_integer_from(0_u64)
                } else {
                    TypeValue::unknown_unsigned_integer()
                }
            }
            RuntimeType::U32 => {
                if let Some(v) = value {
                    TypeValue::Uint32(Value::Var(Self::value_as_u32(v)))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::Uint32(Value::Var(0))
                } else {
                    TypeValue::Uint32(Value::Unknown)
                }
            }
            RuntimeType::I32 => {
                if let Some(v) = value {
                    TypeValue::Int32(Value::Var(Self::value_as_i32(v)))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::Int32(Value::Var(0))
                } else {
                    TypeValue::Int32(Value::Unknown)
                }
            }
            RuntimeType::I64 | RuntimeType::Enum(_) => {
                if let Some(v) = value {
                    TypeValue::var_signed_integer_from(Self::value_as_i64(v))
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    TypeValue::var_signed_integer_from(0)
                } else {
                    TypeValue::unknown_signed_integer()
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
                    let s = Self::intern_string(
                        string_pool,
                        Self::value_as_string(v),
                    );
                    TypeValue::String {
                        value: Value::Var(s),
                        constraints: None,
                    }
                } else if syntax == Syntax::Proto3 {
                    // In proto3 unknown values are set to their default
                    // values.
                    let s = Self::intern_string(string_pool, b"");
                    TypeValue::String {
                        value: Value::Var(s),
                        constraints: None,
                    }
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
                        generate_compile_time_fields,
                        string_pool,
                    )
                } else {
                    Self::from_proto_descriptor_and_msg_with_pool(
                        msg_descriptor,
                        None,
                        enum_as_fields,
                        generate_compile_time_fields,
                        string_pool,
                    )
                };
                TypeValue::Struct(structure)
            }
        }
    }

    fn collect_repeated<T, F>(repeated: ReflectRepeatedRef<'_>, f: F) -> Vec<T>
    where
        F: FnMut(ReflectValueRef<'_>) -> T,
    {
        let mut vec = Vec::with_capacity(repeated.len());
        vec.extend(repeated.into_iter().map(f));
        vec
    }

    fn new_array(
        ty: &RuntimeType,
        repeated: Option<ReflectRepeatedRef>,
        enum_as_fields: bool,
        generate_compile_time_fields: bool,
        string_pool: &mut FxHashSet<InternedString>,
    ) -> TypeValue {
        if !generate_compile_time_fields
            && repeated.as_ref().is_some_and(|r| r.is_empty())
        {
            let empty_rc = match ty {
                RuntimeType::I32
                | RuntimeType::I64
                | RuntimeType::U32
                | RuntimeType::U64
                | RuntimeType::Enum(_) => EMPTY_ARRAY_INTEGERS.with(Rc::clone),
                RuntimeType::F32 | RuntimeType::F64 => {
                    EMPTY_ARRAY_FLOATS.with(Rc::clone)
                }
                RuntimeType::Bool => EMPTY_ARRAY_BOOLS.with(Rc::clone),
                RuntimeType::String | RuntimeType::VecU8 => {
                    EMPTY_ARRAY_STRINGS.with(Rc::clone)
                }
                RuntimeType::Message(_) => EMPTY_ARRAY_STRUCTS.with(Rc::clone),
            };
            return TypeValue::Array(empty_rc);
        }

        let array = match ty {
            RuntimeType::I32
            | RuntimeType::I64
            | RuntimeType::U32
            | RuntimeType::U64 => {
                if let Some(repeated) = repeated {
                    Array::Integers(Self::collect_repeated(
                        repeated,
                        Self::value_as_i64,
                    ))
                } else {
                    Array::Integers(vec![])
                }
            }
            RuntimeType::F32 => {
                if let Some(repeated) = repeated {
                    Array::Floats(Self::collect_repeated(
                        repeated,
                        Self::value_as_f64,
                    ))
                } else {
                    Array::Floats(vec![])
                }
            }
            RuntimeType::F64 => {
                if let Some(repeated) = repeated {
                    Array::Floats(Self::collect_repeated(
                        repeated,
                        Self::value_as_f64,
                    ))
                } else {
                    Array::Floats(vec![])
                }
            }
            RuntimeType::Bool => {
                if let Some(repeated) = repeated {
                    Array::Bools(Self::collect_repeated(
                        repeated,
                        Self::value_as_bool,
                    ))
                } else {
                    Array::Bools(vec![])
                }
            }
            RuntimeType::String => {
                if let Some(repeated) = repeated {
                    Array::Strings(Self::collect_repeated(repeated, |value| {
                        Self::intern_string(
                            string_pool,
                            value.to_str().unwrap().as_bytes(),
                        )
                    }))
                } else {
                    Array::Strings(vec![])
                }
            }
            RuntimeType::VecU8 => {
                if let Some(repeated) = repeated {
                    Array::Strings(Self::collect_repeated(repeated, |value| {
                        Self::intern_string(
                            string_pool,
                            value.to_bytes().unwrap(),
                        )
                    }))
                } else {
                    Array::Strings(vec![])
                }
            }
            RuntimeType::Enum(_) => {
                if let Some(repeated) = repeated {
                    Array::Integers(Self::collect_repeated(
                        repeated,
                        |value| value.to_enum_value().unwrap() as i64,
                    ))
                } else {
                    Array::Integers(vec![])
                }
            }
            RuntimeType::Message(msg_descriptor) => {
                if let Some(repeated) = repeated {
                    Array::Structs(Self::collect_repeated(repeated, |value| {
                        Self::from_proto_descriptor_and_value(
                            msg_descriptor,
                            value,
                            enum_as_fields,
                            generate_compile_time_fields,
                            string_pool,
                        )
                    }))
                } else {
                    Array::Structs(vec![
                        Self::from_proto_descriptor_and_msg_with_pool(
                            msg_descriptor,
                            None,
                            enum_as_fields,
                            generate_compile_time_fields,
                            string_pool,
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
        generate_compile_time_fields: bool,
        syntax: Syntax,
        string_pool: &mut FxHashSet<InternedString>,
    ) -> TypeValue {
        let map = match key_ty {
            RuntimeType::String => Self::new_map_with_string_key(
                value_ty,
                map,
                enum_as_fields,
                generate_compile_time_fields,
                syntax,
                string_pool,
            ),
            RuntimeType::I32
            | RuntimeType::I64
            | RuntimeType::U32
            | RuntimeType::U64 => Self::new_map_with_integer_key(
                value_ty,
                map,
                enum_as_fields,
                generate_compile_time_fields,
                syntax,
                string_pool,
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
        generate_compile_time_fields: bool,
        syntax: Syntax,
        string_pool: &mut FxHashSet<InternedString>,
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
                        generate_compile_time_fields,
                        syntax,
                        string_pool,
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
                    generate_compile_time_fields,
                    syntax,
                    string_pool,
                )),
                map: Default::default(),
            }
        }
    }

    fn new_map_with_string_key(
        value_ty: &RuntimeType,
        map: Option<ReflectMapRef>,
        enum_as_fields: bool,
        generate_compile_time_fields: bool,
        syntax: Syntax,
        string_pool: &mut FxHashSet<InternedString>,
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
                        generate_compile_time_fields,
                        syntax,
                        string_pool,
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
                    generate_compile_time_fields,
                    syntax,
                    string_pool,
                )),
                map: Default::default(),
            }
        }
    }

    fn from_proto_descriptor_and_value(
        msg_descriptor: &MessageDescriptor,
        value: ReflectValueRef,
        enum_as_fields: bool,
        generate_compile_time_fields: bool,
        string_pool: &mut FxHashSet<InternedString>,
    ) -> Rc<Self> {
        if let ReflectValueRef::Message(m) = value {
            Struct::from_proto_descriptor_and_msg_with_pool(
                msg_descriptor,
                Some(m.deref()),
                enum_as_fields,
                generate_compile_time_fields,
                string_pool,
            )
        } else {
            unreachable!()
        }
    }

    fn value_as_i32(value: ReflectValueRef) -> i32 {
        match value {
            ReflectValueRef::I32(v) => v,
            _ => panic!(),
        }
    }

    fn value_as_u32(value: ReflectValueRef) -> u32 {
        match value {
            ReflectValueRef::U32(v) => v,
            _ => panic!(),
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

    fn value_as_u64(value: ReflectValueRef) -> u64 {
        match value {
            ReflectValueRef::U32(v) => v as u64,
            ReflectValueRef::U64(v) => v,
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

    fn value_as_string<'a>(value: ReflectValueRef<'a>) -> &'a [u8] {
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
        if !Rc::ptr_eq(&self.field_meta, &other.field_meta)
            && !self.field_meta.keys().eq(other.field_meta.keys())
        {
            return false;
        }
        for (a, b) in iter::zip(&self.fields, &other.fields) {
            // Field types must match.
            if !a.type_value.eq_type(&b.type_value) {
                return false;
            }
        }
        true
    }
}

impl From<&dyn RegisteredModule> for Rc<Struct> {
    /// Creates a `Rc<Struct>` from a [`RegisteredModule`] definition.
    fn from(module: &dyn RegisteredModule) -> Self {
        // Create the structure that describes the module.
        let mut module_struct = Struct::from_proto_descriptor_and_msg(
            &module.root_descriptor(),
            None,
            true,
            true,
        );

        // Get a mutable reference for the module's structure. This is
        // possible because there's only one Rc pointing to the structure,
        // otherwise the `.unwrap()` panics.
        let module_struct_mut =
            Rc::<Struct>::get_mut(&mut module_struct).unwrap();

        // If the YARA module has an associated Rust module, check if it
        // exports some function and add it to the structure.
        if let Some(rust_module_name) = module.rust_module_name() {
            let functions = WasmExport::get_functions(|export| {
                export.owner_module().is_some_and(|owner| {
                    owner.name() == module.name()
                        && owner.rust_module_name() == Some(rust_module_name)
                })
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
        root.add_field("bar", TypeValue::var_signed_integer_from(1));

        let field1 = root.field_by_name("foo").unwrap();
        let field2 = root.field_by_index(0).unwrap();

        assert_eq!(field1.type_value.ty(), Type::Struct);
        assert_eq!(field1.type_value.ty(), field2.type_value.ty());

        root.add_field("foo.bar", TypeValue::var_signed_integer_from(1));
    }
    #[test]
    fn test_proto_struct() {
        use protobuf::MessageFull;

        use crate::modules::protos::test_proto2::TestProto2;

        let mut structure = Struct::from_proto_descriptor_and_msg(
            &TestProto2::descriptor(),
            None,
            true,
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

        sub.add_field("integer", TypeValue::unknown_signed_integer());
        sub.add_field("string", TypeValue::unknown_string());
        sub.add_field("boolean", TypeValue::unknown_bool());

        let sub = Rc::new(sub);

        let mut a = Struct::default();
        let mut b = Struct::default();

        a.add_field("boolean", TypeValue::var_bool_from(true));
        a.add_field("integer", TypeValue::var_signed_integer_from(1));
        a.add_field("structure", TypeValue::Struct(sub.clone()));
        a.add_field(
            "floats_array",
            TypeValue::Array(Rc::new(Array::Floats(vec![]))),
        );

        // At this point a != b because b is still empty.
        assert_ne!(a, b);

        b.add_field("boolean", TypeValue::var_bool_from(false));
        b.add_field("integer", TypeValue::var_signed_integer_from(1));
        b.add_field("structure", TypeValue::Struct(sub));
        b.add_field(
            "floats_array",
            TypeValue::Array(Rc::new(Array::Floats(vec![]))),
        );

        // At this point a == b.
        assert_eq!(a, b);

        a.add_field("foo", TypeValue::var_bool_from(false));
        b.add_field("foo", TypeValue::unknown_signed_integer());

        // At this point a != b again because field "foo" have a different type
        // on each structure.
        assert_ne!(a, b);
    }

    #[test]
    fn test_is_enum() {
        use crate::modules::protos::test_proto2::TestProto2;
        use protobuf::MessageFull;

        let s = Struct::new();
        assert!(!s.is_enum());

        let mut structure = Struct::from_proto_descriptor_and_msg(
            &TestProto2::descriptor(),
            None,
            true,
            true,
        );

        let structure = Rc::<Struct>::get_mut(&mut structure).unwrap();
        let mut is_enum_flags = Vec::new();

        structure.enum_substructures(&mut |sub| {
            is_enum_flags.push(sub.is_enum());
        });

        // The root message and its nested messages (and intermediate container structs)
        // are not enums, while the enum substructures are marked with is_enum = true.
        assert_eq!(
            vec![false, false, false, true, true, false, true, true],
            is_enum_flags
        );
    }
}
