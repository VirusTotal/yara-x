use bstr::{BStr, ByteSlice};
use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use protobuf::reflect::{
    EnumDescriptor, FieldDescriptor, MessageDescriptor, MessageRef,
    RuntimeFieldType, RuntimeType,
};
use protobuf::MessageDyn;

use crate::modules::Module;
use crate::types::{Type, Value};

/// Trait implemented by types that allow looking up for an identifier.
pub trait SymbolLookup<'a> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>>;
}

pub trait SymbolIndex<'a> {
    fn index(&self, index: usize) -> Option<Symbol<'a>>;
}

#[derive(Clone)]
pub enum SymbolValue<'a> {
    Value(Value),
    Struct(Arc<dyn SymbolLookup<'a> + Send + Sync + 'a>),
    Array(Arc<dyn SymbolIndex<'a> + Send + Sync + 'a>),
}

#[derive(Clone)]
pub struct Symbol<'a> {
    ty: Type,
    value: SymbolValue<'a>,
    location: Location,
}

impl<'a> Symbol<'a> {
    pub fn new(ty: Type, value: SymbolValue<'a>) -> Self {
        Self { ty, value, location: Location::None }
    }

    pub fn new_struct(
        symbol_table: Arc<dyn SymbolLookup<'a> + Send + Sync + 'a>,
    ) -> Self {
        Self {
            ty: Type::Struct,
            value: SymbolValue::Struct(symbol_table),
            location: Location::None,
        }
    }

    pub fn new_integer(i: i64) -> Self {
        Self {
            ty: Type::Integer,
            value: SymbolValue::Value(Value::Integer(i)),
            location: Location::None,
        }
    }

    pub fn set_location(mut self, location: Location) -> Self {
        self.location = location;
        self
    }

    #[inline]
    pub fn location(&self) -> &Location {
        &self.location
    }

    #[inline]
    pub fn mem_location(&self) -> Option<i32> {
        if let Location::Memory(location) = self.location {
            Some(location)
        } else {
            None
        }
    }

    #[inline]
    pub fn value(&self) -> &SymbolValue<'a> {
        &self.value
    }

    #[inline]
    pub fn ty(&self) -> Type {
        self.ty
    }

    fn as_integer(&self) -> Option<i64> {
        if let SymbolValue::Value(Value::Integer(i)) = self.value {
            Some(i)
        } else {
            None
        }
    }

    fn as_bstr(&self) -> Option<&BStr> {
        if let SymbolValue::Value(Value::String(s)) = &self.value {
            Some(s.as_bstr())
        } else {
            None
        }
    }
}

impl From<Type> for Symbol<'_> {
    fn from(ty: Type) -> Self {
        Self::new(ty, SymbolValue::Value(Value::Unknown))
    }
}

#[derive(Clone)]
pub enum Location {
    None,
    Memory(i32),
}

/// A hash map the contains [`Module`] instances implements [`SymbolLookup`].
///
/// The identifier in this case is a module name. If a module with the given
/// identifier exists in the map, a [`Symbol`] of type [`Type::Struct`] that
/// wraps a &[`Module`] is returned.
impl<'a> SymbolLookup<'a> for &'a HashMap<&'a str, Module> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        self.get(ident).map(|module| Symbol::new_struct(Arc::new(module)))
    }
}

/// &[`Module`] also implements [`SymbolLookup`].
impl<'a> SymbolLookup<'a> for &Module {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        self.descriptor.lookup(ident)
    }
}

/// Implements [`SymbolLookup`] for `Option<Symbol>` so that lookup
/// operations can be chained.
///
/// For example you can do:
///
/// ```text
/// symbol_table.lookup("foo").lookup("bar")
/// ```
///
/// If the field `foo` is a structure, this will return the [`Symbol`]
/// for the field `bar` within that structure.
///
/// This can be done because the `Option<Symbol>` returned by the
/// first call to `lookup` also have a `lookup` method.
impl<'a> SymbolLookup<'a> for Option<Symbol<'a>> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        if let Some(symbol) = self {
            if let SymbolValue::Struct(s) = symbol.value() {
                s.lookup(ident)
            } else {
                None
            }
        } else {
            None
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
                RuntimeFieldType::Singular(ty) => {
                    Some(runtime_type_to_symbol(ty))
                }
                RuntimeFieldType::Repeated(ty) => {
                    let item_ty = runtime_type_to_type(ty);
                    Some(Symbol::new(
                        Type::Array(item_ty.into()),
                        SymbolValue::Array(Arc::new(field)),
                    ))
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
                .map(|nested_enum| Symbol::new_struct(Arc::new(nested_enum)))
        }
    }
}

impl<'a> SymbolIndex<'a> for FieldDescriptor {
    fn index(&self, _index: usize) -> Option<Symbol<'a>> {
        None
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
        RuntimeType::Message(m) => Symbol::new_struct(Arc::new(m)),
    }
}

/// [`EnumDescriptor`] also implements [`SymbolLookup`].
impl<'a> SymbolLookup<'a> for EnumDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        let descriptor = self.value_by_name(ident)?;
        Some(Symbol::new_integer(descriptor.value() as i64))
    }
}

impl<'a> SymbolLookup<'a> for MessageRef<'a> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        todo!()
    }
}

/// Implements [`SymbolLookup`] for [`Box<dyn MessageDyn>`].
///
/// A [`Box<dyn MessageDyn>`] represents an arbitrary protobuf message
/// containing structured data. By implementing the [`SymbolLookup`] trait
/// for this type arbitrary protobuf messages can be wrapped in a [`Symbol`]
/// of type [`Type::Struct`] and added to a symbol table.
///
/// When symbols are looked up in a protobuf message, the returned [`Symbol`]
/// will have the value of the corresponding field in the message. Notice
/// however that in proto2 optional fields can be empty, and in those cases
/// the symbol's value will be [`None`].
///
/// In proto3 empty values don't exist, if a field isn't explicitly assigned
/// a value, it will have the default value for its type (i.e: zero for numeric
/// types, empty strings for string types, etc)
///
impl<'a> SymbolLookup<'a> for Box<dyn MessageDyn> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        let message_descriptor = self.descriptor_dyn();
        if let Some(field) = message_descriptor.field_by_name(ident) {
            match field.runtime_field_type() {
                RuntimeFieldType::Singular(ty) => match ty {
                    RuntimeType::I32 => {
                        let value = field
                            .get_singular(self.as_ref())
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
                            .get_singular(self.as_ref())
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
                            .get_singular(self.as_ref())
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
                            .get_singular(self.as_ref())
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
                            .get_singular(self.as_ref())
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
                            .get_singular(self.as_ref())
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
                            .get_singular(self.as_ref())
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
                            field.get_singular(self.as_ref())
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
                    RuntimeType::Message(_) => Some(Symbol::new_struct(
                        Arc::new(field.get_message(self.as_ref())),
                    )),
                },
                RuntimeFieldType::Repeated(ty) => {
                    //let x = field.get_repeated()
                    todo!()
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
                .map(|nested_enum| Symbol::new_struct(Arc::new(nested_enum)))
        }
    }
}

/// A symbol table is a structure used for resolving symbols during the
/// compilation process.
///
/// A symbol table is basically a map, where keys are identifiers and
/// values are [`Symbol`] instances that contain information about the
/// type and possibly the current value for that identifier. [`SymbolTable`]
/// implements the [`SymbolLookup`] trait, so symbols are found in the
/// table by using the [`SymbolLookup::lookup`] method.
///
/// When the identifier represents a nested structure, the returned
/// [`Symbol`] will be of type [`Type::Struct`], which encapsulates another
/// object that also implements the [`SymbolLookup`] trait, possibly another
/// [`SymbolTable`].
pub struct SymbolTable<'a> {
    map: HashMap<String, Symbol<'a>>,
}

impl<'a> SymbolTable<'a> {
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
        symbol: Symbol<'a>,
    ) -> Option<Symbol<'a>>
    where
        I: Into<String>,
    {
        self.map.insert(ident.into(), symbol)
    }
}

impl Default for SymbolTable<'_> {
    fn default() -> Self {
        SymbolTable::new()
    }
}

impl<'a> SymbolLookup<'a> for SymbolTable<'a> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        self.map.get(ident).cloned()
    }
}

impl<'a> SymbolLookup<'a> for &SymbolTable<'a> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        self.map.get(ident).cloned()
    }
}

impl<'a> SymbolLookup<'a> for RwLock<SymbolTable<'a>> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        self.read().unwrap().lookup(ident)
    }
}

/// A set of stacked symbol tables.
///
/// As the name suggests, this type represents a set of symbol tables stacked
/// one on top of each other. The `lookup` operation is performed first on the
/// symbol table at the top of the stack, and if the symbol is not found, it
/// keeps calling the `lookup` function on the next symbol table until the
/// symbol is found, or the bottom of the stack is reached.
///
/// If the symbol table at the top of the stack contains an identifier "foo",
/// it hides any other identifier "foo" that may exists on a symbol table
/// that is deeper in the stack.
///
pub struct StackedSymbolTable<'a> {
    stack: VecDeque<Arc<dyn SymbolLookup<'a> + 'a>>,
}

impl<'a> StackedSymbolTable<'a> {
    /// Creates a new [`StackedSymbolTable`].
    pub fn new() -> Self {
        Self { stack: VecDeque::new() }
    }

    /// Pushes a new symbol table to the stack.
    pub fn push(&mut self, symbol_table: Arc<dyn SymbolLookup<'a> + 'a>) {
        self.stack.push_back(symbol_table)
    }

    /// Pop a symbol table from the stack.
    pub fn pop(&mut self) -> Option<Arc<dyn SymbolLookup<'a> + 'a>> {
        self.stack.pop_back()
    }
}

impl<'a> SymbolLookup<'a> for StackedSymbolTable<'a> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        // Look for the identifier starting at the top of the stack, and
        // going down the stack until it's found or the bottom of the
        // stack is reached.
        for t in self.stack.iter().rev() {
            let symbol = t.lookup(ident);
            if symbol.is_some() {
                return symbol;
            }
        }
        // The symbol was not found in any of the symbol tables..
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::symbols::{SymbolLookup, SymbolValue};
    use crate::types::{Type, Value};
    use bstr::{BStr, BString};
    use pretty_assertions::assert_eq;

    #[test]
    #[cfg(feature = "test_proto2-module")]
    fn message_lookup() {
        use protobuf::{Enum, MessageFull};

        use crate::modules::protos::test_proto2::test::Enumeration;
        use crate::modules::protos::test_proto2::Test;

        let test = Test::descriptor();

        assert_eq!(test.lookup("int32_zero").unwrap().ty(), Type::Integer);
        assert_eq!(test.lookup("string_foo").unwrap().ty(), Type::String);

        assert_eq!(
            test.lookup("nested").lookup("int32_zero").unwrap().ty(),
            Type::Integer
        );

        assert_eq!(
            test.lookup("Enumeration").lookup("ITEM_1").unwrap().as_integer(),
            Some(Enumeration::ITEM_1.value() as i64)
        );
    }

    #[test]
    #[cfg(feature = "test_proto2-module")]
    fn message_dyn_lookup() {
        use protobuf::{Enum, Message, MessageField, MessageFull};

        use crate::modules::protos::test_proto2::test::Enumeration;
        use crate::modules::protos::test_proto2::NestedProto2;
        use crate::modules::protos::test_proto2::Test;

        let mut test = Test::new();
        let mut nested = NestedProto2::new();

        test.set_int32_zero(0);
        test.set_int64_zero(0);
        test.set_sint32_zero(0);
        test.set_sint64_zero(0);
        test.set_uint32_zero(0);
        test.set_uint64_zero(0);
        test.set_fixed32_zero(0);
        test.set_fixed64_zero(0);
        test.set_sfixed32_zero(0);
        test.set_sfixed64_zero(0);
        test.set_float_zero(0.0);

        test.set_int32_one(1);
        test.set_int64_one(1);
        test.set_sint32_one(1);
        test.set_sint64_one(1);
        test.set_uint32_one(1);
        test.set_uint64_one(1);
        test.set_fixed32_one(1);
        test.set_fixed64_one(1);
        test.set_sfixed32_one(1);
        test.set_sfixed64_one(1);
        test.set_float_one(1.0);

        test.set_string_foo("foo".to_string());
        test.set_string_bar("bar".to_string());

        test.set_bytes_foo("foo".as_bytes().to_vec());
        test.set_bytes_bar("bar".as_bytes().to_vec());

        nested.set_int32_zero(0);

        test.nested = MessageField::some(nested);

        let mut buf = Vec::new();
        test.write_to_vec(&mut buf).unwrap();

        let message_dyn =
            Test::descriptor().parse_from_bytes(buf.as_slice()).unwrap();

        assert_eq!(
            message_dyn.lookup("int32_zero").unwrap().as_integer(),
            Some(0)
        );

        assert_eq!(
            message_dyn.lookup("int32_one").unwrap().as_integer(),
            Some(1)
        );

        assert_eq!(
            message_dyn.lookup("string_foo").unwrap().as_bstr(),
            Some(BStr::new(b"foo"))
        );

        assert_eq!(
            message_dyn
                .lookup("nested")
                .lookup("int32_zero")
                .unwrap()
                .as_integer(),
            Some(0)
        );

        assert_eq!(
            message_dyn
                .lookup("Enumeration")
                .lookup("ITEM_1")
                .unwrap()
                .as_integer(),
            Some(Enumeration::ITEM_1.value() as i64)
        );
    }
}
