use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use bstr::BString;
use protobuf::reflect::{
    EnumDescriptor, MessageDescriptor, RuntimeFieldType, RuntimeType,
};
use protobuf::MessageDyn;

use crate::modules::Module;
use crate::types::{Type, TypeValue, Value};

/// Trait implemented by types that allow looking up for an identifier.
pub trait SymbolLookup {
    fn lookup(&self, ident: &str) -> Option<Symbol>;
}

#[derive(Clone)]
pub struct Symbol {
    type_value: TypeValue,
    location: Location,
}

impl Symbol {
    pub fn new(type_value: TypeValue) -> Self {
        Self { type_value, location: Location::None }
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
    pub fn type_value(&self) -> &TypeValue {
        &self.type_value
    }

    #[inline]
    pub fn value(&self) -> Option<&Value> {
        self.type_value.value()
    }

    #[inline]
    pub fn ty(&self) -> Type {
        self.type_value.ty()
    }
}

impl From<TypeValue> for Symbol {
    fn from(type_value: TypeValue) -> Self {
        Self::new(type_value)
    }
}

impl From<Type> for Symbol {
    fn from(ty: Type) -> Self {
        Self::new(ty.into())
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
/// identifier exists in the map, a `TypeValue::Struct` wrapping a &[`Module`]
/// is returned.
impl SymbolLookup for &'static HashMap<&str, Module> {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        self.get(ident)
            .map(|module| TypeValue::new_struct(Arc::new(module)).into())
    }
}

/// &[`Module`] also implements [`SymbolLookup`].
impl SymbolLookup for &Module {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
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
impl SymbolLookup for Option<Symbol> {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        if let Some(symbol) = self {
            if let Some(Value::Struct(s)) = &symbol.value() {
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
/// can be wrapped in a [`TypeValue::Struct`] and added to a symbol table.
///
/// When symbols are looked up in a protobuf message descriptor only the type
/// will be returned. Values will be [`None`] in all cases, as the descriptor
/// is not an instance of the protobuf message, only a description of it.
/// Therefore it doesn't have associated data.
impl SymbolLookup for MessageDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
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
                    todo!()
                }
                RuntimeFieldType::Map(_, _) => {
                    todo!()
                }
            }
        } else {
            // If the message doesn't have a field with the requested name,
            // let's look if there's a nested enum that has that name.
            self.nested_enums().find(|e| e.name() == ident).map(
                |nested_enum| {
                    TypeValue::new_struct(Arc::new(nested_enum)).into()
                },
            )
        }
    }
}

fn runtime_type_to_symbol(rt: RuntimeType) -> Symbol {
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
        RuntimeType::Message(m) => TypeValue::new_struct(Arc::new(m)).into(),
    }
}

/// [`EnumDescriptor`] also implements [`SymbolLookup`].
impl SymbolLookup for EnumDescriptor {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        let descriptor = self.value_by_name(ident)?;
        Some(TypeValue::new_integer(descriptor.value() as i64).into())
    }
}

/// Implements [`SymbolLookup`] for [`Box<dyn MessageDyn>`].
///
/// A [`Box<dyn MessageDyn>`] represents an arbitrary protobuf message
/// containing structured data. By implementing the [`SymbolLookup`] trait
/// for this type arbitrary protobuf messages can be wrapped in a
/// [`TypeValue::Struct`] and added to a symbol table.
///
/// When symbols are looked up in a protobuf message the returned
/// [`TypeValue`] will contain the value of the corresponding field in the
/// message. Notice however that in proto2 optional fields can be
/// empty, and in those cases the value in the returned [`TypeValue`]
/// will be `None`. In proto3 empty values don't exist, if a field is
/// not explicitly assigned a value, it will have the default value
/// for its type (i.e: zero for numeric types, empty strings for string
/// types, etc)
///
impl SymbolLookup for Box<dyn MessageDyn> {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        let message_descriptor = self.descriptor_dyn();
        if let Some(field) = message_descriptor.field_by_name(ident) {
            match field.runtime_field_type() {
                RuntimeFieldType::Singular(ty) => match ty {
                    RuntimeType::I32 => {
                        let type_value = if let Some(value) =
                            field.get_singular(self.as_ref())
                        {
                            TypeValue::from(value.to_i32().unwrap() as i64)
                        } else {
                            TypeValue::from(None::<i64>)
                        };
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::I64 => {
                        let type_value = TypeValue::from(
                            field
                                .get_singular(self.as_ref())
                                .and_then(|f| f.to_i64()),
                        );
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::U32 => {
                        let type_value = TypeValue::from(
                            field
                                .get_singular(self.as_ref())
                                .and_then(|f| f.to_u32()),
                        );
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::U64 => {
                        todo!()
                    }
                    RuntimeType::F32 => {
                        let type_value = TypeValue::from(
                            field
                                .get_singular(self.as_ref())
                                .and_then(|f| f.to_f32()),
                        );
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::F64 => {
                        let type_value = TypeValue::from(
                            field
                                .get_singular(self.as_ref())
                                .and_then(|f| f.to_f64()),
                        );
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::Bool => {
                        let type_value = TypeValue::from(
                            field
                                .get_singular(self.as_ref())
                                .and_then(|f| f.to_bool()),
                        );
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::String | RuntimeType::VecU8 => {
                        let type_value = if let Some(value) =
                            field.get_singular(self.as_ref())
                        {
                            TypeValue::from(value.to_str())
                        } else {
                            TypeValue::from(None::<BString>)
                        };
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::Enum(_) => {
                        let type_value = TypeValue::from(
                            field
                                .get_singular(self.as_ref())
                                .and_then(|f| f.to_enum_value()),
                        );
                        Some(Symbol::new(type_value))
                    }
                    RuntimeType::Message(_) => {
                        Some(Symbol::new(TypeValue::new_struct(Arc::new(
                            field.get_message(self.as_ref()).clone_box(),
                        ))))
                    }
                },
                RuntimeFieldType::Repeated(_) => {
                    todo!()
                }
                RuntimeFieldType::Map(_, _) => {
                    todo!()
                }
            }
        } else {
            // If the message doesn't have a field with the requested name,
            // let's look if there's a nested enum that has that name.
            message_descriptor.nested_enums().find(|e| e.name() == ident).map(
                |nested_enum| {
                    Symbol::new(TypeValue::new_struct(Arc::new(nested_enum)))
                },
            )
        }
    }
}

/// A symbol table is a structure used for resolving symbols during the
/// compilation process.
///
/// A symbol table is basically a map, where keys are identifiers and
/// values are [`TypeValue`] instances that contain information about the
/// type and possibly the current value for that identifier. [`SymbolTable`]
/// implements the [`SymbolLookup`] trait, so symbols are found in the
/// table by using the [`SymbolLookup::lookup`] method.
///
/// When the identifier represents a nested structure, the returned
/// [`TypeValue`] will be the [`TypeValue::Struct`] variant, which will
/// encapsulate another object that also implements the [`SymbolLookup`]
/// trait, possibly another [`SymbolTable`].
pub struct SymbolTable {
    map: HashMap<String, Symbol>,
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
    pub fn insert<I>(&mut self, ident: I, symbol: Symbol) -> Option<Symbol>
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

impl SymbolLookup for SymbolTable {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        self.map.get(ident).cloned()
    }
}

impl SymbolLookup for &SymbolTable {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
        self.map.get(ident).cloned()
    }
}

impl SymbolLookup for RwLock<SymbolTable> {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
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
pub struct StackedSymbolTable {
    stack: VecDeque<Arc<dyn SymbolLookup>>,
}

impl StackedSymbolTable {
    /// Creates a new [`StackedSymbolTable`].
    pub fn new() -> Self {
        Self { stack: VecDeque::new() }
    }

    /// Pushes a new symbol table to the stack.
    pub fn push(&mut self, symbol_table: Arc<dyn SymbolLookup>) {
        self.stack.push_back(symbol_table)
    }

    /// Pop a symbol table from the stack.
    pub fn pop(&mut self) -> Option<Arc<dyn SymbolLookup>> {
        self.stack.pop_back()
    }
}

impl SymbolLookup for StackedSymbolTable {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
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
    use crate::symbols::SymbolLookup;
    use crate::types::{Type, Value};
    use bstr::BString;
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
            test.lookup("Enumeration")
                .lookup("ITEM_1")
                .unwrap()
                .value()
                .unwrap(),
            &Value::Integer(Enumeration::ITEM_1.value() as i64)
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
            message_dyn.lookup("int32_zero").unwrap().value(),
            Some(&Value::Integer(0))
        );

        assert_eq!(
            message_dyn.lookup("int32_one").unwrap().value(),
            Some(&Value::Integer(1))
        );

        assert_eq!(
            message_dyn.lookup("string_foo").unwrap().value(),
            Some(&Value::String(BString::from("foo")))
        );

        assert_eq!(
            message_dyn.lookup("nested").lookup("int32_zero").unwrap().value(),
            Some(&Value::Integer(0))
        );

        assert_eq!(
            message_dyn
                .lookup("Enumeration")
                .lookup("ITEM_1")
                .unwrap()
                .value()
                .unwrap(),
            &Value::Integer(Enumeration::ITEM_1.value() as i64)
        );
    }
}
