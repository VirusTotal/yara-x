use bstr::{BStr, ByteSlice};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

mod protos;

pub use protos::*;

use crate::modules::Module;
use crate::types::{Type, Value};

/// Trait implemented by types that allow looking up for an identifier.
pub trait SymbolLookup<'a> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>>;
}

pub trait SymbolIndex<'a> {
    fn index(&self, index: usize) -> Option<Symbol<'a>>;
    fn item_type(&self) -> Type;
}

#[derive(Clone)]
pub enum SymbolValue<'a> {
    Value(Value),
    Struct(Rc<dyn SymbolLookup<'a> + 'a>),
    Array(Rc<dyn SymbolIndex<'a> + 'a>),
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

    pub fn new_struct(symbol_table: Rc<dyn SymbolLookup<'a> + 'a>) -> Self {
        Self {
            ty: Type::Struct,
            value: SymbolValue::Struct(symbol_table),
            location: Location::None,
        }
    }

    pub fn new_array(array: Rc<dyn SymbolIndex<'a> + 'a>) -> Self {
        Self {
            ty: Type::Array,
            value: SymbolValue::Array(array),
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
        self.get(ident).map(|module| Symbol::new_struct(Rc::new(module)))
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

impl<'a> SymbolLookup<'a> for RefCell<SymbolTable<'a>> {
    fn lookup(&self, ident: &str) -> Option<Symbol<'a>> {
        self.borrow().map.get(ident).cloned()
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
    stack: VecDeque<Rc<dyn SymbolLookup<'a> + 'a>>,
}

impl<'a> StackedSymbolTable<'a> {
    /// Creates a new [`StackedSymbolTable`].
    pub fn new() -> Self {
        Self { stack: VecDeque::new() }
    }

    /// Pushes a new symbol table to the stack.
    pub fn push(&mut self, symbol_table: Rc<dyn SymbolLookup<'a> + 'a>) {
        self.stack.push_back(symbol_table)
    }

    /// Pop a symbol table from the stack.
    pub fn pop(&mut self) -> Option<Rc<dyn SymbolLookup<'a> + 'a>> {
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
    use crate::symbols::{ProtoMessage, SymbolLookup, SymbolValue};
    use crate::types::{Type, Value};
    use bstr::{BStr, BString};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

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
            test.lookup("nested").lookup("nested_int32_zero").unwrap().ty(),
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

        nested.set_nested_int32_zero(0);

        test.nested = MessageField::some(nested);

        let mut buf = Vec::new();
        test.write_to_vec(&mut buf).unwrap();

        let message_dyn =
            Test::descriptor().parse_from_bytes(buf.as_slice()).unwrap();

        let message_dyn = ProtoMessage::new(
            Test::descriptor()
                .parse_from_bytes(buf.as_slice())
                .unwrap()
                .into(),
        );

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
                .lookup("nested_int32_zero")
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
