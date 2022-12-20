use bstr::{BStr, ByteSlice};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use crate::ast::Type;
use crate::types::RuntimeValue;

/// Trait implemented by types that allow looking up for an identifier.
pub trait SymbolLookup {
    fn lookup(&self, ident: &str) -> Option<Symbol>;
}

pub trait SymbolIndex<I> {
    fn index(&self, index: I) -> Option<Symbol>;
    fn item_type(&self) -> Type;
    fn item_value(&self) -> RuntimeValue;
}

#[derive(Clone)]
pub struct Symbol {
    ty: Type,
    value: RuntimeValue,
    mem_offset: Option<i32>,
    field_index: Option<i32>,
}

impl Symbol {
    pub fn new(ty: Type, value: RuntimeValue) -> Self {
        Self { ty, value, mem_offset: None, field_index: None }
    }

    pub fn set_mem_offset(&mut self, offset: i32) -> &Self {
        self.mem_offset = Some(offset);
        self
    }

    #[inline]
    pub fn mem_offset(&self) -> Option<i32> {
        self.mem_offset
    }

    pub fn set_field_index(&mut self, index: i32) -> &Self {
        self.field_index = Some(index);
        self
    }

    #[inline]
    pub fn field_index(&self) -> Option<i32> {
        self.field_index
    }

    #[inline]
    pub fn value(&self) -> &RuntimeValue {
        &self.value
    }

    #[inline]
    pub fn ty(&self) -> Type {
        self.ty
    }

    fn as_integer(&self) -> Option<i64> {
        if let RuntimeValue::Integer(value) = self.value {
            value
        } else {
            None
        }
    }

    fn as_bstr(&self) -> Option<&BStr> {
        if let RuntimeValue::String(Some(s)) = &self.value {
            Some(s.as_bstr())
        } else {
            None
        }
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
            if let RuntimeValue::Struct(s) = symbol.value() {
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

impl SymbolLookup for RefCell<SymbolTable> {
    fn lookup(&self, ident: &str) -> Option<Symbol> {
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
    stack: VecDeque<Rc<dyn SymbolLookup + 'a>>,
}

impl<'a> StackedSymbolTable<'a> {
    /// Creates a new [`StackedSymbolTable`].
    pub fn new() -> Self {
        Self { stack: VecDeque::new() }
    }

    /// Pushes a new symbol table to the stack.
    pub fn push(&mut self, symbol_table: Rc<dyn SymbolLookup + 'a>) {
        self.stack.push_back(symbol_table)
    }

    /// Pop a symbol table from the stack.
    pub fn pop(&mut self) -> Option<Rc<dyn SymbolLookup + 'a>> {
        self.stack.pop_back()
    }
}

impl<'a> SymbolLookup for StackedSymbolTable<'a> {
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
    use crate::ast::Type;
    use crate::symbols::SymbolLookup;
    use crate::types::RuntimeStruct;
    use bstr::BStr;
    use pretty_assertions::assert_eq;

    #[test]
    #[cfg(feature = "test_proto2-module")]
    fn message_lookup() {
        use protobuf::{Enum, MessageFull};

        use crate::modules::protos::test_proto2::test_proto2::Enumeration;
        use crate::modules::protos::test_proto2::TestProto2;

        let test = RuntimeStruct::from_proto_descriptor_and_msg(
            &TestProto2::descriptor(),
            None,
            true,
        );

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

        use crate::modules::protos::test_proto2::test_proto2::Enumeration;
        use crate::modules::protos::test_proto2::NestedProto2;
        use crate::modules::protos::test_proto2::TestProto2;

        let mut test = TestProto2::new();
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

        let descriptor = TestProto2::descriptor();
        let message = descriptor.parse_from_bytes(buf.as_slice()).unwrap();
        let structure = RuntimeStruct::from_proto_descriptor_and_msg(
            &descriptor,
            Some(message.as_ref()),
            true,
        );

        assert_eq!(
            structure.lookup("int32_zero").unwrap().as_integer(),
            Some(0)
        );

        assert_eq!(
            structure.lookup("int32_one").unwrap().as_integer(),
            Some(1)
        );

        assert_eq!(
            structure.lookup("string_foo").unwrap().as_bstr(),
            Some(BStr::new(b"foo"))
        );

        assert_eq!(
            structure
                .lookup("nested")
                .lookup("nested_int32_zero")
                .unwrap()
                .as_integer(),
            Some(0)
        );

        assert_eq!(
            structure
                .lookup("Enumeration")
                .lookup("ITEM_1")
                .unwrap()
                .as_integer(),
            Some(Enumeration::ITEM_1.value() as i64)
        );
    }
}
