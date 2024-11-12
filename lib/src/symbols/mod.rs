use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::{mem, ptr};

#[cfg(test)]
use bstr::BString;

use crate::compiler::{RuleId, Var};
use crate::types::{AclEntry, Func, Type, TypeValue, Value};

/// Trait implemented by types that allow looking up for a symbol.
pub(crate) trait SymbolLookup {
    fn lookup(&self, ident: &str) -> Option<Symbol>;
}

/// Kinds of symbol.
///
/// Used by the compiler to determine how to generate code that
/// accesses the symbol.
#[derive(Clone, Debug)]
pub(crate) enum Symbol {
    /// The symbol refers to a WASM-side variable.
    Var { var: Var, type_value: TypeValue },
    /// The symbol refers to a field in a structure.
    Field {
        /// Index the field occupies in its parent structure.
        index: usize,
        /// `true` if the symbol refers to a field in the root structure. If it
        /// is `false` it refers to the structure whose reference is at the top
        /// of the WASM stack.
        is_root: bool,
        /// Type and value for this field.
        type_value: TypeValue,
        /// Access control list (ACL) for accessing this field.
        acl: Option<Vec<AclEntry>>,
    },
    /// The symbol refers to a rule.
    Rule(RuleId),
    /// The symbol refers to a function.
    Func(Rc<Func>),
}

impl Hash for Symbol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);
        match self {
            Symbol::Var { var, .. } => {
                var.hash(state);
            }
            Symbol::Field { index, is_root, .. } => {
                index.hash(state);
                is_root.hash(state);
            }
            Symbol::Rule(rule_id) => {
                rule_id.hash(state);
            }
            Symbol::Func(func) => func.hash(state),
        }
    }
}

impl PartialEq for Symbol {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Symbol::Var { var: this_var, .. } => {
                if let Symbol::Var { var: other_var, .. } = other {
                    this_var == other_var
                } else {
                    false
                }
            }
            Symbol::Field {
                index: this_index, is_root: this_is_root, ..
            } => {
                if let Symbol::Field {
                    index: other_index,
                    is_root: other_is_root,
                    ..
                } = other
                {
                    this_index == other_index && this_is_root == other_is_root
                } else {
                    false
                }
            }
            Symbol::Rule(this) => {
                if let Symbol::Rule(other) = other {
                    this == other
                } else {
                    false
                }
            }
            Symbol::Func(this) => {
                if let Symbol::Func(other) = other {
                    ptr::eq(&**this, &**other)
                } else {
                    false
                }
            }
        }
    }
}

impl Eq for Symbol {}

impl Symbol {
    pub fn ty(&self) -> Type {
        match &self {
            Symbol::Var { var, .. } => var.ty(),
            Symbol::Field { type_value, .. } => type_value.ty(),
            Symbol::Rule(_) => Type::Bool,
            Symbol::Func(_) => Type::Func,
        }
    }

    pub fn type_value(&self) -> TypeValue {
        match &self {
            Symbol::Var { type_value, .. } => type_value.clone(),
            Symbol::Field { type_value, .. } => type_value.clone(),
            Symbol::Rule(_) => TypeValue::Bool(Value::Unknown),
            Symbol::Func(func) => TypeValue::Func(func.clone()),
        }
    }

    #[cfg(test)]
    fn as_integer(&self) -> Option<i64> {
        if let TypeValue::Integer(value) = self.type_value() {
            value.extract().cloned()
        } else {
            None
        }
    }

    #[cfg(test)]
    fn as_string(&self) -> Option<BString> {
        if let TypeValue::String(value) = self.type_value() {
            value.extract().map(|s| BString::from(s.as_slice()))
        } else {
            None
        }
    }
}

/// Implements [`SymbolLookup`] for `Option<Symbol>` so that lookup
/// operations can be chained.
///
/// For example, you can do:
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
            if let TypeValue::Struct(s) = symbol.type_value() {
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
pub(crate) struct SymbolTable {
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

    /// Returns true if the symbol table already contains a symbol with
    /// the given identifier.
    #[inline]
    pub fn contains<I>(&self, ident: I) -> bool
    where
        I: AsRef<str>,
    {
        self.map.contains_key(ident.as_ref())
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
/// it hides any other identifier "foo" that may exist on a symbol table that
/// is deeper in the stack.
pub(crate) struct StackedSymbolTable<'a> {
    stack: VecDeque<Rc<dyn SymbolLookup + 'a>>,
}

impl<'a> StackedSymbolTable<'a> {
    /// Creates a new [`StackedSymbolTable`].
    pub(crate) fn new() -> Self {
        Self { stack: VecDeque::new() }
    }

    /// Creates a new symbol table and pushes it into the stack.
    pub(crate) fn push_new(&mut self) -> Rc<RefCell<SymbolTable>> {
        let symbol_table = Rc::new(RefCell::new(SymbolTable::new()));
        self.stack.push_back(symbol_table.clone());
        symbol_table
    }

    /// Pushes a new symbol table into the stack.
    pub(crate) fn push(&mut self, symbol_table: Rc<dyn SymbolLookup + 'a>) {
        self.stack.push_back(symbol_table)
    }

    /// Pop a symbol table from the stack.
    ///
    /// Returns the symbol table removed from the stack or None if the stack
    /// was empty.
    pub(crate) fn pop(&mut self) -> Option<Rc<dyn SymbolLookup + 'a>> {
        self.stack.pop_back()
    }

    /// Returns the number of symbol tables in the stack.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.stack.len()
    }

    /// Removes the symbol tables at the top of the stack,
    /// keeping only the bottom `len`.
    ///
    /// If the stack has more than `len` elements this has no effect.
    #[inline]
    pub(crate) fn truncate(&mut self, len: usize) {
        self.stack.truncate(len)
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
#[cfg(feature = "test_proto2-module")]
mod tests {
    use bstr::BString;

    use crate::symbols::SymbolLookup;
    use crate::types::{Struct, Type};

    #[test]
    fn message_lookup() {
        use protobuf::{Enum, MessageFull};

        use crate::modules::protos::test_proto2::test_proto2::Enumeration;
        use crate::modules::protos::test_proto2::test_proto2::Enumeration2;
        use crate::modules::protos::test_proto2::TestProto2;

        let test = Struct::from_proto_descriptor_and_msg(
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

        assert_eq!(
            test.lookup("items").lookup("ITEM_4").unwrap().as_integer(),
            Some(Enumeration2::ITEM_4.value() as i64)
        );
    }

    #[test]
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
        test.set_double_zero(0.0);

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
        test.set_double_one(1.0);

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
        let structure = Struct::from_proto_descriptor_and_msg(
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
            structure.lookup("string_foo").unwrap().as_string(),
            Some(BString::from(b"foo"))
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
