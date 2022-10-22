use bstr::BStr;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

pub mod compiler;
pub mod formatter;
pub mod parser;

mod ascii_tree;
mod report;

/// Stores information about variables and constants defined or
/// used in YARA rules.
///
/// Given an identifier, the symbol table provides information about that
/// identifier, including its type and value. Symbol tables can be nested,
/// which means that a symbol in a table can lead to another table that
/// contains more symbols. This allows representing namespaces, or nested
/// structures.
pub struct SymbolTable<'a> {
    symbols: HashMap<&'a str, Symbol<'a>>,
}

impl<'a> SymbolTable<'a> {
    /// Creates a new symbol table.
    fn new() -> Self {
        Self { symbols: HashMap::new() }
    }

    /// Looks up a symbol in the table.
    fn lookup(&self, ident: &str) -> Option<&Symbol> {
        self.symbols.get(ident)
    }

    /// Inserts an identifier into the symbol table.
    ///
    /// If the symbol table didn't have the identifier, [`None`] is returned.
    /// If the symbol table did have the identifier, the symbol is updated with
    /// the new one, and the old symbol is returned.
    fn insert<I>(
        &mut self,
        ident: &'a str,
        symbol: Symbol<'a>,
    ) -> Option<Symbol<'a>> {
        self.symbols.insert(ident, symbol)
    }
}

/// These are the different types of symbols that can be stored in a [`SymbolTable`].
pub enum Symbol<'a> {
    Variable(Variable<'a>),
    Table(SymbolTable<'a>),
}

impl<'a> Symbol<'a> {
    pub fn value(&self) -> Option<&Value> {
        match self {
            Symbol::Variable(v) => v.value.as_ref(),
            Symbol::Table(_) => None,
        }
    }
}

/// Represents the value associated to an expression, when it can be determined
/// at compile time. For example, the value of `2+2` can be determined during
/// compilation, it would be `Integer(4)`.
#[derive(Debug, Clone)]
pub enum Value<'a> {
    Bool(bool),
    Integer(i64),
    Float(f32),
    String(&'a BStr),
}

impl<'a> Display for Value<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Integer(v) => write!(f, "{}", v),
            Self::Float(v) => write!(f, "{:.1}", v),
            Self::String(v) => write!(f, "{:?}", v),
        }
    }
}

impl<'a> Value<'a> {
    pub fn as_integer(&self) -> i64 {
        if let Self::Integer(i) = self {
            return *i;
        } else {
            panic!("{:?}", self);
        }
    }
}

pub struct Variable<'a> {
    value: Option<Value<'a>>,
    ty: ValueType,
}

/// All the different types of expressions that can be found in YARA.
///
/// For example, the kind for expression `2+2` is `Integer`, for `2.0 / 2` is
/// `Float` and for `true or false` is `Bool`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ValueType {
    Bool,
    Integer,
    Float,
    String,
}

impl Display for ValueType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "boolean"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::String => write!(f, "string"),
        }
    }
}
