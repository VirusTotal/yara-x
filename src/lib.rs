use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use crate::ast::Type;
use bstr::BString;

pub mod ast;
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
#[derive(Debug)]
pub struct Struct<'a> {
    fields: HashMap<&'a str, Variable<'a>>,
}

impl<'a> Struct<'a> {
    /// Creates a new symbol table.
    fn new() -> Self {
        Self { fields: HashMap::new() }
    }

    /// Get a field from the structure.
    fn get_field(&self, ident: &str) -> Option<&Variable<'a>> {
        self.fields.get(ident)
    }

    /// Inserts an identifier into the symbol table.
    ///
    /// If the symbol table didn't have the identifier, [`None`] is returned.
    /// If the symbol table did have the identifier, the symbol is updated with
    /// the new one, and the old symbol is returned.
    fn insert(
        &mut self,
        ident: &'a str,
        field: Variable<'a>,
    ) -> Option<Variable<'a>> {
        self.fields.insert(ident, field)
    }
}

/// Represents the value associated to an expression, when it can be determined
/// at compile time. For example, the value of `2+2` can be determined during
/// compilation, it would be `Integer(4)`.
#[derive(Debug, Clone)]
pub enum Value<'a> {
    Unknown,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(BString),
    Struct(&'a Struct<'a>),
    Array(Vec<Value<'a>>),
}

impl<'a> Display for Value<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Integer(v) => write!(f, "{}", v),
            Self::Float(v) => write!(f, "{:.1}", v),
            Self::String(v) => write!(f, "{:?}", v),
            Self::Struct(_) => write!(f, "struct"),
            Self::Unknown => write!(f, "unknown"),
            Self::Array(_) => write!(f, "array"),
        }
    }
}

impl<'a> Value<'a> {
    /// Returns the value as an i64.
    ///
    /// Panics if the value is not Value::Integer.
    pub fn as_integer(&self) -> i64 {
        if let Self::Integer(i) = self {
            *i
        } else {
            panic!("{:?}", self);
        }
    }

    /// Returns the value as a bool.
    ///
    /// Panics if the value is not Value::Bool.
    pub fn as_bool(&self) -> bool {
        if let Self::Bool(b) = self {
            *b
        } else {
            panic!("{:?}", self);
        }
    }

    /// Returns the value as a struct.
    ///
    /// Panics if the value is not Value::Struct.
    pub fn as_struct(&self) -> &'a Struct<'a> {
        if let Self::Struct(t) = self {
            *t
        } else {
            panic!("{:?}", self);
        }
    }
}

#[derive(Debug)]
pub struct Variable<'a> {
    ty: Type,
    value: Value<'a>,
}
