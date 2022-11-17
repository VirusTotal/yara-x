use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use crate::ast::Type;
use bstr::BString;

pub mod ast;
pub mod compiler;
pub mod formatter;
pub mod parser;
pub mod scanner;
pub use warnings::*;

mod ascii_tree;
mod modules;
mod report;
mod symbol_table;
mod warnings;
mod wasm;

#[cfg(test)]
mod tests;
