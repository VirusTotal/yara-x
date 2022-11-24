use crate::ast::Type;

pub mod ast;
pub mod compiler;
pub mod formatter;
pub mod parser;
pub mod scanner;
pub use warnings::*;

mod ascii_tree;
mod modules;
mod report;
mod string_pool;
mod symbol_table;
mod warnings;
mod wasm;

#[cfg(test)]
mod tests;
