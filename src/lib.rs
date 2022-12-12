pub mod ast;
pub mod compiler;
pub mod formatter;
pub mod parser;
pub mod scanner;

pub use warnings::*;

mod modules;
mod report;
mod string_pool;
mod symbols;
mod types;
mod warnings;
mod wasm;

#[cfg(test)]
mod tests;
