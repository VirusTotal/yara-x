/*! This crate implements a YARA compiler and scanner completely written in
Rust from scratch. It is 99% compatible with existing YARA rules and intends to
be a safer, more efficient implementation of YARA.

There are two main types in this crate: [`Compiler`] and [`Scanner`]. A compiler
takes YARA source code and produces compiled [`Rules`] that are passed to the
scanner for scanning files or in-memory data. The [`Rules`] produced by the
compiler can be safely passed to multiple instances of [`Scanner`], but each
instance of the scanner can be used for scanning a single file or memory buffer
at a time. The scanner can be re-used for scanning multiple files or memory-buffers,
though.

# Example

```rust
# use yara_x;
// Create a compiler.
let compiler = yara_x::Compiler::new();

// Add some YARA source code to compile.
let compiler = compiler.add_source(r#"
    rule lorem_ipsum {
      strings:
        $ = "Lorem ipsum"
      condition:
        all of them
    }
"#).unwrap();

// Obtain the compiled YARA rules.
let rules = compiler.build().unwrap();

// Create a scanner that uses the compiled rules.
let mut scanner = yara_x::Scanner::new(&rules);

// Scan some data.
let results = scanner.scan("Lorem ipsum".as_bytes());

assert_eq!(results.num_matching_rules(), 1);
```
*/

pub use compiler::{compile, CompileError, Compiler, Error, Rules};
pub use scanner::matches::Match;
pub use scanner::{
    Matches, MatchingRules, NonMatchingRules, Pattern, Patterns, Rule,
    ScanResults, Scanner,
};

mod compiler;
mod modules;
mod scanner;
mod string_pool;
mod symbols;
mod wasm;

#[cfg(test)]
mod tests;
