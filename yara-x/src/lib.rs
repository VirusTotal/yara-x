/*! This crate implements a YARA compiler and scanner, completely written in
Rust from scratch. It is 99% compatible with existing YARA rules.

# Example

```rust
use yara_x;

// Compile the source code.
let rules = yara_x::compile(r#"
    rule test {
      condition: true
    }
"#).unwrap();

// Create a scanner that uses the compiled YARA rules.
let mut scanner = yara_x::Scanner::new(&rules);

// Scan some data.
let results = scanner.scan("Lorem ipsum".as_bytes());

assert_eq!(results.num_matching_rules(), 1);
```
*/
pub use compiler::*;
pub use scanner::*;

mod compiler;
mod modules;
mod scanner;
mod string_pool;
mod symbols;
mod wasm;

#[cfg(test)]
mod tests;
