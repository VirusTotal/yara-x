/*! A YARA compiler and scanner completely written in Rust from scratch.

It is 99% compatible with existing YARA rules and intends to be a safer, more
efficient implementation of YARA.

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
let mut compiler = yara_x::Compiler::new();

// Add some YARA source code to compile.
compiler.add_source(r#"
    rule lorem_ipsum {
      strings:
        $ = "Lorem ipsum"
      condition:
        all of them
    }
"#).unwrap();

// Obtain the compiled YARA rules.
let rules = compiler.build();

// Create a scanner that uses the compiled rules.
let mut scanner = yara_x::Scanner::new(&rules);

// Scan some data.
let results = scanner.scan("Lorem ipsum".as_bytes()).unwrap();

assert_eq!(results.matching_rules().len(), 1);
```
*/

#![deny(missing_docs)]

pub use compiler::compile;
pub use compiler::CompileError;
pub use compiler::Compiler;
pub use compiler::Error;
pub use compiler::Rules;
pub use compiler::SerializationError;
pub use compiler::Warning;

pub use scanner::Match;
pub use scanner::Matches;
pub use scanner::MatchingRules;
pub use scanner::MetaValue;
pub use scanner::Metadata;
pub use scanner::ModuleOutputs;
pub use scanner::NonMatchingRules;
pub use scanner::Pattern;
pub use scanner::Patterns;
pub use scanner::Rule;
pub use scanner::ScanError;
pub use scanner::ScanResults;
pub use scanner::Scanner;

pub use modules::mods;

pub use variables::Variable;
pub use variables::VariableError;

mod compiler;
mod modules;
mod re;
mod scanner;
mod string_pool;
mod symbols;
mod types;
mod variables;
mod wasm;

#[cfg(test)]
mod tests;

mod utils {
    /// Tries to match `target` as the enum variant `pat`. Returns the
    /// inner value contained in the variant, or panics if `target` does
    /// not match `pat`.
    ///
    /// For example...
    ///
    /// ```ignore
    /// cast!(target, pat)
    /// ```
    ///
    /// expands to...
    ///
    /// ```ignore
    /// if let pat(inner) = target {
    ///     inner
    /// } else {
    ///     panic!("mismatch variant when cast to {}", stringify!($pat));     ///
    /// }
    /// ```
    macro_rules! cast {
        ($target: expr, $pat: path) => {{
            if let $pat(inner) = $target {
                inner
            } else {
                panic!("mismatch variant when cast to {}", stringify!($pat));
            }
        }};
    }

    pub(crate) use cast;
}
