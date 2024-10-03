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
pub use compiler::Compiler;
pub use compiler::Rules;
pub use compiler::RulesIter;
pub use compiler::SourceCode;
pub use models::Match;
pub use models::Matches;
pub use models::MetaValue;
pub use models::Metadata;
pub use models::Pattern;
pub use models::Patterns;
pub use models::Rule;
pub use modules::mods;
pub use scanner::MatchingRules;
pub use scanner::ModuleOutputs;
pub use scanner::NonMatchingRules;
pub use scanner::ScanError;
pub use scanner::ScanOptions;
pub use scanner::ScanResults;
pub use scanner::Scanner;
pub use variables::Variable;

mod compiler;
mod modules;
mod re;
mod scanner;
mod string_pool;
mod symbols;
mod types;
mod variables;
mod wasm;

mod models;
#[cfg(test)]
mod tests;

pub mod errors {
    //! Errors returned by this crate.
    //!
    //! This module contains the definitions for all error types returned by this
    //! crate.
    pub use crate::compiler::errors::*;
    pub use crate::compiler::InvalidWarningCode;
    pub use crate::scanner::ScanError;
    pub use crate::variables::VariableError;
}

pub mod warnings {
    //! Warnings returned while compiling rules.
    pub use crate::compiler::warnings::*;
}

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
