/*! Scans data with already compiled YARA rules.

*/

use crate::compiler::CompiledRules;
use crate::wasm;
use wasmtime::Store;

/// Scans data with already compiled YARA rules.
pub struct Scanner<'a> {
    rules: &'a CompiledRules,
    wasm_store: wasmtime::Store<ScanContext>,
    wasm_instance: wasmtime::Instance,
}

impl<'a> Scanner<'a> {
    /// Creates a new scanner.
    pub fn new(rules: &'a CompiledRules) -> Self {
        let mut wasm_store = Store::new(&crate::wasm::ENGINE, ScanContext {});

        let wasm_instance = wasm::LINKER
            .instantiate(&mut wasm_store, rules.compiled_wasm_mod())
            .unwrap();

        Self { rules, wasm_store, wasm_instance }
    }

    /// Scans a data.
    pub fn scan(&mut self, data: &[u8]) {
        // Get the main function that executes all rule conditions.
        let main_fn = self
            .wasm_instance
            .get_typed_func::<(), (), _>(&mut self.wasm_store, "main")
            .unwrap();

        // Invoke the main function.
        main_fn.call(&mut self.wasm_store, ()).unwrap();
    }
}

/// Structure that holds information a about the current scan.
#[derive(Debug)]
pub(crate) struct ScanContext {}

#[cfg(test)]
mod tests {
    use crate::compiler::Compiler;
    use crate::scanner::Scanner;

    #[test]
    fn scan() {
        let rules = Compiler::new()
            .add_source(r#"rule test {strings: $a = "foo" condition: $a}"#)
            .unwrap()
            .build()
            .unwrap();

        let scanner = Scanner::new(&rules).scan(&[]);

        assert!(false);
    }
}
