/*! Scans data with already compiled YARA rules.

*/

use crate::compiler::{CompiledRule, CompiledRules};
use crate::wasm;
use bitvec::prelude::*;
use bitvec::vec::BitVec;
use wasmtime::{Store, TypedFunc};

#[cfg(test)]
mod tests;

/// Scans data with already compiled YARA rules.
pub struct Scanner<'r, 'd> {
    compiled_rules: &'r CompiledRules,
    wasm_store: wasmtime::Store<ScanContext<'d>>,
    wasm_instance: wasmtime::Instance,
    wasm_main_fn: TypedFunc<(), ()>,
}

impl<'r, 'd> Scanner<'r, 'd> {
    /// Creates a new scanner.
    pub fn new(compiled_rules: &'r CompiledRules) -> Self {
        let mut wasm_store = Store::new(
            &crate::wasm::ENGINE,
            ScanContext {
                scanned_data: None,
                num_rules_matching: 0,
                rule_matches: BitVec::repeat(
                    false,
                    compiled_rules.rules().len(),
                ),
            },
        );

        let wasm_instance = wasm::LINKER
            .instantiate(&mut wasm_store, compiled_rules.compiled_wasm_mod())
            .unwrap();

        let wasm_main_fn = wasm_instance
            .get_typed_func::<(), (), _>(&mut wasm_store, "main")
            .unwrap();

        Self { compiled_rules, wasm_store, wasm_instance, wasm_main_fn }
    }

    /// Scans a data buffer.
    pub fn scan(&'r mut self, data: &'d [u8]) -> ScanResults<'r, 'd> {
        let ctx = self.wasm_store.data_mut();

        ctx.rule_matches.fill(false);
        ctx.num_rules_matching = 0;
        ctx.scanned_data = Some(data);

        // Invoke the main function.
        self.wasm_main_fn.call(&mut self.wasm_store, ()).unwrap();

        ScanResults::new(self)
    }
}

/// Results of a scan operation.
pub struct ScanResults<'r, 'd> {
    scanner: &'r Scanner<'r, 'd>,
}

impl<'r, 'd> ScanResults<'r, 'd> {
    fn new(scanner: &'r Scanner<'r, 'd>) -> Self {
        Self { scanner }
    }

    /// Returns the number of rules that matched.
    pub fn matching_rules(&self) -> usize {
        self.scanner.wasm_store.data().num_rules_matching
    }

    pub fn iter(&self) -> IterMatches<'r, 'd> {
        IterMatches::new(self.scanner)
    }

    pub fn iter_non_matches(&self) -> IterNonMatches<'r, 'd> {
        IterNonMatches::new(self.scanner)
    }
}

pub struct IterMatches<'r, 'd> {
    scanner: &'r Scanner<'r, 'd>,
    iterator: bitvec::slice::IterOnes<'r, usize, Lsb0>,
}

impl<'r, 'd> IterMatches<'r, 'd> {
    fn new(scanner: &'r Scanner<'r, 'd>) -> Self {
        Self {
            scanner,
            iterator: scanner.wasm_store.data().rule_matches.iter_ones(),
        }
    }
}

impl<'r, 'd> Iterator for IterMatches<'r, 'd> {
    type Item = &'r CompiledRule;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = self.iterator.next()?;
        Some(&self.scanner.compiled_rules.rules()[rule_id])
    }
}

pub struct IterNonMatches<'r, 'd> {
    scanner: &'r Scanner<'r, 'd>,
    iterator: bitvec::slice::IterZeros<'r, usize, Lsb0>,
}

impl<'r, 'd> IterNonMatches<'r, 'd> {
    fn new(scanner: &'r Scanner<'r, 'd>) -> Self {
        Self {
            scanner,
            iterator: scanner.wasm_store.data().rule_matches.iter_zeros(),
        }
    }
}

impl<'r, 'd> Iterator for IterNonMatches<'r, 'd> {
    type Item = &'r CompiledRule;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = self.iterator.next()?;
        Some(&self.scanner.compiled_rules.rules()[rule_id])
    }
}

/// Structure that holds information a about the current scan.
#[derive(Debug)]
pub(crate) struct ScanContext<'d> {
    /// Vector of bits where bit N is set to 1 if the rule with RuleID = N
    /// matched.
    pub(crate) rule_matches: BitVec,
    /// Number of rules that matched.
    pub(crate) num_rules_matching: usize,
    /// Data being scanned.
    pub(crate) scanned_data: Option<&'d [u8]>,
}
