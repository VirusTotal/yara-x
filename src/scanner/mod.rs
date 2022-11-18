/*! Scans data with already compiled YARA rules.

*/

use crate::compiler::{CompiledRule, CompiledRules, RuleId};
use crate::wasm;
use bitvec::prelude::*;
use bitvec::vec::BitVec;
use std::slice::Iter;
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
                rules_matching: Vec::new(),
                rules_matching_bitmap: BitVec::repeat(
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

        ctx.rules_matching_bitmap.fill(false);
        ctx.rules_matching.clear();
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
        self.scanner.wasm_store.data().rules_matching.len()
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
    iterator: Iter<'r, RuleId>,
}

impl<'r, 'd> IterMatches<'r, 'd> {
    fn new(scanner: &'r Scanner<'r, 'd>) -> Self {
        Self {
            scanner,
            iterator: scanner.wasm_store.data().rules_matching.iter(),
        }
    }
}

impl<'r, 'd> Iterator for IterMatches<'r, 'd> {
    type Item = &'r CompiledRule;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = *self.iterator.next()?;
        Some(&self.scanner.compiled_rules.rules()[rule_id as usize])
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
            iterator: scanner
                .wasm_store
                .data()
                .rules_matching_bitmap
                .iter_zeros(),
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
    /// matched. This is used for determining whether a rule has matched
    /// or not without having to iterate the `rules_matching` vector, and
    /// also for iterating over the non-matching rules in an efficient way.
    pub(crate) rules_matching_bitmap: BitVec,
    /// Vector containing the IDs of the rules that matched.
    pub(crate) rules_matching: Vec<RuleId>,
    /// Data being scanned.
    pub(crate) scanned_data: Option<&'d [u8]>,
}
