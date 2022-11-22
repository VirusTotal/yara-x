/*! Scans data with already compiled YARA rules.

*/

use crate::compiler::{CompiledRule, CompiledRules, RuleId};
use crate::string_pool::BStringPool;
use crate::wasm;
use bitvec::prelude::*;
use bitvec::vec::BitVec;
use std::ptr::null;
use std::slice::Iter;
use wasmtime::{Store, TypedFunc};

#[cfg(test)]
mod tests;

/// Scans data with already compiled YARA rules.
pub struct Scanner<'r> {
    wasm_store: wasmtime::Store<ScanContext<'r>>,
    wasm_instance: wasmtime::Instance,
    wasm_main_fn: TypedFunc<(), ()>,
}

impl<'r> Scanner<'r> {
    /// Creates a new scanner.
    pub fn new(compiled_rules: &'r CompiledRules) -> Self {
        let mut wasm_store = Store::new(
            &crate::wasm::ENGINE,
            ScanContext {
                compiled_rules,
                scanned_data: null(),
                scanned_data_len: 0,
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

        Self { wasm_store, wasm_instance, wasm_main_fn }
    }

    /// Scans a data buffer.
    pub fn scan(&mut self, data: &[u8]) -> ScanResults {
        let ctx = self.wasm_store.data_mut();

        ctx.rules_matching_bitmap.fill(false);
        ctx.rules_matching.clear();
        ctx.scanned_data = data.as_ptr();
        ctx.scanned_data_len = data.len();

        // Invoke the main function.
        self.wasm_main_fn.call(&mut self.wasm_store, ()).unwrap();

        let ctx = self.wasm_store.data_mut();

        // Set pointer to data back to nil. This means that accessing
        // `scanned_data` can't be read from within `ScanResults`.
        ctx.scanned_data = null();
        ctx.scanned_data_len = 0;

        ScanResults::new(self.wasm_store.data())
    }
}

/// Results of a scan operation.
pub struct ScanResults<'a> {
    ctx: &'a ScanContext<'a>,
}

impl<'r> ScanResults<'r> {
    fn new(ctx: &'r ScanContext<'r>) -> Self {
        Self { ctx }
    }

    /// Returns the number of rules that matched.
    pub fn matching_rules(&self) -> usize {
        self.ctx.rules_matching.len()
    }

    pub fn iter(&self) -> IterMatches<'r> {
        IterMatches::new(self.ctx)
    }

    pub fn iter_non_matches(&self) -> IterNonMatches<'r> {
        IterNonMatches::new(self.ctx)
    }
}

pub struct IterMatches<'r> {
    ctx: &'r ScanContext<'r>,
    iterator: Iter<'r, RuleId>,
}

impl<'r> IterMatches<'r> {
    fn new(ctx: &'r ScanContext<'r>) -> Self {
        Self { ctx, iterator: ctx.rules_matching.iter() }
    }
}

impl<'r> Iterator for IterMatches<'r> {
    type Item = &'r CompiledRule;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = *self.iterator.next()?;
        Some(&self.ctx.compiled_rules.rules()[rule_id as usize])
    }
}

pub struct IterNonMatches<'r> {
    ctx: &'r ScanContext<'r>,
    iterator: bitvec::slice::IterZeros<'r, usize, Lsb0>,
}

impl<'r> IterNonMatches<'r> {
    fn new(ctx: &'r ScanContext<'r>) -> Self {
        Self { ctx, iterator: ctx.rules_matching_bitmap.iter_zeros() }
    }
}

impl<'r> Iterator for IterNonMatches<'r> {
    type Item = &'r CompiledRule;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = self.iterator.next()?;
        Some(&self.ctx.compiled_rules.rules()[rule_id])
    }
}

/// Structure that holds information a about the current scan.
pub(crate) struct ScanContext<'r> {
    /// Vector of bits where bit N is set to 1 if the rule with RuleID = N
    /// matched. This is used for determining whether a rule has matched
    /// or not without having to iterate the `rules_matching` vector, and
    /// also for iterating over the non-matching rules in an efficient way.
    pub(crate) rules_matching_bitmap: BitVec,
    /// Vector containing the IDs of the rules that matched.
    pub(crate) rules_matching: Vec<RuleId>,
    /// Data being scanned.
    pub(crate) scanned_data: *const u8,
    /// Length of data being scanned.
    pub(crate) scanned_data_len: usize,
    /// Compiled rules for this scan.
    pub(crate) compiled_rules: &'r CompiledRules,
}
