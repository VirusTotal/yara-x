/*! Scanner for scanning data in blocks.

This scanner is designed for scenarios where the data to be scanned is not
available as a single contiguous block of memory, but rather arrives in
smaller, discrete blocks, allowing for incremental scanning.
*/
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::mem;
use std::mem::transmute;
use std::pin::Pin;

use wasmtime::Store;

use crate::scanner::context::{create_wasm_store_and_ctx, ScanState};
use crate::scanner::{DataSnippets, ScanContext, ScannedData};
use crate::{Rules, ScanError, ScanResults};

/// Scans data in blocks
///
/// This scanner is designed for scenarios where the data to be scanned is not
/// available as a single contiguous block of memory, but rather arrives in
/// smaller, discrete blocks, allowing for incremental scanning.
///
/// # Examples
///
/// ```
/// # use yara_x::{blocks, compile};
///
/// let rules = compile(r#"rule test { strings: $a = "abc" condition: $a }"#).unwrap();
///
/// let mut scanner = blocks::Scanner::new(&rules);
///
/// // Scan the first block of data.
/// scanner.scan(0, b"xabcy").unwrap();
///
/// // Scan a second block of data, which can overlap with the first.
/// scanner.scan(3, b"cyz").unwrap();
///
/// // Finish the scan and get the results.
/// let results = scanner.finish().unwrap();
///
/// assert_eq!(results.matching_rules().len(), 1);
/// ```
///
/// # Data Consistency in Overlapping Blocks
///
/// When [`Scanner::scan`] is invoked multiple times with different
/// blocks that may overlap, the user is responsible for ensuring data
/// consistency. This means that if the same region of the original data
/// is present in two or more overlapping blocks, the content of that
/// region must be identical across all calls to `scan`. The scanner
/// does not verify this consistency and assumes the user provides
/// accurate and consistent data.
pub struct Scanner<'r> {
    _rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static, 'static>>>>,
    scanning: bool,
    snippets: BTreeMap<usize, Vec<u8>>,
}

impl<'r> Scanner<'r> {
    /// Creates a new block scanner.
    pub fn new(rules: &'r Rules) -> Scanner<'r> {
        Scanner {
            _rules: rules,
            wasm_store: create_wasm_store_and_ctx(rules),
            scanning: false,
            snippets: BTreeMap::new(),
        }
    }
}
impl<'r> Scanner<'r> {
    /// Scans a block of data.
    ///
    /// This method processes a given block of data, searching for patterns
    /// defined in the YARA rules. The `base` argument specifies the offset
    /// of the current block within the overall data being scanned. In most
    /// cases you will want to call this method multiple times, providing a
    /// different block on each call.
    ///
    /// # Arguments
    ///
    /// * `base` - The starting offset of the `data` block within overall
    ///   data being scanned.
    /// * `data` - The byte slice representing the current block of data to
    ///   scan.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or a `ScanError` if the scan operation
    /// fails.
    pub fn scan(
        &mut self,
        base: usize,
        data: &[u8],
    ) -> Result<&mut Self, ScanError> {
        if !self.scanning {
            self.scan_context_mut().reset();
            self.scanning = true;
        }

        let ctx = self.scan_context_mut();

        ctx.scan_state = ScanState::Scanning(ScannedData::Slice((base, data)));
        ctx.search_for_patterns()?;

        for (_, match_list) in ctx.pattern_matches.matches_per_pattern() {
            for m in match_list.iter().filter(|m| m.base == base) {
                if let Some(match_data) = data.get(m.range.clone()) {
                    // Snippets are indexed by their offsets within the scanned
                    // data. This offset is not relative to the start of the
                    // memory block, it takes into account the block's base
                    // offset.
                    //
                    // The matching data is stored into the snippets B-tree map.
                    // If an entry exists for the same offset, it will be replaced
                    // with the new matching data only if it's larger than the
                    // existing one.
                    match self.snippets.entry(m.base + m.range.start) {
                        Entry::Occupied(mut entry) => {
                            let snippet = entry.get_mut();
                            if match_data.len() > snippet.len() {
                                debug_assert!(match_data.starts_with(snippet));
                                entry.insert(match_data.to_vec());
                            } else {
                                debug_assert!(snippet.starts_with(match_data));
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(match_data.to_vec());
                        }
                    }
                } else {
                    debug_assert!(false)
                }
            }
        }

        Ok(self)
    }

    /// Finalizes the scanning process.
    ///
    /// After all data blocks have been scanned, this method evaluates the
    /// conditions of the YARA rules and produces the final scan results.
    pub fn finish(&mut self) -> Result<ScanResults<'_, 'r>, ScanError> {
        self.scanning = false;

        let ctx = self.scan_context_mut();

        ctx.eval_conditions()?;

        ctx.scan_state = ScanState::Finished(DataSnippets::MultiBlock(
            mem::take(&mut self.snippets),
        ));

        Ok(ScanResults::new(ctx))
    }
}

impl<'r> Scanner<'r> {
    #[inline]
    fn scan_context_mut<'a>(&mut self) -> &'a mut ScanContext<'r, 'a> {
        unsafe {
            transmute::<
                &mut ScanContext<'static, 'static>,
                &mut ScanContext<'r, 'a>,
            >(self.wasm_store.data_mut())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compile;
    use crate::scanner::blocks::Scanner;

    #[test]
    fn block_scanner() {
        let rules =
            compile(r#"rule test { strings: $a = "ipsum" condition: $a }"#)
                .unwrap();

        let mut scanner = Scanner::new(&rules);

        let results = scanner
            .scan(0, b"Lorem ipsum")
            .unwrap()
            .scan(1000, b"dolor sit amet")
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(results.matching_rules().len(), 1);

        let rule = results.matching_rules().next().unwrap();
        let pattern = rule.patterns().next().unwrap();
        let match_ = pattern.matches().next().unwrap();

        assert_eq!(match_.data(), b"ipsum".as_slice());
        assert_eq!(match_.range(), 6..11);
    }
}
