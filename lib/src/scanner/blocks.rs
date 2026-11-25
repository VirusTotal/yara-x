/*! Scanner for scanning data in blocks.

This scanner is designed for scenarios where the data to be scanned is not
available as a single contiguous block of memory, but rather arrives in
smaller, discrete blocks, allowing for incremental scanning.
*/
use std::cmp;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::mem;
use std::time::Duration;

use crate::errors::VariableError;
use crate::scanner::DataSnippets;
use crate::scanner::context::{PinnedScanContext, ScanState};
use crate::{Rules, ScanError, ScanResults, Variable};

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
/// # Limitations of Block Scanning
///
/// Block scanning works by analyzing data in chunks rather than as a whole
/// file. This makes it useful for streaming or memory-constrained scenarios,
/// but it comes with important limitations compared to standard scanning:
///
/// 1) Modules won't work. Parsers for structured formats (e.g., PE, ELF)
///    require access to the entire file and cannot be applied in block
///    scanning mode.
/// 2) Other modules like `hash` won't work either, as they require access to
///    all the scanned data during the evaluation of the rule's condition,
///    something that can't be guaranteed in block scanning mode. The hash
///    functions will return `undefined` when used in a multi-block context.
/// 3) Built-in functions like `uint8`, `uint16`, `uint32`, etc., have the
///    same limitation. They also return `undefined` in block scanning mode.
/// 4) The `filesize` keyword returns `undefined` in block scanning mode.
/// 5) Patterns won't match across block boundaries. Every match will be
///    completely contained within one of the blocks.
///
/// All these limitations imply that in block scanning mode you should only
/// use rules that rely on text, hex or regex patterns.
///
/// # Data Consistency in Overlapping Blocks
///
/// When [`Scanner::scan`] is invoked multiple times with different blocks
/// that may overlap, the user is responsible for ensuring data consistency.
/// This means that if the same region of the original data is present in two
/// or more overlapping blocks, the content of that region must be identical
/// across all calls to this function.
///
/// Generally speaking, the scanner does not verify this consistency and
/// assumes the user provides accurate and consistent data. In debug releases
/// the scanner may try to verify this consistency, but only when some pattern
/// matches in the overlapping region.
pub struct Scanner<'r> {
    ctx: PinnedScanContext<'r>,
    needs_reset: bool,
    snippets: BTreeMap<usize, Vec<u8>>,
}

impl<'r> Scanner<'r> {
    /// Creates a new block scanner.
    pub fn new(rules: &'r Rules) -> Scanner<'r> {
        Scanner {
            ctx: PinnedScanContext::new(rules),
            needs_reset: true,
            snippets: BTreeMap::new(),
        }
    }

    /// Sets the context size for matches.
    ///
    /// This specifies how many bytes at the left and right of each match will
    /// be reported by [`crate::Match::data_with_context`]. By default, the
    /// match context size is 0, which means that [`crate::Match::data_with_context`]
    /// will return exactly the same data as [`crate::Match::data`].
    pub fn match_context_size(&mut self, size: usize) -> &mut Self {
        self.ctx.get_mut().match_context_size = size;
        self
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
        // Reset the scanner if needed. This is done before scanning the first
        // block after the scanner has been created, or when a previous scan
        // has finished and the scanner is going to be reused.
        if self.needs_reset {
            self.ctx.get_mut().reset();
            self.needs_reset = false;
        }
        // Even when the scanner is not reset, we must clear unconfirmed matches
        // between blocks. Otherwise, matches partially detected in one block
        // could incorrectly be confirmed by data from a different block.
        //
        // This prevents matches from spanning multiple blocks — a scenario that
        // could occur with patterns split into multiple subpatterns, for
        // example:
        //
        // { 01 02 03 [-] 04 05 06}
        //
        // In this case, the subpattern `01 02 03` might match in one block, and
        // `04 05 06` in the next. While supporting cross-block matches is
        // technically possible, it would be inconsistent with patterns that
        // cannot span blocks. To maintain a simple, uniform rule — that matches
        // never cross block boundaries — we clear all unconfirmed matches here.
        else {
            self.ctx.get_mut().tracker.unconfirmed_matches.clear();
        }

        let ctx = self.ctx.get_mut();

        ctx.tracker.block_matches.get_or_insert_with(Vec::new).clear();
        ctx.scan_state = ScanState::ScanningBlock((base, data));

        ctx.set_pattern_search_done(false);
        let search_res = ctx.search_for_patterns();
        ctx.scan_state = ScanState::Idle;
        search_res?;

        let context_size = ctx.match_context_size;

        // Gather snippets of data for every match newly inserted or extended
        // in the block that was just scanned.
        for match_range in
            ctx.tracker.block_matches.as_mut().unwrap().drain(..)
        {
            let context_start =
                cmp::max(match_range.start.saturating_sub(context_size), base);

            let context_end = cmp::min(
                match_range.end.saturating_add(context_size),
                base + data.len(),
            );

            let block_start = context_start - base;
            let block_end = context_end - base;

            if let Some(context_data) = data.get(block_start..block_end) {
                // Snippets are indexed by the offset where the context starts.
                match self.snippets.entry(context_start) {
                    Entry::Occupied(mut entry) => {
                        let snippet = entry.get_mut();
                        if context_data.len() > snippet.len() {
                            entry.insert(context_data.to_vec());
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(context_data.to_vec());
                    }
                }
            } else {
                debug_assert!(false)
            }
        }

        Ok(self)
    }

    /// Finalizes the scanning process.
    ///
    /// After all data blocks have been scanned, this method evaluates the
    /// conditions of the YARA rules and produces the final scan results.
    pub fn finish(&mut self) -> Result<ScanResults<'_, 'r>, ScanError> {
        if self.needs_reset {
            self.ctx.get_mut().reset();
        }

        self.needs_reset = true;

        let ctx = self.ctx.get_mut();

        // In block scanning mode patterns are searched as each block is
        // scanned, never lazily during condition evaluation because block data
        // is no longer available here. Ensure the flag is set even when
        // `finish` is called without scanning any blocks (e.g. an empty
        // stream).
        ctx.set_pattern_search_done(true);
        ctx.eval_conditions()?;

        ctx.scan_state = ScanState::Finished(DataSnippets::MultiBlock(
            mem::take(&mut self.snippets),
        ));

        Ok(ScanResults::new(ctx))
    }

    /// Sets the value of a global variable.
    ///
    /// The variable must has been previously defined by calling
    /// [`crate::Compiler::define_global`], and the type it has during the
    /// definition must match the type of the new value (`T`).
    ///
    /// The variable will retain the new value in subsequent scans, unless this
    /// function is called again for setting a new value.
    pub fn set_global<T: TryInto<Variable>>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<&mut Self, VariableError>
    where
        VariableError: From<<T as TryInto<Variable>>::Error>,
    {
        self.ctx.get_mut().set_global(ident, value)?;
        Ok(self)
    }

    /// Sets a timeout for scan operations.
    ///
    /// The scan functions will return an [ScanError::Timeout] once the
    /// provided timeout duration has elapsed. The scanner will make every
    /// effort to stop promptly after the designated timeout duration. However,
    /// in some cases, particularly with rules containing only a few patterns,
    /// the scanner could potentially continue running for a longer period than
    /// the specified timeout.
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.ctx.get_mut().set_timeout(timeout);
        self
    }

    /// Sets the maximum number of matches per pattern.
    ///
    /// When some pattern reaches the maximum number of patterns it won't
    /// produce more matches.
    pub fn max_matches_per_pattern(&mut self, n: usize) -> &mut Self {
        self.ctx.get_mut().tracker.pattern_matches.max_matches_per_pattern(n);
        self
    }

    /// Enables or disables fast scan mode.
    ///
    /// In fast scan mode, the scanner avoids tracking matches for patterns
    /// when it is not necessary (e.g. when a rule condition only performs a
    /// simple boolean check `$a`).
    ///
    /// Note that using fast scan mode implies that not all matches will be
    /// reported. For instance, when iterating matches using [`ScanResults`],
    /// you won't get all occurrences of the pattern in the file, only the first
    /// one.
    pub fn fast_scan(&mut self, yes: bool) -> &mut Self {
        self.ctx.get_mut().tracker.fast_scan = yes;
        self
    }

    /// Sets a callback that is invoked every time a YARA rule calls the
    /// `console` module.
    ///
    /// The `callback` function is invoked with a string representing the
    /// message being logged. The function can print the message to stdout,
    /// append it to a file, etc. If no callback is set these messages are
    /// ignored.
    ///
    /// Any data borrowed by `callback` must outlive the [`Scanner`], because
    /// the callback is owned by the scanner and dropped when the scanner is
    /// dropped:
    ///
    /// ```compile_fail,E0505
    /// # use std::io::{BufWriter, Write};
    /// # use yara_x::{Rules, ScanError, blocks};
    /// fn console_output(rules: &Rules, data: &[u8]) -> Result<Vec<u8>, ScanError> {
    ///     let mut scanner = blocks::Scanner::new(rules);
    ///     let mut log = Vec::new();
    ///     let mut writer = BufWriter::new(&mut log);
    ///     scanner.console_log(move |msg| writeln!(writer, "{msg}").unwrap());
    ///     scanner.scan(0, data)?;
    ///     scanner.finish()?;
    ///     Ok(log)
    /// }
    /// ```
    pub fn console_log<F>(&mut self, callback: F) -> &mut Self
    where
        F: FnMut(String) + 'r,
    {
        self.ctx.get_mut().console_log = Some(Box::new(callback));
        self
    }

    /// Returns profiling data for the slowest N rules.
    ///
    /// The profiling data reflects the cumulative execution time of each rule
    /// across all scanned files. This information is useful for identifying
    /// performance bottlenecks. To reset the profiling data and start fresh
    /// for subsequent scans, use [`crate::Scanner::clear_profiling_data`].
    #[cfg(feature = "rules-profiling")]
    pub fn slowest_rules(
        &self,
        n: usize,
    ) -> Vec<crate::scanner::ProfilingData<'_>> {
        self.ctx.get().slowest_rules(n)
    }

    /// Clears all accumulated profiling data.
    ///
    /// This method resets the profiling data collected during rule execution
    /// across scanned files. Use this to start a new profiling session, ensuring
    /// the results reflect only the data gathered after this method is called.
    #[cfg(feature = "rules-profiling")]
    pub fn clear_profiling_data(&mut self) {
        self.ctx.get_mut().clear_profiling_data()
    }
}

impl<'r> From<crate::scanner::Scanner<'r>> for Scanner<'r> {
    fn from(scanner: crate::scanner::Scanner<'r>) -> Self {
        Self {
            ctx: scanner.ctx,
            needs_reset: true,
            snippets: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::blocks::Scanner;
    use crate::{Compiler, compile};
    use std::time::Duration;

    #[test]
    fn block_scanner_1() {
        let rules = compile(
            r#"
            rule test { strings: $a = "ipsum" condition: $a }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);

        let results = scanner
            .scan(0, b"Lorem ipsum")
            .unwrap()
            .scan(1000, b"dolor ipsum sit amet")
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(results.matching_rules().len(), 1);

        let rule = results.matching_rules().next().unwrap();
        let pattern = rule.patterns().next().unwrap();
        let mut matches = pattern.matches();

        let match1 = matches.next().unwrap();
        assert_eq!(match1.data(), b"ipsum".as_slice());
        assert_eq!(match1.range(), 6..11);

        let match2 = matches.next().unwrap();
        assert_eq!(match2.data(), b"ipsum".as_slice());
        assert_eq!(match2.range(), 1006..1011);
    }

    #[test]
    fn block_scanner_context() {
        let rules = compile(
            r#"
            rule test { strings: $a = "ipsum" condition: $a }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);

        let results = scanner
            .match_context_size(5)
            .scan(0, b"Lorem ipsum sit amet")
            .unwrap()
            .scan(1000, b"dolor ipsum sit amet")
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(results.matching_rules().len(), 1);

        let rule = results.matching_rules().next().unwrap();
        let pattern = rule.patterns().next().unwrap();
        let mut matches = pattern.matches();

        let match1 = matches.next().unwrap();
        let (data1, range1) = match1.data_with_context();
        assert_eq!(data1, b"orem ipsum sit ".as_slice());
        assert_eq!(range1, 5..10);

        let match2 = matches.next().unwrap();
        let (data2, range2) = match2.data_with_context();
        assert_eq!(data2, b"olor ipsum sit ".as_slice());
        assert_eq!(range2, 5..10);
    }

    #[test]
    fn block_scanner_2() {
        let rules = compile(
            r#"
            rule test { strings: $a = /ipsum.*amet/s condition: $a }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);

        let results = scanner
            .scan(0, b"Lorem ipsum")
            .unwrap()
            .scan(1000, b"dolor ipsum sit amet")
            .unwrap()
            .finish()
            .unwrap();

        let rule = results.matching_rules().next().unwrap();
        let pattern = rule.patterns().next().unwrap();
        let mut matches = pattern.matches();

        let match_ = matches.next().unwrap();
        assert_eq!(match_.data(), b"ipsum sit amet".as_slice());
        assert_eq!(match_.range(), 1006..1020);
    }

    #[test]
    fn block_scanner_match_in_range() {
        let rules = compile(
            r#"
            rule test { strings: $a = "ipsum" condition: $a in (1003..1008) }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);

        let results = scanner
            .scan(0, b"Lorem ipsum")
            .unwrap()
            .scan(1000, b"dolor ipsum sit amet")
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(results.matching_rules().len(), 1);

        let rule = results.matching_rules().next().unwrap();
        let pattern = rule.patterns().next().unwrap();
        let mut matches = pattern.matches();

        let match1 = matches.next().unwrap();
        assert_eq!(match1.data(), b"ipsum".as_slice());
        assert_eq!(match1.range(), 6..11);

        let match2 = matches.next().unwrap();
        assert_eq!(match2.data(), b"ipsum".as_slice());
        assert_eq!(match2.range(), 1006..1011);
    }

    #[test]
    fn block_scanner_match_at_offset() {
        let rules = compile(
            r#"
            rule test { strings: $a = "ipsum" condition: $a at 1006 }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);

        let results = scanner
            .scan(1000, b"dolor ipsum sit amet")
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(results.matching_rules().len(), 1);
    }

    #[test]
    fn block_scanner_global() {
        let mut compiler = Compiler::new();

        compiler
            .define_global("foo", "")
            .unwrap()
            .add_source(
                r#"
                rule test { condition: foo == "foo" }"#,
            )
            .unwrap();

        let rules = compiler.build();
        let mut scanner = Scanner::new(&rules);
        scanner.set_global("foo", "foo").unwrap();
        let results = scanner.finish().unwrap();
        assert_eq!(results.matching_rules().len(), 1);
    }

    #[test]
    fn block_scanner_timeout() {
        let rules = compile(
            r#"
            rule slow {
                condition: 
                    for any i in (0..1000000000) : (
                         uint8(i) == 0xCC
                    )
            }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);
        scanner.set_timeout(Duration::from_secs(1));
        let err = scanner.finish().unwrap_err();
        assert_eq!(err.to_string(), "timeout");
    }

    #[test]
    fn block_scanner_filesize() {
        let rules = compile(
            r#"
            rule filesize_undefined {
                condition: 
                    not defined filesize 
            }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);
        let results = scanner.finish().unwrap();

        assert_eq!(results.matching_rules().len(), 1);
    }

    #[test]
    fn block_scanner_finish_without_blocks() {
        let rules = compile(
            r#"
            rule found { strings: $a = "foo" condition: $a }
            rule not_found { strings: $a = "foo" condition: not $a }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);

        // Calling `finish` without scanning any block behaves like empty data.
        let results = scanner.finish().unwrap();

        assert_eq!(results.matching_rules().len(), 1);
        assert_eq!(
            results.matching_rules().next().unwrap().identifier(),
            "not_found"
        );

        // Subsequent scans on the same scanner still search patterns normally.
        let results = scanner.scan(0, b"foo").unwrap().finish().unwrap();

        assert_eq!(results.matching_rules().len(), 1);
        assert_eq!(
            results.matching_rules().next().unwrap().identifier(),
            "found"
        );
    }

    #[test]
    fn block_scanner_fast_scan() {
        let rules = compile(
            r#"
            rule test {
                strings:
                    $a = "foo"
                condition:
                    $a
            }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);
        let results = scanner
            .fast_scan(true)
            .scan(0, b"foofoofoo")
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(results.matching_rules().len(), 1);

        let rule = results.matching_rules().next().unwrap();
        let pattern = rule.patterns().next().unwrap();
        let mut matches = pattern.matches();

        // Only a single match is returned because of the fast scan mode!
        let match1 = matches.next().unwrap();
        assert_eq!(match1.data(), b"foo".as_slice());
        assert_eq!(match1.range(), 0..3);

        assert!(matches.next().is_none());
    }

    #[test]
    fn block_scanner_overlapping_greedy_regexp() {
        let rules = compile(
            r#"
            rule test {
                strings:
                    $a = /aaaB+/
                condition:
                    $a
            }"#,
        )
        .unwrap();

        let mut scanner = Scanner::new(&rules);
        // Block 0 (offsets 0..13): matches "aaaBBB" at 7..13.
        // Block 1 (offsets 6..23): overlaps block 0 and extends the match at
        // offset 7 to "aaaBBBBBB" (7..16).
        let results = scanner
            .match_context_size(2)
            .scan(0, b"prefix aaaBBB")
            .unwrap()
            .scan(6, b" aaaBBBBBB suffix")
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(results.matching_rules().len(), 1);

        let rule = results.matching_rules().next().unwrap();
        let pattern = rule.patterns().next().unwrap();
        let mut matches = pattern.matches();

        let match_ = matches.next().unwrap();
        assert_eq!(match_.range(), 7..16);
        assert_eq!(match_.data(), b"aaaBBBBBB".as_slice());
        assert_eq!(
            match_.data_with_context(),
            (b" aaaBBBBBB s".as_slice(), 1..10)
        );
        assert!(matches.next().is_none());
    }
}
