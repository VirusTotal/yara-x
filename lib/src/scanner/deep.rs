/*! Scanner for deep scanning data and extracted container files.

This scanner is designed for recursive scanning scenarios where the data to be
scanned contains archive or container files (e.g., ZIP archives). It unpacks
supported container formats and traverses the extracted file hierarchy in
depth-first search order.
*/

use std::ops::ControlFlow;
use std::path::Path;
use std::time::Duration;

use protobuf::MessageDyn;

use crate::errors::VariableError;
use crate::extractor::{ExtractEvent, Extractor};
use crate::scanner::{ScanOptions, ScannedData};
use crate::{Rules, ScanError, ScanResults, Variable};

/// Events emitted during a deep scan operation.
pub enum ScanEvent<'a, 'r> {
    /// Emitted when a file or data buffer is about to be scanned.
    ///
    /// The path is relative to the root container, or empty (`Path::new("")`)
    /// for the top-level file or data buffer.
    Started(&'a Path),

    /// Emitted after scanning the raw content of a file or data buffer,
    /// before scanning any inner files extracted from it.
    Scanned(&'a Path, &'a ScanResults<'a, 'r>),

    /// Emitted once a file or data buffer, along with all inner files
    /// extracted from it (if any), has been completely scanned.
    Finished(&'a Path),
}

/// Scans data and container contents recursively.
///
/// This scanner is designed for recursive scanning scenarios where the input
/// data contains archive or container formats (e.g., ZIP archives). Unlike the
/// standard [`crate::Scanner`], `Scanner` unpacks container files automatically
/// and traverses the extracted file tree in depth-first search (DFS) order up
/// to a maximum extraction depth.
///
/// The `callback` function is invoked with [`ScanEvent`] notifications for the
/// main data buffer and for every file extracted from it:
///
/// 1. [`ScanEvent::Started`] before scanning the file or data buffer.
/// 2. [`ScanEvent::Scanned`] with the [`ScanResults`] after scanning the
///    raw file or data buffer, before any inner files extracted from it are
///    scanned.
/// 3. [`ScanEvent::Finished`] once the file or data buffer and all inner files
///    extracted from it (if any) have been completely scanned.
///
/// For the main data passed in `data`, the path associated with these events
/// is empty (`Path::new("")`).
///
/// # Flow Control
///
/// The callback closure returns [`std::ops::ControlFlow<B>`], giving explicit
/// control over scan traversal and early termination:
///
/// - Returning [`std::ops::ControlFlow::Continue(())`] instructs the scanner
///   to proceed normally.
///
/// - Returning [`std::ops::ControlFlow::Break(b)`] immediately halts further
///   scanning and extraction recursion, returning
///   `Ok(ControlFlow::Break(b))`.
///
/// # Timeouts
///
/// Any scan timeout configured via [`Scanner::set_timeout`] applies
/// **cumulatively** across the entire scan operation. The cumulative scanning
/// time spent across all unpacked files is tracked against a single deadline.
///
/// # Examples
///
/// ```
/// # use yara_x::{deep, compile};
/// # use std::ops::ControlFlow;
///
/// let rules = compile("rule test { condition: true }").unwrap();
/// let mut scanner = deep::Scanner::new(&rules);
///
/// let _ = scanner.scan(b"dummy haystack", |event| {
///     if let deep::ScanEvent::Scanned(_path, results) = event {
///         assert_eq!(results.matching_rules().count(), 1);
///     }
///     ControlFlow::<()>::Continue(())
/// });
/// ```
pub struct Scanner<'r> {
    pub(super) inner: crate::Scanner<'r>,
    /// Container extractor.
    extractor: Extractor,
}

impl<'r> Scanner<'r> {
    /// Creates a new deep scanner.
    pub fn new(rules: &'r Rules) -> Self {
        Self { inner: crate::Scanner::new(rules), extractor: Extractor::new() }
    }

    /// Sets the maximum container extraction depth.
    ///
    /// If set to 0 scans only the main input buffer (or file) without
    /// extracting any files from it. If set to 1 extracts and scans immediate
    /// inner files, but no further.
    ///
    /// Default value is 1.
    pub fn max_depth(&mut self, depth: usize) -> &mut Self {
        self.extractor.max_depth(depth);
        self
    }

    /// Sets the maximum total number of files to extract during a scan.
    ///
    /// Default value is 5.
    pub fn max_files(&mut self, max_files: usize) -> &mut Self {
        self.extractor.max_files(max_files);
        self
    }

    /// Sets a timeout for scan operations.
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.inner.set_timeout(timeout);
        self
    }

    /// Sets the maximum number of matches per pattern.
    pub fn max_matches_per_pattern(&mut self, n: usize) -> &mut Self {
        self.inner.max_matches_per_pattern(n);
        self
    }

    /// Enables or disables fast scan mode.
    pub fn fast_scan(&mut self, yes: bool) -> &mut Self {
        self.inner.fast_scan(yes);
        self
    }

    /// Enables or disables memory-mapped files.
    pub fn use_mmap(&mut self, yes: bool) -> &mut Self {
        self.inner.use_mmap(yes);
        self
    }

    /// Sets a maximum size for scanned data.
    pub fn max_scan_size(&mut self, size: usize) -> &mut Self {
        self.inner.max_scan_size(size);
        self
    }

    /// Sets a callback function for handling console log messages.
    pub fn console_log<F>(&mut self, callback: F) -> &mut Self
    where
        F: FnMut(String) + Send + Sync + 'static,
    {
        self.inner.console_log(callback);
        self
    }

    /// Sets the match context size.
    pub fn match_context_size(&mut self, size: usize) -> &mut Self {
        self.inner.match_context_size(size);
        self
    }

    /// Sets the value of a global variable.
    pub fn set_global<T: TryInto<Variable>>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<&mut Self, VariableError>
    where
        VariableError: From<<T as TryInto<Variable>>::Error>,
    {
        self.inner.set_global(ident, value)?;
        Ok(self)
    }

    /// Sets the output data for a YARA module.
    pub fn set_module_output(
        &mut self,
        data: Box<dyn MessageDyn>,
    ) -> Result<&mut Self, ScanError> {
        self.inner.set_module_output(data)?;
        Ok(self)
    }

    /// Sets the raw output data for a YARA module.
    pub fn set_module_output_raw(
        &mut self,
        name: &str,
        data: &[u8],
    ) -> Result<&mut Self, ScanError> {
        self.inner.set_module_output_raw(name, data)?;
        Ok(self)
    }

    /// Returns profiling data for the slowest N rules.
    #[cfg(feature = "rules-profiling")]
    pub fn slowest_rules(
        &self,
        n: usize,
    ) -> Vec<crate::scanner::ProfilingData<'_>> {
        self.inner.slowest_rules(n)
    }

    /// Clears all accumulated profiling data.
    #[cfg(feature = "rules-profiling")]
    pub fn clear_profiling_data(&mut self) {
        self.inner.clear_profiling_data()
    }

    /// Scans in-memory data recursively, unpacking container files and
    /// executing `callback` for each scan event.
    pub fn scan<F, B>(
        &mut self,
        data: &[u8],
        callback: F,
    ) -> Result<ControlFlow<B>, ScanError>
    where
        F: FnMut(ScanEvent<'_, 'r>) -> ControlFlow<B>,
    {
        self.scan_internal(data, None, callback)
    }

    /// Like [`Scanner::scan`], but allows specifying additional scan options.
    pub fn scan_with_options<F, B>(
        &mut self,
        data: &[u8],
        options: ScanOptions,
        callback: F,
    ) -> Result<ControlFlow<B>, ScanError>
    where
        F: FnMut(ScanEvent<'_, 'r>) -> ControlFlow<B>,
    {
        self.scan_internal(data, Some(&options), callback)
    }

    /// Scans a file recursively, unpacking container files and
    /// executing `callback` for each scan event.
    pub fn scan_file<P, F, B>(
        &mut self,
        target: P,
        callback: F,
    ) -> Result<ControlFlow<B>, ScanError>
    where
        P: AsRef<Path>,
        F: FnMut(ScanEvent<'_, 'r>) -> ControlFlow<B>,
    {
        let data = self.inner.load_file(target.as_ref())?;
        self.scan_internal(data.as_ref(), None, callback)
    }

    /// Like [`Scanner::scan_file`], but allows specifying additional scan options.
    pub fn scan_file_with_options<P, F, B>(
        &mut self,
        target: P,
        options: ScanOptions,
        callback: F,
    ) -> Result<ControlFlow<B>, ScanError>
    where
        P: AsRef<Path>,
        F: FnMut(ScanEvent<'_, 'r>) -> ControlFlow<B>,
    {
        let data = self.inner.load_file(target.as_ref())?;
        self.scan_internal(data.as_ref(), Some(&options), callback)
    }

    fn scan_internal<'opts, F, B>(
        &mut self,
        data: &[u8],
        options: Option<&ScanOptions<'opts>>,
        mut callback: F,
    ) -> Result<ControlFlow<B>, ScanError>
    where
        F: FnMut(ScanEvent<'_, 'r>) -> ControlFlow<B>,
    {
        self.inner.scan_context_mut().reset(false);

        let root_path = Path::new("");

        if let ControlFlow::Break(b) = callback(ScanEvent::Started(root_path))
        {
            return Ok(ControlFlow::Break(b));
        }

        let scan_results = self.inner.scan_internal(
            ScannedData::Slice(data),
            options,
            true,
        )?;

        if let ControlFlow::Break(b) =
            callback(ScanEvent::Scanned(root_path, &scan_results))
        {
            return Ok(ControlFlow::Break(b));
        }

        let mut result = Ok(ControlFlow::Continue(()));

        let _ = self.extractor.extract_dfs(data, |event| match event {
            ExtractEvent::Extracted(_module, path, bytes) => {
                if self.inner.scan_context().timeout_expired() {
                    result = Err(ScanError::Timeout);
                    return ControlFlow::Break(());
                }

                if let ControlFlow::Break(b) =
                    callback(ScanEvent::Started(path))
                {
                    result = Ok(ControlFlow::Break(b));
                    return ControlFlow::Break(());
                }

                let scan_results = match self.inner.scan_internal(
                    ScannedData::Slice(bytes),
                    options,
                    true,
                ) {
                    Ok(results) => results,
                    Err(err) => {
                        result = Err(err);
                        return ControlFlow::Break(());
                    }
                };

                match callback(ScanEvent::Scanned(path, &scan_results)) {
                    ControlFlow::Continue(()) => ControlFlow::Continue(()),
                    ControlFlow::Break(b) => {
                        result = Ok(ControlFlow::Break(b));
                        ControlFlow::Break(())
                    }
                }
            }
            ExtractEvent::Finished(path) => {
                match callback(ScanEvent::Finished(path)) {
                    ControlFlow::Continue(()) => ControlFlow::Continue(()),
                    ControlFlow::Break(b) => {
                        result = Ok(ControlFlow::Break(b));
                        ControlFlow::Break(())
                    }
                }
            }
        });

        if let Ok(ControlFlow::Continue(())) = result
            && let ControlFlow::Break(b) =
                callback(ScanEvent::Finished(root_path))
        {
            return Ok(ControlFlow::Break(b));
        }

        result
    }
}
