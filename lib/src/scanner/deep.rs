/*! Scanner for deep scanning data and extracted container files.

This scanner is designed for recursive scanning scenarios where the data to be
scanned contains archive or container files (e.g., ZIP archives). It unpacks
supported container formats and traverses the extracted file hierarchy in
breadth-first search order.
*/

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::Duration;

use protobuf::MessageDyn;

use crate::errors::VariableError;
use crate::modules::{ScannedDataWithPath, registered_modules};
use crate::scanner::{ScanOptions, ScannedData};
use crate::{Rules, ScanError, ScanResults, Variable};

/// Extracts files from archive and container formats recursively.
///
/// Automatically unpacks container files (e.g., ZIP archives) using YARA modules
/// that support extraction, and traverses the extracted file tree in  up to a
/// maximum extraction depth.
///
/// The `callback` function is invoked for the main input buffer and for every
/// file extracted from it. The function receives two arguments:
///
/// 1. The file path within the container. For the main input buffer (or file),
///    this path is empty (`Path::new("")`).
///
/// 2. The extracted data as a byte slice (`&[u8]`).
///
/// # Flow Control
///
/// The callback closure returns [`std::ops::ControlFlow<B>`], giving explicit
/// control over extraction traversal and early termination:
///
/// - Returning [`std::ops::ControlFlow::Continue(())`] instructs the extractor
///   to proceed normally to the next file in the queue.
///
/// - Returning [`std::ops::ControlFlow::Break(b)`] immediately halts further
///   extraction recursion, returning `Ok(ControlFlow::Break(b))`.
#[derive(Debug, Clone)]
pub struct Extractor {
    max_depth: usize,
}

impl Default for Extractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor {
    /// Creates a new extractor.
    pub fn new() -> Self {
        Self { max_depth: 1 }
    }

    /// Sets the maximum container extraction depth.
    ///
    /// If set to 0 extracts nothing (only yields the main input buffer).
    /// If set to 1 extracts immediate inner files.
    ///
    /// Default value is 1.
    pub fn max_depth(&mut self, depth: usize) -> &mut Self {
        self.max_depth = depth;
        self
    }

    /// Extracts files from in-memory data recursively, executing `callback`
    /// for each buffer.
    pub fn extract<F, B>(&self, data: &[u8], mut callback: F) -> ControlFlow<B>
    where
        F: FnMut(&Path, &[u8]) -> ControlFlow<B>,
    {
        let mut queue = VecDeque::from([(
            ScannedDataWithPath {
                path: PathBuf::new(),
                data: ScannedData::Slice(data),
            },
            0,
        )]);

        while let Some((parent, depth)) = queue.pop_front() {
            if depth < self.max_depth {
                for extract_fn in registered_modules()
                    .filter_map(|module| module.extract_fn())
                {
                    let mut children = match extract_fn(&parent.data) {
                        Ok(children) => children,
                        _ => continue,
                    };

                    if !parent.path.as_os_str().is_empty() {
                        for child in children.iter_mut() {
                            child.path = parent.path.join(&child.path)
                        }
                    }

                    queue.extend(
                        children.into_iter().map(|child| (child, depth + 1)),
                    );
                }
            }

            if let ControlFlow::Break(b) =
                callback(&parent.path, parent.data.as_ref())
            {
                return ControlFlow::Break(b);
            }
        }

        ControlFlow::Continue(())
    }
}

/// Scans data and container contents recursively.
///
/// This scanner is designed for recursive scanning scenarios where the input
/// data contains archive or container formats (e.g., ZIP archives). Unlike the
/// standard [`crate::Scanner`], `Scanner` unpacks container files automatically
/// and traverses the extracted file tree in breadth-first search (BFS) order up
/// to a maximum extraction depth.
///
/// The `callback` function is invoked for the main data buffer and for every
/// file extracted from it. The function receives two arguments:
///
/// 1. The file path within the container. For the main data passed in `data`,
///    this path is empty (`Path::new("")`).
///
/// 2. The [`ScanResults`] corresponding to that file or data buffer.
///
/// # Flow Control
///
/// The callback closure returns [`std::ops::ControlFlow<B>`], giving explicit
/// control over scan traversal and early termination:
///
/// - Returning [`std::ops::ControlFlow::Continue(())`] instructs the scanner
///   to proceed normally to the next file in the queue.
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
/// let _ = scanner.scan(b"dummy haystack", |path, results| {
///     assert_eq!(results.matching_rules().count(), 1);
///     ControlFlow::<()>::Continue(())
/// });
pub struct Scanner<'r> {
    inner: crate::Scanner<'r>,
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
    /// executing `callback` for each buffer.
    pub fn scan<F, B>(
        &mut self,
        data: &[u8],
        callback: F,
    ) -> Result<ControlFlow<B>, ScanError>
    where
        F: FnMut(&Path, &ScanResults) -> ControlFlow<B>,
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
        F: FnMut(&Path, &ScanResults) -> ControlFlow<B>,
    {
        self.scan_internal(data, Some(&options), callback)
    }

    /// Scans a file recursively, unpacking container files and
    /// executing `callback` for each buffer.
    pub fn scan_file<P, F, B>(
        &mut self,
        target: P,
        callback: F,
    ) -> Result<ControlFlow<B>, ScanError>
    where
        P: AsRef<Path>,
        F: FnMut(&Path, &ScanResults) -> ControlFlow<B>,
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
        F: FnMut(&Path, &ScanResults) -> ControlFlow<B>,
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
        F: FnMut(&Path, &ScanResults) -> ControlFlow<B>,
    {
        self.inner.scan_context_mut().reset(false);

        let mut result = Ok(ControlFlow::Continue(()));

        let _ = self.extractor.extract(data, |path, bytes| {
            if self.inner.scan_context().timeout_expired() {
                result = Err(ScanError::Timeout);
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

            match callback(path, &scan_results) {
                ControlFlow::Continue(()) => ControlFlow::Continue(()),
                ControlFlow::Break(b) => {
                    result = Ok(ControlFlow::Break(b));
                    ControlFlow::Break(())
                }
            }
        });

        result
    }
}
