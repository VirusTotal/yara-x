/*! This module implements the YARA scanner.

The scanner takes the rules produces by the compiler and scans data with them.
*/
use std::collections::{hash_map, BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::fs;
use std::io::Read;
use std::mem::transmute;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::slice::Iter;
use std::sync::atomic::AtomicU64;
use std::sync::Once;
use std::time::Duration;

use bitvec::prelude::*;
use memmap2::{Mmap, MmapOptions};
use protobuf::{CodedInputStream, MessageDyn};
use thiserror::Error;
use wasmtime::Store;

use crate::compiler::{RuleId, Rules};
use crate::models::Rule;
use crate::modules::{Module, ModuleError, BUILTIN_MODULES};
use crate::scanner::context::create_wasm_store_and_ctx;
use crate::types::{Struct, TypeValue};
use crate::variables::VariableError;
use crate::wasm::MATCHING_RULES_BITMAP_BASE;
use crate::{modules, Variable};

pub(crate) use crate::scanner::context::RuntimeObject;
pub(crate) use crate::scanner::context::RuntimeObjectHandle;
pub(crate) use crate::scanner::context::ScanContext;
pub(crate) use crate::scanner::context::ScanState;
pub(crate) use crate::scanner::matches::Match;

mod context;
mod matches;

pub mod blocks;

#[cfg(test)]
mod tests;

/// Error returned when a scan operation fails.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ScanError {
    /// The scan was aborted after the timeout period.
    #[error("timeout")]
    Timeout,
    /// Could not open the scanned file.
    #[error("can not open `{path}`: {err}")]
    OpenError {
        /// Path of the file being scanned.
        path: PathBuf,
        /// Error that occurred.
        err: std::io::Error,
    },
    /// Could not map the scanned file into memory.
    #[error("can not map `{path}`: {err}")]
    MapError {
        /// Path of the file being scanned.
        path: PathBuf,
        /// Error that occurred.
        err: std::io::Error,
    },
    /// Could not deserialize the protobuf message for some YARA module.
    #[error("can not deserialize protobuf message for YARA module `{module}`: {err}")]
    ProtoError {
        /// Module name.
        module: String,
        /// Error that occurred.
        err: protobuf::Error,
    },
    /// The module is unknown.
    #[error("unknown module `{module}`")]
    UnknownModule {
        /// Module name.
        module: String,
    },
    /// Some module produced an error when it was invoked.
    #[error("error in module `{module}`: {err}")]
    ModuleError {
        /// Module name.
        module: String,
        /// Error that occurred.
        err: ModuleError,
    },
}

/// Global counter that gets incremented every 1 second by a dedicated thread.
///
/// This counter is used for determining when a scan operation has timed out.
static HEARTBEAT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Used for spawning the thread that increments `HEARTBEAT_COUNTER`.
static INIT_HEARTBEAT: Once = Once::new();

/// Represents the data being scanned.
///
/// The scanned data can be backed by a slice owned by someone else, or a
/// vector or memory-mapped file owned by `ScannedData` itself.
pub enum ScannedData<'d> {
    Slice(&'d [u8]),
    Vec(Vec<u8>),
    Mmap(Mmap),
}

impl AsRef<[u8]> for ScannedData<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            ScannedData::Slice(s) => s,
            ScannedData::Vec(v) => v.as_ref(),
            ScannedData::Mmap(m) => m.as_ref(),
        }
    }
}

impl<'d> TryInto<ScannedData<'d>> for &'d [u8] {
    type Error = ScanError;
    fn try_into(self) -> Result<ScannedData<'d>, Self::Error> {
        Ok(ScannedData::Slice(self))
    }
}

impl<'d, const N: usize> TryInto<ScannedData<'d>> for &'d [u8; N] {
    type Error = ScanError;
    fn try_into(self) -> Result<ScannedData<'d>, Self::Error> {
        Ok(ScannedData::Slice(self))
    }
}

/// Contains information about the time spent on a rule.
#[cfg(feature = "rules-profiling")]
pub struct ProfilingData<'r> {
    /// Rule namespace.
    pub namespace: &'r str,
    /// Rule name.
    pub rule: &'r str,
    /// Time spent executing the rule's condition.
    pub condition_exec_time: Duration,
    /// Time spent matching the rule's patterns.
    pub pattern_matching_time: Duration,
}

/// Optional information for the scan operation.
#[derive(Debug, Default)]
pub struct ScanOptions<'a> {
    module_metadata: HashMap<&'a str, &'a [u8]>,
}

impl<'a> ScanOptions<'a> {
    /// Creates a new instance of `ScanOptions` with no additional information
    /// for the scan operation.
    ///
    /// Use other methods to add additional information.
    pub fn new() -> Self {
        Self { module_metadata: Default::default() }
    }

    /// Adds metadata for a YARA module.
    pub fn set_module_metadata(
        mut self,
        module_name: &'a str,
        metadata: &'a [u8],
    ) -> Self {
        self.module_metadata.insert(module_name, metadata);
        self
    }
}

/// Scans data with already compiled YARA rules.
///
/// The scanner receives a set of compiled [`Rules`] and scans data with those
/// rules. The same scanner can be used for scanning multiple files or
/// in-memory data sequentially, but you need multiple scanners for scanning in
/// parallel.
pub struct Scanner<'r> {
    _rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static, 'static>>>>,
    use_mmap: bool,
}

impl<'r> Scanner<'r> {
    /// Creates a new scanner.
    pub fn new(rules: &'r Rules) -> Self {
        let wasm_store = create_wasm_store_and_ctx(rules);
        Self { _rules: rules, wasm_store, use_mmap: true }
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
        self.scan_context_mut().set_timeout(timeout);
        self
    }

    /// Sets the maximum number of matches per pattern.
    ///
    /// When some pattern reaches the maximum number of patterns it won't
    /// produce more matches.
    pub fn max_matches_per_pattern(&mut self, n: usize) -> &mut Self {
        self.scan_context_mut().pattern_matches.max_matches_per_pattern(n);
        self
    }

    /// Specifies whether [`Scanner::scan_file`] and [`Scanner::scan_file_with_options`]
    /// may use memory-mapped files to read input.
    ///
    /// By default, the scanner uses memory mapping for very large files, as this
    /// is typically faster than copying file contents into memory. However, this
    /// approach has a drawback: if another process truncates the file during
    /// scanning, a `SIGBUS` signal may occur.
    ///
    /// Setting this option disables memory mapping and forces the scanner to
    /// always read files into an in-memory buffer instead. This method is slower,
    /// but safer.
    pub fn use_mmap(&mut self, yes: bool) -> &mut Self {
        self.use_mmap = yes;
        self
    }

    /// Sets a callback that is invoked every time a YARA rule calls the
    /// `console` module.
    ///
    /// The `callback` function is invoked with a string representing the
    /// message being logged. The function can print the message to stdout,
    /// append it to a file, etc. If no callback is set these messages are
    /// ignored.
    pub fn console_log<F>(&mut self, callback: F) -> &mut Self
    where
        F: FnMut(String) + 'r,
    {
        self.scan_context_mut().console_log = Some(Box::new(callback));
        self
    }

    /// Scans in-memory data.
    pub fn scan<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        self.scan_impl(data.try_into()?, None)
    }

    /// Scans a file.
    pub fn scan_file<'a, P>(
        &'a mut self,
        target: P,
    ) -> Result<ScanResults<'a, 'r>, ScanError>
    where
        P: AsRef<Path>,
    {
        self.scan_impl(self.load_file(target.as_ref())?, None)
    }

    /// Like [`Scanner::scan`], but allows to specify additional scan options.
    pub fn scan_with_options<'a, 'opts>(
        &'a mut self,
        data: &'a [u8],
        options: ScanOptions<'opts>,
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        self.scan_impl(ScannedData::Slice(data), Some(options))
    }

    /// Like [`Scanner::scan_file`], but allows to specify additional scan
    /// options.
    pub fn scan_file_with_options<'opts, P>(
        &mut self,
        target: P,
        options: ScanOptions<'opts>,
    ) -> Result<ScanResults<'_, 'r>, ScanError>
    where
        P: AsRef<Path>,
    {
        self.scan_impl(self.load_file(target.as_ref())?, Some(options))
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
        self.scan_context_mut().set_global(ident, value)?;
        Ok(self)
    }

    /// Sets the output data for a YARA module.
    ///
    /// Each YARA module generates an output consisting of a data structure that
    /// contains information about the scanned file. This data structure is
    /// represented by a Protocol Buffer message. Typically, you won't need to
    /// provide this data yourself, as the YARA module automatically generates
    /// different outputs for each file it scans.
    ///
    /// However, there are two scenarios in which you may want to provide the
    /// output for a module yourself:
    ///
    /// 1) When the module does not produce any output on its own.
    /// 2) When you already know the output of the module for the upcoming file
    ///    to be scanned, and you prefer to reuse this data instead of generating
    ///    it again.
    ///
    /// Case 1) applies to certain modules lacking a main function, thus
    /// incapable of producing any output on their own. For such modules, you
    /// must set the output before scanning the associated data. Since the
    /// module's output typically varies with each scanned file, you need to
    /// call [`Scanner::set_module_output`] prior to each invocation of
    /// [`Scanner::scan`]. Once [`Scanner::scan`] is executed, the module's
    /// output is consumed and will be empty unless set again before the
    /// subsequent call.
    ///
    /// Case 2) applies when you have previously stored the module's output for
    /// certain scanned data. In such cases, when rescanning the data, you can
    /// utilize this function to supply the module's output, thereby preventing
    /// redundant computation by the module. This optimization enhances
    /// performance by eliminating the need for the module to reparse the
    /// scanned data.
    ///
    /// <br>
    ///
    /// The `data` argument must be a Protocol Buffer message corresponding
    /// to any of the existing YARA modules.
    pub fn set_module_output(
        &mut self,
        data: Box<dyn MessageDyn>,
    ) -> Result<&mut Self, ScanError> {
        let descriptor = data.descriptor_dyn();
        let full_name = descriptor.full_name();

        // Check if the protobuf message passed to this function corresponds
        // with any of the existing modules.
        if !BUILTIN_MODULES
            .iter()
            .any(|m| m.1.root_struct_descriptor.full_name() == full_name)
        {
            return Err(ScanError::UnknownModule {
                module: full_name.to_string(),
            });
        }

        self.scan_context_mut()
            .user_provided_module_outputs
            .insert(full_name.to_string(), data);

        Ok(self)
    }

    /// Similar to [`Scanner::set_module_output`], but receives a module name
    /// and the protobuf message as raw data.
    ///
    /// `name` can be either the YARA module name (i.e: "pe", "elf", "dotnet",
    /// etc.) or the fully-qualified name for the protobuf message associated
    /// to the module (i.e: "pe.PE", "elf.ELF", "dotnet.Dotnet", etc.).
    pub fn set_module_output_raw(
        &mut self,
        name: &str,
        data: &[u8],
    ) -> Result<&mut Self, ScanError> {
        // Try to find the module by name first, if not found, then try
        // to find a module where the fully-qualified name for its protobuf
        // message matches the `name` arguments.
        let descriptor = if let Some(module) = BUILTIN_MODULES.get(name) {
            Some(&module.root_struct_descriptor)
        } else {
            BUILTIN_MODULES.values().find_map(|module| {
                if module.root_struct_descriptor.full_name() == name {
                    Some(&module.root_struct_descriptor)
                } else {
                    None
                }
            })
        };

        if descriptor.is_none() {
            return Err(ScanError::UnknownModule { module: name.to_string() });
        }

        let mut is = CodedInputStream::from_bytes(data);

        // Default recursion limit is 100, that's not enough for some deeply
        // nested structures like the process tree in the `vt` module.
        is.set_recursion_limit(500);

        self.set_module_output(
            descriptor.unwrap().parse_from(&mut is).map_err(|err| {
                ScanError::ProtoError { module: name.to_string(), err }
            })?,
        )
    }

    /// Returns profiling data for the slowest N rules.
    ///
    /// The profiling data reflects the cumulative execution time of each rule
    /// across all scanned files. This information is useful for identifying
    /// performance bottlenecks. To reset the profiling data and start fresh
    /// for subsequent scans, use [`Scanner::clear_profiling_data`].
    #[cfg(feature = "rules-profiling")]
    pub fn slowest_rules(&self, n: usize) -> Vec<ProfilingData<'_>> {
        self.scan_context().slowest_rules(n)
    }

    /// Clears all accumulated profiling data.
    ///
    /// This method resets the profiling data collected during rule execution
    /// across scanned files. Use this to start a new profiling session, ensuring
    /// the results reflect only the data gathered after this method is called.
    #[cfg(feature = "rules-profiling")]
    pub fn clear_profiling_data(&mut self) {
        self.scan_context_mut().clear_profiling_data()
    }
}

impl<'r> Scanner<'r> {
    #[cfg(feature = "rules-profiling")]
    #[inline]
    fn scan_context<'a>(&self) -> &ScanContext<'r, 'a> {
        unsafe {
            transmute::<&ScanContext<'static, 'static>, &ScanContext<'r, '_>>(
                self.wasm_store.data(),
            )
        }
    }
    #[inline]
    fn scan_context_mut<'a>(&mut self) -> &mut ScanContext<'r, 'a> {
        unsafe {
            transmute::<
                &mut ScanContext<'static, 'static>,
                &mut ScanContext<'r, '_>,
            >(self.wasm_store.data_mut())
        }
    }

    fn load_file<'a>(
        &self,
        path: &Path,
    ) -> Result<ScannedData<'a>, ScanError> {
        let mut file = fs::File::open(path).map_err(|err| {
            ScanError::OpenError { path: path.to_path_buf(), err }
        })?;

        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        let mut buffered_file;
        let mapped_file;

        // For files smaller than ~500MB reading the whole file is faster than
        // using a memory-mapped file.
        let data = if self.use_mmap && size > 500_000_000 {
            mapped_file = unsafe {
                MmapOptions::new().map_copy_read_only(&file).map_err(|err| {
                    ScanError::MapError { path: path.to_path_buf(), err }
                })
            }?;
            ScannedData::Mmap(mapped_file)
        } else {
            buffered_file = Vec::with_capacity(size as usize);
            file.read_to_end(&mut buffered_file).map_err(|err| {
                ScanError::OpenError { path: path.to_path_buf(), err }
            })?;
            ScannedData::Vec(buffered_file)
        };

        Ok(data)
    }

    fn scan_impl<'a, 'opts>(
        &'a mut self,
        data: ScannedData<'a>,
        options: Option<ScanOptions<'opts>>,
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        let ctx = self.scan_context_mut();

        // Clear information about matches found in a previous scan, if any.
        ctx.reset();

        // Set the global variable `filesize` to the size of the scanned data.
        ctx.set_filesize(data.as_ref().len() as i64);

        // Indicate that the scanner is currently scanning the given data.
        ctx.scan_state = ScanState::ScanningData(data);

        for module_name in ctx.compiled_rules.imports() {
            // Lookup the module in the list of built-in modules.
            let module = modules::BUILTIN_MODULES
                .get(module_name)
                .unwrap_or_else(|| panic!("module `{module_name}` not found"));

            let root_struct_name = module.root_struct_descriptor.full_name();

            let module_output;
            // If the user already provided some output for the module by
            // calling `Scanner::set_module_output`, use that output. If not,
            // call the module's main function (if the module has a main
            // function) for getting its output.
            if let Some(output) =
                ctx.user_provided_module_outputs.remove(root_struct_name)
            {
                module_output = Some(output);
            } else {
                let meta: Option<&'opts [u8]> =
                    options.as_ref().and_then(|options| {
                        options.module_metadata.get(module_name).copied()
                    });

                if let Some(main_fn) = module.main_fn {
                    module_output = Some(
                        main_fn(ctx.scanned_data().unwrap(), meta).map_err(
                            |err| ScanError::ModuleError {
                                module: module_name.to_string(),
                                err,
                            },
                        )?,
                    );
                } else {
                    module_output = None;
                }
            }

            if let Some(module_output) = &module_output {
                // Make sure that the module is returning a protobuf message of
                // the expected type.
                debug_assert_eq!(
                    module_output.descriptor_dyn().full_name(),
                    module.root_struct_descriptor.full_name(),
                    "main function of module `{}` must return `{}`, but returned `{}`",
                    module_name,
                    module.root_struct_descriptor.full_name(),
                    module_output.descriptor_dyn().full_name(),
                );

                // Make sure that the module is returning a protobuf message
                // where all required fields are initialized. This only applies
                // to proto2, proto3 doesn't have "required" fields, all fields
                // are optional.
                debug_assert!(
                    module_output.is_initialized_dyn(),
                    "module `{}` returned a protobuf `{}` where some required fields are not initialized ",
                    module_name,
                    module.root_struct_descriptor.full_name()
                );
            }

            // When constant folding is enabled we don't need to generate
            // structure fields for enums. This is because during the
            // optimization process symbols like MyEnum.ENUM_ITEM are resolved
            // to their constant values at compile time. In other words, the
            // compiler determines that MyEnum.ENUM_ITEM is equal to some value
            // X, and uses that value in the generated code.
            //
            // However, without constant folding, enums are treated as any
            // other field in a struct, and their values are determined at scan
            // time. For that reason these fields must be generated for enums
            // when constant folding is disabled.
            let generate_fields_for_enums =
                !cfg!(feature = "constant-folding");

            let module_struct = Struct::from_proto_descriptor_and_msg(
                &module.root_struct_descriptor,
                module_output.as_deref(),
                generate_fields_for_enums,
            );

            if let Some(module_output) = module_output {
                ctx.module_outputs
                    .insert(root_struct_name.to_string(), module_output);
            }

            // The data structure obtained from the module is added to the
            // root structure. Any data from previous scans will be replaced
            // with the new data structure.
            ctx.root_struct
                .add_field(module_name, TypeValue::Struct(module_struct));
        }

        // The user provided module outputs are not needed anymore. Let's
        // clear any remaining entry in the hash map (which can happen if
        // the user has set outputs for modules that are not even imported
        // by the rules.
        ctx.user_provided_module_outputs.clear();

        // Clear the flag that indicates that the search phase was done.
        ctx.set_pattern_search_done(false);

        // Evaluate the conditions of every rule, this will call
        // `ScanContext::search_for_patterns` if necessary.
        ctx.eval_conditions()?;

        let data = match ctx.scan_state.take() {
            ScanState::ScanningData(data) => data,
            _ => unreachable!(),
        };

        ctx.scan_state = ScanState::Finished(DataSnippets::SingleBlock(data));

        Ok(ScanResults::new(ctx))
    }
}

/// Helper type that exposes the data matched during a scan operation.
///
/// Matching data can be accessed through the [`Match::data`] method. Normally,
/// this data can be retrieved by slicing directly into the scanned input.
/// However, that requires the original input to remain valid until the scan
/// results are processed. This works fine for a single contiguous block of
/// memory, but is impractical when scanning multiple blocks, since holding
/// onto all of them until the end would consume excessive memory.
///
/// To handle this, two strategies are used:
///
/// - **Single-block scans**: Data is accessed directly from the input slice.
/// - **Multi-block scans**: Matching fragments are copied and retained in a
///   BTreeMap until the results are processed. The keys in the btree are
///   the offsets where the snippets start and the values are vectors with
///   the snippet's data.
///
/// Each strategy corresponds to a variant in this enum.
pub(crate) enum DataSnippets<'d> {
    SingleBlock(ScannedData<'d>),
    MultiBlock(BTreeMap<usize, Vec<u8>>),
}

impl DataSnippets<'_> {
    pub(crate) fn get(&self, range: Range<usize>) -> Option<&[u8]> {
        match self {
            Self::SingleBlock(data) => data.as_ref().get(range),
            Self::MultiBlock(btree) => {
                // Find in the btree the snippet that starts exactly at the
                // offset indicated by range.start, if not found, take the
                // previous one, which may also contain the requested range.
                let (snippet_offset, snippet_data) =
                    btree.range(..=range.start).next_back()?;

                // Calculate the start and end of the slice within the snippet.
                let start = range.start - snippet_offset;
                let end = range.end - snippet_offset;

                // Returns the data, or `None` if `start` and `end` are not
                // within the snippet boundaries.
                snippet_data.get(start..end)
            }
        }
    }
}

/// Results of a scan operation.
///
/// Allows iterating over both the matching and non-matching rules.
pub struct ScanResults<'a, 'r> {
    ctx: &'a ScanContext<'r, 'a>,
}

impl Debug for ScanResults<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScanResults")
    }
}

impl<'a, 'r> ScanResults<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r, 'a>) -> Self {
        Self { ctx }
    }

    /// Returns an iterator that yields the matching rules in arbitrary order.
    pub fn matching_rules(&self) -> MatchingRules<'_, 'r> {
        MatchingRules::new(self.ctx)
    }

    /// Returns an iterator that yields the non-matching rules in arbitrary
    /// order.
    pub fn non_matching_rules(&self) -> NonMatchingRules<'_, 'r> {
        NonMatchingRules::new(self.ctx)
    }

    /// Returns the protobuf produced by a YARA module after processing the
    /// data.
    ///
    /// The result will be `None` if the module doesn't exist or didn't
    /// produce any output.
    pub fn module_output(
        &self,
        module_name: &str,
    ) -> Option<&'a dyn MessageDyn> {
        let module = BUILTIN_MODULES.get(module_name)?;
        let module_output = self
            .ctx
            .module_outputs
            .get(module.root_struct_descriptor.full_name())?
            .as_ref();
        Some(module_output)
    }

    /// Returns an iterator that yields tuples composed of a YARA module name
    /// and the protobuf produced by that module.
    ///
    /// Only returns the modules that produced some output.
    pub fn module_outputs(&self) -> ModuleOutputs<'a, 'r> {
        ModuleOutputs::new(self.ctx)
    }
}

/// Iterator that yields the rules that matched during a scan.
///
/// Private rules are not included by default, use
/// [`MatchingRules::include_private`] for changing this behaviour.
pub struct MatchingRules<'a, 'r> {
    ctx: &'a ScanContext<'r, 'a>,
    iterator: Iter<'a, RuleId>,
    len_non_private: usize,
    len_private: usize,
    include_private: bool,
}

impl<'a, 'r> MatchingRules<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r, 'a>) -> Self {
        Self {
            ctx,
            iterator: ctx.matching_rules.iter(),
            include_private: false,
            len_non_private: ctx.matching_rules.len()
                - ctx.num_matching_private_rules,
            len_private: ctx.num_matching_private_rules,
        }
    }

    /// Specifies whether the iterator should yield private rules.
    ///
    /// This does not reset the iterator to its initial state, the iterator will
    /// continue from its current position.
    pub fn include_private(mut self, yes: bool) -> Self {
        self.include_private = yes;
        self
    }
}

impl<'a, 'r> Iterator for MatchingRules<'a, 'r> {
    type Item = Rule<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let rules = self.ctx.compiled_rules;
        loop {
            let rule_id = *self.iterator.next()?;
            let rule_info = rules.get(rule_id);
            if rule_info.is_private {
                self.len_private -= 1;
            } else {
                self.len_non_private -= 1;
            }
            if self.include_private || !rule_info.is_private {
                return Some(Rule { ctx: Some(self.ctx), rule_info, rules });
            }
        }
    }
}

impl ExactSizeIterator for MatchingRules<'_, '_> {
    #[inline]
    fn len(&self) -> usize {
        if self.include_private {
            self.len_non_private + self.len_private
        } else {
            self.len_non_private
        }
    }
}

/// Iterator that yields the rules that didn't match during a scan.
///
/// Private rules are not included by default, use
/// [`NonMatchingRules::include_private`] for changing this behaviour.
pub struct NonMatchingRules<'a, 'r> {
    ctx: &'a ScanContext<'r, 'a>,
    iterator: bitvec::slice::IterZeros<'a, u8, Lsb0>,
    include_private: bool,
    len_private: usize,
    len_non_private: usize,
}

impl<'a, 'r> NonMatchingRules<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r, 'a>) -> Self {
        let num_rules = ctx.compiled_rules.num_rules();
        let main_memory = ctx
            .wasm_main_memory
            .unwrap()
            .data(unsafe { ctx.wasm_store.as_ref() });

        let base = MATCHING_RULES_BITMAP_BASE as usize;

        // Create a BitSlice that covers the region of main memory containing
        // the bitmap that tells which rules matched and which did not.
        let matching_rules_bitmap = BitSlice::<_, Lsb0>::from_slice(
            &main_memory[base..base + num_rules / 8 + 1],
        );

        // The BitSlice will cover more bits than necessary, for example, if
        // there are 3 rules the BitSlice will have 8 bits because it is
        // created from a u8 slice that has 1 byte. Here we make sure that
        // the BitSlice has exactly as many bits as existing rules.
        let matching_rules_bitmap = &matching_rules_bitmap[0..num_rules];

        Self {
            ctx,
            iterator: matching_rules_bitmap.iter_zeros(),
            include_private: false,
            len_non_private: ctx.compiled_rules.num_rules()
                - ctx.matching_rules.len()
                - ctx.num_non_matching_private_rules,
            len_private: ctx.num_non_matching_private_rules,
        }
    }

    /// Specifies whether the iterator should yield private rules.
    ///
    /// This does not reset the iterator to its initial state, the iterator will
    /// continue from its current position.
    pub fn include_private(mut self, yes: bool) -> Self {
        self.include_private = yes;
        self
    }
}

impl<'a, 'r> Iterator for NonMatchingRules<'a, 'r> {
    type Item = Rule<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let rules = self.ctx.compiled_rules;

        loop {
            let rule_id = RuleId::from(self.iterator.next()?);
            let rule_info = rules.get(rule_id);

            if rule_info.is_private {
                self.len_private -= 1;
            } else {
                self.len_non_private -= 1;
            }

            if self.include_private || !rule_info.is_private {
                return Some(Rule { ctx: Some(self.ctx), rule_info, rules });
            }
        }
    }
}

impl ExactSizeIterator for NonMatchingRules<'_, '_> {
    #[inline]
    fn len(&self) -> usize {
        if self.include_private {
            self.len_non_private + self.len_private
        } else {
            self.len_non_private
        }
    }
}

/// Iterator that returns the outputs produced by YARA modules.
pub struct ModuleOutputs<'a, 'r> {
    ctx: &'a ScanContext<'r, 'a>,
    len: usize,
    iterator: hash_map::Iter<'a, &'a str, Module>,
}

impl<'a, 'r> ModuleOutputs<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r, 'a>) -> Self {
        Self {
            ctx,
            len: ctx.module_outputs.len(),
            iterator: BUILTIN_MODULES.iter(),
        }
    }
}

impl ExactSizeIterator for ModuleOutputs<'_, '_> {
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

impl<'a> Iterator for ModuleOutputs<'a, '_> {
    type Item = (&'a str, &'a dyn MessageDyn);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (name, module) = self.iterator.next()?;
            if let Some(module_output) = self
                .ctx
                .module_outputs
                .get(module.root_struct_descriptor.full_name())
            {
                return Some((*name, module_output.as_ref()));
            }
        }
    }
}

#[cfg(test)]
mod snippet_tests {
    use super::DataSnippets;
    use std::collections::BTreeMap;

    #[test]
    fn snippets() {
        let mut btree_map = BTreeMap::new();

        btree_map.insert(0, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        btree_map.insert(50, vec![51, 52, 53, 54]);

        let snippets = DataSnippets::MultiBlock(btree_map);

        assert_eq!(snippets.get(0..2), Some([1, 2].as_slice()));
        assert_eq!(snippets.get(1..3), Some([2, 3].as_slice()));
        assert_eq!(snippets.get(8..9), Some([9].as_slice()));
        assert_eq!(snippets.get(9..10), None);
        assert_eq!(snippets.get(50..51), Some([51].as_slice()));
        assert_eq!(snippets.get(50..54), Some([51, 52, 53, 54].as_slice()));
        assert_eq!(snippets.get(52..54), Some([53, 54].as_slice()));
        assert_eq!(snippets.get(50..56), None);
    }
}
