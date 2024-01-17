/*! This module implements the YARA scanner.

The scanner takes the rules produces by the compiler and scans data with them.
*/

use std::cell::RefCell;
use std::collections::hash_map;
use std::io::Read;
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::ptr::{null, NonNull};
use std::rc::Rc;
use std::slice::Iter;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::Duration;
use std::{cmp, fs, thread};

use bitvec::prelude::*;
use fmmap::{MmapFile, MmapFileExt};
use indexmap::IndexMap;
use protobuf::MessageDyn;
use rustc_hash::FxHashMap;
use thiserror::Error;
use wasmtime::{
    AsContext, AsContextMut, Global, GlobalType, MemoryType, Mutability,
    Store, TypedFunc, Val, ValType,
};

use crate::compiler::{IdentId, PatternId, RuleId, RuleInfo, Rules};
use crate::modules::{Module, BUILTIN_MODULES};
use crate::types::{Struct, TypeValue};
use crate::variables::VariableError;
use crate::wasm::{ENGINE, MATCHING_RULES_BITMAP_BASE};
use crate::{modules, wasm, Variable};

pub(crate) use crate::scanner::context::*;

mod context;
mod matches;

#[cfg(test)]
mod tests;

/// Error returned by [`Scanner::scan`] and [`Scanner::scan_file`].
#[derive(Error, Debug)]
pub enum ScanError {
    /// The scan was aborted after the timeout period.
    #[error("timeout")]
    Timeout,
    /// Could not open the scanned file.
    #[error("can not open `{path}`: {source}")]
    OpenError { path: PathBuf, source: std::io::Error },
    /// Could not map the scanned file into memory.
    #[error("can not map `{path}`: {source}")]
    MapError { path: PathBuf, source: fmmap::error::Error },
}

/// Global counter that gets incremented every 1 second by a dedicated thread.
///
/// This counter is used for determining the when a scan operation has timed
/// out.
static HEARTBEAT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Used for spawning the thread that increments `HEARTBEAT_COUNTER`.
static INIT_HEARTBEAT: Once = Once::new();

pub enum ScannedData<'a> {
    Slice(&'a [u8]),
    Vec(Vec<u8>),
    Mmap(MmapFile),
}

impl<'a> AsRef<[u8]> for ScannedData<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            ScannedData::Slice(s) => s,
            ScannedData::Vec(v) => v.as_ref(),
            ScannedData::Mmap(m) => m.as_slice(),
        }
    }
}

/// Scans data with already compiled YARA rules.
///
/// The scanner receives a set of compiled [`Rules`] and scans data with those
/// rules. The same scanner can be used for scanning multiple files or
/// in-memory data sequentially, but you need multiple scanners for scanning in
/// parallel.
pub struct Scanner<'r> {
    wasm_store: Pin<Box<Store<ScanContext<'r>>>>,
    wasm_main_func: TypedFunc<(), i32>,
    filesize: Global,
    timeout: Option<Duration>,
}

impl<'r> Scanner<'r> {
    const DEFAULT_MAX_MATCHES_PER_PATTERN: usize = 1_000_000;
    const DEFAULT_SCAN_TIMEOUT: u64 = 315_360_000;

    /// Creates a new scanner.
    pub fn new(rules: &'r Rules) -> Self {
        let num_rules = rules.rules().len() as u32;
        let num_patterns = rules.num_patterns() as u32;

        // The ScanContext structure belongs to the WASM store, but at the same
        // time it must have a reference to the store because it is required
        // for accessing the WASM memory from code that only has a reference
        // to ScanContext. This kind of circular data structures are not
        // natural to Rust, and they can be achieved either by using unsafe
        // pointers, or by using Rc::Weak. In this case we are storing a
        // pointer to the store in ScanContext. The store is put into a
        // pinned box in order to make sure that it doesn't move from
        // its original memory address and the pointer remains valid.
        let mut wasm_store = Box::pin(Store::new(
            &crate::wasm::ENGINE,
            ScanContext {
                wasm_store: NonNull::dangling(),
                runtime_objects: IndexMap::new(),
                compiled_rules: rules,
                console_log: None,
                current_struct: None,
                root_struct: rules.globals().make_root(),
                scanned_data: null(),
                scanned_data_len: 0,
                private_matching_rules: Vec::new(),
                non_private_matching_rules: Vec::new(),
                global_matching_rules: FxHashMap::default(),
                main_memory: None,
                module_outputs: FxHashMap::default(),
                pattern_matches: FxHashMap::default(),
                unconfirmed_matches: FxHashMap::default(),
                deadline: 0,
                limit_reached: BitVec::repeat(false, num_patterns as usize),
                max_matches_per_pattern: Self::DEFAULT_MAX_MATCHES_PER_PATTERN,
                regexp_cache: RefCell::new(FxHashMap::default()),
                #[cfg(feature = "rules-profiling")]
                time_spent_in_pattern: FxHashMap::default(),
            },
        ));

        // Initialize the ScanContext.wasm_store pointer that was initially
        // dangling.
        wasm_store.data_mut().wasm_store =
            NonNull::from(wasm_store.as_ref().deref());

        // Global variable that will hold the value for `filesize`. This is
        // initialized to 0 because the file size is not known until some
        // data is scanned.
        let filesize = Global::new(
            wasm_store.as_context_mut(),
            GlobalType::new(ValType::I64, Mutability::Var),
            Val::I64(0),
        )
        .unwrap();

        // Global variable that is set to `true` when the Aho-Corasick pattern
        // search phase has been executed.
        let pattern_search_done = Global::new(
            wasm_store.as_context_mut(),
            GlobalType::new(ValType::I32, Mutability::Var),
            Val::I32(0),
        )
        .unwrap();

        // Global variable that is set to `true` when a timeout occurs during
        // the scanning phase.
        let timeout_occurred = Global::new(
            wasm_store.as_context_mut(),
            GlobalType::new(ValType::I32, Mutability::Var),
            Val::I32(0),
        )
        .unwrap();

        // Compute the base offset for the bitmap that contains matching
        // information for patterns. This bitmap has 1 bit per pattern,
        // the N-th bit is set if pattern with PatternId = N matched. The
        // bitmap starts right after the bitmap that contains matching
        // information for rules.
        //
        // TODO: `u32::div_ceil` was stabilized in Rust 1.73. Once we bump
        // the MSRV to 1.73 we can stop using `num`.
        // https://doc.rust-lang.org/std/primitive.u32.html#method.div_ceil
        let matching_patterns_bitmap_base = MATCHING_RULES_BITMAP_BASE as u32
            + num::Integer::div_ceil(&num_rules, &8);

        // Compute the required memory size in 64KB pages.
        let mem_size = num::Integer::div_ceil(
            &(matching_patterns_bitmap_base
                + num::Integer::div_ceil(&num_patterns, &8)),
            &65536,
        );

        let matching_patterns_bitmap_base = Global::new(
            wasm_store.as_context_mut(),
            GlobalType::new(ValType::I32, Mutability::Const),
            Val::I32(matching_patterns_bitmap_base as i32),
        )
        .unwrap();

        // Create module's main memory.
        let main_memory = wasmtime::Memory::new(
            wasm_store.as_context_mut(),
            MemoryType::new(mem_size, None),
        )
        .unwrap();

        // Instantiate the module. This takes the wasm code provided by the
        // `wasm_mod` function and links its imported functions with the
        // implementations that YARA provides.
        let wasm_instance = wasm::new_linker()
            .define(wasm_store.as_context(), "yara_x", "filesize", filesize)
            .unwrap()
            .define(
                wasm_store.as_context(),
                "yara_x",
                "pattern_search_done",
                pattern_search_done,
            )
            .unwrap()
            .define(
                wasm_store.as_context(),
                "yara_x",
                "timeout_occurred",
                timeout_occurred,
            )
            .unwrap()
            .define(
                wasm_store.as_context(),
                "yara_x",
                "matching_patterns_bitmap_base",
                matching_patterns_bitmap_base,
            )
            .unwrap()
            .define(
                wasm_store.as_context(),
                "yara_x",
                "main_memory",
                main_memory,
            )
            .unwrap()
            .instantiate(wasm_store.as_context_mut(), rules.wasm_mod())
            .unwrap();

        // Obtain a reference to the "main" function exported by the module.
        let wasm_main_func = wasm_instance
            .get_typed_func::<(), i32>(wasm_store.as_context_mut(), "main")
            .unwrap();

        wasm_store.data_mut().main_memory = Some(main_memory);

        Self { wasm_store, wasm_main_func, filesize, timeout: None }
    }

    /// Sets a timeout for scan operations.
    ///
    /// The scan functions will return an [ScanError::Timeout] once the
    /// provided timeout duration has elapsed. It's important to note that the
    /// timeout might not be entirely precise, the scanner will make every
    /// effort to stop promptly after the designated timeout duration. However,
    /// in some cases, particularly with rules containing only a few patterns,
    /// the scanner could potentially continue running for a longer period than
    /// the specified timeout.
    pub fn timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the maximum number of matches per pattern.
    ///
    /// When some pattern reaches the maximum number of patterns it won't
    /// produce more matches.
    pub fn max_matches_per_pattern(&mut self, n: usize) -> &mut Self {
        self.wasm_store.data_mut().max_matches_per_pattern = n;
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
        self.wasm_store.data_mut().console_log = Some(Box::new(callback));
        self
    }

    /// Scans a file.
    pub fn scan_file<'a, P>(
        &'a mut self,
        path: P,
    ) -> Result<ScanResults<'a, 'r>, ScanError>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();

        let mut file = fs::File::open(path).map_err(|err| {
            ScanError::OpenError { path: path.to_path_buf(), source: err }
        })?;

        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        let mut buffered_file;
        let mapped_file;

        // For files smaller than ~500MB reading the whole file is faster than
        // using a memory-mapped file.
        let data = if size < 500_000_000 {
            buffered_file = Vec::with_capacity(size as usize);
            file.read_to_end(&mut buffered_file).map_err(|err| {
                ScanError::OpenError { path: path.to_path_buf(), source: err }
            })?;
            ScannedData::Vec(buffered_file)
        } else {
            mapped_file = MmapFile::open(path).map_err(|err| {
                ScanError::MapError { path: path.to_path_buf(), source: err }
            })?;
            ScannedData::Mmap(mapped_file)
        };

        self.scan_impl(data)
    }

    /// Scans in-memory data.
    pub fn scan<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        self.scan_impl(ScannedData::Slice(data))
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
        let ctx = self.wasm_store.data_mut();

        if let Some(field) = ctx.root_struct.field_by_name_mut(ident) {
            let variable: Variable = value.try_into()?;
            let type_value: TypeValue = variable.into();
            // The new type must match the the old one.
            if type_value.eq_type(&field.type_value) {
                field.type_value = type_value;
            } else {
                return Err(VariableError::InvalidType {
                    variable: ident.to_string(),
                    expected_type: field.type_value.ty().to_string(),
                    actual_type: type_value.ty().to_string(),
                });
            }
        } else {
            return Err(VariableError::Undefined(ident.to_string()));
        }

        Ok(self)
    }
}

impl<'r> Scanner<'r> {
    fn scan_impl<'a>(
        &'a mut self,
        data: ScannedData<'a>,
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        // Clear information about matches found in a previous scan, if any.
        self.clear_matches();

        // Timeout in seconds. This is either the value provided by the user or
        // 315.360.000 which is the number of seconds in a year. Using u64::MAX
        // doesn't work because this value is added to the current epoch, and
        // will cause an overflow. We need an integer large enough, but that
        // has room before the u64 limit is reached. For this same reason if
        // the user specifies a value larger than 315.360.000 we limit it to
        // 315.360.000 anyways. One year should be enough, I hope you don't
        // plan to run a YARA scan that takes longer.
        let timeout_secs =
            self.timeout.map_or(Self::DEFAULT_SCAN_TIMEOUT, |t| {
                cmp::min(
                    t.as_secs_f32().ceil() as u64,
                    Self::DEFAULT_SCAN_TIMEOUT,
                )
            });

        // Sets the deadline for the WASM store. The WASM main function will
        // abort if the deadline is reached while the function is being
        // executed.
        self.wasm_store.set_epoch_deadline(timeout_secs);
        self.wasm_store
            .epoch_deadline_callback(|_| Err(ScanError::Timeout.into()));

        // If the user specified some timeout, start the heartbeat thread, if
        // not previously started. The heartbeat thread increments the WASM
        // engine epoch and HEARTBEAT_COUNTER every second. There's a single
        // instance of this thread, independently of the number of concurrent
        // scans.
        if self.timeout.is_some() {
            INIT_HEARTBEAT.call_once(|| {
                thread::spawn(|| loop {
                    loop {
                        thread::sleep(Duration::from_secs(1));
                        ENGINE.increment_epoch();
                        HEARTBEAT_COUNTER
                            .fetch_update(
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                                |x| Some(x + 1),
                            )
                            .unwrap();
                    }
                });
            });
        }

        // Set the global variable `filesize` to the size of the scanned data.
        self.filesize
            .set(
                self.wasm_store.as_context_mut(),
                Val::I64(data.as_ref().len() as i64),
            )
            .unwrap();

        let ctx = self.wasm_store.data_mut();

        ctx.deadline =
            HEARTBEAT_COUNTER.load(Ordering::Relaxed) + timeout_secs;
        ctx.scanned_data = data.as_ref().as_ptr();
        ctx.scanned_data_len = data.as_ref().len();

        // Free all runtime objects left around by previous scans.
        ctx.runtime_objects.clear();

        for module_name in ctx.compiled_rules.imports() {
            // Lookup the module in the list of built-in modules.
            let module = modules::BUILTIN_MODULES.get(module_name).unwrap();

            // Call the module's main function, if any. This function returns
            // a data structure serialized as a protocol buffer. The format of
            // the data is specified by the .proto file associated to the
            // module.
            let module_output = if let Some(main_fn) = module.main_fn {
                main_fn(data.as_ref())
            } else {
                // Implement the case in which the module doesn't have a main
                // function and the serialized data should be provided by the
                // user.
                todo!()
            };

            // Make sure that the module is returning a protobuf message of the
            // expected type.
            debug_assert_eq!(
                module_output.descriptor_dyn().full_name(),
                module.root_struct_descriptor.full_name(),
                "main function of module `{}` must return `{}`, but returned `{}`",
                module_name,
                module.root_struct_descriptor.full_name(),
                module_output.descriptor_dyn().full_name(),
            );

            // Make sure that the module is returning a protobuf message where
            // all required fields are initialized. This only applies to
            // proto2, proto3 doesn't have "required" fields, all
            // fields are optional.
            debug_assert!(
                module_output.is_initialized_dyn(),
                "module `{}` returned a protobuf `{}` where some required fields are not initialized ",
                module_name,
                module.root_struct_descriptor.full_name()
            );

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

            let module_struct = Struct::from_proto_msg(
                module_output.deref(),
                generate_fields_for_enums,
            );

            // Update the module's output in stored in ScanContext.
            ctx.module_outputs.insert(
                module_output.descriptor_dyn().full_name().to_string(),
                module_output,
            );

            // The data structure obtained from the module is added to the
            // root structure. Any data from previous scans will be replaced
            // with the new data structure.
            ctx.root_struct.add_field(
                module_name,
                TypeValue::Struct(Rc::new(module_struct)),
            );
        }

        // Invoke the main function, which evaluates the rules' conditions. It
        // calls ScanContext::search_for_patterns (which does the Aho-Corasick
        // scanning) only if necessary.
        //
        // This will return Err(ScanError::Timeout), when the scan timeout is
        // reached while WASM code is being executed. If the timeout occurs
        // while ScanContext::search_for_patterns is being executed, the result
        // will be Ok(1). If the scan completes successfully the result is
        // Ok(0).`
        let func_result =
            self.wasm_main_func.call(self.wasm_store.as_context_mut(), ());

        let ctx = self.wasm_store.data_mut();

        // Set pointer to data back to nil. This means that accessing
        // `scanned_data` from within `ScanResults` is not possible.
        ctx.scanned_data = null();
        ctx.scanned_data_len = 0;

        // Clear the value of `current_struct` as it may contain a reference
        // to some struct.
        ctx.current_struct = None;

        // Move all the in `global_matching_rules` to `private_matching_rules`
        // and `non_private_matching_rules`, leaving `global_matching_rules`
        // empty.
        for rules in ctx.global_matching_rules.values_mut() {
            for rule_id in rules.drain(0..) {
                if ctx.compiled_rules.get(rule_id).is_private {
                    ctx.private_matching_rules.push(rule_id);
                } else {
                    ctx.non_private_matching_rules.push(rule_id);
                }
            }
        }

        match func_result {
            Ok(0) => Ok(ScanResults::new(self.wasm_store.data(), data)),
            Ok(1) => Err(ScanError::Timeout),
            Ok(_) => unreachable!(),
            Err(err) if err.is::<ScanError>() => {
                Err(err.downcast::<ScanError>().unwrap())
            }
            Err(err) => panic!(
                "unexpected error while executing WASM main function: {}",
                err
            ),
        }
    }

    // Clear information about previous matches.
    fn clear_matches(&mut self) {
        let ctx = self.wasm_store.data_mut();
        let num_rules = ctx.compiled_rules.rules().len();
        let num_patterns = ctx.compiled_rules.num_patterns();

        // Clear the unconfirmed matches.
        for (_, matches) in ctx.unconfirmed_matches.iter_mut() {
            matches.clear()
        }

        // If some pattern or rule matched, clear the matches. Notice that a
        // rule may match without any pattern being matched, because there
        // there are rules without patterns, or that match if the pattern is
        // not found.
        if !ctx.pattern_matches.is_empty()
            || !ctx.non_private_matching_rules.is_empty()
        {
            // The hash map that tracks the pattern matches is not completely
            // cleared with pattern_matches.clear() because that would cause
            // that all the vectors are deallocated. Instead, each of the
            // vectors are cleared individually, which removes the items
            // while maintaining the vector capacity. This way the vector may
            // be reused in later scans without memory allocations.
            for (_, matches) in ctx.pattern_matches.iter_mut() {
                matches.clear()
            }

            // Clear the list of matching rules.
            ctx.non_private_matching_rules.clear();

            let mem = ctx
                .main_memory
                .unwrap()
                .data_mut(self.wasm_store.as_context_mut());

            // Starting at MATCHING_RULES_BITMAP in main memory there's a
            // bitmap were the N-th bit indicates if the rule with
            // ID = N matched or not, If some rule matched in a
            // previous call the bitmap will contain some
            // bits set to 1 and need to be cleared.
            let base = MATCHING_RULES_BITMAP_BASE as usize;
            let bitmap = BitSlice::<_, Lsb0>::from_slice_mut(
                &mut mem[base..base
                    + (num_rules / 8 + 1)
                    + (num_patterns / 8 + 1)],
            );

            // Set to zero all bits in the bitmap.
            bitmap.fill(false);
        }
    }
}

/// Results of a scan operation.
///
/// Allows iterating over both the matching and non-matching rules.
pub struct ScanResults<'a, 'r> {
    ctx: &'a ScanContext<'r>,
    data: ScannedData<'a>,
}

impl<'a, 'r> ScanResults<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r>, data: ScannedData<'a>) -> Self {
        Self { ctx, data }
    }

    /// Returns an iterator that yields the matching rules in arbitrary order.
    pub fn matching_rules(&'a self) -> MatchingRules<'a, 'r> {
        MatchingRules::new(self.ctx, &self.data)
    }

    /// Returns an iterator that yields the non-matching rules in arbitrary
    /// order.
    pub fn non_matching_rules(&'a self) -> NonMatchingRules<'a, 'r> {
        NonMatchingRules::new(self.ctx, &self.data)
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
pub struct MatchingRules<'a, 'r> {
    ctx: &'a ScanContext<'r>,
    data: &'a ScannedData<'a>,
    iterator: Iter<'a, RuleId>,
}

impl<'a, 'r> MatchingRules<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r>, data: &'a ScannedData<'a>) -> Self {
        Self { ctx, data, iterator: ctx.non_private_matching_rules.iter() }
    }
}

impl<'a, 'r> Iterator for MatchingRules<'a, 'r> {
    type Item = Rule<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = *self.iterator.next()?;
        let rules = self.ctx.compiled_rules;
        let rule_info = rules.get(rule_id);
        Some(Rule { rule_info, rules, ctx: self.ctx, data: self.data })
    }
}

impl<'a, 'r> ExactSizeIterator for MatchingRules<'a, 'r> {
    #[inline]
    fn len(&self) -> usize {
        self.iterator.len()
    }
}

/// Iterator that yields the rules that didn't match during a scan.
pub struct NonMatchingRules<'a, 'r> {
    ctx: &'a ScanContext<'r>,
    data: &'a ScannedData<'a>,
    iterator: bitvec::slice::IterZeros<'a, u8, Lsb0>,
    len: usize,
}

impl<'a, 'r> NonMatchingRules<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r>, data: &'a ScannedData<'a>) -> Self {
        let num_rules = ctx.compiled_rules.rules().len();
        let main_memory =
            ctx.main_memory.unwrap().data(unsafe { ctx.wasm_store.as_ref() });

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
            data,
            iterator: matching_rules_bitmap.iter_zeros(),
            // The number of non-matching rules is the total number of rules
            // minus the number of matching rules, both private and
            // non-private.
            len: ctx.compiled_rules.rules().len()
                - ctx.private_matching_rules.len()
                - ctx.non_private_matching_rules.len(),
        }
    }
}

impl<'a, 'r> Iterator for NonMatchingRules<'a, 'r> {
    type Item = Rule<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.len = self.len.saturating_sub(1);
            let rule_id = RuleId::from(self.iterator.next()?);
            let rules = self.ctx.compiled_rules;
            let rule_info = rules.get(rule_id);
            // Private rules are not returned, if the current rule is private
            // keep in the loop and try with the next one.
            if !rule_info.is_private {
                return Some(Rule {
                    rule_info,
                    rules,
                    ctx: self.ctx,
                    data: self.data,
                });
            }
        }
    }
}

impl<'a, 'r> ExactSizeIterator for NonMatchingRules<'a, 'r> {
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

/// Iterator that returns the outputs produced by YARA modules.
pub struct ModuleOutputs<'a, 'r> {
    ctx: &'a ScanContext<'r>,
    iterator: hash_map::Iter<'a, &'a str, Module>,
}

impl<'a, 'r> ModuleOutputs<'a, 'r> {
    fn new(ctx: &'a ScanContext<'r>) -> Self {
        Self { ctx, iterator: BUILTIN_MODULES.iter() }
    }
}

impl<'a, 'r> Iterator for ModuleOutputs<'a, 'r> {
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

/// A structure that describes a rule.
pub struct Rule<'a, 'r> {
    ctx: &'a ScanContext<'r>,
    data: &'a ScannedData<'a>,
    pub(crate) rules: &'r Rules,
    pub(crate) rule_info: &'r RuleInfo,
}

impl<'a, 'r> Rule<'a, 'r> {
    /// Returns the rule's name.
    pub fn name(&self) -> &'r str {
        self.rules.ident_pool().get(self.rule_info.ident_id).unwrap()
    }

    /// Returns the rule's namespace.
    pub fn namespace(&self) -> &'r str {
        self.rules.ident_pool().get(self.rule_info.namespace_ident_id).unwrap()
    }

    /// Returns the patterns defined by this rule.
    pub fn patterns(&self) -> Patterns<'a, 'r> {
        Patterns {
            ctx: self.ctx,
            data: self.data,
            iterator: self.rule_info.patterns.iter(),
        }
    }
}

/// An iterator that returns the patterns defined by a rule.
pub struct Patterns<'a, 'r> {
    ctx: &'a ScanContext<'r>,
    data: &'a ScannedData<'a>,
    iterator: Iter<'a, (IdentId, PatternId)>,
}

impl<'a, 'r> Iterator for Patterns<'a, 'r> {
    type Item = Pattern<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let (ident_id, pattern_id) = self.iterator.next()?;
        Some(Pattern {
            ctx: self.ctx,
            data: self.data,
            pattern_id: *pattern_id,
            ident_id: *ident_id,
        })
    }
}

/// Represents a pattern defined by a rule.
pub struct Pattern<'a, 'r> {
    ctx: &'a ScanContext<'r>,
    data: &'a ScannedData<'a>,
    pattern_id: PatternId,
    ident_id: IdentId,
}

impl<'a, 'r> Pattern<'a, 'r> {
    /// Returns the pattern's identifier (e.g: $a, $b).
    pub fn identifier(&self) -> &'r str {
        self.ctx.compiled_rules.ident_pool().get(self.ident_id).unwrap()
    }

    /// Returns the matches found for this pattern.
    pub fn matches(&self) -> Matches<'a> {
        Matches {
            data: self.data,
            iterator: self
                .ctx
                .pattern_matches
                .get(&self.pattern_id)
                .map(|match_list| match_list.iter()),
        }
    }
}

/// Iterator that returns the matches for a pattern.
pub struct Matches<'a> {
    data: &'a ScannedData<'a>,
    iterator: Option<Iter<'a, matches::Match>>,
}

impl<'a> Iterator for Matches<'a> {
    type Item = Match<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let iter = self.iterator.as_mut()?;
        Some(Match { inner: iter.next()?, data: self.data })
    }
}

/// Represents a match.
pub struct Match<'a> {
    inner: &'a matches::Match,
    data: &'a ScannedData<'a>,
}

impl<'a> Match<'a> {
    /// Range within the original data where the match occurred.
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.inner.range.clone()
    }

    /// Slice containing the data that matched.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data.as_ref().get(self.inner.range.clone()).unwrap()
    }

    /// XOR key used for decrypting the data if the pattern had the `xor`
    /// modifier, or `None` if otherwise.
    #[inline]
    pub fn xor_key(&self) -> Option<u8> {
        self.inner.xor_key
    }
}
