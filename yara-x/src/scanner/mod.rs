/*! This module implements the YARA scanner.

The scanner takes the rules produces by the compiler and scans data with them.
*/

use std::ops::Deref;
use std::path::Path;
use std::pin::Pin;
use std::ptr::{null, NonNull};
use std::rc::Rc;
use std::slice::Iter;

use base64::Engine;
use bitvec::prelude::*;
use bstr::ByteSlice;
use fmmap::{MmapFile, MmapFileExt};
use protobuf::{MessageDyn, MessageFull};
use rustc_hash::FxHashMap;
use wasmtime::{
    AsContext, AsContextMut, Global, GlobalType, MemoryType, Mutability,
    Store, TypedFunc, Val, ValType,
};

use crate::compiler::{
    AtomInfo, FullWord, IdentId, LiteralId, PatternId, RuleId, RuleInfo,
    Rules, SubPattern,
};
use crate::scanner::matches::{Match, MatchList};
use crate::string_pool::BStringPool;
use crate::types::{Struct, TypeValue};
use crate::wasm::MATCHING_RULES_BITMAP_BASE;
use crate::{modules, wasm};

pub(crate) mod matches;

#[cfg(test)]
mod tests;

/// Scans data with already compiled YARA rules.
///
/// The scanner receives a set of compiled [`Rules`] and scans data with those
/// rules. The same scanner can be used for scanning multiple files or in-memory
/// data sequentially, but you need multiple scanners for scanning in parallel.
pub struct Scanner<'r> {
    wasm_store: Pin<Box<Store<ScanContext<'r>>>>,
    wasm_main_fn: TypedFunc<(), ()>,
    filesize: Global,
}

impl<'r> Scanner<'r> {
    /// Creates a new scanner.
    pub fn new(rules: &'r Rules) -> Self {
        // The ScanContext structure belongs to the WASM store, but at the same
        // time it must have a reference to the store because it is required
        // for accessing the WASM memory from code that only has a reference
        // to ScanContext. This kind of circular data structures are not
        // natural to Rust, and they can be achieved either by using unsafe
        // pointers, or by using Rc::Weak. In this case we are storing a pointer
        // to the store in ScanContext. The store is put into a pinned box in
        // order to make sure that it doesn't move from its original memory
        // address and the pointer remains valid.
        let mut wasm_store = Box::pin(Store::new(
            &crate::wasm::ENGINE,
            ScanContext {
                wasm_store: NonNull::dangling(),
                compiled_rules: rules,
                string_pool: BStringPool::new(),
                current_struct: None,
                root_struct: Struct::new(),
                scanned_data: null(),
                scanned_data_len: 0,
                rules_matching: Vec::new(),
                main_memory: None,
                vars_stack: Vec::new(),
                module_outputs: FxHashMap::default(),
                pattern_matches: FxHashMap::default(),
                pattern_matched: false,
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

        let num_rules = rules.rules().len() as u32;
        let num_patterns = rules.num_patterns() as u32;

        // Compute the base offset for the bitmap that contains matching
        // information for patterns. This bitmap has 1 bit per pattern,
        // the N-th bit is set if pattern with PatternId = N matched. The
        // bitmap starts right after the bitmap that contains matching
        // information for rules.
        let matching_patterns_bitmap_base =
            wasm::MATCHING_RULES_BITMAP_BASE as u32 + num_rules / 8 + 1;

        // Compute the required memory size in 64KB pages.
        let mem_size =
            matching_patterns_bitmap_base + num_patterns / 8 % 65536 + 1;

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
        // `compiled_wasm_mod` function and links its imported functions with
        // the implementations that YARA provides (see wasm.rs).
        let wasm_instance = wasm::new_linker()
            .define(wasm_store.as_context(), "yara_x", "filesize", filesize)
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
            .instantiate(
                wasm_store.as_context_mut(),
                rules.compiled_wasm_mod(),
            )
            .unwrap();

        // Obtain a reference to the "main" function exported by the module.
        let wasm_main_fn = wasm_instance
            .get_typed_func::<(), ()>(wasm_store.as_context_mut(), "main")
            .unwrap();

        wasm_store.data_mut().main_memory = Some(main_memory);

        Self { wasm_store, wasm_main_fn, filesize }
    }

    /// Scans a file.
    pub fn scan_file<'s, P>(
        &'s mut self,
        path: P,
    ) -> std::io::Result<ScanResults<'s, 'r>>
    where
        P: AsRef<Path>,
    {
        let file = MmapFile::open(path).unwrap();
        Ok(self.scan(file.as_slice()))
    }

    /// Scans in-memory data.
    pub fn scan<'s>(&'s mut self, data: &[u8]) -> ScanResults<'s, 'r> {
        // Clear information about matches found in a previous scan, if any.
        self.clear_matches();

        // Set the global variable `filesize` to the size of the scanned data.
        self.filesize
            .set(self.wasm_store.as_context_mut(), Val::I64(data.len() as i64))
            .unwrap();

        let ctx = self.wasm_store.data_mut();

        ctx.scanned_data = data.as_ptr();
        ctx.scanned_data_len = data.len();

        // If the string pool is too large, destroy it and create a new one
        // empty. Re-using the same string pool in multiple scans improves
        // performance, as the pool doesn't need to be destroyed and created
        // again on every scan. The price to pay the accumulation of strings
        // in the pool.
        if ctx.string_pool.size() > 1_000_000 {
            ctx.string_pool = BStringPool::new();
        }

        for module_name in ctx.compiled_rules.imports() {
            // Lookup the module in the list of built-in modules.
            let module = modules::BUILTIN_MODULES.get(module_name).unwrap();

            // Call the module's main function if any. This function returns
            // a data structure serialized as a protocol buffer. The format of
            // the data is specified by the .proto file associated to the
            // module.
            let module_output = if let Some(main_fn) = module.main_fn {
                main_fn(ctx)
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
            // all required fields are initialized.
            debug_assert!(
                module_output.is_initialized_dyn(),
                "module `{}` returned a protobuf `{}` where some required fields are not initialized ",
                module_name,
                module.root_struct_descriptor.full_name()
            );

            // When compile-time optimizations are enabled we don't need to
            // generate structure fields for enums. This is because during the
            // optimization process symbols like MyEnum.ENUM_ITEM are resolved
            // to their constant values at compile time. In other words, the
            // compiler determines that MyEnum.ENUM_ITEM is equal to some value
            // X, and uses that value in the generated code.
            //
            // However, without optimizations, enums are treated as any other
            // field in a struct, and its value is determined at scan time.
            // For that reason these fields must be generated for enums when
            // optimizations are disabled.
            let generate_fields_for_enums =
                !cfg!(feature = "compile-time-optimization");

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
            // symbol table (data from previous scans is replaced). This
            // structure implements the SymbolLookup trait, which is used
            // by the runtime for obtaining the values of individual fields
            // in the data structure, as they are used in the rule conditions.
            ctx.root_struct.add_field(
                module_name,
                TypeValue::Struct(Rc::new(module_struct)),
            );
        }

        // Invoke the main function, which evaluates the rules' conditions. It
        // triggers the Aho-Corasick scanning phase only if necessary. See
        // ScanContext::search_for_patterns.
        self.wasm_main_fn.call(self.wasm_store.as_context_mut(), ()).unwrap();

        let ctx = self.wasm_store.data_mut();

        // Set pointer to data back to nil. This means that accessing
        // `scanned_data` from within `ScanResults` is not possible.
        ctx.scanned_data = null();
        ctx.scanned_data_len = 0;

        // Clear the value of `current_struct` as it may contain a reference
        // to some struct.
        ctx.current_struct = None;

        ScanResults::new(ctx)
    }

    // Clear information about previous matches.
    fn clear_matches(&mut self) {
        let ctx = self.wasm_store.data_mut();
        let num_rules = ctx.compiled_rules.rules().len();
        let num_patterns = ctx.compiled_rules.num_patterns();

        // If some pattern or rule matched, clear the matches. Notice that a
        // rule may match without any pattern being matched, because there
        // there are rules without patterns, or that match if the pattern is
        // not found.
        if ctx.pattern_matched || !ctx.rules_matching.is_empty() {
            ctx.pattern_matched = false;

            // Clear the list of matching rules.
            ctx.rules_matching.clear();

            // The hash map that tracks the pattern matches is not completely
            // cleared with pattern_matches.clear() because that would cause
            // that all the arrays are deallocated. Instead, each of the arrays
            // are cleared individually, which removes the items in the array
            // while maintaining the array capacity. This way the array may be
            // reused in later scans without memory allocations.
            for (_, matches) in ctx.pattern_matches.iter_mut() {
                matches.clear()
            }

            let mem = ctx
                .main_memory
                .unwrap()
                .data_mut(self.wasm_store.as_context_mut());

            // Starting at MATCHING_RULES_BITMAP in main memory there's a bitmap
            // were the N-th bit indicates if the rule with ID = N matched or not,
            // If some rule matched in a previous call the bitmap will contain some
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
/// Allows iterating over both the matching and non-matching rules. For better
/// ergonomics it implements the [`IntoIterator`] trait, which allows iterating
/// over the matching rules in a `for` loop like shown below.
///
/// ```rust
/// # use yara_x;
/// let rules = yara_x::compile(
///     r#"rule test {
///         strings:
///            $a = "foo"
///         condition:
///            $a
///     }"#,
/// ).unwrap();
///
/// for matching_rule in yara_x::Scanner::new(&rules).scan(b"foobar") {
///     // do something with the matching rule ...
/// }
/// ```
pub struct ScanResults<'s, 'r> {
    ctx: &'s ScanContext<'r>,
}

impl<'s, 'r> ScanResults<'s, 'r> {
    fn new(ctx: &'s ScanContext<'r>) -> Self {
        Self { ctx }
    }

    /// Returns the number of rules that matched.
    pub fn num_matching_rules(&self) -> usize {
        self.ctx.rules_matching.len()
    }

    /// Returns an iterator that yields the matching rules.
    pub fn matching_rules(&self) -> MatchingRules<'s, 'r> {
        MatchingRules::new(self.ctx)
    }

    /// Returns an iterator that yields the non-matching rules.
    pub fn non_matching_rules(&self) -> NonMatchingRules<'s, 'r> {
        NonMatchingRules::new(self.ctx)
    }
}

impl<'s, 'r> IntoIterator for ScanResults<'s, 'r> {
    type Item = Rule<'s, 'r>;
    type IntoIter = MatchingRules<'s, 'r>;

    /// Consumes the scan results and returns a [`MatchingRules`] iterator.
    fn into_iter(self) -> Self::IntoIter {
        self.matching_rules()
    }
}

/// Iterator that yields the rules that matched during a scan.
pub struct MatchingRules<'s, 'r> {
    ctx: &'s ScanContext<'r>,
    iterator: Iter<'s, RuleId>,
}

impl<'s, 'r> MatchingRules<'s, 'r> {
    fn new(ctx: &'s ScanContext<'r>) -> Self {
        Self { ctx, iterator: ctx.rules_matching.iter() }
    }
}

impl<'s, 'r> Iterator for MatchingRules<'s, 'r> {
    type Item = Rule<'s, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = *self.iterator.next()?;
        let rules = self.ctx.compiled_rules;
        let rule_info = rules.get(rule_id);

        Some(Rule { rule_info, rules, ctx: self.ctx })
    }
}

/// Iterator that yields the rules that didn't match during a scan.
pub struct NonMatchingRules<'s, 'r> {
    ctx: &'s ScanContext<'r>,
    iterator: bitvec::slice::IterZeros<'s, u8, Lsb0>,
}

impl<'s, 'r> NonMatchingRules<'s, 'r> {
    fn new(ctx: &'s ScanContext<'r>) -> Self {
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

        Self { ctx, iterator: matching_rules_bitmap.iter_zeros() }
    }
}

impl<'s, 'r> Iterator for NonMatchingRules<'s, 'r> {
    type Item = Rule<'s, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = RuleId::from(self.iterator.next()?);
        let rules = self.ctx.compiled_rules;
        let rule_info = rules.get(rule_id);

        Some(Rule { rule_info, rules, ctx: self.ctx })
    }
}

/// A structure that describes a rule.
pub struct Rule<'s, 'r> {
    ctx: &'s ScanContext<'r>,
    pub(crate) rules: &'r Rules,
    pub(crate) rule_info: &'r RuleInfo,
}

impl<'s, 'r> Rule<'s, 'r> {
    /// Returns the rule's name.
    pub fn name(&self) -> &str {
        self.rules.ident_pool().get(self.rule_info.ident_id).unwrap()
    }

    /// Returns the rule's namespace.
    pub fn namespace(&self) -> &str {
        self.rules.ident_pool().get(self.rule_info.namespace_id).unwrap()
    }

    /// Returns the patterns defined by this rule.
    pub fn patterns(&self) -> Patterns<'s, 'r> {
        Patterns { ctx: self.ctx, iterator: self.rule_info.patterns.iter() }
    }
}

/// An iterator that returns the patterns defined by a rule.
pub struct Patterns<'s, 'r> {
    ctx: &'s ScanContext<'r>,
    iterator: Iter<'s, (IdentId, PatternId)>,
}

impl<'s, 'r> Iterator for Patterns<'s, 'r> {
    type Item = Pattern<'s, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let (ident_id, pattern_id) = self.iterator.next()?;
        Some(Pattern {
            ctx: self.ctx,
            pattern_id: *pattern_id,
            ident_id: *ident_id,
        })
    }
}

/// Represents a pattern defined by a rule.
pub struct Pattern<'s, 'r> {
    ctx: &'s ScanContext<'r>,
    pattern_id: PatternId,
    ident_id: IdentId,
}

impl<'r> Pattern<'_, 'r> {
    /// Returns the pattern's identifier (e.g: $a, $b).
    pub fn identifier(&self) -> &'r str {
        self.ctx.compiled_rules.ident_pool().get(self.ident_id).unwrap()
    }

    /// Returns the matches found for this pattern.
    pub fn matches(&self) -> Matches {
        Matches {
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
    iterator: Option<Iter<'a, Match>>,
}

impl Iterator for Matches<'_> {
    type Item = Match;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(iter) = &mut self.iterator {
            let next = iter.next()?;
            Some(next.clone())
        } else {
            None
        }
    }
}

pub(crate) type RuntimeStringId = u32;

/// Structure that holds information about the current scan.
pub(crate) struct ScanContext<'r> {
    /// Pointer to the WASM store.
    wasm_store: NonNull<Store<ScanContext<'r>>>,
    /// Pointer to the data being scanned.
    scanned_data: *const u8,
    /// Length of data being scanned.
    scanned_data_len: usize,
    /// Vector containing the IDs of the rules that matched.
    pub(crate) rules_matching: Vec<RuleId>,
    /// Compiled rules for this scan.
    pub(crate) compiled_rules: &'r Rules,
    /// Structure that contains top-level symbols, like module names
    /// and external variables. Symbols are normally looked up in this
    /// structure, except if `current_struct` is set to some other
    /// structure that overrides `root_struct`.
    pub(crate) root_struct: Struct,
    /// Currently active structure that overrides the `root_struct` if
    /// set.
    pub(crate) current_struct: Option<Rc<Struct>>,
    /// String pool where the strings produced at runtime are stored. This
    /// for example stores the strings returned by YARA modules.
    pub(crate) string_pool: BStringPool<RuntimeStringId>,
    /// Module's main memory.
    pub(crate) main_memory: Option<wasmtime::Memory>,
    /// The host-side stack of local variables.
    ///
    /// See [`crate::compiler::Context::new_var`] for a more detailed
    /// description of what is this, and what "host-side" means in this
    /// case.
    pub(crate) vars_stack: Vec<TypeValue>,
    /// Hash map that contains the protobuf messages returned by YARA modules.
    /// Keys are the fully qualified protobuf message name, and values are
    /// the message returned by the corresponding module.
    pub(crate) module_outputs: FxHashMap<String, Box<dyn MessageDyn>>,
    /// Hash map that tracks the matches occurred during a scan. The keys
    /// are the PatternId of the matching pattern, and values are a list
    pub(crate) pattern_matches: FxHashMap<PatternId, MatchList>,
    // True if some pattern matched during the scan.
    pub(crate) pattern_matched: bool,
}

impl ScanContext<'_> {
    /// Returns a slice with the data being scanned.
    pub(crate) fn scanned_data<'a>(&self) -> &'a [u8] {
        unsafe {
            std::slice::from_raw_parts::<u8>(
                self.scanned_data,
                self.scanned_data_len,
            )
        }
    }

    /// Returns the protobuf struct produced by a module.
    ///
    /// The main function of a module returns a protobuf message with data
    /// produced by the module for the current scan. Accessing this data
    /// from some other function exported by the module is useful in certain
    /// cases, and that's the purpose of this function.
    ///
    /// This function is generic over `T`, where `T` is some protobuf message
    /// type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::modules::protos::my_module::MyModuleProto;
    /// let module_data: MyModuleProto = ctx.module_data::<MyModuleProto>()
    /// ```
    pub(crate) fn module_output<T: MessageFull>(&self) -> Option<&T> {
        let m = self.module_outputs.get(T::descriptor().full_name())?.as_ref();
        <dyn MessageDyn>::downcast_ref(m)
    }

    /// Called during the scan process when a rule has matched for tracking
    /// the matching rules.
    pub(crate) fn track_rule_match(&mut self, rule_id: RuleId) {
        // Store the RuleId in the vector of matching rules.
        self.rules_matching.push(rule_id);

        let wasm_store = unsafe { self.wasm_store.as_mut() };
        let main_mem = self.main_memory.unwrap().data_mut(wasm_store);

        let base = MATCHING_RULES_BITMAP_BASE as usize;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(&mut main_mem[base..]);

        // The RuleId-th bit in the `rule_matches` bit vector is set to 1.
        bits.set(rule_id.into(), true);
    }

    /// Called during the scan process when a pattern has matched for tracking
    /// the matching patterns.
    pub(crate) fn track_pattern_match(
        &mut self,
        pattern_id: PatternId,
        match_: Match,
    ) {
        let wasm_store = unsafe { self.wasm_store.as_mut() };
        let main_mem = self.main_memory.unwrap().data_mut(wasm_store);
        let num_rules = self.compiled_rules.rules().len();

        let base = MATCHING_RULES_BITMAP_BASE as usize + num_rules / 8 + 1;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(&mut main_mem[base..]);

        bits.set(pattern_id.into(), true);

        self.pattern_matched = true;
        self.pattern_matches.entry(pattern_id).or_default().add(match_)
    }

    /// Search for patterns in the data.
    ///
    /// The pattern search phase is when YARA scans the data looking for the
    /// patterns declared in rules. All the patterns are searched simultaneously
    /// using the Aho-Corasick algorithm. This phase is triggered lazily during
    /// the evaluation of the rule conditions, when some of the conditions need
    /// to know if a pattern matched or not.
    ///
    /// This function won't be called if the conditions can be fully evaluated
    /// without looking for any of the patterns. If it must be called, it will be
    /// called only once.
    pub(crate) fn search_for_patterns(&mut self) {
        let ac = self.compiled_rules.aho_corasick();

        for atom_match in ac.find_overlapping_iter(self.scanned_data()) {
            let matched_atom =
                &self.compiled_rules.atoms()[atom_match.pattern()];

            // Subtract the backtrack value from the offset where the atom
            // matched. If the result is negative the atom can't be inside
            // the scanned data and therefore is not a possible match.
            let (match_start, overflow) = atom_match
                .start()
                .overflowing_sub(matched_atom.atom.backtrack as usize);

            if overflow {
                continue;
            }

            let (pattern_id, sub_pattern) = &self
                .compiled_rules
                .get_sub_pattern(matched_atom.sub_pattern_id);

            let match_ = match sub_pattern {
                SubPattern::Fixed { pattern, full_word } => self
                    .verify_fixed_match(
                        match_start,
                        *pattern,
                        false,
                        *full_word,
                    ),
                SubPattern::FixedCaseInsensitive { pattern, full_word } => {
                    self.verify_fixed_match(
                        match_start,
                        *pattern,
                        true,
                        *full_word,
                    )
                }
                SubPattern::Xor { pattern, full_word } => self
                    .verify_xor_match(
                        match_start,
                        matched_atom,
                        *pattern,
                        *full_word,
                    ),
                SubPattern::Base64 { pattern, padding }
                | SubPattern::Base64Wide { pattern, padding } => self
                    .verify_base64_match(
                        (*padding).into(),
                        match_start,
                        *pattern,
                        None,
                        matches!(sub_pattern, SubPattern::Base64Wide { .. }),
                    ),
                SubPattern::CustomBase64 { pattern, alphabet, padding }
                | SubPattern::CustomBase64Wide {
                    pattern,
                    alphabet,
                    padding,
                } => {
                    let alphabet = self
                        .compiled_rules
                        .lit_pool()
                        .get_str(*alphabet)
                        .map(|alphabet| {
                            // `Alphabet::new` validates the string again. This
                            // is not really necessary as we already know that
                            // the string represents a valid alphabet, it would
                            // be better if could use the private function
                            // `Alphabet::from_str_unchecked`
                            base64::alphabet::Alphabet::new(alphabet).unwrap()
                        });

                    assert!(alphabet.is_some());

                    self.verify_base64_match(
                        (*padding).into(),
                        match_start,
                        *pattern,
                        alphabet,
                        matches!(
                            sub_pattern,
                            SubPattern::CustomBase64Wide { .. }
                        ),
                    )
                }
            };

            if let Some(m) = match_ {
                self.track_pattern_match(*pattern_id, m);
            }
        }
    }

    fn verify_fixed_match(
        &self,
        match_start: usize,
        pattern_id: LiteralId,
        case_insensitive: bool,
        full_word: FullWord,
    ) -> Option<Match> {
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();
        let data = self.scanned_data();

        // Offset where the match should end (inclusive).
        let match_end = match_start + pattern.len() - 1;

        // The match can not end past the end of the scanned data.
        if match_end >= data.len() {
            return None;
        }

        match full_word {
            FullWord::Ascii => {
                if match_start >= 1
                    && data[match_start - 1].is_ascii_alphanumeric()
                {
                    return None;
                }

                if match_end + 1 < data.len()
                    && data[match_end + 1].is_ascii_alphanumeric()
                {
                    return None;
                }
            }
            FullWord::Wide => {
                if match_start >= 2
                    && data[match_start - 1] == 0
                    && data[match_start - 2].is_ascii_alphanumeric()
                {
                    return None;
                }

                if match_end + 2 < data.len()
                    && data[match_end + 2] == 0
                    && data[match_end + 1].is_ascii_alphanumeric()
                {
                    return None;
                }
            }
            FullWord::Disabled => {}
        }

        let match_found = if case_insensitive {
            pattern.eq_ignore_ascii_case(&data[match_start..=match_end])
        } else {
            memx::memeq(&data[match_start..=match_end], pattern.as_bytes())
        };

        if match_found {
            Some(Match {
                // The end of the range is exclusive.
                range: match_start..match_end + 1,
                xor_key: None,
            })
        } else {
            None
        }
    }

    fn verify_xor_match(
        &self,
        match_start: usize,
        matched_atom: &AtomInfo,
        pattern_id: LiteralId,
        full_word: FullWord,
    ) -> Option<Match> {
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();
        let data = self.scanned_data();

        // Offset where the match should end (inclusive).
        let match_end = match_start + pattern.len() - 1;

        // The match can not end past the end of the scanned data.
        if match_end >= data.len() {
            return None;
        }

        let mut pattern = pattern.to_owned();

        // The atom that matched is the result of XORing the pattern with some
        // key. The key can be obtained by XORing some byte in the atom with
        // the corresponding byte in the pattern.
        let key = matched_atom.atom.as_ref()[0]
            ^ pattern[matched_atom.atom.backtrack as usize];

        match full_word {
            FullWord::Ascii => {
                if match_start >= 1
                    && (data[match_start - 1] ^ key).is_ascii_alphanumeric()
                {
                    return None;
                }

                if match_end + 1 < data.len()
                    && (data[match_end + 1] ^ key).is_ascii_alphanumeric()
                {
                    return None;
                }
            }
            FullWord::Wide => {
                if match_start >= 2
                    && (data[match_start - 1] ^ key) == 0
                    && (data[match_start - 2] ^ key).is_ascii_alphanumeric()
                {
                    return None;
                }

                if match_end + 2 < data.len()
                    && (data[match_end + 2] ^ key) == 0
                    && (data[match_end + 1] ^ key).is_ascii_alphanumeric()
                {
                    return None;
                }
            }
            FullWord::Disabled => {}
        }

        // Now we can XOR the whole pattern with the obtained key and make sure
        // that it matches the data. This only makes sense if the key is not
        // zero.
        if key != 0 {
            for i in 0..pattern.len() {
                pattern[i] ^= key;
            }
        }

        if memx::memeq(&data[match_start..=match_end], pattern.as_bytes()) {
            Some(Match {
                range: match_start..match_end + 1,
                xor_key: Some(key),
            })
        } else {
            None
        }
    }

    fn verify_base64_match(
        &self,
        padding: usize,
        match_start: usize,
        pattern_id: LiteralId,
        alphabet: Option<base64::alphabet::Alphabet>,
        wide: bool,
    ) -> Option<Match> {
        // Get the pattern in its original form, not encoded as base64.
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();

        // Compute the size of the pattern once it is encoded as base64.
        let len = base64::encoded_len(pattern.len(), false).unwrap();

        // A portion of the pattern in base64 form was found at match_start,
        // but decoding the base64 string starting at that offset is not ok
        // because some characters may have been removed from both the left
        // and the right sides of the base64 string that has been found. For
        // example, for the pattern "foobar" one of the base64 patterns that
        // are searched for is "Zvb2Jhc", but once this pattern is found in
        // the scanned data we can't simply decode that string and expect
        // to find "foobar" in the decoded data.
        //
        // What we must do is use two more characters from the left, and one
        // more from the right of "Zvb2Jhc", like for example "eGZvb2Jhcg",
        // which is decoded as "xfoobar". The actual number of additional
        // characters that must be used from the left and right of the pattern
        // found depends on the padding and the rest of dividing the pattern's
        // length by 4. The table below covers all possible cases using the
        // plain text patterns "foobar", "fooba" and "foob".
        //
        // padding          base64                      len (mod 4)
        //    0   foobar    Zm9vYmFy    len(b64(foobar))  8 (0)  [Zm9vYmFy]
        //    0   fooba     Zm9vYmE     len(b64(fooba))   7 (3)  [Zm9vYm]E
        //    0   foob      Zm9vYg      len(b64(foob))    6 (2)  [Zm9vY]g
        //
        //    1   xfoobar   eGZvb2Jhcg  len(b64(foobar))  8 (0)  eG[Zvb2Jhc]g
        //    1   xfooba    eGZvb2Jh    len(b64(fooba))   7 (3)  eG[Zvb2Jh]
        //    1   xfoob     eGZvb2I     len(b64(foob))    6 (2)  eG[Zvb2]I
        //
        //    2   xxfoobar  eHhmb29iYXI len(b64(foobar))  8 (0)  eHh[mb29iYX]I
        //    2   xxfooba   eHhmb29iYQ  len(b64(fooba))   7 (3)  eHh[mb29iY]Q
        //    2   xxfoob    eHhmb29i    len(b64(foob))    6 (2)  eHh[mb29i]
        //
        // In the rightmost column the portion of the base64 pattern that is
        // searched using the Aho-Corasick algorithm is enclosed in [].
        let (mut decode_start_delta, mut decode_len, mut match_len) =
            match padding {
                0 => match len % 4 {
                    0 => (0, len, len),
                    2 => (0, len + 2, len - 1),
                    3 => (0, len + 1, len - 1),
                    _ => unreachable!(),
                },
                1 => match len % 4 {
                    0 => (2, len + 4, len - 1),
                    2 => (2, len + 2, len - 2),
                    3 => (2, len + 1, len - 1),
                    _ => unreachable!(),
                },
                2 => match len % 4 {
                    0 => (3, len + 4, len - 1),
                    2 => (3, len + 2, len - 1),
                    3 => (3, len + 5, len - 1),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            };

        // In wide mode each base64 character is two bytes long, adjust
        // decode_start_delta and lengths accordingly.
        if wide {
            decode_start_delta *= 2;
            decode_len *= 2;
            match_len *= 2;
        }

        // decode_range is the range within the scanned data that we are going
        // to decode as base64. It starts at match_start - decode_start_delta,
        // but if match_start < decode_start_delta this is not a real match.
        let mut decode_range = if let (decode_start, false) =
            match_start.overflowing_sub(decode_start_delta)
        {
            decode_start..decode_start + decode_len
        } else {
            return None;
        };

        // If the end of decode_range is past the end of the scanned data
        // truncate it to scanned_data_len.
        if decode_range.end > self.scanned_data_len {
            decode_range.end = self.scanned_data_len;
        }

        let base64_engine = base64::engine::GeneralPurpose::new(
            alphabet.as_ref().unwrap_or(&base64::alphabet::STANDARD),
            base64::engine::general_purpose::NO_PAD,
        );

        let decoded = if wide {
            // Collect the ASCII characters at even positions and make sure
            // that bytes at odd positions are zeroes.
            let mut ascii = Vec::with_capacity(decode_range.len() / 2);
            for (i, b) in self.scanned_data()[decode_range].iter().enumerate()
            {
                if i % 2 == 0 {
                    ascii.push(*b)
                } else if *b != 0 {
                    return None;
                }
            }
            base64_engine.decode(ascii.as_slice())
        } else {
            base64_engine.decode(&self.scanned_data()[decode_range])
        };

        if let Ok(decoded) = decoded {
            // If the decoding was successful, ignore the padding and compare
            // to the pattern.
            let decoded = &decoded[padding..];
            if decoded.len() >= pattern.len()
                && pattern.eq(&decoded[0..pattern.len()])
            {
                Some(Match {
                    range: match_start..match_start + match_len,
                    xor_key: None,
                })
            } else {
                None
            }
        } else {
            None
        }
    }
}
