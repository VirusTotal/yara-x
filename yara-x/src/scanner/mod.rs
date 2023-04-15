/*! This module implements the YARA scanner.

The scanner takes the rules produces by the compiler and scans data with them.
*/

use base64::Engine;
use std::ops::Deref;
use std::path::Path;
use std::pin::Pin;
use std::ptr::{null, NonNull};
use std::rc::Rc;
use std::slice::Iter;

use bitvec::prelude::*;
use bstr::ByteSlice;
use fmmap::{MmapFile, MmapFileExt};
use wasmtime::{
    AsContext, AsContextMut, Global, GlobalType, MemoryType, Mutability,
    Store, TypedFunc, Val, ValType,
};

use yara_x_parser::types::{Struct, TypeValue};

use crate::compiler::{Rule, RuleId, Rules};
use crate::string_pool::BStringPool;
use crate::wasm::MATCHING_RULES_BITMAP_BASE;
use crate::{modules, wasm, AtomInfo, LiteralId, PatternId, SubPattern};

#[cfg(test)]
mod tests;

/// Scans data with already compiled YARA rules.
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
                patterns_found: false,
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
            .define("yara_x", "filesize", filesize)
            .unwrap()
            .define(
                "yara_x",
                "matching_patterns_bitmap_base",
                matching_patterns_bitmap_base,
            )
            .unwrap()
            .define("yara_x", "main_memory", main_memory)
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

        // TODO: this should be done only if the string pool is too large.
        ctx.string_pool = BStringPool::new();

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
                module_output,
                generate_fields_for_enums,
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

        ScanResults::new(self)
    }

    // Clear information about previous matches.
    fn clear_matches(&mut self) {
        let ctx = self.wasm_store.data_mut();
        let num_rules = ctx.compiled_rules.rules().len();
        let num_patterns = ctx.compiled_rules.num_patterns();

        if ctx.patterns_found || !ctx.rules_matching.is_empty() {
            // Clear the list of matching rules.
            ctx.rules_matching.clear();
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
pub struct ScanResults<'s, 'r> {
    scanner: &'s Scanner<'r>,
}

impl<'s, 'r> ScanResults<'s, 'r> {
    fn new(scanner: &'s Scanner<'r>) -> Self {
        Self { scanner }
    }

    /// Returns the number of rules that matched.
    pub fn num_matching_rules(&self) -> usize {
        self.scanner.wasm_store.data().rules_matching.len()
    }

    /// Returns an iterator that yields the matching rules.
    pub fn iter(&self) -> Matches<'s, 'r> {
        Matches::new(self.scanner)
    }

    /// Returns an iterator that yields the non-matching rules.
    pub fn iter_non_matches(&self) -> NonMatches<'s, 'r> {
        NonMatches::new(self.scanner)
    }
}

/// Iterator that yields the rules that matched.
pub struct Matches<'s, 'r> {
    scanner: &'s Scanner<'r>,
    iterator: Iter<'s, RuleId>,
}

impl<'s, 'r> Matches<'s, 'r> {
    fn new(scanner: &'s Scanner<'r>) -> Self {
        Self {
            scanner,
            iterator: scanner.wasm_store.data().rules_matching.iter(),
        }
    }
}

impl<'s, 'r> Iterator for Matches<'s, 'r> {
    type Item = Rule<'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = *self.iterator.next()?;
        let rules = self.scanner.wasm_store.data().compiled_rules;
        let rule_info = rules.get(rule_id);

        Some(Rule { rule_info, rules })
    }
}

/// Iterator that yields the rules that didn't match.
pub struct NonMatches<'s, 'r> {
    scanner: &'s Scanner<'r>,
    iterator: bitvec::slice::IterZeros<'s, u8, Lsb0>,
}

impl<'s, 'r> NonMatches<'s, 'r> {
    fn new(scanner: &'s Scanner<'r>) -> Self {
        let ctx = scanner.wasm_store.data();
        let num_rules = ctx.compiled_rules.rules().len();
        let main_memory =
            ctx.main_memory.unwrap().data(scanner.wasm_store.as_context());

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

        Self { scanner, iterator: matching_rules_bitmap.iter_zeros() }
    }
}

impl<'s, 'r> Iterator for NonMatches<'s, 'r> {
    type Item = Rule<'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = RuleId::from(self.iterator.next()?);
        let rules = self.scanner.wasm_store.data().compiled_rules;
        let rule_info = rules.get(rule_id);

        Some(Rule { rule_info, rules })
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
    /// True if some pattern has been found. This is simply a flag that
    /// indicates that the bitmap that tells which patterns has matched
    /// needs to be cleared.
    pub(crate) patterns_found: bool,
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
}

impl ScanContext<'_> {
    /// An slice with the data being scanned.
    pub(crate) fn scanned_data<'a>(&self) -> &'a [u8] {
        unsafe {
            std::slice::from_raw_parts::<u8>(
                self.scanned_data,
                self.scanned_data_len,
            )
        }
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
    pub(crate) fn track_pattern_match(&mut self, pattern_id: PatternId) {
        self.patterns_found = true;

        let wasm_store = unsafe { self.wasm_store.as_mut() };
        let main_mem = self.main_memory.unwrap().data_mut(wasm_store);
        let num_rules = self.compiled_rules.rules().len();

        let base = MATCHING_RULES_BITMAP_BASE as usize + num_rules / 8 + 1;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(&mut main_mem[base..]);

        bits.set(pattern_id.into(), true);
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

            let match_verified = match sub_pattern {
                SubPattern::Fixed(pattern_lit_id) => self.verify_fixed_match(
                    match_start,
                    *pattern_lit_id,
                    false,
                ),
                SubPattern::FixedCaseInsensitive(pattern_lit_id) => {
                    self.verify_fixed_match(match_start, *pattern_lit_id, true)
                }
                SubPattern::Xor(pattern_lit_id) => self.verify_xor_match(
                    match_start,
                    matched_atom,
                    *pattern_lit_id,
                ),
                SubPattern::Base64(id, padding)
                | SubPattern::Base64Wide(id, padding) => self
                    .verify_base64_match(
                        *padding,
                        match_start,
                        *id,
                        None,
                        matches!(sub_pattern, SubPattern::Base64Wide(..)),
                    ),

                SubPattern::CustomBase64(id, alphabet, padding)
                | SubPattern::CustomBase64Wide(id, alphabet, padding) => {
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
                        *padding,
                        match_start,
                        *id,
                        alphabet,
                        matches!(
                            sub_pattern,
                            SubPattern::CustomBase64Wide(..)
                        ),
                    )
                }
            };

            if match_verified {
                self.track_pattern_match(*pattern_id);
            }
        }
    }

    fn verify_fixed_match(
        &self,
        match_start: usize,
        pattern_id: LiteralId,
        case_insensitive: bool,
    ) -> bool {
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();

        if self.scanned_data_len < match_start + pattern.len() {
            return false;
        }

        let data =
            &self.scanned_data()[match_start..match_start + pattern.len()];

        if case_insensitive {
            pattern.eq_ignore_ascii_case(data)
        } else {
            memx::memeq(data, pattern.as_bytes())
        }
    }

    fn verify_xor_match(
        &self,
        match_start: usize,
        matched_atom: &AtomInfo,
        pattern_id: LiteralId,
    ) -> bool {
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();

        if self.scanned_data_len < match_start + pattern.len() {
            return false;
        }

        let mut pattern = pattern.to_owned();

        // The atom that matched is the result of XORing the pattern with some
        // key. The key can be obtained by XORing some byte in the atom with
        // the corresponding byte in the pattern.
        let key = matched_atom.atom.as_ref()[0]
            ^ pattern[matched_atom.atom.backtrack as usize];

        // Now we can XOR the whole pattern with the obtained key and make sure
        // that it matches the data. This only makes sense if the key is not
        // zero.
        if key != 0 {
            for i in 0..pattern.len() {
                pattern[i] ^= key;
            }
        }

        let data =
            &self.scanned_data()[match_start..match_start + pattern.len()];

        memx::memeq(data, pattern.as_bytes())
    }

    fn verify_base64_match(
        &self,
        padding: u8,
        match_start: usize,
        pattern_id: LiteralId,
        alphabet: Option<base64::alphabet::Alphabet>,
        wide: bool,
    ) -> bool {
        // The pattern is stored in its original form, not encoded as base64.
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();

        // Compute the size of the pattern once it is encoded as base64.
        let mut len = base64::encoded_len(pattern.len(), false).unwrap();

        // The base64 pattern was found at match_start, but decoding the base64
        // string starting at that position is not ok, as it may not be the
        // real starting point for the base64 string (remember that some
        // characters may have been removed from the left and right of the
        // pattern). Based on the padding and the pattern's length, we decide
        // where to start decoding and how many characters to use. The starting
        // point is either at match_start, match_start - 2, or match_start - 3,
        // depending on the padding. That's ok even if the base64 string in the
        // scanned data starts way before match_start, we are relying on the
        // fact that you can partially decode a base64 string starting from a
        // middle point, provided that this point is at a 4-characters boundary
        // within the string.
        let (mut left_adjustment, mut right_adjustment) = match padding {
            0 => (0, 0),
            1 => match len % 4 {
                0 => (2, 0),
                2 => (2, 1),
                3 => (2, 1),
                _ => unreachable!(),
            },
            2 => match len % 4 {
                0 => (3, 0),
                2 => (3, 1),
                3 => (3, 0),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        // In wide mode each base64 character is two bytes long, adjust the
        // length and adjustments accordingly.
        if wide {
            left_adjustment *= 2;
            right_adjustment *= 2;
            len *= 2;
        }

        let range = if let (adjusted_start, false) =
            match_start.overflowing_sub(left_adjustment)
        {
            adjusted_start..match_start + len - right_adjustment
        } else {
            return false;
        };

        if range.end > self.scanned_data_len {
            return false;
        }

        let base64_engine = base64::engine::GeneralPurpose::new(
            alphabet.as_ref().unwrap_or(&base64::alphabet::STANDARD),
            base64::engine::general_purpose::NO_PAD,
        );

        let decoded = if wide {
            // Collect the ASCII characters at even positions and make sure
            // that bytes at odd positions are zeroes.
            let mut ascii = Vec::with_capacity(len / 2);
            for (i, b) in self.scanned_data()[range].iter().enumerate() {
                if i % 2 == 0 {
                    ascii.push(*b)
                } else if *b != 0 {
                    return false;
                }
            }
            base64_engine.decode(ascii.as_slice())
        } else {
            base64_engine.decode(&self.scanned_data()[range])
        };

        if let Ok(decoded) = decoded {
            pattern.eq(&decoded[padding as usize..])
        } else {
            false
        }
    }
}
