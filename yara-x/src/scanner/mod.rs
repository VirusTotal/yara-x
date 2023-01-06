/*! Scans data with already compiled YARA rules.

*/

use std::fs::File;
use std::path::Path;
use std::ptr::null;
use std::rc::Rc;
use std::slice::Iter;

use yara_x_parser::types::{Struct, TypeValue};

use crate::compiler::{CompiledRule, CompiledRules, RuleId};
use crate::string_pool::BStringPool;
use crate::{modules, wasm};
use bitvec::prelude::*;
use memmap::MmapOptions;

use crate::wasm::MATCHING_RULES_BITMAP_BASE;

use wasmtime::{
    Global, GlobalType, MemoryType, Mutability, Store, TypedFunc, Val, ValType,
};

#[cfg(test)]
mod tests;

/// Scans data with already compiled YARA rules.
pub struct Scanner<'r> {
    wasm_store: wasmtime::Store<ScanContext<'r>>,
    wasm_main_fn: TypedFunc<(), ()>,
    filesize: wasmtime::Global,
}

impl<'r> Scanner<'r> {
    /// Creates a new scanner.
    pub fn new(compiled_rules: &'r CompiledRules) -> Self {
        let mut wasm_store = Store::new(
            &crate::wasm::ENGINE,
            ScanContext {
                compiled_rules,
                string_pool: BStringPool::new(),
                current_struct: None,
                root_struct: Struct::new(),
                scanned_data: null(),
                scanned_data_len: 0,
                rules_matching: Vec::new(),
                main_memory: None,
                lookup_stack_top: None,
                lookup_start: None,
                vars_stack: Vec::new(),
            },
        );

        // Global variable that will hold the value for `filesize`. This is
        // initialized to 0 because the file size is not known until some
        // data is scanned.
        let filesize = Global::new(
            &mut wasm_store,
            GlobalType::new(ValType::I64, Mutability::Var),
            Val::I64(0),
        )
        .unwrap();

        let lookup_start = Global::new(
            &mut wasm_store,
            GlobalType::new(ValType::I32, Mutability::Var),
            Val::I32(-1),
        )
        .unwrap();

        let lookup_stack_top = Global::new(
            &mut wasm_store,
            GlobalType::new(ValType::I32, Mutability::Var),
            Val::I32(0),
        )
        .unwrap();

        let num_rules = compiled_rules.rules().len() as u32;
        let num_patterns = compiled_rules.patterns().len() as u32;

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
            &mut wasm_store,
            GlobalType::new(ValType::I32, Mutability::Const),
            Val::I32(matching_patterns_bitmap_base as i32),
        )
        .unwrap();

        // Create module's main memory.
        let main_memory = wasmtime::Memory::new(
            &mut wasm_store,
            MemoryType::new(mem_size, None),
        )
        .unwrap();

        // Instantiate the module. This takes the wasm code provided by the
        // `compiled_wasm_mod` function and links its imported functions with
        // the implementations that YARA provides (see wasm.rs).
        let wasm_instance = wasm::new_linker()
            .define("yr", "filesize", filesize)
            .unwrap()
            .define(
                "yr",
                "matching_patterns_bitmap_base",
                matching_patterns_bitmap_base,
            )
            .unwrap()
            .define("yr", "lookup_start", lookup_start)
            .unwrap()
            .define("yr", "lookup_stack_top", lookup_stack_top)
            .unwrap()
            .define("yr", "main_memory", main_memory)
            .unwrap()
            .instantiate(&mut wasm_store, compiled_rules.compiled_wasm_mod())
            .unwrap();

        // Obtain a reference to the "main" function exported by the module.
        let wasm_main_fn = wasm_instance
            .get_typed_func::<(), (), _>(&mut wasm_store, "main")
            .unwrap();

        wasm_store.data_mut().main_memory = Some(main_memory);
        wasm_store.data_mut().lookup_stack_top = Some(lookup_stack_top);
        wasm_store.data_mut().lookup_start = Some(lookup_start);

        Self { wasm_store, wasm_main_fn, filesize }
    }

    /// Scans a file.
    pub fn scan_file<'s, P: AsRef<Path>>(
        &'s mut self,
        path: P,
    ) -> std::io::Result<ScanResults<'s, 'r>> {
        let file = File::open(path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        Ok(self.scan(&mmap[..]))
    }

    /// Scans a data buffer.
    pub fn scan<'s>(&'s mut self, data: &[u8]) -> ScanResults<'s, 'r> {
        let ctx = self.wasm_store.data_mut();

        // Get the number of rules.
        let num_rules = ctx.compiled_rules.rules().len();

        // Starting at MATCHING_RULES_BITMAP in main memory there's a bitmap
        // were the N-th bit indicates if the rule with ID = N matched or not.
        // If some rule matched in a previous call the bitmap will contain some
        // bits set to 1 and need to be cleared.
        if !ctx.rules_matching.is_empty() {
            // Clear the list of matching rules.
            ctx.rules_matching.clear();
            let offset = wasm::MATCHING_RULES_BITMAP_BASE as usize;
            let mem = ctx.main_memory.unwrap().data_mut(&mut self.wasm_store);
            let bitmap = BitSlice::<_, Lsb0>::from_slice_mut(
                &mut mem[offset..offset + num_rules / 8 + 1],
            );
            // Set to zero all bits in the bitmap.
            bitmap.fill(false);
        }

        // Set the global variable `filesize` to the size of the scanned data.
        self.filesize
            .set(&mut self.wasm_store, Val::I64(data.len() as i64))
            .unwrap();

        let ctx = self.wasm_store.data_mut();

        ctx.scanned_data = data.as_ptr();
        ctx.scanned_data_len = data.len();

        // TODO: this should be done only if the string pool is too large.
        ctx.string_pool = BStringPool::new();

        for module_name in ctx.compiled_rules.imported_modules() {
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
            ctx.root_struct.insert(
                module_name,
                TypeValue::Struct(Rc::new(module_struct)),
            );
        }

        // Invoke the main function.
        self.wasm_main_fn.call(&mut self.wasm_store, ()).unwrap();

        let ctx = self.wasm_store.data_mut();

        // Set pointer to data back to nil. This means that accessing
        // `scanned_data` from within `ScanResults` is not possible.
        ctx.scanned_data = null();
        ctx.scanned_data_len = 0;

        ScanResults::new(self)
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
    pub fn matching_rules(&self) -> usize {
        self.scanner.wasm_store.data().rules_matching.len()
    }

    pub fn iter(&self) -> IterMatches<'s, 'r> {
        IterMatches::new(self.scanner)
    }

    pub fn iter_non_matches(&self) -> IterNonMatches<'s, 'r> {
        IterNonMatches::new(self.scanner)
    }
}

/// Iterator that returns the rules that matched,
pub struct IterMatches<'s, 'r> {
    rules: &'r [CompiledRule],
    iterator: Iter<'s, RuleId>,
}

impl<'s, 'r> IterMatches<'s, 'r> {
    fn new(scanner: &'s Scanner<'r>) -> Self {
        Self {
            iterator: scanner.wasm_store.data().rules_matching.iter(),
            rules: scanner.wasm_store.data().compiled_rules.rules(),
        }
    }
}

impl<'s, 'r> Iterator for IterMatches<'s, 'r> {
    type Item = &'r CompiledRule;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = *self.iterator.next()?;
        Some(&self.rules[rule_id as usize])
    }
}

/// Iterator that returns the rules that didn't match.
pub struct IterNonMatches<'s, 'r> {
    rules: &'r [CompiledRule],
    iterator: bitvec::slice::IterZeros<'s, u8, Lsb0>,
}

impl<'s, 'r> IterNonMatches<'s, 'r> {
    fn new(scanner: &'s Scanner<'r>) -> Self {
        let main_memory = scanner
            .wasm_store
            .data()
            .main_memory
            .unwrap()
            .data(&scanner.wasm_store);

        let bits = BitSlice::<_, Lsb0>::from_slice(
            &main_memory[MATCHING_RULES_BITMAP_BASE as usize..],
        );

        Self {
            iterator: bits.iter_zeros(),
            rules: scanner.wasm_store.data().compiled_rules.rules(),
        }
    }
}

impl<'s, 'r> Iterator for IterNonMatches<'s, 'r> {
    type Item = &'r CompiledRule;

    fn next(&mut self) -> Option<Self::Item> {
        let rule_id = self.iterator.next()?;
        Some(&self.rules[rule_id])
    }
}

pub(crate) type RuntimeStringId = u32;

/// Structure that holds information a about the current scan.
pub(crate) struct ScanContext<'r> {
    /// Vector containing the IDs of the rules that matched.
    pub(crate) rules_matching: Vec<RuleId>,
    /// Data being scanned.
    pub(crate) scanned_data: *const u8,
    /// Length of data being scanned.
    pub(crate) scanned_data_len: usize,
    /// Compiled rules for this scan.
    pub(crate) compiled_rules: &'r CompiledRules,
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

    pub(crate) lookup_start: Option<wasmtime::Global>,
    pub(crate) lookup_stack_top: Option<wasmtime::Global>,
}
