use std::marker::PhantomData;
use std::mem::transmute;
use std::pin::Pin;
use std::time::Duration;

use wasmtime::{
    AsContext, AsContextMut, Global, GlobalType, MemoryType, Mutability,
    Store, TypedFunc, Val, ValType,
};

use crate::scanner::context::create_wasm_store_and_ctx;
use crate::scanner::{ScanContext, ScannedData};
use crate::wasm::MATCHING_RULES_BITMAP_BASE;
use crate::{wasm, Rules, ScanError};

trait ScannerState {}

struct Idle {}

struct Scanning {}

impl ScannerState for Idle {}
impl ScannerState for Scanning {}

struct BlockScanner<'r, S: ScannerState> {
    _state: PhantomData<S>,
    rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static, 'static>>>>,
    wasm_main_func: TypedFunc<(), i32>,
    filesize: Global,
    timeout: Option<Duration>,
}

impl<'r> BlockScanner<'r, Idle> {
    const DEFAULT_SCAN_TIMEOUT: u64 = 315_360_000;

    /// Creates a new scanner.
    pub fn new(rules: &'r Rules) -> BlockScanner<'r, Idle> {
        let mut wasm_store = create_wasm_store_and_ctx(rules);

        let num_rules = rules.num_rules() as u32;
        let num_patterns = rules.num_patterns() as u32;

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

        // Compute the base offset for the bitmap that contains matching
        // information for patterns. This bitmap has 1 bit per pattern, the
        // N-th bit is set if pattern with PatternId = N matched. The bitmap
        // starts right after the bitmap that contains matching information
        // for rules.
        let matching_patterns_bitmap_base =
            MATCHING_RULES_BITMAP_BASE as u32 + num_rules.div_ceil(8);

        // Compute the required memory size in 64KB pages.
        let mem_size = u32::div_ceil(
            matching_patterns_bitmap_base + num_patterns.div_ceil(8),
            65536,
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
            MemoryType::new(mem_size, Some(mem_size)),
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

        BlockScanner {
            _state: PhantomData,
            rules,
            wasm_store,
            wasm_main_func,
            filesize,
            timeout: None,
        }
    }
}

impl<'r> BlockScanner<'r, Idle> {
    pub fn start(mut self) -> BlockScanner<'r, Scanning> {
        // Clear information about matches found in a previous scan, if any.
        self.scan_context_mut().reset();
        // Return the scanner, but transmuted into a BlockScanner<Scanning>.
        unsafe {
            transmute::<BlockScanner<Idle>, BlockScanner<Scanning>>(self)
        }
    }
}

impl<'r> BlockScanner<'r, Scanning> {
    pub fn scan(
        &mut self,
        base: usize,
        data: &[u8],
    ) -> Result<&mut Self, ScanError> {
        let ctx = self.scan_context_mut();
        ctx.scanned_data = Some(ScannedData::Slice(data));
        ctx.search_for_patterns()?;
        Ok(self)
    }

    pub fn finish(self) -> BlockScanner<'r, Idle> {
        unsafe {
            transmute::<BlockScanner<Scanning>, BlockScanner<Idle>>(self)
        }
    }
}

impl<'r, S: ScannerState> BlockScanner<'r, S> {
    #[inline]
    fn scan_context(&self) -> &ScanContext<'r, '_> {
        unsafe {
            transmute::<&ScanContext<'static, 'static>, &ScanContext<'r, '_>>(
                self.wasm_store.data(),
            )
        }
    }
    #[inline]
    fn scan_context_mut(&mut self) -> &mut ScanContext<'r, '_> {
        unsafe {
            transmute::<
                &mut ScanContext<'static, 'static>,
                &mut ScanContext<'r, '_>,
            >(self.wasm_store.data_mut())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compile;
    use crate::scanner::block::{BlockScanner, Idle};

    #[test]
    fn block_scanner() {
        let rules = compile("rule test { condition: true }").unwrap();
        let s = BlockScanner::new(&rules);

        let mut a = s.start();

        a.scan(0, b"").unwrap();
        a.scan(1000, b"").unwrap();

        let s = a.finish();

        //s.scan(b"")
    }
}
