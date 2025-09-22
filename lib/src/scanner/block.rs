use std::marker::PhantomData;
use std::mem::transmute;
use std::pin::Pin;

use wasmtime::Store;

use crate::scanner::context::create_wasm_store_and_ctx;
use crate::scanner::{ScanContext, ScannedData};
use crate::{Rules, ScanError};

trait ScannerState {}

struct Idle {}

struct Scanning {}

impl ScannerState for Idle {}
impl ScannerState for Scanning {}

struct BlockScanner<'r, S: ScannerState> {
    _state: PhantomData<S>,
    rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static, 'static>>>>,
}

impl<'r> BlockScanner<'r, Idle> {
    /// Creates a new scanner.
    pub fn new(rules: &'r Rules) -> BlockScanner<'r, Idle> {
        BlockScanner {
            _state: PhantomData,
            rules,
            wasm_store: create_wasm_store_and_ctx(rules),
        }
    }
}

impl<'r> BlockScanner<'r, Idle> {
    pub fn start(&mut self) -> &mut BlockScanner<'r, Scanning> {
        self.scan_context_mut().reset();
        unsafe {
            transmute::<&mut BlockScanner<Idle>, &mut BlockScanner<Scanning>>(
                self,
            )
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

    pub fn finish(&mut self) -> Result<(), ScanError> {
        let ctx = self.scan_context_mut();
        ctx.eval_conditions()
    }
}

impl<'r, S: ScannerState> BlockScanner<'r, S> {
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
        let rules =
            compile(r#"rule test { strings: $a = "ipsum" condition: $a }"#)
                .unwrap();

        let mut scanner = BlockScanner::new(&rules);

        scanner
            .start()
            .scan(0, b"Lorem ipsum")
            .unwrap()
            .scan(1000, b"dolor sit amet")
            .unwrap()
            .finish()
            .unwrap();
    }
}
