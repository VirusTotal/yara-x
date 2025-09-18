use std::marker::PhantomData;
use std::mem::transmute;
use std::pin::Pin;
use std::time::Duration;

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
    timeout: Option<Duration>,
}

impl<'r> BlockScanner<'r, Idle> {
    const DEFAULT_SCAN_TIMEOUT: u64 = 315_360_000;

    /// Creates a new scanner.
    pub fn new(rules: &'r Rules) -> BlockScanner<'r, Idle> {
        let wasm_store = create_wasm_store_and_ctx(rules);
        BlockScanner { _state: PhantomData, rules, wasm_store, timeout: None }
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
