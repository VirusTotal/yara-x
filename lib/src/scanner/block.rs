use std::mem::transmute;
use std::pin::Pin;

use wasmtime::Store;

use crate::scanner::context::{create_wasm_store_and_ctx, ScanState};
use crate::scanner::{ScanContext, ScannedData};
use crate::{Rules, ScanError};

struct BlockScanner<'r> {
    _rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static, 'static>>>>,
    scanning: bool,
}

impl<'r> BlockScanner<'r> {
    /// Creates a new scanner.
    pub fn new(rules: &'r Rules) -> BlockScanner<'r> {
        BlockScanner {
            _rules: rules,
            wasm_store: create_wasm_store_and_ctx(rules),
            scanning: false,
        }
    }
}
impl BlockScanner<'_> {
    pub fn scan(
        &mut self,
        base: usize,
        data: &[u8],
    ) -> Result<&mut Self, ScanError> {
        if !self.scanning {
            self.scan_context_mut().reset();
            self.scanning = true;
        }
        self.scan_context_mut().scan_state =
            ScanState::Scanning(ScannedData::Slice(data));
        self.scan_context_mut().search_for_patterns()?;
        Ok(self)
    }

    pub fn finish(&mut self) -> Result<(), ScanError> {
        self.scanning = false;
        self.scan_context_mut().eval_conditions()
    }
}

impl<'r> BlockScanner<'r> {
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
    use crate::scanner::block::BlockScanner;

    #[test]
    fn block_scanner() {
        let rules =
            compile(r#"rule test { strings: $a = "ipsum" condition: $a }"#)
                .unwrap();

        let mut scanner = BlockScanner::new(&rules);

        scanner
            .scan(0, b"Lorem ipsum")
            .unwrap()
            .scan(1000, b"dolor sit amet")
            .unwrap()
            .finish()
            .unwrap();
    }
}
