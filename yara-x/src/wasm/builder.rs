use rustc_hash::FxHashMap;
use walrus::FunctionId;
use walrus::ValType::{I32, I64};

use super::WasmSymbols;

/// Builds the WebAssembly module for a set of compiled rules.
pub(crate) struct ModuleBuilder {
    module: walrus::Module,
    wasm_symbols: WasmSymbols,
    pub(crate) wasm_funcs: FxHashMap<String, FunctionId>,
    pub(crate) main_fn: walrus::FunctionBuilder,
}

macro_rules! global_var {
    ($module:ident, $name:ident, $ty:ident) => {
        let ($name, _) =
            $module.add_import_global("yara_x", stringify!($name), $ty, true);
    };
}

macro_rules! global_const {
    ($module:ident, $name:ident, $ty:ident) => {
        let ($name, _) =
            $module.add_import_global("yara_x", stringify!($name), $ty, false);
    };
}

impl ModuleBuilder {
    /// Creates a new module builder.
    pub fn new() -> Self {
        let config = walrus::ModuleConfig::new();
        let mut module = walrus::Module::with_config(config);
        let mut wasm_funcs = FxHashMap::default();

        for export in super::WASM_EXPORTS {
            let ty = module.types.add(
                export.func.walrus_args().as_slice(),
                export.func.walrus_results().as_slice(),
            );
            let fully_qualified_name = export.fully_qualified_mangled_name();
            let (func_id, _) = module.add_import_func(
                export.rust_module_path,
                fully_qualified_name.as_str(),
                ty,
            );
            wasm_funcs.insert(fully_qualified_name, func_id);
        }

        global_const!(module, matching_patterns_bitmap_base, I32);
        global_var!(module, lookup_stack_top, I32);
        global_var!(module, lookup_start, I32);
        global_var!(module, filesize, I64);

        let (main_memory, _) =
            module.add_import_memory("yara_x", "main_memory", false, 1, None);

        let wasm_symbols = WasmSymbols {
            main_memory,
            matching_patterns_bitmap_base,
            lookup_start,
            lookup_stack_top,
            filesize,
            i64_tmp: module.locals.add(I64),
            i32_tmp: module.locals.add(I32),
        };

        let main_fn =
            walrus::FunctionBuilder::new(&mut module.types, &[], &[]);

        Self { module, wasm_symbols, wasm_funcs, main_fn }
    }

    /// Returns the symbols imported by the module.
    pub fn wasm_symbols(&self) -> WasmSymbols {
        self.wasm_symbols.clone()
    }

    /// Builds the module and consumes the builder.
    pub fn build(mut self) -> walrus::Module {
        let main_fn = self.main_fn.finish(Vec::new(), &mut self.module.funcs);
        self.module.exports.add("main", main_fn);
        self.module
    }
}
