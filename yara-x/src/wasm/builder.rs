use rustc_hash::FxHashMap;
use walrus::ir::{Block, InstrSeqId};
use walrus::ValType::{F64, I32, I64};
use walrus::{FunctionId, InstrSeqBuilder};

use super::WasmSymbols;

/// Builds the WASM module for a set of compiled rules.
///
/// The produced WASM module exports a `main` function that contains the logic
/// for the rule conditions in the set of compiled rules. This function returns
/// an `i32` with two possible values, `0` if everything was ok, or `1` if a
/// timeout occurred. The overall structure of the `main` function is:
///
///  ```text
///  ;; namespace 0
///  block
///    block
///      ;; instr_seq_1 goes here
///    end
///    block
///      ;; instr_seq_2 goes here
///    end
///  end
///  ;; namespace 1
///  block
///    block
///      ;; instr_seq_1 goes here
///    end
///    block
///      ;; instr_seq_2 goes here
///    end    
///  end
///  ;; more namespaces ...
///  return 0
/// ```
///
/// There's a WASM code block for each namespace (at least one), and each of
/// those blocks contain two other blocks: one for `instr_seq_1` and the other
/// one for `instr_seq_2`.
///
/// Instruction sequences `instr_seq_1` and `instr_seq_2` grow independently
/// as you add WASM instructions to them. They are finalized when either
/// [`WasmModuleBuilder::new_namespace`] or [`WasmModuleBuilder::build`] are
/// called. `new_namespace` finalizes the current instruction sequences, put
/// them into a namespace code block, and creates a new pair of `instr_seq_1`
/// and `instr_seq_2` that will be empty. In the other hand `build` does
/// the same than `new_namespace` but instead of creating a new pair of
/// instruction sequences it consumes the builder and produces the final
/// WASM module.
pub(crate) struct WasmModuleBuilder {
    module: walrus::Module,
    wasm_symbols: WasmSymbols,
    builder: walrus::FunctionBuilder,
    namespace: InstrSeqId,
    instr_seq_1: InstrSeqId,
    instr_seq_2: InstrSeqId,
    wasm_exports: FxHashMap<String, FunctionId>,
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

impl WasmModuleBuilder {
    /// Creates a new module builder.
    pub fn new() -> Self {
        let config = walrus::ModuleConfig::new();
        let mut module = walrus::Module::with_config(config);
        let mut wasm_exports = FxHashMap::default();

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
            wasm_exports.insert(fully_qualified_name, func_id);
        }

        global_const!(module, matching_patterns_bitmap_base, I32);
        global_var!(module, filesize, I64);

        let (main_memory, _) =
            module.add_import_memory("yara_x", "main_memory", false, 1, None);

        let wasm_symbols = WasmSymbols {
            main_memory,
            matching_patterns_bitmap_base,
            filesize,
            pattern_search_done: module.locals.add(I32),
            i64_tmp: module.locals.add(I64),
            i32_tmp: module.locals.add(I32),
            f64_tmp: module.locals.add(F64),
        };

        // The main function receives no arguments and returns an `i32`.
        let mut builder =
            walrus::FunctionBuilder::new(&mut module.types, &[], &[I32]);

        let namespace = builder.dangling_instr_seq(None).id();
        let instr_seq_1 = builder.dangling_instr_seq(None).id();
        let instr_seq_2 = builder.dangling_instr_seq(None).id();

        Self {
            module,
            wasm_symbols,
            wasm_exports,
            builder,
            namespace,
            instr_seq_1,
            instr_seq_2,
        }
    }

    pub fn wasm_symbols(&self) -> WasmSymbols {
        self.wasm_symbols.clone()
    }

    pub fn wasm_exports(&self) -> FxHashMap<String, FunctionId> {
        self.wasm_exports.clone()
    }

    pub fn current_namespace(&mut self) -> InstrSeqId {
        self.namespace
    }

    pub fn instr_seq_1(&mut self) -> InstrSeqBuilder {
        self.builder.instr_seq(self.instr_seq_1)
    }

    pub fn instr_seq_2(&mut self) -> InstrSeqBuilder {
        self.builder.instr_seq(self.instr_seq_2)
    }

    pub fn new_namespace(&mut self) {
        self.finalize_namespace();
        self.namespace = self.builder.dangling_instr_seq(None).id();
        self.instr_seq_1 = self.builder.dangling_instr_seq(None).id();
        self.instr_seq_2 = self.builder.dangling_instr_seq(None).id();
    }

    fn finalize_namespace(&mut self) {
        let mut ns = self.builder.instr_seq(self.namespace);

        ns.instr(Block { seq: self.instr_seq_1 });
        ns.instr(Block { seq: self.instr_seq_2 });

        self.builder.func_body().instr(Block { seq: self.namespace });
    }

    /// Builds the WASM module and consumes the builder.
    pub fn build(mut self) -> walrus::Module {
        self.finalize_namespace();

        // Emit the final return statement.
        self.builder.func_body().i32_const(1);
        self.builder.func_body().return_();

        let main_fn = self.builder.finish(Vec::new(), &mut self.module.funcs);
        self.module.exports.add("main", main_fn);
        self.module
    }
}
