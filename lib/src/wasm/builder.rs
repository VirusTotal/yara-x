use rustc_hash::FxHashMap;
use std::mem;
use walrus::ir::{Block, InstrSeqId};
use walrus::ValType::{F64, I32, I64};
use walrus::{FunctionBuilder, FunctionId, InstrSeqBuilder};

use super::WasmSymbols;

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

/// Builds the WASM module for a set of compiled rules.
///
/// The produced WASM module exports a `main` function that is the entry point
/// for the module. The `main` function calls namespaces functions, each of
/// these functions contain the logic for one or more YARA namespaces. This is
/// how the main function looks like:
///
///  ```text
/// func main {
///   call namespaces_0
///   ...
///   call namespaces_N
/// }
/// ```
///
/// Each of the `namespaces_X` function contains a block per YARA namespace,
/// and each of these blocks contains two inner blocks, for global and
/// non-global rules respectively. For example:
/// ```text
/// func namespaces_0 {
///   block {              ;; block for namespace 0
///     block {            ;; block for global rules
///        ...
///     }
///     block {            ;; block for non-global rules
///        ...
///     }
///   }
///   block {              ;; block for namespace 1
///     block {            ;; block for global rules
///        ...
///     }
///     block {            ;; block for non-global rules
///        ...
///     }
///   }
///   ...  more blocks
/// }
/// ```
///
/// The number of YARA namespaces per `namespaces_X` function is controlled with
/// the [`WasmModuleBuilder::namespaces_per_func`] method. This has an impact
/// in the total number of functions contained in the WASM module and their
/// sizes. The least namespaces per function, the higher the number of
/// functions but the smaller their sizes. This has an effect in the module
/// compilation time, and the sweet spot seems to be around 10-20 namespaces
/// per function. Too few namespaces per function increases compilation time
/// due to the higher number of functions, too much namespaces per function
/// increases compilation because each function becomes too large and complex.
///
/// In turn, each of the namespace blocks calls one or more rules functions
/// which contains the logic for multiple YARA rules. This is how one of the
/// namespace blocks looks in details:
/// ```text
///   block outer {               ;; block for namespace 1
///     block {                   ;; block for global rules
///        call global_rules_0    ;; calls a function that contains the logic
///                               ;; for one or more global rules
///        br_if outer            ;; exit the outer block if result is 1
///        ...
///        call global_rules_n
///        br_if outer
///     }
///     block {            ;; block for non-global rules
///        call rules_0    ;; calls a function that contains the logic for one
///                        ;; or more non-global rules
///        ...
///        call rules_n
///     }
///   }
/// ```
///
/// Each of the rules function contains the code for multiple YARA rules. The
/// [`WasmModuleBuilder::rules_per_func`] method controls the number of YARA
/// rules per function. As in the case of namespaces, this has an impact in
/// compilation time. This is how these functions look like:
/// ```text
/// func global_rules_0 {
///    ... code for global rule 1.
///    ...
///    ... code for global rule N
///    return 0             ;; when global rules matched, the result is 0.
/// }
///
/// func rules_0 {
///     ... code for non-global rule 1
///     ...
///     ... code for non-global rule 2
/// }
/// ```
///
/// Each of the functions containing global rules (i.e: `global_rules_N`) return
/// one of the following values:
///
///   0 - When all global rules matches
///   1 - When some global rule didn't match
///   2 - If a timeout occurs
pub(crate) struct WasmModuleBuilder {
    module: walrus::Module,
    wasm_symbols: WasmSymbols,
    wasm_exports: FxHashMap<String, FunctionId>,
    main_func: FunctionBuilder,
    namespace_func: FunctionBuilder,
    rules_func: FunctionBuilder,
    global_rules_func: FunctionBuilder,
    namespace_block: InstrSeqId,
    global_rules_block: InstrSeqId,
    rules_block: InstrSeqId,
    num_rules: usize,
    num_global_rules: usize,
    num_namespaces: usize,
    namespaces_per_func: usize,
    rules_per_func: usize,
}

impl WasmModuleBuilder {
    const GLOBAL_RULES_FUNC_RET: [walrus::ValType; 1] = [I32; 1];
    const RULES_FUNC_RET: [walrus::ValType; 0] = [];

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
        global_var!(module, pattern_search_done, I32);
        global_var!(module, timeout_occurred, I32);

        let (main_memory, _) =
            module.add_import_memory("yara_x", "main_memory", false, 1, None);

        let wasm_symbols = WasmSymbols {
            main_memory,
            matching_patterns_bitmap_base,
            filesize,
            pattern_search_done,
            timeout_occurred,
            i64_tmp: module.locals.add(I64),
            i32_tmp: module.locals.add(I32),
            f64_tmp: module.locals.add(F64),
        };

        let global_rules_func = FunctionBuilder::new(
            &mut module.types,
            &[],
            &Self::GLOBAL_RULES_FUNC_RET,
        );

        let mut namespace_func =
            FunctionBuilder::new(&mut module.types, &[], &[]);

        let rules_func = FunctionBuilder::new(
            &mut module.types,
            &[],
            &Self::RULES_FUNC_RET,
        );

        // The main function receives no arguments and returns an I32.
        let mut main_func =
            FunctionBuilder::new(&mut module.types, &[], &[I32]);

        // The first instructions in the main function initialize the global
        // variables `pattern_search_done` and `timeout_occurred` to 0 (false).
        main_func.func_body().i32_const(0);
        main_func.func_body().global_set(pattern_search_done);
        main_func.func_body().i32_const(0);
        main_func.func_body().global_set(timeout_occurred);

        let namespace_block = namespace_func.dangling_instr_seq(None).id();
        let global_rules_block = namespace_func.dangling_instr_seq(None).id();
        let rules_block = namespace_func.dangling_instr_seq(None).id();

        Self {
            module,
            wasm_symbols,
            wasm_exports,
            main_func,
            global_rules_func,
            namespace_func,
            rules_func,
            namespace_block,
            global_rules_block,
            rules_block,
            num_rules: 0,
            num_global_rules: 0,
            num_namespaces: 0,
            namespaces_per_func: 10,
            rules_per_func: 10,
        }
    }

    pub fn wasm_symbols(&self) -> WasmSymbols {
        self.wasm_symbols.clone()
    }

    /// Returns a hash map where keys are fully qualified mangled function
    /// names (i.e: `my_module.my_struct.my_func@ii@i`) and values are function
    /// identifiers returned by the `walrus` crate. ([`walrus::FunctionId`]).
    pub fn wasm_exports(&self) -> FxHashMap<String, FunctionId> {
        self.wasm_exports.clone()
    }

    /// Configure the number of YARA that namespaces that will be put in each
    /// WASM function.
    pub fn namespaces_per_func(&mut self, n: usize) -> &mut Self {
        self.namespaces_per_func = n;
        self
    }

    /// Configure the number of YARA rules that will be put in each WASM
    /// function.
    pub fn rules_per_func(&mut self, n: usize) -> &mut Self {
        self.rules_per_func = n;
        self
    }

    /// Returns a instruction sequence builder that can be used for emitting
    /// code for a global YARA rule. The code emitted for a global rule must
    /// return early with `return 1` if the rule didn't match.
    pub fn new_global_rule(&mut self) -> InstrSeqBuilder {
        if self.num_global_rules == self.rules_per_func {
            self.finish_global_rule_func();
            self.num_global_rules = 0;
        }
        self.num_global_rules += 1;
        self.global_rules_func.func_body()
    }

    /// Returns an instruction sequence builder that can be used for emitting
    /// code for a non-global YARA rule.
    pub fn new_rule(&mut self) -> InstrSeqBuilder {
        if self.num_rules == self.rules_per_func {
            self.finish_rule_func();
            self.num_rules = 0;
        }
        self.num_rules += 1;
        self.rules_func.func_body()
    }

    pub fn new_namespace(&mut self) {
        self.finish_global_rule_func();
        self.finish_rule_func();
        self.finish_namespace_block();
        if self.num_namespaces == self.namespaces_per_func {
            self.finish_namespace_func();
            self.num_namespaces = 0;
        }
        self.num_namespaces += 1;
        self.num_rules = 0;
        self.num_global_rules = 0;
    }

    /// Builds the WASM module and consumes the builder.
    pub fn build(mut self) -> walrus::Module {
        self.finish_global_rule_func();
        self.finish_rule_func();
        self.finish_namespace_block();
        self.finish_namespace_func();

        // Emit the last few instructions for the main function, which consist
        // in putting the return value in the stack. The return value is 0 if
        // everything went ok and 1 if a timeout occurred.
        self.main_func
            .func_body()
            .global_get(self.wasm_symbols.timeout_occurred);

        let main_func =
            self.main_func.finish(Vec::new(), &mut self.module.funcs);

        self.module.exports.add("main", main_func);
        self.module
    }
}

impl WasmModuleBuilder {
    fn finish_namespace_block(&mut self) {
        let global_rules = !self
            .namespace_func
            .instr_seq(self.global_rules_block)
            .instrs()
            .is_empty();

        let rules = !self
            .namespace_func
            .instr_seq(self.rules_block)
            .instrs()
            .is_empty();

        if global_rules {
            self.namespace_func
                .instr_seq(self.namespace_block)
                .instr(Block { seq: self.global_rules_block });
        }

        if rules {
            self.namespace_func
                .instr_seq(self.namespace_block)
                .instr(Block { seq: self.rules_block });
        }

        match (global_rules, rules) {
            (true, true) | (true, false) => {
                self.namespace_func
                    .func_body()
                    .instr(Block { seq: self.namespace_block });
            }
            (false, true) => {
                self.namespace_func
                    .func_body()
                    .instr(Block { seq: self.rules_block });
            }
            (false, false) => {}
        }

        self.namespace_block =
            self.namespace_func.dangling_instr_seq(None).id();

        self.global_rules_block =
            self.namespace_func.dangling_instr_seq(None).id();

        self.rules_block = self.namespace_func.dangling_instr_seq(None).id();
    }

    fn finish_namespace_func(&mut self) {
        let namespace_func = mem::replace(
            &mut self.namespace_func,
            FunctionBuilder::new(&mut self.module.types, &[], &[]),
        );

        self.namespace_block =
            self.namespace_func.dangling_instr_seq(None).id();

        self.global_rules_block =
            self.namespace_func.dangling_instr_seq(None).id();

        self.rules_block = self.namespace_func.dangling_instr_seq(None).id();

        self.main_func.func_body().call(
            self.module.funcs.add_local(namespace_func.local_func(Vec::new())),
        );
    }

    fn finish_global_rule_func(&mut self) {
        let mut global_rules_func = mem::replace(
            &mut self.global_rules_func,
            FunctionBuilder::new(
                &mut self.module.types,
                &[],
                &Self::GLOBAL_RULES_FUNC_RET,
            ),
        );

        if !global_rules_func.func_body().instrs().is_empty() {
            // The last instruction in a global rules function leaves a
            // 0 in the stack as its return value. This is reached only
            // when all global rules match. If any global rules doesn't
            // match, the function exits early with a return value of 1.
            global_rules_func.func_body().i32_const(0);

            let mut block =
                self.namespace_func.instr_seq(self.global_rules_block);

            block.call(
                self.module
                    .funcs
                    .add_local(global_rules_func.local_func(Vec::new())),
            );

            block.br_if(self.namespace_block);
        }
    }

    fn finish_rule_func(&mut self) {
        let mut rule_func = mem::replace(
            &mut self.rules_func,
            FunctionBuilder::new(
                &mut self.module.types,
                &[],
                &Self::RULES_FUNC_RET,
            ),
        );

        if !rule_func.func_body().instrs().is_empty() {
            let mut rules_block =
                self.namespace_func.instr_seq(self.rules_block);

            rules_block.call(
                self.module.funcs.add_local(rule_func.local_func(Vec::new())),
            );
        }
    }
}
