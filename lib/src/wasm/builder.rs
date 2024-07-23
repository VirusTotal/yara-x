use crate::compiler::RuleId;
use crate::wasm;
use rustc_hash::FxHashMap;
use std::mem;
use walrus::ir::{Block, InstrSeqId, UnaryOp};
use walrus::ValType::{F64, I32, I64};
use walrus::{FunctionBuilder, FunctionId, InstrSeqBuilder};

use super::WasmSymbols;

macro_rules! global_var {
    ($module:ident, $name:ident, $ty:ident) => {
        let ($name, _) = $module.add_import_global(
            "yara_x",
            stringify!($name),
            $ty,
            true,  // mutable
            false, // shared
        );
    };
}

macro_rules! global_const {
    ($module:ident, $name:ident, $ty:ident) => {
        let ($name, _) = $module.add_import_global(
            "yara_x",
            stringify!($name),
            $ty,
            false, // mutable
            false, // shared
        );
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
///   ... initialization of some global variables.
///
///   call namespaces_0
///   ...
///   call namespaces_1
///   ...
///   call namespaces_N
///
///  ... returns 0 if everything went ok or 1 if a timeout occurred.
/// }
/// ```
///
/// Each of the `namespaces_X` function contains a block per YARA namespace:
///
/// ```text
/// func namespaces_0 {
///   block {              ;; block for namespace 0
///      ...
///   }
///   block {              ;; block for namespace 1
///      ...
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
///
/// ```text
/// block namespaces_n {   ;; block for namespace N
///   call rules_0         ;; calls a function that contains the logic
///                        ;; for one or more rules
///   br_if namespaces_n   ;; exit the namespace block if result is 1
///   ...
///   call rules_n
///   br_if namespaces_n
/// }
/// ```
///
/// Each of the rules function contains the code for multiple YARA rules. The
/// [`WasmModuleBuilder::rules_per_func`] method controls the number of YARA
/// rules per function. As in the case of namespaces, this has an impact in
/// compilation time. This is how these functions look like:
/// ```text
/// func rules_0 {
///   ... code for rule 1
///   ... code for rule 2
///   ... code for global rule 1
///
///   ...
///   return 0
/// }
/// ```
///
/// Each of the functions containing rules (i.e: `rules_N`) return one of the
/// following values:
///
///   0 - When all global rules matched
///   1 - When some global rule didn't match
///
pub(crate) struct WasmModuleBuilder {
    module: walrus::Module,
    wasm_symbols: WasmSymbols,
    wasm_exports: FxHashMap<String, FunctionId>,
    main_func: FunctionBuilder,
    namespace_func: FunctionBuilder,
    rules_func: FunctionBuilder,
    namespace_block: InstrSeqId,
    rule_id: RuleId,
    num_rules: usize,
    num_namespaces: usize,
    namespaces_per_func: usize,
    rules_per_func: usize,
    global_rule: bool,
}

impl WasmModuleBuilder {
    const RULES_FUNC_RET: [walrus::ValType; 1] = [I32; 1];

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

        let (main_memory, _) = module.add_import_memory(
            "yara_x",
            "main_memory",
            false, // shared
            false, // memory64
            1,
            None,
            None,
        );

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

        Self {
            module,
            wasm_symbols,
            wasm_exports,
            main_func,
            namespace_func,
            rules_func,
            namespace_block,
            rule_id: RuleId::default(),
            num_rules: 0,
            num_namespaces: 0,
            namespaces_per_func: 10,
            rules_per_func: 10,
            global_rule: false,
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

    /// Returns an instruction sequence builder that can be used for emitting
    /// code for a YARA rule.
    ///
    /// The code emitted for the rule must leave an i32 in the stack with value
    /// 1 or 0 indicating whether the rule matched or not.
    pub fn start_rule(
        &mut self,
        rule_id: RuleId,
        global: bool,
    ) -> InstrSeqBuilder {
        if self.num_rules == self.rules_per_func {
            self.finish_rule_func();
            self.num_rules = 0;
        }
        self.num_rules += 1;
        self.rule_id = rule_id;
        self.global_rule = global;

        self.rules_func.func_body()
    }

    /// This finishes the code for a rule.
    ///
    /// Each call to [`WasmModuleBuilder::start_rule`] must be followed by a
    /// call to this function once the code for rule has been emitted.
    pub fn finish_rule(&mut self) {
        let global_rule_no_match =
            self.function_id(wasm::export__global_rule_no_match.mangled_name);

        let export_rule =
            self.function_id(wasm::export__rule_match.mangled_name);

        let mut instr = self.rules_func.func_body();

        // Check if the result from the condition is zero (false).
        instr.unop(UnaryOp::I32Eqz).if_else(
            None,
            |then_| {
                // The condition is false. For normal rules we don't do anything,
                // but for global rules we must call `global_rule_no_match`, and
                // return 1.
                //
                // By returning 1 the function that contains the logic for this
                // rule exits immediately, preventing that any other rule in the
                // same namespace is executed.
                //
                // This guarantees that any global rule that returns false, forces
                // any other rule in the same namespace to be false. The purpose of
                // calling  `global_rule_no_match` is reverting any previous matches
                // that occurred in the same namespace.
                if self.global_rule {
                    then_
                        // Call `global_rule_no_match`.
                        .i32_const(self.rule_id.into())
                        .call(global_rule_no_match)
                        // Return 1.
                        .i32_const(1)
                        .return_();
                }
            },
            |else_| {
                // The condition is true, call `rule_match`.
                else_.i32_const(self.rule_id.into()).call(export_rule);
            },
        );
    }

    /// Starts a new namespace.
    pub fn new_namespace(&mut self) {
        self.finish_rule_func();
        self.finish_namespace_block();
        if self.num_namespaces == self.namespaces_per_func {
            self.finish_namespace_func();
            self.num_namespaces = 0;
        }
        self.num_namespaces += 1;
        self.num_rules = 0;
    }

    /// Builds the WASM module and consumes the builder.
    pub fn build(mut self) -> walrus::Module {
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
    /// Given a function mangled name returns its id.
    ///
    /// # Panics
    ///
    /// If a no function with the given name exists.
    pub fn function_id(&self, fn_mangled_name: &str) -> FunctionId {
        *self.wasm_exports.get(fn_mangled_name).unwrap_or_else(|| {
            panic!("can't find function `{}`", fn_mangled_name)
        })
    }

    fn finish_namespace_block(&mut self) {
        if !self
            .namespace_func
            .instr_seq(self.namespace_block)
            .instrs()
            .is_empty()
        {
            // Add the current block to the namespace function and create a
            // new block.
            self.namespace_func
                .func_body()
                .instr(Block { seq: self.namespace_block });

            self.namespace_block =
                self.namespace_func.dangling_instr_seq(None).id();
        }
    }

    fn finish_namespace_func(&mut self) {
        let namespace_func = mem::replace(
            &mut self.namespace_func,
            FunctionBuilder::new(&mut self.module.types, &[], &[]),
        );

        self.namespace_block =
            self.namespace_func.dangling_instr_seq(None).id();

        self.main_func.func_body().call(
            self.module.funcs.add_local(namespace_func.local_func(Vec::new())),
        );
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
            // The last instruction in a rules function leaves a 0 in the
            // stack as its return value. This is reached only when all
            // global rules match. If any global rules doesn't match, the
            // function exits early with a return value of 1.
            rule_func.func_body().i32_const(0);

            let mut namespace_block =
                self.namespace_func.instr_seq(self.namespace_block);

            namespace_block.call(
                self.module.funcs.add_local(rule_func.local_func(Vec::new())),
            );

            let namespace_block_id = namespace_block.id();

            // If the rules function returned 1 is because some global rule
            // didn't match, in this case we exit early from the namespace
            // block, preventing any other rule in the namespace from being
            // executed.
            namespace_block.br_if(namespace_block_id);
        }
    }
}
