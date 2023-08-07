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
/// functions contain the logic for one or more YARA namespaces. This is how
/// the main function looks like:
///
///  ```text
/// func main {
///   call namespaces_0
///   ...
///   call namespaces_N
/// }
/// ```
///
/// Each namespaces function contains a block per YARA namespace, and each of these
/// blocks contains two inner blocks, for global and non-global rules respectively.
/// For example:
///
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
/// The number of YARA namespaces per namespaces function is controlled with
/// the [`WasmModuleBuilder::namespaces_per_func`] method. This has an impact
/// in the total number of functions contained in the WASM module and their
/// sizes. The least namespaces per function, the higher the number of
/// functions but smaller their sizes. This has an effect in the module
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
///
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
///
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

        let (main_memory, _) =
            module.add_import_memory("yara_x", "main_memory", false, 1, None);

        let wasm_symbols = WasmSymbols {
            main_memory,
            matching_patterns_bitmap_base,
            filesize,
            pattern_search_done,
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

        let mut main_func = FunctionBuilder::new(&mut module.types, &[], &[]);

        main_func.func_body().i32_const(0);
        main_func.func_body().global_set(pattern_search_done);

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
            namespaces_per_func: 20,
            rules_per_func: 10,
        }
    }

    pub fn wasm_symbols(&self) -> WasmSymbols {
        self.wasm_symbols.clone()
    }

    pub fn wasm_exports(&self) -> FxHashMap<String, FunctionId> {
        self.wasm_exports.clone()
    }

    pub fn namespaces_per_func(&mut self, n: usize) -> &mut Self {
        self.namespaces_per_func = n;
        self
    }

    pub fn rules_per_func(&mut self, n: usize) -> &mut Self {
        self.rules_per_func = n;
        self
    }

    /// Returns a instruction sequence builder that can be used for emitting
    /// code for a global YARA rule. The code emitted for a global rule must
    /// early with `return 1` if the rule didn't match.
    pub fn new_global_rule(&mut self) -> InstrSeqBuilder {
        if self.num_global_rules == self.rules_per_func {
            self.finish_global_rule_func();
            self.num_global_rules = 0;
        }
        self.num_global_rules += 1;
        self.global_rules_func.func_body()
    }

    /// Returns a instruction sequence builder that can be used for emitting
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

        let main_func =
            self.main_func.finish(Vec::new(), &mut self.module.funcs);

        self.module.exports.add("main", main_func);
        self.module
    }
}

impl WasmModuleBuilder {
    fn finish_namespace_block(&mut self) {
        let emit_global_rules = self
            .namespace_func
            .instr_seq(self.global_rules_block)
            .instrs()
            .len()
            > 0;

        let emit_non_global_rules =
            self.namespace_func.instr_seq(self.rules_block).instrs().len() > 0;

        if emit_global_rules {
            self.namespace_func
                .instr_seq(self.namespace_block)
                .instr(Block { seq: self.global_rules_block });
        }

        if emit_non_global_rules {
            self.namespace_func
                .instr_seq(self.namespace_block)
                .instr(Block { seq: self.rules_block });
        }

        match (emit_global_rules, emit_non_global_rules) {
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

        if global_rules_func.func_body().instrs().len() > 0 {
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

        if rule_func.func_body().instrs().len() > 0 {
            let mut block_2 = self.namespace_func.instr_seq(self.rules_block);

            block_2.call(
                self.module.funcs.add_local(rule_func.local_func(Vec::new())),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::wasm::builder::WasmModuleBuilder;
    use pretty_assertions::assert_eq;
    use wasmprinter;

    #[test]
    fn module_builder() {
        let mut builder = WasmModuleBuilder::new();

        builder.namespaces_per_func(2);
        builder.rules_per_func(2);

        /*builder.new_rule().i32_const(0);
                builder.new_rule().i32_const(1);
                builder.new_rule().i32_const(2);
                builder.new_global_rule().i32_const(0);

                builder.new_namespace();
                builder.new_rule().i32_const(3);
                builder.new_rule().i32_const(4);
        */

        builder.new_namespace();
        builder.new_global_rule();
        builder.new_rule().i32_const(4);

        builder.new_namespace();
        builder.new_rule().i32_const(5);

        builder.new_namespace();
        builder.new_rule().i32_const(6);

        let mut module = builder.build();
        let wasm = module.emit_wasm();
        let text = wasmprinter::print_bytes(wasm).unwrap();

        assert_eq!(
            text,
            r#"(module
  (type (;0;) (func))
  (type (;1;) (func (result i32)))
  (type (;2;) (func (result i64 i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32) (result i64)))
  (type (;5;) (func (param i32 i32) (result i32 i32)))
  (type (;6;) (func (param i32 i32) (result i64 i32)))
  (type (;7;) (func (param i32 i32) (result f64 i32)))
  (type (;8;) (func (param i32 i32 i32)))
  (type (;9;) (func (param i32 i64) (result i32)))
  (type (;10;) (func (param i32 i64) (result i64 i32)))
  (type (;11;) (func (param i32 i64 i64) (result i32)))
  (type (;12;) (func (param i32 i64 i64) (result i64)))
  (type (;13;) (func (param i64) (result i64)))
  (type (;14;) (func (param i64) (result i64 i32)))
  (type (;15;) (func (param i64 i32) (result i32)))
  (type (;16;) (func (param i64 i32 i32) (result i32)))
  (type (;17;) (func (param i64 i32 i32) (result i32 i32)))
  (type (;18;) (func (param i64 i32 i32) (result i64 i32)))
  (type (;19;) (func (param i64 i32 i32) (result i64 i64)))
  (type (;20;) (func (param i64 i32 i32) (result i64 f64)))
  (type (;21;) (func (param i64 i32 i32) (result f64 i32)))
  (type (;22;) (func (param i64 i32 i32 i32) (result i32)))
  (type (;23;) (func (param i64 i32 i32 i32) (result i64)))
  (type (;24;) (func (param i64 i64) (result i32)))
  (type (;25;) (func (param i64 i64) (result i64)))
  (type (;26;) (func (param f64 f64) (result f64)))
  (import "yara_x::wasm" "int32be@i@iu" (func (;0;) (type 14)))
  (import "yara_x::wasm" "int16be@i@iu" (func (;1;) (type 14)))
  (import "yara_x::wasm" "int8be@i@iu" (func (;2;) (type 14)))
  (import "yara_x::wasm" "int32@i@iu" (func (;3;) (type 14)))
  (import "yara_x::wasm" "int16@i@iu" (func (;4;) (type 14)))
  (import "yara_x::wasm" "int8@i@iu" (func (;5;) (type 14)))
  (import "yara_x::wasm" "uint32be@i@iu" (func (;6;) (type 14)))
  (import "yara_x::wasm" "uint16be@i@iu" (func (;7;) (type 14)))
  (import "yara_x::wasm" "uint8be@i@iu" (func (;8;) (type 14)))
  (import "yara_x::wasm" "uint32@i@iu" (func (;9;) (type 14)))
  (import "yara_x::wasm" "uint16@i@iu" (func (;10;) (type 14)))
  (import "yara_x::wasm" "uint8@i@iu" (func (;11;) (type 14)))
  (import "yara_x::wasm" "str_matches@sr@b" (func (;12;) (type 15)))
  (import "yara_x::wasm" "str_len@s@i" (func (;13;) (type 13)))
  (import "yara_x::wasm" "str_iequals@ss@b" (func (;14;) (type 24)))
  (import "yara_x::wasm" "str_iendswith@ss@b" (func (;15;) (type 24)))
  (import "yara_x::wasm" "str_istartswith@ss@b" (func (;16;) (type 24)))
  (import "yara_x::wasm" "str_icontains@ss@b" (func (;17;) (type 24)))
  (import "yara_x::wasm" "str_endswith@ss@b" (func (;18;) (type 24)))
  (import "yara_x::wasm" "str_startswith@ss@b" (func (;19;) (type 24)))
  (import "yara_x::wasm" "str_contains@ss@b" (func (;20;) (type 24)))
  (import "yara_x::wasm" "str_ge@ss@b" (func (;21;) (type 24)))
  (import "yara_x::wasm" "str_le@ss@b" (func (;22;) (type 24)))
  (import "yara_x::wasm" "str_gt@ss@b" (func (;23;) (type 24)))
  (import "yara_x::wasm" "str_lt@ss@b" (func (;24;) (type 24)))
  (import "yara_x::wasm" "str_ne@ss@b" (func (;25;) (type 24)))
  (import "yara_x::wasm" "str_eq@ss@b" (func (;26;) (type 24)))
  (import "yara_x::wasm" "map_lookup_by_index_string_struct@iiii@s" (func (;27;) (type 23)))
  (import "yara_x::wasm" "map_lookup_by_index_integer_struct@iiii@i" (func (;28;) (type 23)))
  (import "yara_x::wasm" "map_lookup_by_index_string_string@iii@ss" (func (;29;) (type 19)))
  (import "yara_x::wasm" "map_lookup_by_index_integer_string@iii@is" (func (;30;) (type 19)))
  (import "yara_x::wasm" "map_lookup_by_index_string_bool@iii@sb" (func (;31;) (type 18)))
  (import "yara_x::wasm" "map_lookup_by_index_string_float@iii@sf" (func (;32;) (type 20)))
  (import "yara_x::wasm" "map_lookup_by_index_string_integer@iii@si" (func (;33;) (type 19)))
  (import "yara_x::wasm" "map_lookup_by_index_integer_bool@iii@ib" (func (;34;) (type 18)))
  (import "yara_x::wasm" "map_lookup_by_index_integer_float@iii@if" (func (;35;) (type 20)))
  (import "yara_x::wasm" "map_lookup_by_index_integer_integer@iii@ii" (func (;36;) (type 19)))
  (import "yara_x::wasm" "map_lookup_string_struct@sii@u" (func (;37;) (type 16)))
  (import "yara_x::wasm" "map_lookup_integer_struct@iii@u" (func (;38;) (type 16)))
  (import "yara_x::wasm" "map_lookup_string_string@sii@su" (func (;39;) (type 18)))
  (import "yara_x::wasm" "map_lookup_integer_string@iii@su" (func (;40;) (type 18)))
  (import "yara_x::wasm" "map_lookup_integer_bool@iii@bu" (func (;41;) (type 17)))
  (import "yara_x::wasm" "map_lookup_integer_float@iii@fu" (func (;42;) (type 21)))
  (import "yara_x::wasm" "map_lookup_integer_integer@iii@iu" (func (;43;) (type 18)))
  (import "yara_x::wasm" "map_lookup_string_bool@sii@bu" (func (;44;) (type 17)))
  (import "yara_x::wasm" "map_lookup_string_float@sii@fu" (func (;45;) (type 21)))
  (import "yara_x::wasm" "map_lookup_string_integer@sii@iu" (func (;46;) (type 18)))
  (import "yara_x::wasm" "array_indexing_struct@iiii@u" (func (;47;) (type 22)))
  (import "yara_x::wasm" "array_indexing_string@iii@su" (func (;48;) (type 18)))
  (import "yara_x::wasm" "array_indexing_bool@iii@bu" (func (;49;) (type 17)))
  (import "yara_x::wasm" "array_indexing_float@iii@fu" (func (;50;) (type 21)))
  (import "yara_x::wasm" "array_indexing_integer@iii@iu" (func (;51;) (type 18)))
  (import "yara_x::wasm" "lookup_bool@ii@bu" (func (;52;) (type 5)))
  (import "yara_x::wasm" "lookup_float@ii@fu" (func (;53;) (type 7)))
  (import "yara_x::wasm" "lookup_integer@ii@iu" (func (;54;) (type 6)))
  (import "yara_x::wasm" "lookup_value@iii@" (func (;55;) (type 8)))
  (import "yara_x::wasm" "lookup_string@ii@su" (func (;56;) (type 6)))
  (import "yara_x::wasm" "map_len@i@i" (func (;57;) (type 4)))
  (import "yara_x::wasm" "array_len@i@i" (func (;58;) (type 4)))
  (import "yara_x::wasm" "pat_offset@ii@iu" (func (;59;) (type 10)))
  (import "yara_x::wasm" "pat_length@ii@iu" (func (;60;) (type 10)))
  (import "yara_x::wasm" "pat_matches_in@iii@i" (func (;61;) (type 12)))
  (import "yara_x::wasm" "pat_matches@i@i" (func (;62;) (type 4)))
  (import "yara_x::wasm" "is_pat_match_in@iii@b" (func (;63;) (type 11)))
  (import "yara_x::wasm" "is_pat_match_at@ii@b" (func (;64;) (type 9)))
  (import "yara_x::wasm" "global_rule_no_match@i@" (func (;65;) (type 3)))
  (import "yara_x::wasm" "rule_match@i@" (func (;66;) (type 3)))
  (import "yara_x::wasm" "search_for_patterns@@b" (func (;67;) (type 1)))
  (import "yara_x::modules::test_proto2" "test_proto2.to_int@s@iu" (func (;68;) (type 14)))
  (import "yara_x::modules::test_proto2" "test_proto2.get_foo@@su" (func (;69;) (type 2)))
  (import "yara_x::modules::test_proto2" "test_proto2.head@i@su" (func (;70;) (type 14)))
  (import "yara_x::modules::test_proto2" "test_proto2.undef_i64@@iu" (func (;71;) (type 2)))
  (import "yara_x::modules::test_proto2" "test_proto2.nested.nested_func@@b" (func (;72;) (type 1)))
  (import "yara_x::modules::test_proto2" "test_proto2.uppercase@s@s" (func (;73;) (type 13)))
  (import "yara_x::modules::test_proto2" "test_proto2.add@ff@f" (func (;74;) (type 26)))
  (import "yara_x::modules::test_proto2" "test_proto2.add@ii@i" (func (;75;) (type 25)))
  (import "yara_x" "matching_patterns_bitmap_base" (global (;0;) i32))
  (import "yara_x" "filesize" (global (;1;) (mut i64)))
  (import "yara_x" "pattern_search_done" (global (;2;) (mut i32)))
  (import "yara_x" "main_memory" (memory (;0;) 1))
  (func (;76;) (type 0)
    block ;; label = @1
      call 79
    end
    block ;; label = @1
      call 80
    end
  )
  (func (;77;) (type 0)
    i32.const 0
    global.set 2
    call 76
    call 78
  )
  (func (;78;) (type 0)
    block ;; label = @1
      call 81
    end
  )
  (func (;79;) (type 0)
    i32.const 4
  )
  (func (;80;) (type 0)
    i32.const 5
  )
  (func (;81;) (type 0)
    i32.const 6
  )
  (export "main" (func 77))
)"#
        );
    }
}
