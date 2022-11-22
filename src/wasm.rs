/*! WebAssembly runtime

During the compilation process the condition associated to each YARA rule is
translated into WebAssembly code. This code is later compiled to native code
and executed by [wasmtime](https://wasmtime.dev/), a WebAssembly runtime
embedded in YARA.

For each instance of [`CompiledRules`] the compiler creates a WebAssembly
module. This module exports a function called `main`, which contains the code
that evaluates the conditions of all the compiled rules. The `main` function
is invoked at scan time, and for each matching rule the WebAssembly module
calls YARA back (via the `rule_match` function) and reports the match.

The WebAssembly module also calls YARA in many other cases, for example
when it needs to invoke YARA built-in functions like `uint8(...)`, when it
needs to get the value for the `filesize` keyword, etc.

This module implements the logic for building these WebAssembly modules, and
the functions exposed to them by YARA's WebAssembly runtime.
 */

use crate::compiler::{PatternId, RuleId};
use lazy_static::lazy_static;
use std::ops::Add;
use walrus::InstrSeqBuilder;
use walrus::ValType::{Externref, I32, I64};
use wasmtime::ExternRef;
use wasmtime::{AsContextMut, Caller, Config, Engine, Linker, ValType};

use crate::scanner::ScanContext;
use crate::string_pool::StringId;

/// Builds the WebAssembly module for a set of compiled rules.
pub(crate) struct ModuleBuilder {
    module: walrus::Module,
    wasm_symbols: WasmSymbols,
    main_fn: walrus::FunctionBuilder,
}

impl ModuleBuilder {
    /// Creates a new module builder.
    pub fn new() -> Self {
        let config = walrus::ModuleConfig::new();
        let mut module = walrus::Module::with_config(config);

        let ty = module.types.add(&[I32], &[]);
        let (rule_match, _) =
            module.add_import_func("internal", "rule_match", ty);

        let ty = module.types.add(&[I32], &[I32]);
        let (is_pat_match, _) =
            module.add_import_func("internal", "is_pat_match", ty);

        let ty = module.types.add(&[I32, I64], &[I32]);
        let (is_pat_match_at, _) =
            module.add_import_func("internal", "is_pat_match_at", ty);

        let ty = module.types.add(&[I32, I64, I64], &[I32]);
        let (is_pat_match_in, _) =
            module.add_import_func("internal", "is_pat_match_in", ty);

        let ty = module.types.add(&[I32], &[Externref]);
        let (lit_lookup, _) =
            module.add_import_func("internal", "lit_lookup", ty);

        let ty = module.types.add(&[], &[Externref]);
        let (test, _) = module.add_import_func("internal", "test", ty);

        let ty = module.types.add(&[Externref], &[Externref]);
        let (concat, _) = module.add_import_func("internal", "concat", ty);

        let ty = module.types.add(&[Externref], &[]);
        let (dbg, _) = module.add_import_func("internal", "dbg", ty);

        let wasm_symbols = WasmSymbols {
            rule_match,
            is_pat_match,
            is_pat_match_at,
            is_pat_match_in,
            lit_lookup,
            test,
            concat,
            dbg,
            i64_tmp: module.locals.add(I64),
            i32_tmp: module.locals.add(I32),
            ref_tmp: module.locals.add(Externref),
            exception_flag: module.locals.add(I32),
        };

        let main_fn =
            walrus::FunctionBuilder::new(&mut module.types, &[], &[]);

        Self { module, wasm_symbols, main_fn }
    }

    /// Returns a [`InstrSeqBuilder`] for the module's main function.
    ///
    /// This allows adding code to the module's `main` function.
    pub fn main_fn(&mut self) -> InstrSeqBuilder {
        self.main_fn.func_body()
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

/// Table with functions and variables used by the WebAssembly module.
///
/// The WebAssembly module generated for evaluating rule conditions needs to
/// call back to YARA for multiple tasks. For example, it calls YARA for
/// reporting rule matches, for asking if a pattern matches at a given offset,
/// for executing functions like `uint32()`, etc.
///
/// This table contains the [`FunctionId`] for such functions, which are
/// imported by the WebAssembly module and implemented by YARA. It also
/// contains the definition of some variables used by the module.
#[derive(Clone)]
pub(crate) struct WasmSymbols {
    /// Called when a rule matches.
    /// Signature: (rule_id: i32) -> ()
    pub rule_match: walrus::FunctionId,

    /// Ask YARA whether a pattern matched or not.
    /// Signature: (pattern_id: i32) -> (i32)
    pub is_pat_match: walrus::FunctionId,

    /// Ask YARA whether a pattern matched at a specific offset.
    /// Signature: (pattern_id: i32, offset: i64) -> (i32)
    pub is_pat_match_at: walrus::FunctionId,

    /// Ask YARA whether a pattern matched within a range of offsets.
    /// Signature: (pattern_id: i32, lower_bound: i64, upper_bound: i64) -> (i32)
    pub is_pat_match_in: walrus::FunctionId,

    pub lit_lookup: walrus::FunctionId,

    pub test: walrus::FunctionId,
    pub concat: walrus::FunctionId,
    pub dbg: walrus::FunctionId,

    /// Local variables used for temporary storage.
    pub i64_tmp: walrus::LocalId,
    pub i32_tmp: walrus::LocalId,
    pub ref_tmp: walrus::LocalId,

    /// Set to 1 when an exception is raised. This is used by the exception
    /// handling logic.
    pub exception_flag: walrus::LocalId,
}

lazy_static! {
    pub(crate) static ref CONFIG: Config = Config::default();
    pub(crate) static ref ENGINE: Engine = Engine::new(&CONFIG).unwrap();
    pub(crate) static ref LINKER: Linker<ScanContext<'static>> = {
        let mut linker = Linker::<ScanContext>::new(&ENGINE);
        linker.func_wrap("internal", "rule_match", rule_match).unwrap();
        linker.func_wrap("internal", "is_pat_match", is_pat_match).unwrap();
        linker
            .func_wrap("internal", "is_pat_match_at", is_pat_match_at)
            .unwrap();
        linker
            .func_wrap("internal", "is_pat_match_in", is_pat_match_in)
            .unwrap();

        linker.func_wrap("internal", "test", test).unwrap();
        linker.func_wrap("internal", "concat", concat).unwrap();
        linker.func_wrap("internal", "dbg", dbg).unwrap();

        linker
    };
}

/// Invoked from WebAssembly to notify when a rule matches.
pub(crate) fn rule_match(
    mut caller: Caller<'_, ScanContext>,
    rule_id: RuleId,
) {
    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();

    // The RuleID-th bit in the `rule_matches` bit vector is set to 1.
    scan_ctx.rules_matching_bitmap.set(rule_id as usize, true);
    scan_ctx.rules_matching.push(rule_id);
}

/// Invoked from WebAssembly to ask whether a pattern matches or not.
///
/// Returns 1 if the pattern identified by `pattern_id` matches, or 0 if
/// otherwise.
pub(crate) fn is_pat_match(
    caller: Caller<'_, ScanContext>,
    pattern_id: PatternId,
) -> i32 {
    // TODO
    0
}

/// Invoked from WebAssembly to ask whether a pattern matches at a given file
/// offset.
///
/// Returns 1 if the pattern identified by `pattern_id` matches at `offset`,
/// or 0 if otherwise.
pub(crate) fn is_pat_match_at(
    caller: Caller<'_, ScanContext>,
    pattern_id: PatternId,
    offset: i64,
) -> i32 {
    // TODO
    0
}

/// Invoked from WebAssembly to ask whether a pattern at some offset within
/// given range.
///
/// Returns 1 if the pattern identified by `pattern_id` matches at some offset
/// in the range [`lower_bound`, `upper_bound`].
pub(crate) fn is_pat_match_in(
    caller: Caller<'_, ScanContext>,
    pattern_id: PatternId,
    lower_bound: i64,
    upper_bound: i64,
) -> i32 {
    // TODO
    0
}

pub(crate) fn lit_lookup(
    caller: Caller<'_, ScanContext>,
    pattern_id: StringId,
) -> Option<ExternRef> {
    None
}

pub(crate) fn dbg(
    caller: Caller<'_, ScanContext>,
    extern_ref: Option<ExternRef>,
) {
    let ext_ref = extern_ref.unwrap();
    let s = ext_ref.data().downcast_ref::<String>().unwrap();
    dbg!(s);
}

pub(crate) enum Str {
    String(String),
}

pub(crate) fn test(caller: Caller<'_, ScanContext>) -> Option<ExternRef> {
    Some(ExternRef::new(Str::String("foo".to_string())))
}

pub(crate) fn concat(
    caller: Caller<'_, ScanContext>,
    extern_ref: Option<ExternRef>,
) -> Option<ExternRef> {
    let ext_ref = extern_ref.unwrap();
    let s = ext_ref.data().downcast_ref::<Str>().unwrap();

    if let Str::String(s) = s {
        let s = String::from(s);
        let s1 = s.add("bar");
        return Some(ExternRef::new(s1));
    }

    None
}
