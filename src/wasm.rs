/*! WebAssembly runtime

During the compilation process the condition associated to each YARA rule is
translated into WebAssembly code. This code is later compiled to native code
and executed by [wasmtime](https://wasmtime.dev/), a WebAssembly runtime
embedded in YARA.

For each instance of [`CompiledRules`] the compiler creates a WebAssembly
module. This module exports a function called `main`, which contains the code
that evaluates the conditions of all the compiled rules. The `main` function
is invoked at scan time, and for each rule the WebAssembly module calls
YARA back (via the `rule_result` function) and reports if the rule matched
or not.

The WebAssembly module also calls YARA in many other cases, for example
when it needs to invoke YARA built-in functions like `uint8(...)`, when it
needs to get the value for the `filesize` keyword, etc.

This module implements the logic for building these WebAssembly modules, and
the functions exposed to them by YARA's WebAssembly runtime.
 */

use crate::compiler::{PatternID, RuleID};
use lazy_static::lazy_static;
use std::borrow::BorrowMut;
use walrus::InstrSeqBuilder;
use walrus::ValType::{I32, I64};
use wasmtime::{AsContextMut, Caller, Config, Engine, Linker};

use crate::scanner::ScanContext;

/// Builds the WebAssembly module for a set of compiled rules.
pub(crate) struct ModuleBuilder {
    module: walrus::Module,
    fn_table: BuiltinFnTable,
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

        let fn_table = BuiltinFnTable {
            rule_match,
            is_pat_match,
            is_pat_match_at,
            is_pat_match_in,
        };

        let main_fn =
            walrus::FunctionBuilder::new(&mut module.types, &[], &[]);

        Self { module, fn_table, main_fn }
    }

    /// Returns a [`InstrSeqBuilder`] for the module's main function.
    ///
    /// This allows adding code to the module's `main` function.
    pub fn main_fn(&mut self) -> InstrSeqBuilder {
        self.main_fn.func_body()
    }

    /// Returns the functions imported by the module.
    pub fn imports(&self) -> BuiltinFnTable {
        self.fn_table.clone()
    }

    /// Builds the module and consumes the builder.
    pub fn build(mut self) -> walrus::Module {
        let main_fn = self.main_fn.finish(Vec::new(), &mut self.module.funcs);
        self.module.exports.add("main", main_fn);
        self.module
    }
}

/// Table with built-in functions imported by the WebAssembly module.
///
/// The WebAssembly module generated for evaluating rule conditions needs to
/// call back to YARA for multiple tasks. For example, it calls YARA for
/// reporting rule matches, for asking if a pattern matches at a given offset,
/// for executing functions like `uint32()`, etc.
///
/// This table contains the [`FunctionId`] for such functions, which are
/// imported by the WebAssembly module and implemented by YARA.
#[derive(Clone)]
pub(crate) struct BuiltinFnTable {
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
}

lazy_static! {
    pub(crate) static ref CONFIG: Config = Config::default();
    pub(crate) static ref ENGINE: Engine = Engine::new(&CONFIG).unwrap();
    pub(crate) static ref LINKER: Linker<ScanContext> = {
        let mut linker = Linker::<ScanContext>::new(&ENGINE);
        linker.func_wrap("internal", "rule_match", rule_match).unwrap();
        linker.func_wrap("internal", "is_pat_match", is_pat_match).unwrap();
        linker
            .func_wrap("internal", "is_pat_match_at", is_pat_match_at)
            .unwrap();
        linker
            .func_wrap("internal", "is_pat_match_in", is_pat_match_in)
            .unwrap();
        linker
    };
}

/// Invoked from WebAssembly to notify when a rule matches.
fn rule_match(mut caller: Caller<'_, ScanContext>, rule_id: RuleID) {
    // The RuleID-th bit in the `rule_matches` bit vector is set to 1.
    caller
        .as_context_mut()
        .data_mut()
        .rule_matches
        .set(rule_id as usize, true);
}

/// Invoked from WebAssembly to ask whether a pattern matches or not.
///
/// Returns 1 if the pattern identified by `pattern_id` matches, or 0 if
/// otherwise.
fn is_pat_match(
    caller: Caller<'_, ScanContext>,
    pattern_id: PatternID,
) -> i32 {
    // TODO
    0
}

/// Invoked from WebAssembly to ask whether a pattern matches at a given file
/// offset.
///
/// Returns 1 if the pattern identified by `pattern_id` matches at `offset`,
/// or 0 if otherwise.
fn is_pat_match_at(
    caller: Caller<'_, ScanContext>,
    pattern_id: PatternID,
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
fn is_pat_match_in(
    caller: Caller<'_, ScanContext>,
    pattern_id: PatternID,
    lower_bound: i64,
    upper_bound: i64,
) -> i32 {
    // TODO
    0
}
