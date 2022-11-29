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

use bstr::{BStr, BString, ByteSlice};
use lazy_static::lazy_static;
use walrus::InstrSeqBuilder;
use walrus::ValType::{Externref, F64, I32, I64};
use wasmtime::ExternRef;
use wasmtime::{AsContextMut, Caller, Config, Engine, Linker};

use crate::compiler::{IdentId, LiteralId, PatternId, RuleId};
use crate::scanner::ScanContext;
use crate::symbols::{SymbolLookup, TypeValue};

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

        let ty = module.types.add(&[], &[I64]);
        let (filesize, _) = module.add_import_func("yr", "filesize", ty);

        let ty = module.types.add(&[I32], &[]);
        let (rule_match, _) = module.add_import_func("yr", "rule_match", ty);

        let ty = module.types.add(&[I32], &[I32]);
        let (is_pat_match, _) =
            module.add_import_func("yr", "is_pat_match", ty);

        let ty = module.types.add(&[I32, I64], &[I32]);
        let (is_pat_match_at, _) =
            module.add_import_func("yr", "is_pat_match_at", ty);

        let ty = module.types.add(&[I32, I64, I64], &[I32]);
        let (is_pat_match_in, _) =
            module.add_import_func("yr", "is_pat_match_in", ty);

        let ty = module.types.add(&[I64], &[Externref]);
        let (literal_to_ref, _) =
            module.add_import_func("yr", "literal_to_ref", ty);

        // String comparison
        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_eq, _) = module.add_import_func("yr", "str_eq", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_ne, _) = module.add_import_func("yr", "str_ne", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_gt, _) = module.add_import_func("yr", "str_gt", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_lt, _) = module.add_import_func("yr", "str_lt", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_ge, _) = module.add_import_func("yr", "str_ge", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_le, _) = module.add_import_func("yr", "str_le", ty);

        // String operations
        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_contains, _) =
            module.add_import_func("yr", "str_contains", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_startswith, _) =
            module.add_import_func("yr", "str_startswith", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_endswith, _) =
            module.add_import_func("yr", "str_endswith", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_icontains, _) =
            module.add_import_func("yr", "str_icontains", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_istartswith, _) =
            module.add_import_func("yr", "str_istartswith", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_iendswith, _) =
            module.add_import_func("yr", "str_iendswith", ty);

        let ty = module.types.add(&[Externref, Externref], &[I32]);
        let (str_iequals, _) = module.add_import_func("yr", "str_iequals", ty);

        let ty = module.types.add(&[Externref], &[I64]);
        let (str_len, _) = module.add_import_func("yr", "str_len", ty);

        // Lookup functions
        let ty = module.types.add(&[I64], &[I64, I32]);
        let (lookup_integer, _) =
            module.add_import_func("yr", "lookup_integer", ty);

        let ty = module.types.add(&[I64], &[F64, I32]);
        let (lookup_float, _) =
            module.add_import_func("yr", "lookup_float", ty);

        let ty = module.types.add(&[I64], &[I32, I32]);
        let (lookup_bool, _) = module.add_import_func("yr", "lookup_bool", ty);

        let ty = module.types.add(&[I64], &[I64, I32]);
        let (lookup_string, _) =
            module.add_import_func("yr", "lookup_string", ty);

        let ty = module.types.add(&[I64], &[I64, I32]);
        let (lookup_struct, _) =
            module.add_import_func("yr", "lookup_struct", ty);

        let ty = module.types.add(&[], &[]);
        let (clear_current_struct, _) =
            module.add_import_func("yr", "clear_current_struct", ty);

        let wasm_symbols = WasmSymbols {
            rule_match,
            is_pat_match,
            is_pat_match_at,
            is_pat_match_in,
            literal_to_ref,
            lookup_integer,
            lookup_float,
            lookup_bool,
            lookup_string,
            lookup_struct,
            clear_current_struct,
            str_eq,
            str_ne,
            str_lt,
            str_gt,
            str_le,
            str_ge,
            str_contains,
            str_startswith,
            str_endswith,
            str_icontains,
            str_istartswith,
            str_iendswith,
            str_iequals,
            str_len,
            filesize,
            main_memory: module.memories.add_local(false, 1024, None),
            i64_tmp: module.locals.add(I64),
            i32_tmp: module.locals.add(I32),
            ref_tmp: module.locals.add(Externref),
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

/// String types handled by YARA's WebAssembly runtime.
///
/// At runtime, when the the WebAssembly code generated for rule conditions is
/// being executed, text strings can adopt multiple forms. The difference
/// between them resides in the place in which the string's data is stored.
///
/// For example, literal strings appearing in the source code are stored in
/// a string pool created at compile time, these strings are identified by the
/// [`LiteralId`] returned by the pool. Instead of making copies of those
/// literal strings, the runtime passes the [`LiteralId`] around when referring
/// to them.
///
/// Similarly, functions exported by YARA modules can return strings that
/// appear verbatim in the data being scanned. Instead of making a copy, the
/// runtime passes around only the offset within the data where the string
/// starts and its length.
///
/// In some other cases a function may need to return a string that doesn't
/// appear neither in the scanned data nor as a literal in the source code,
/// in such cases the runtime needs to allocate memory for storing the
/// string.
pub(crate) enum RuntimeString {
    /// A literal string appearing in the source code. The string is identified
    /// by its [`LiteralId`] within the literal strings pool.
    Literal(LiteralId),
    /// A string represented found in the scanned data, represented by the
    /// offset within the data and its length.
    Slice { offset: usize, length: usize },
    /// A string owned by the runtime.
    Owned(BString),
}

impl RuntimeString {
    /// Returns this string as a &[`BStr`].
    fn as_bstr<'a>(&'a self, ctx: &'a ScanContext) -> &'a BStr {
        match self {
            RuntimeString::Literal(id) => {
                ctx.compiled_rules.lit_pool().get(*id).unwrap()
            }
            RuntimeString::Slice { offset, length } => {
                let slice = unsafe {
                    std::slice::from_raw_parts::<u8>(
                        ctx.scanned_data,
                        ctx.scanned_data_len,
                    )
                };
                BStr::new(&slice[*offset..*offset + *length])
            }
            RuntimeString::Owned(s) => s.as_bstr(),
        }
    }

    #[inline]
    fn len(&self, ctx: &ScanContext) -> usize {
        self.as_bstr(ctx).len()
    }

    #[inline]
    fn eq(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).eq(other.as_bstr(ctx))
    }

    #[inline]
    fn ne(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).ne(other.as_bstr(ctx))
    }

    #[inline]
    fn lt(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).lt(other.as_bstr(ctx))
    }

    #[inline]
    fn gt(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).gt(other.as_bstr(ctx))
    }

    #[inline]
    fn le(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).le(other.as_bstr(ctx))
    }

    #[inline]
    fn ge(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).ge(other.as_bstr(ctx))
    }

    #[inline]
    fn contains(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.contains_str(other)
        } else {
            self.as_bstr(ctx).contains_str(other.as_bstr(ctx))
        }
    }

    #[inline]
    fn starts_with(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.starts_with_str(other)
        } else {
            self.as_bstr(ctx).starts_with_str(other.as_bstr(ctx))
        }
    }

    #[inline]
    fn ends_with(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.ends_with_str(other)
        } else {
            self.as_bstr(ctx).ends_with_str(other.as_bstr(ctx))
        }
    }

    #[inline]
    fn equals(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.eq(&other)
        } else {
            self.as_bstr(ctx).eq(other.as_bstr(ctx))
        }
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
    pub main_memory: walrus::MemoryId,

    /// Ask YARA for the size of the data being scanned.
    /// Signature: () -> (i64)     
    pub filesize: walrus::FunctionId,

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

    /// Creates a [`ExternRef`] from a [`LiteralId`] that identifies a string
    /// in the literals pool.
    /// Signature: (string_id: i64) -> (Externref)
    pub literal_to_ref: walrus::FunctionId,

    pub lookup_integer: walrus::FunctionId,
    pub lookup_float: walrus::FunctionId,
    pub lookup_bool: walrus::FunctionId,
    pub lookup_string: walrus::FunctionId,
    pub lookup_struct: walrus::FunctionId,
    pub clear_current_struct: walrus::FunctionId,

    /// String comparison functions.
    /// Signature: (lhs: Externref, rhs: Externref) -> (i32)
    pub str_eq: walrus::FunctionId,
    pub str_ne: walrus::FunctionId,
    pub str_lt: walrus::FunctionId,
    pub str_gt: walrus::FunctionId,
    pub str_le: walrus::FunctionId,
    pub str_ge: walrus::FunctionId,

    /// String operation functions.
    /// Signature: (lhs: Externref, rhs: Externref) -> (i32)
    pub str_contains: walrus::FunctionId,
    pub str_startswith: walrus::FunctionId,
    pub str_endswith: walrus::FunctionId,
    pub str_icontains: walrus::FunctionId,
    pub str_istartswith: walrus::FunctionId,
    pub str_iendswith: walrus::FunctionId,
    pub str_iequals: walrus::FunctionId,
    pub str_len: walrus::FunctionId,

    /// Local variables used for temporary storage.
    pub i64_tmp: walrus::LocalId,
    pub i32_tmp: walrus::LocalId,
    pub ref_tmp: walrus::LocalId,
}

lazy_static! {
    pub(crate) static ref CONFIG: Config = Config::default();
    pub(crate) static ref ENGINE: Engine = Engine::new(&CONFIG).unwrap();
    pub(crate) static ref LINKER: Linker<ScanContext<'static>> = {
        let mut linker = Linker::<ScanContext>::new(&ENGINE);

        linker.func_wrap("yr", "filesize", filesize).unwrap();
        linker.func_wrap("yr", "str_eq", str_eq).unwrap();
        linker.func_wrap("yr", "str_ne", str_ne).unwrap();
        linker.func_wrap("yr", "str_lt", str_lt).unwrap();
        linker.func_wrap("yr", "str_gt", str_gt).unwrap();
        linker.func_wrap("yr", "str_le", str_le).unwrap();
        linker.func_wrap("yr", "str_ge", str_ge).unwrap();
        linker.func_wrap("yr", "str_contains", str_contains).unwrap();
        linker.func_wrap("yr", "str_startswith", str_startswith).unwrap();
        linker.func_wrap("yr", "str_endswith", str_endswith).unwrap();
        linker.func_wrap("yr", "str_icontains", str_icontains).unwrap();
        linker.func_wrap("yr", "str_istartswith", str_istartswith).unwrap();
        linker.func_wrap("yr", "str_iequals", str_iequals).unwrap();
        linker.func_wrap("yr", "str_iendswith", str_iendswith).unwrap();
        linker.func_wrap("yr", "str_len", str_len).unwrap();
        linker.func_wrap("yr", "rule_match", rule_match).unwrap();
        linker.func_wrap("yr", "is_pat_match", is_pat_match).unwrap();
        linker.func_wrap("yr", "is_pat_match_at", is_pat_match_at).unwrap();
        linker.func_wrap("yr", "is_pat_match_in", is_pat_match_in).unwrap();
        linker.func_wrap("yr", "literal_to_ref", literal_to_ref).unwrap();
        linker.func_wrap("yr", "lookup_integer", lookup_integer).unwrap();
        linker.func_wrap("yr", "lookup_float", lookup_float).unwrap();
        linker.func_wrap("yr", "lookup_bool", lookup_bool).unwrap();
        linker.func_wrap("yr", "lookup_string", lookup_string).unwrap();
        linker.func_wrap("yr", "lookup_struct", lookup_struct).unwrap();
        linker
            .func_wrap("yr", "clear_current_struct", clear_current_struct)
            .unwrap();

        linker
    };
}

type MaybeUndef<T> = (T, i32);

trait Empty<T> {
    fn empty() -> T;
}

impl Empty<i64> for i64 {
    fn empty() -> i64 {
        0
    }
}

impl Empty<i32> for i32 {
    fn empty() -> i32 {
        0
    }
}

impl Empty<f64> for f64 {
    fn empty() -> f64 {
        0.0
    }
}

fn defined<T>(value: T) -> MaybeUndef<T> {
    (value, 0)
}

fn undefined<T: Empty<T>>() -> MaybeUndef<T> {
    (T::empty(), 1)
}

/// Invoked from WebAssembly to ask for the size of the data being scanned.
pub(crate) fn filesize(caller: Caller<'_, ScanContext>) -> i64 {
    caller.data().scanned_data_len as i64
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
    _caller: Caller<'_, ScanContext>,
    _pattern_id: PatternId,
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
    _caller: Caller<'_, ScanContext>,
    _pattern_id: PatternId,
    _offset: i64,
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
    _caller: Caller<'_, ScanContext>,
    _pattern_id: PatternId,
    _lower_bound: i64,
    _upper_bound: i64,
) -> i32 {
    // TODO
    0
}

/// Creates a new [`RuntimeString`] for a literal string, and wraps it in a
/// [`ExternRef`].
pub(crate) fn literal_to_ref(
    _caller: Caller<'_, ScanContext>,
    literal_id: i64,
) -> Option<ExternRef> {
    Some(ExternRef::new(RuntimeString::Literal(LiteralId::from(
        literal_id as u32,
    ))))
}

macro_rules! lookup_ident_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            ident_id: i64,
        ) -> ($return_type, i32) {
            let scan_ctx = caller.data();

            let ident = scan_ctx
                .compiled_rules
                .ident_pool()
                .get(IdentId::from(ident_id as u32))
                .unwrap();

            let current_struct = &scan_ctx.current_struct;

            let symbol = if let Some(structure) = current_struct {
                structure.lookup(ident)
            } else {
                scan_ctx.symbol_table.lookup(ident)
            };

            match symbol.unwrap().type_value() {
                $type(Some(v)) => defined(*v as $return_type),
                $type(None) => undefined(),
                _ => unreachable!(),
            }
        }
    };
}

lookup_ident_fn!(lookup_integer, i64, TypeValue::Integer);
lookup_ident_fn!(lookup_float, f64, TypeValue::Float);
lookup_ident_fn!(lookup_bool, i32, TypeValue::Bool);

pub(crate) fn lookup_string(
    caller: Caller<'_, ScanContext>,
    ident_id: i64,
) -> MaybeUndef<i64> {
    let scan_ctx = caller.data();

    let ident = scan_ctx
        .compiled_rules
        .ident_pool()
        .get(IdentId::from(ident_id as u32))
        .unwrap();

    let current_struct = &scan_ctx.current_struct;

    let symbol = if let Some(structure) = current_struct {
        structure.lookup(ident)
    } else {
        scan_ctx.symbol_table.lookup(ident)
    };

    defined(0)
}

pub(crate) fn clear_current_struct(mut caller: Caller<'_, ScanContext>) {
    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();
    scan_ctx.current_struct = None;
}

pub(crate) fn lookup_struct(
    mut caller: Caller<'_, ScanContext>,
    ident_id: i64,
) -> (i64, i32) {
    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();

    let ident = scan_ctx
        .compiled_rules
        .ident_pool()
        .get(IdentId::from(ident_id as u32))
        .unwrap();

    let current_struct = &scan_ctx.current_struct;

    let symbol = if let Some(structure) = current_struct {
        structure.lookup(ident)
    } else {
        scan_ctx.symbol_table.lookup(ident)
    };

    match symbol.unwrap().type_value() {
        TypeValue::Struct(symbol_table) => {
            scan_ctx.current_struct = Some(symbol_table.clone());
        }
        _ => unreachable!(),
    }

    defined(0)
}

macro_rules! str_cmp_fn {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            lhs: Option<ExternRef>,
            rhs: Option<ExternRef>,
        ) -> i32 {
            let lhs_ref = lhs.unwrap();
            let rhs_ref = rhs.unwrap();
            let lhs_str =
                lhs_ref.data().downcast_ref::<RuntimeString>().unwrap();
            let rhs_str =
                rhs_ref.data().downcast_ref::<RuntimeString>().unwrap();

            lhs_str.$op(rhs_str, caller.data()) as i32
        }
    };
}

str_cmp_fn!(str_eq, eq);
str_cmp_fn!(str_ne, ne);
str_cmp_fn!(str_lt, lt);
str_cmp_fn!(str_gt, gt);
str_cmp_fn!(str_le, le);
str_cmp_fn!(str_ge, ge);

macro_rules! str_op_fn {
    ($name:ident, $op:tt, $case_insensitive:literal) => {
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            lhs: Option<ExternRef>,
            rhs: Option<ExternRef>,
        ) -> i32 {
            let lhs_ref = lhs.unwrap();
            let rhs_ref = rhs.unwrap();
            let lhs_str =
                lhs_ref.data().downcast_ref::<RuntimeString>().unwrap();
            let rhs_str =
                rhs_ref.data().downcast_ref::<RuntimeString>().unwrap();

            lhs_str.$op(rhs_str, caller.data(), $case_insensitive) as i32
        }
    };
}

str_op_fn!(str_contains, contains, false);
str_op_fn!(str_startswith, starts_with, false);
str_op_fn!(str_endswith, ends_with, false);
str_op_fn!(str_icontains, contains, true);
str_op_fn!(str_istartswith, starts_with, true);
str_op_fn!(str_iendswith, ends_with, true);
str_op_fn!(str_iequals, equals, true);

pub(crate) fn str_len(
    caller: Caller<'_, ScanContext>,
    string: Option<ExternRef>,
) -> i64 {
    let string_ref = string.unwrap();
    let string = string_ref.data().downcast_ref::<RuntimeString>().unwrap();

    string.len(caller.data()) as i64
}
