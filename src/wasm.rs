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

use std::stringify;

use bstr::{BStr, BString, ByteSlice};
use lazy_static::lazy_static;
use walrus::InstrSeqBuilder;
use walrus::ValType::{Externref, F64, I32, I64};
use wasmtime::ExternRef;
use wasmtime::{AsContextMut, Caller, Config, Engine, Linker};

use crate::compiler::{IdentId, LiteralId, PatternId, RuleId};
use crate::scanner::ScanContext;
use crate::symbols::{Symbol, SymbolValue};
use crate::types::Value;

/// Builds the WebAssembly module for a set of compiled rules.
pub(crate) struct ModuleBuilder {
    module: walrus::Module,
    wasm_symbols: WasmSymbols,
    main_fn: walrus::FunctionBuilder,
}

/// Helper macro tha adds imports to a module.
///
/// # Example
///
/// This add an import for a function named `my_function`, that receives an
/// `i64` and returns an `Externref`.
///
/// ```ignore
/// import!(module, my_function, [I64], [Externref]);
/// ```
macro_rules! import {
    ($module:ident, $fn_name:ident, [$( $arg:ident ),*], [$( $result:ident ),*] ) => {
        let ty = $module.types.add(&[$( $arg ),*], &[$( $result ),*]);
        let ($fn_name, _) =
            $module.add_import_func("yr", stringify!($fn_name), ty);
    };
}

macro_rules! global {
    ($module:ident, $name:ident, $ty:ident ) => {
        let ($name, _) =
            $module.add_import_global("yr", stringify!($name), $ty, true);
    };
}

impl ModuleBuilder {
    /// Module's memory size in pages. Page size is 64KB.
    pub(crate) const MODULE_MEMORY_SIZE: u32 = 1;

    /// Creates a new module builder.
    pub fn new() -> Self {
        let config = walrus::ModuleConfig::new();
        let mut module = walrus::Module::with_config(config);

        global!(module, filesize, I64);

        import!(module, rule_match, [I32], []);
        import!(module, is_pat_match, [I32], [I32]);
        import!(module, is_pat_match_at, [I32, I64], [I32]);
        import!(module, is_pat_match_in, [I32, I64, I64], [I32]);
        import!(module, literal_to_ref, [I64], [Externref]);

        import!(module, str_eq, [Externref, Externref], [I32]);
        import!(module, str_ne, [Externref, Externref], [I32]);
        import!(module, str_gt, [Externref, Externref], [I32]);
        import!(module, str_lt, [Externref, Externref], [I32]);
        import!(module, str_ge, [Externref, Externref], [I32]);
        import!(module, str_le, [Externref, Externref], [I32]);

        import!(module, str_contains, [Externref, Externref], [I32]);
        import!(module, str_icontains, [Externref, Externref], [I32]);
        import!(module, str_startswith, [Externref, Externref], [I32]);
        import!(module, str_endswith, [Externref, Externref], [I32]);
        import!(module, str_istartswith, [Externref, Externref], [I32]);
        import!(module, str_iendswith, [Externref, Externref], [I32]);
        import!(module, str_iequals, [Externref, Externref], [I32]);
        import!(module, str_len, [Externref], [I64]);

        import!(module, symbol_lookup_integer, [I64], [I64, I32]);
        import!(module, symbol_lookup_float, [I64], [F64, I32]);
        import!(module, symbol_lookup_bool, [I64], [I32, I32]);
        import!(module, symbol_lookup_string, [I64], [Externref]);
        import!(module, symbol_lookup_array, [I64], []);
        import!(module, symbol_lookup_struct, [I64], []);
        import!(module, symbol_lookup_map, [I64], []);

        import!(module, array_lookup_integer, [I64], [I64, I32]);
        import!(module, map_lookup_integer, [Externref], [I64, I32]);

        let wasm_symbols = WasmSymbols {
            rule_match,
            is_pat_match,
            is_pat_match_at,
            is_pat_match_in,
            literal_to_ref,
            symbol_lookup_integer,
            symbol_lookup_float,
            symbol_lookup_bool,
            symbol_lookup_string,
            symbol_lookup_struct,
            symbol_lookup_array,
            symbol_lookup_map,
            array_lookup_integer,
            map_lookup_integer,
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
            main_memory: module.memories.add_local(
                false,
                Self::MODULE_MEMORY_SIZE,
                None,
            ),
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
    pub filesize: walrus::GlobalId,

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

    /// Functions that given an `IdentId`, search for the identifier in the
    /// current symbol table and return its value. In the case of structs,
    /// arrays and maps the value is not returned, but is stored in
    /// ScanContext::current_struct, ScanContext::current_array and
    /// ScanContext::current_map, respectively.
    pub symbol_lookup_integer: walrus::FunctionId,
    pub symbol_lookup_float: walrus::FunctionId,
    pub symbol_lookup_bool: walrus::FunctionId,
    pub symbol_lookup_string: walrus::FunctionId,
    pub symbol_lookup_struct: walrus::FunctionId,
    pub symbol_lookup_array: walrus::FunctionId,
    pub symbol_lookup_map: walrus::FunctionId,

    pub array_lookup_integer: walrus::FunctionId,
    pub map_lookup_integer: walrus::FunctionId,

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
    pub(crate) static ref CONFIG: Config = {
        let mut config = Config::default();
        config.cranelift_opt_level(wasmtime::OptLevel::SpeedAndSize);
        config
    };
    pub(crate) static ref ENGINE: Engine = Engine::new(&CONFIG).unwrap();
    pub(crate) static ref LINKER: Linker<ScanContext<'static>> = new_linker();
}

macro_rules! add_function {
    ($linker:ident, $name:ident) => {
        $linker.func_wrap("yr", stringify!($name), $name).unwrap();
    };
}

pub(crate) fn new_linker<'r>() -> Linker<ScanContext<'r>> {
    let mut linker = Linker::<ScanContext<'r>>::new(&ENGINE);

    add_function!(linker, filesize);
    add_function!(linker, str_eq);
    add_function!(linker, str_ne);
    add_function!(linker, str_lt);
    add_function!(linker, str_gt);
    add_function!(linker, str_le);
    add_function!(linker, str_ge);
    add_function!(linker, str_contains);
    add_function!(linker, str_startswith);
    add_function!(linker, str_endswith);
    add_function!(linker, str_icontains);
    add_function!(linker, str_istartswith);
    add_function!(linker, str_iequals);
    add_function!(linker, str_iendswith);
    add_function!(linker, str_len);
    add_function!(linker, rule_match);
    add_function!(linker, is_pat_match);
    add_function!(linker, is_pat_match_at);
    add_function!(linker, is_pat_match_in);
    add_function!(linker, literal_to_ref);
    add_function!(linker, symbol_lookup_integer);
    add_function!(linker, symbol_lookup_float);
    add_function!(linker, symbol_lookup_string);
    add_function!(linker, symbol_lookup_bool);
    add_function!(linker, symbol_lookup_struct);
    add_function!(linker, symbol_lookup_array);
    add_function!(linker, symbol_lookup_map);
    add_function!(linker, array_lookup_integer);
    add_function!(linker, map_lookup_integer);

    linker
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

/// Given the IdentId for some identifier of type [`crate::Type::String`],
/// looks for the identifier in the current symbol table, creates an externref
/// for the string, and pushes the externref in the wasm stack. If the
/// identifier is not found, it pushes a null externref instead.
pub(crate) fn symbol_lookup_string(
    mut caller: Caller<'_, ScanContext>,
    ident_id: i64,
) -> Option<ExternRef> {
    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();

    let ident = scan_ctx
        .compiled_rules
        .ident_pool()
        .get(IdentId::from(ident_id as u32))
        .unwrap();

    let symbol = scan_ctx.lookup(ident);

    match symbol.value() {
        SymbolValue::Value(Value::String(s)) => {
            Some(ExternRef::new(RuntimeString::Owned(s.clone())))
        }
        SymbolValue::Value(Value::Unknown) => None,
        _ => unreachable!(),
    }
}

/// Given the IdentId for some identifier of type [`crate::Type::Struct`],
/// looks for the identifier in the current symbol and stores a reference
/// to the structure in [`ScanContext::current_struct`]. The next call to
/// `lookup_xxx` will use the structure's symbol table instead of the main
/// symbol table.
pub(crate) fn symbol_lookup_struct(
    mut caller: Caller<'_, ScanContext>,
    ident_id: i64,
) {
    // Search for the identifier in the pool
    let ident = caller
        .data()
        .compiled_rules
        .ident_pool()
        .get(IdentId::from(ident_id as u32))
        .unwrap();

    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();
    let symbol = scan_ctx.lookup(ident);

    scan_ctx.current_struct =
        if let SymbolValue::Struct(symbol_table) = symbol.value() {
            Some(symbol_table.to_owned())
        } else {
            // This should not happen, the symbol with the given identifier
            // must exist and be a struct.
            unreachable!()
        };
}

/// Given the IdentId for some identifier of type [`crate::Type::Array`],
/// looks for the identifier in the current symbol and stores a reference
/// to the array in [`ScanContext::current_struct`].
pub(crate) fn symbol_lookup_array(
    mut caller: Caller<'_, ScanContext>,
    ident_id: i64,
) {
    let ident = caller
        .data()
        .compiled_rules
        .ident_pool()
        .get(IdentId::from(ident_id as u32))
        .unwrap();

    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();
    let symbol = scan_ctx.lookup(ident);

    scan_ctx.current_array = if let SymbolValue::Array(array) = symbol.value()
    {
        Some(array.to_owned())
    } else {
        // This should not happen, the symbol with the given identifier
        // must exist and be an array.
        unreachable!()
    };
}

/// Given the IdentId for some identifier of type [`crate::Type::Map`],
/// looks for the identifier in the current symbol and stores a reference
/// to the array in [`ScanContext::current_map`].
pub(crate) fn symbol_lookup_map(
    mut caller: Caller<'_, ScanContext>,
    ident_id: i64,
) {
    let ident = caller
        .data()
        .compiled_rules
        .ident_pool()
        .get(IdentId::from(ident_id as u32))
        .unwrap();

    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();
    let symbol = scan_ctx.lookup(ident);

    scan_ctx.current_map = if let SymbolValue::Map(map) = symbol.value() {
        Some(map.to_owned())
    } else {
        // This should not happen, the symbol with the given identifier
        // must exist and be a map.
        unreachable!()
    };
}

/// Macro that generates functions similar to [`lookup_struct`] and
/// [`lookup_string`] but for integers, floats and booleans.
macro_rules! symbol_lookup_ident_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            ident_id: i64,
        ) -> MaybeUndef<$return_type> {
            let mut store_ctx = caller.as_context_mut();
            let scan_ctx = store_ctx.data_mut();

            let ident = scan_ctx
                .compiled_rules
                .ident_pool()
                .get(IdentId::from(ident_id as u32))
                .unwrap();

            let symbol = scan_ctx.lookup(ident);

            if let SymbolValue::Value($type(value)) = symbol.value() {
                defined(*value as $return_type)
            } else {
                undefined()
            }
        }
    };
}

symbol_lookup_ident_fn!(symbol_lookup_integer, i64, Value::Integer);
symbol_lookup_ident_fn!(symbol_lookup_float, f64, Value::Float);
symbol_lookup_ident_fn!(symbol_lookup_bool, i32, Value::Bool);

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

pub(crate) fn array_lookup_integer(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
) -> MaybeUndef<i64> {
    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();

    let array = scan_ctx.current_array.take().unwrap();
    if let Some(symbol) = array.index(index as usize) {
        match symbol.value() {
            SymbolValue::Value(Value::Integer(value)) => defined(*value),
            SymbolValue::Value(Value::Unknown) => undefined(),
            _ => unreachable!(),
        }
    } else {
        undefined()
    }
}

pub(crate) fn map_lookup_integer(
    mut caller: Caller<'_, ScanContext>,
    key: Option<ExternRef>,
) -> MaybeUndef<i64> {
    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();

    let map = scan_ctx.current_map.take().unwrap();
    let k = key.unwrap();

    let r = k.data().downcast_ref::<RuntimeString>().unwrap();
    let a = r.as_bstr(scan_ctx);

    if let Some(symbol) = map.index(a.to_owned()) {
        match symbol.value() {
            SymbolValue::Value(Value::Integer(value)) => defined(*value),
            SymbolValue::Value(Value::Unknown) => undefined(),
            _ => unreachable!(),
        }
    } else {
        undefined()
    }
}
