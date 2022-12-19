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
needs to invoke a function exported by a YARA module, etc.

This module implements the logic for building these WebAssembly modules, and
the functions exposed to them by YARA's WebAssembly runtime.
 */

use std::borrow::{Borrow, BorrowMut};
use std::stringify;

use bstr::{BStr, ByteSlice};
use lazy_static::lazy_static;
use wasmtime::{AsContextMut, Caller, Config, Engine, Linker};

use crate::compiler::{LiteralId, PatternId, RuleId};
use crate::scanner::{RuntimeStringId, ScanContext};
use crate::types::{RuntimeMap, RuntimeValue};

pub(crate) mod builder;

/// Offset in module's main memory where the space for loop variables start.
pub(crate) const LOOP_VARS_START: i32 = 0;
/// Offset in module's main memory where the space for loop variables end.
pub(crate) const LOOP_VARS_END: i32 = LOOP_VARS_START + 1024;

/// Offset in module's main memory where the space for lookup indexes start.
pub(crate) const LOOKUP_INDEXES_START: i32 = LOOP_VARS_END;
/// Offset in module's main memory where the space for lookup indexes end.
pub(crate) const LOOKUP_INDEXES_END: i32 = LOOKUP_INDEXES_START + 1024;

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
    /// The WebAssembly module's main memory.
    pub main_memory: walrus::MemoryId,

    pub lookup_stack_top: walrus::GlobalId,

    /// Global variable that contains the value for `filesize`.
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

    /// Functions that given an `IdentId`, search for the identifier in the
    /// current symbol table and return its value. In the case of structs,
    /// arrays and maps the value is not returned, but is stored in
    /// ScanContext::current_struct, ScanContext::current_array and
    /// ScanContext::current_map, respectively.
    pub lookup_integer: walrus::FunctionId,
    pub lookup_float: walrus::FunctionId,
    pub lookup_bool: walrus::FunctionId,
    pub lookup_string: walrus::FunctionId,

    pub array_lookup_integer: walrus::FunctionId,
    pub array_lookup_float: walrus::FunctionId,
    pub array_lookup_bool: walrus::FunctionId,
    pub array_lookup_string: walrus::FunctionId,
    pub array_lookup_struct: walrus::FunctionId,

    pub map_lookup_integer_integer: walrus::FunctionId,
    pub map_lookup_string_integer: walrus::FunctionId,
    pub map_lookup_integer_float: walrus::FunctionId,
    pub map_lookup_string_float: walrus::FunctionId,
    pub map_lookup_integer_bool: walrus::FunctionId,
    pub map_lookup_string_bool: walrus::FunctionId,
    pub map_lookup_integer_string: walrus::FunctionId,
    pub map_lookup_string_string: walrus::FunctionId,
    pub map_lookup_integer_struct: walrus::FunctionId,
    pub map_lookup_string_struct: walrus::FunctionId,

    /// String comparison functions.
    /// Signature: (lhs_0: i64, lhs_1: i64, rhs_0: i64, rhs_1: i64) -> (i32)
    pub str_eq: walrus::FunctionId,
    pub str_ne: walrus::FunctionId,
    pub str_lt: walrus::FunctionId,
    pub str_gt: walrus::FunctionId,
    pub str_le: walrus::FunctionId,
    pub str_ge: walrus::FunctionId,

    /// String operation functions.
    /// Signature: (lhs_0: i64, lhs_1: i64, rhs_0: i64, rhs_1: i64) -> (i32)
    pub str_contains: walrus::FunctionId,
    pub str_startswith: walrus::FunctionId,
    pub str_endswith: walrus::FunctionId,
    pub str_icontains: walrus::FunctionId,
    pub str_istartswith: walrus::FunctionId,
    pub str_iendswith: walrus::FunctionId,
    pub str_iequals: walrus::FunctionId,
    pub str_len: walrus::FunctionId,

    /// Local variable used for temporary storage.
    pub i64_tmp: walrus::LocalId,
}

/// Represents a [`RuntimeString`] as a tuple that can be passed from
/// WebAssembly to host and vice-versa.
///
/// The types that we can pass to (and receive from) WebAssembly functions are
/// only primitive types (i64, i32, f64 and f32). In order to be able to pass
/// a [`RuntimeString`] to and from WebAssembly, it must be represented as a
/// tuple of primitive types.
///
/// This tuple is composed of two `u64` values, containing all the information
/// required for uniquely identifying the string. This is how the information
/// is encoded:
///
/// * `RuntimeString:Undef`  -> `(X, 0)`
///    A zero in the second value is enough for representing an undefined string,
///    `X` can be an arbitrary value.
///
/// * `RuntimeString:Literal`  -> `(LiteralId, 1)`
///
/// * `RuntimeString:Owned`  -> `(RuntimeStringId, 2)`
///
/// * `RuntimeString:Owned`  -> `(Offset, Len << 32 | 3)`
///   The offset within the scanned data is stored in the first value, and the
///   length of the string in the higher 32-bits of the second value. The lower
///   32-bits have the value 3.
///
pub(crate) type RuntimeStringWasm = (u64, u64);

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
/// starts, and its length.
///
/// In some other cases a function may need to return a string that doesn't
/// appear neither in the scanned data nor as a literal in the source code,
/// in such cases the runtime stores the string a pool maintained by
/// [`ScanContext`], and passes around only the ID that allows locating the
/// string in that pool.
#[derive(Debug, PartialEq)]
pub(crate) enum RuntimeString {
    /// An undefined string.
    Undef,
    /// A literal string appearing in the source code. The string is identified
    /// by its [`LiteralId`] within the literal strings pool.
    Literal(LiteralId),
    /// A string represented found in the scanned data, represented by the
    /// offset within the data and its length.
    Slice { offset: usize, length: usize },
    /// A string owned by the runtime. The string is identified by its
    /// [`RuntimeStringId`] within the string pool stored in [`ScanContext`].
    Owned(RuntimeStringId),
}

impl RuntimeString {
    /// Returns this string as a &[`BStr`].
    fn as_bstr<'a>(&'a self, ctx: &'a ScanContext) -> &'a BStr {
        match self {
            RuntimeString::Undef => {
                panic!("as_bstr() called for RuntimeString::Undef")
            }
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
            RuntimeString::Owned(id) => ctx.string_pool.get(*id).unwrap(),
        }
    }

    /// Returns this string as a tuple of primitive types suitable to be
    /// passed to WebAssembly.
    pub(crate) fn as_wasm(&self) -> RuntimeStringWasm {
        match self {
            // Undefined strings are represented as (0, 0)
            RuntimeString::Undef => (0, 0),
            // Literal strings are represented as (1, LiteralId)
            RuntimeString::Literal(id) => (u64::from(*id), 1),
            // Owned strings are represented as (2, RuntimeStringId)
            RuntimeString::Owned(id) => (*id as u64, 2),
            // Slices are represented as (length << 32 | 1, offset). This
            // implies that slice length is limited to 4GB, as it must fit
            // in the upper 32-bits of the first item in the tuple.
            RuntimeString::Slice { offset, length } => {
                if *length <= u32::MAX as usize {
                    (*offset as u64, (*length << 32 | 3) as u64)
                } else {
                    panic!(
                        "runtime-string slices can't be larger than {}",
                        u32::MAX
                    )
                }
            }
        }
    }

    /// Creates a [`RuntimeString`] from a [`RuntimeStringTuple`].
    pub(crate) fn from_wasm(tuple: RuntimeStringWasm) -> Self {
        match tuple.1 & 0xff {
            1 => Self::Literal(LiteralId::from(tuple.0 as u32)),
            2 => Self::Owned(tuple.0 as u32),
            3 => Self::Slice {
                offset: tuple.0 as usize,
                length: (tuple.1 >> 32) as usize,
            },
            _ => unreachable!(),
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
    add_function!(linker, lookup_integer);
    add_function!(linker, lookup_float);
    add_function!(linker, lookup_string);
    add_function!(linker, lookup_bool);
    add_function!(linker, array_lookup_integer);
    add_function!(linker, array_lookup_float);
    add_function!(linker, array_lookup_bool);
    add_function!(linker, array_lookup_string);
    add_function!(linker, array_lookup_struct);
    add_function!(linker, map_lookup_integer_integer);
    add_function!(linker, map_lookup_string_integer);
    add_function!(linker, map_lookup_integer_float);
    add_function!(linker, map_lookup_string_float);
    add_function!(linker, map_lookup_integer_bool);
    add_function!(linker, map_lookup_string_bool);
    add_function!(linker, map_lookup_integer_string);
    add_function!(linker, map_lookup_string_string);
    add_function!(linker, map_lookup_integer_struct);
    add_function!(linker, map_lookup_string_struct);

    linker
}

macro_rules! possibly_undef {
    ($ty:ty) => {
        ($ty, i32)
    };
    () => {
        i32
    };
}

macro_rules! defined {
    ($expr:expr) => {
        ($expr, 0)
    };
    () => {
        0
    };
}

macro_rules! undefined {
    (_) => {
        (0.into(), 1)
    };
    () => {
        1
    };
}

/// Invoked from WebAssembly to notify when a rule matches.
pub(crate) fn rule_match(
    mut caller: Caller<'_, ScanContext>,
    rule_id: RuleId,
) {
    let mut store_ctx = caller.as_context_mut();
    let scan_ctx = store_ctx.data_mut();

    // The RuleId-th bit in the `rule_matches` bit vector is set to 1.
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

macro_rules! gen_lookup_common {
    ($caller:ident, $scan_ctx:ident, $value:ident, $code:block) => {{
        let lookup_stack_top = $caller
            .data()
            .lookup_stack_top
            .unwrap()
            .get(&mut $caller.as_context_mut())
            .i32()
            .unwrap();

        let mut store_ctx = $caller.as_context_mut();

        let lookup_stack_ptr =
            store_ctx.data_mut().main_memory.unwrap().data_ptr(&mut store_ctx);

        let lookup_stack = unsafe {
            std::slice::from_raw_parts::<i32>(
                lookup_stack_ptr.offset(LOOKUP_INDEXES_START as isize)
                    as *const i32,
                lookup_stack_top as usize,
            )
        };

        let $scan_ctx = store_ctx.data_mut();

        let mut structure =
            if let Some(ref current_structure) = $scan_ctx.current_struct {
                &current_structure
            } else {
                &$scan_ctx.root_struct
            };

        let mut final_field = None;

        for field_index in lookup_stack {
            let field =
                structure.field_by_index(*field_index as usize).unwrap();
            final_field = Some(field);
            if let RuntimeValue::Struct(s) = &field.value {
                structure = &s
            }
        }

        let $value = &final_field.unwrap().value;

        let result = $code;

        $scan_ctx.current_struct = None;

        result
    }};
}

/// Given the field index for some field of type string, looks for the field
/// in the current structure and returns its value as a [`RuntimeStringWasm`]
/// tuple.
pub(crate) fn lookup_string(
    mut caller: Caller<'_, ScanContext>,
) -> RuntimeStringWasm {
    let string = gen_lookup_common!(caller, scan_ctx, value, {
        match value {
            RuntimeValue::String(Some(value)) => RuntimeString::Owned(
                scan_ctx.string_pool.get_or_intern(value.as_bstr()),
            ),
            RuntimeValue::String(None) => RuntimeString::Undef,
            _ => unreachable!(),
        }
    });

    string.as_wasm()
}

macro_rules! gen_lookup_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
        ) -> possibly_undef!($return_type) {
            gen_lookup_common!(caller, scan_ctx, value, {
                if let $type(Some(value)) = value {
                    defined!(*value as $return_type)
                } else {
                    undefined!(_)
                }
            })
        }
    };
}

gen_lookup_fn!(lookup_integer, i64, RuntimeValue::Integer);
gen_lookup_fn!(lookup_float, f64, RuntimeValue::Float);
gen_lookup_fn!(lookup_bool, i32, RuntimeValue::Bool);

macro_rules! gen_array_lookup_fn {
    ($name:ident, $fn:ident, $return_type:ty) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            index: i64,
        ) -> possibly_undef!($return_type) {
            let array = gen_lookup_common!(caller, scan_ctx, value, {
                match value {
                    RuntimeValue::Array(array) => array.clone(),
                    _ => unreachable!(),
                }
            });

            let array = array.$fn();

            if let Some(value) = array.get(index as usize) {
                defined!(*value as $return_type)
            } else {
                undefined!(_)
            }
        }
    };
}

gen_array_lookup_fn!(array_lookup_integer, as_integer_array, i64);
gen_array_lookup_fn!(array_lookup_float, as_float_array, f64);
gen_array_lookup_fn!(array_lookup_bool, as_bool_array, i32);

pub(crate) fn array_lookup_string(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
) -> RuntimeStringWasm {
    let array = gen_lookup_common!(caller, scan_ctx, value, {
        match value {
            RuntimeValue::Array(array) => array.clone(),
            _ => unreachable!(),
        }
    });

    let array = array.as_string_array();
    let string = array.get(index as usize);

    if let Some(string) = string {
        RuntimeString::Owned(
            caller.data_mut().string_pool.get_or_intern(string.as_bstr()),
        )
        .as_wasm()
    } else {
        RuntimeString::Undef.as_wasm()
    }
}

pub(crate) fn array_lookup_struct(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
) -> possibly_undef!() {
    let array = gen_lookup_common!(caller, scan_ctx, value, {
        match value {
            RuntimeValue::Array(array) => array.clone(),
            _ => unreachable!(),
        }
    });

    let array = array.as_struct_array();

    if let Some(value) = array.get(index as usize) {
        caller.data_mut().current_struct = Some(value.clone());
        defined!()
    } else {
        undefined!()
    }
}

macro_rules! gen_map_string_key_lookup_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            key_0: u64,
            key_1: u64,
        ) -> possibly_undef!($return_type) {
            let map = gen_lookup_common!(caller, scan_ctx, value, {
                match value {
                    RuntimeValue::Map(map) => map.clone(),
                    _ => unreachable!(),
                }
            });

            let key = RuntimeString::from_wasm((key_0, key_1));
            let key_bstr = key.as_bstr(caller.data());

            let value = match map.borrow() {
                RuntimeMap::StringKeys { map, .. } => map.get(key_bstr),
                _ => unreachable!(),
            };

            if let Some($type(value)) = value {
                if let Some(value) = value {
                    defined!(*value as $return_type)
                } else {
                    unreachable!()
                }
            } else {
                undefined!(_)
            }
        }
    };
}

macro_rules! gen_map_integer_key_lookup_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            key: i64,
        ) -> possibly_undef!($return_type) {
            let map = gen_lookup_common!(caller, scan_ctx, value, {
                match value {
                    RuntimeValue::Map(map) => map.clone(),
                    _ => unreachable!(),
                }
            });

            let value = match map.borrow() {
                RuntimeMap::IntegerKeys { map, .. } => map.get(&key),
                _ => unreachable!(),
            };

            if let Some($type(value)) = value {
                if let Some(value) = value {
                    defined!(*value as $return_type)
                } else {
                    unreachable!()
                }
            } else {
                undefined!(_)
            }
        }
    };
}

gen_map_string_key_lookup_fn!(
    map_lookup_string_integer,
    i64,
    RuntimeValue::Integer
);

gen_map_integer_key_lookup_fn!(
    map_lookup_integer_integer,
    i64,
    RuntimeValue::Integer
);

gen_map_string_key_lookup_fn!(
    map_lookup_string_float,
    f64,
    RuntimeValue::Float
);

gen_map_integer_key_lookup_fn!(
    map_lookup_integer_float,
    f64,
    RuntimeValue::Float
);

gen_map_string_key_lookup_fn!(map_lookup_string_bool, i32, RuntimeValue::Bool);

gen_map_integer_key_lookup_fn!(
    map_lookup_integer_bool,
    i32,
    RuntimeValue::Bool
);

pub(crate) fn map_lookup_integer_string(
    mut caller: Caller<'_, ScanContext>,
    key: i64,
) -> RuntimeStringWasm {
    let map = gen_lookup_common!(caller, scan_ctx, value, {
        match value {
            RuntimeValue::Map(map) => map.clone(),
            _ => unreachable!(),
        }
    });

    let value = match map.borrow() {
        RuntimeMap::IntegerKeys { map, .. } => map.get(&key),
        _ => unreachable!(),
    };

    let string = if let Some(value) = value {
        RuntimeString::Owned(
            caller
                .data_mut()
                .string_pool
                .get_or_intern(value.as_bstr().unwrap()),
        )
    } else {
        RuntimeString::Undef
    };

    string.as_wasm()
}

pub(crate) fn map_lookup_string_string(
    mut caller: Caller<'_, ScanContext>,
    key_0: u64,
    key_1: u64,
) -> RuntimeStringWasm {
    let map = gen_lookup_common!(caller, scan_ctx, value, {
        match value {
            RuntimeValue::Map(map) => map.clone(),
            _ => unreachable!(),
        }
    });

    let key = RuntimeString::from_wasm((key_0, key_1));
    let key_bstr = key.as_bstr(caller.data());

    let value = match map.borrow() {
        RuntimeMap::StringKeys { map, .. } => map.get(key_bstr),
        _ => unreachable!(),
    };

    let string = if let Some(value) = value {
        RuntimeString::Owned(
            caller
                .data_mut()
                .string_pool
                .get_or_intern(value.as_bstr().unwrap()),
        )
    } else {
        RuntimeString::Undef
    };

    string.as_wasm()
}

pub(crate) fn map_lookup_integer_struct(
    mut caller: Caller<'_, ScanContext>,
    key: i64,
) -> possibly_undef!() {
    let map = gen_lookup_common!(caller, scan_ctx, value, {
        match value {
            RuntimeValue::Map(map) => map.clone(),
            _ => unreachable!(),
        }
    });

    let value = match map.borrow() {
        RuntimeMap::IntegerKeys { map, .. } => map.get(&key),
        _ => unreachable!(),
    };

    if let Some(value) = value {
        if let RuntimeValue::Struct(s) = value {
            caller.data_mut().borrow_mut().current_struct = Some(s.clone());
            defined!()
        } else {
            unreachable!()
        }
    } else {
        undefined!()
    }
}

pub(crate) fn map_lookup_string_struct(
    mut caller: Caller<'_, ScanContext>,
    key_0: u64,
    key_1: u64,
) -> possibly_undef!() {
    let map = gen_lookup_common!(caller, scan_ctx, value, {
        match value {
            RuntimeValue::Map(map) => map.clone(),
            _ => unreachable!(),
        }
    });

    let key = RuntimeString::from_wasm((key_0, key_1));
    let key_bstr = key.as_bstr(caller.data());

    let value = match map.borrow() {
        RuntimeMap::StringKeys { map, .. } => map.get(key_bstr),
        _ => unreachable!(),
    };

    if let Some(value) = value {
        if let RuntimeValue::Struct(s) = value {
            caller.data_mut().borrow_mut().current_struct = Some(s.clone());
            defined!()
        } else {
            unreachable!()
        }
    } else {
        undefined!()
    }
}

macro_rules! gen_str_cmp_fn {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            lhs_0: u64,
            lhs_1: u64,
            rhs_0: u64,
            rhs_1: u64,
        ) -> i32 {
            let lhs_str = RuntimeString::from_wasm((lhs_0, lhs_1));
            let rhs_str = RuntimeString::from_wasm((rhs_0, rhs_1));

            lhs_str.$op(&rhs_str, caller.data()) as i32
        }
    };
}

gen_str_cmp_fn!(str_eq, eq);
gen_str_cmp_fn!(str_ne, ne);
gen_str_cmp_fn!(str_lt, lt);
gen_str_cmp_fn!(str_gt, gt);
gen_str_cmp_fn!(str_le, le);
gen_str_cmp_fn!(str_ge, ge);

macro_rules! gen_str_op_fn {
    ($name:ident, $op:tt, $case_insensitive:literal) => {
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            lhs_0: u64,
            lhs_1: u64,
            rhs_0: u64,
            rhs_1: u64,
        ) -> i32 {
            let lhs_str = RuntimeString::from_wasm((lhs_0, lhs_1));
            let rhs_str = RuntimeString::from_wasm((rhs_0, rhs_1));

            lhs_str.$op(&rhs_str, caller.data(), $case_insensitive) as i32
        }
    };
}

gen_str_op_fn!(str_contains, contains, false);
gen_str_op_fn!(str_startswith, starts_with, false);
gen_str_op_fn!(str_endswith, ends_with, false);
gen_str_op_fn!(str_icontains, contains, true);
gen_str_op_fn!(str_istartswith, starts_with, true);
gen_str_op_fn!(str_iendswith, ends_with, true);
gen_str_op_fn!(str_iequals, equals, true);

pub(crate) fn str_len(
    caller: Caller<'_, ScanContext>,
    str_0: u64,
    str_1: u64,
) -> i64 {
    let string = RuntimeString::from_wasm((str_0, str_1));
    string.len(caller.data()) as i64
}

#[cfg(test)]
mod tests {
    use crate::compiler::LiteralId;
    use crate::wasm::RuntimeString;
    use pretty_assertions::assert_eq;

    #[test]
    fn runtime_string_wasm_conversion() {
        let s = RuntimeString::Literal(LiteralId::from(1));
        assert_eq!(s, RuntimeString::from_wasm(s.as_wasm()));

        let s = RuntimeString::Slice { length: 100, offset: 0x1000000 };
        assert_eq!(s, RuntimeString::from_wasm(s.as_wasm()));
    }

    #[test]
    #[should_panic]
    fn runtime_string_wasm_max_size() {
        let s = RuntimeString::Slice {
            length: u32::MAX as usize + 1,
            offset: 0x1000000,
        };
        assert_eq!(s, RuntimeString::from_wasm(s.as_wasm()));
    }
}
