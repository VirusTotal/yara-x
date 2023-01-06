/*! WASM runtime

During the compilation process the condition associated to each YARA rule is
translated into WebAssembly (WASM) code. This code is later converted to native
code and executed by [wasmtime](https://wasmtime.dev/), a WASM runtime embedded
in YARA.

For each instance of [`crate::compiler::Rules`] the compiler creates a WASM
module. This WASM module works in close collaboration with YARA's Rust code for
evaluating the rule's conditions. For example, the WASM module exports a
function called `main`, which contains the code that evaluates the conditions
of all the compiled rules. This WASM function is called by YARA at scan time,
and the WASM code calls back the Rust [`rule_match`] function for notifying
YARA about matching rules. The WASM module calls Rust functions in many other
cases, for example when it needs to call YARA built-in functions like
`uint8(...)`.

WASM and Rust code also share information via WASM global variables and by
sharing memory. For example, the value for YARA's `filesize` keyword is
stored in a WASM global variable that is initialized by Rust code, and read
by WASM code when `filesize` is used in the condition.

# Memory layout

The memory of these WASM modules is organized as follows.

```text
  ┌──────────────────────────┐ 0
  │ Variable #0              │ 8
  │ Variable #1              │ 16
  : ...                      :
  │ Variable #n              │ n * 8
  : ...                      :
  │                          │
  ├──────────────────────────┤ 1024
  │ Field lookup indexes     │
  ├──────────────────────────┤ 2048
  │ Matching rules bitmap    │
  │                          │
  :                          :
  │                          │
  ├──────────────────────────┤ (number of rules / 8) + 1
  │ Matching patterns bitmap │
  │                          │
  :                          :
  │                          │
  └──────────────────────────┘
```

# Field lookup

While evaluating rule condition's, the WASM code needs to obtain from YARA the
values stored in structures, maps and arrays. In order to minimize the number
of calls from WASM to Rust, these field lookups are performed in bulk. For
example, suppose that a YARA module named `some_module` exports a structure
named `some_struct` that has an integer field named `some_int`. For accessing,
that field in a YARA rule you would write `some_module.some_struct.some_int`.
The WASM code for obtaining the value of `some_int` consists in a single call
to the [`lookup_integer`] function. This functions receives a series of field
indexes: the index of `some_module` within the global structure, the index
of `some_struct` within `some_module`, and finally the index of `some_int`,
within `some_struct`. These indexes are stored starting at offset 1024 in
the WASM module's main memory (see "Memory layout") before calling
[`lookup_integer`], while the global variable `lookup_stack_top` says how
many indexes to lookup.

 */
use std::borrow::Borrow;
use std::stringify;

use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use bstr::{BStr, ByteSlice};
use lazy_static::lazy_static;
use wasmtime::{AsContextMut, Caller, Config, Engine, Linker};
use yara_x_parser::types::{Map, TypeValue};

use crate::compiler::{LiteralId, PatternId, RuleId};
use crate::scanner::{RuntimeStringId, ScanContext};

pub(crate) mod builder;

/// Offset in module's main memory where the space for loop variables start.
pub(crate) const VARS_STACK_START: i32 = 0;
/// Offset in module's main memory where the space for loop variables end.
pub(crate) const VARS_STACK_END: i32 = VARS_STACK_START + 1024;

/// Offset in module's main memory where the space for lookup indexes start.
pub(crate) const LOOKUP_INDEXES_START: i32 = VARS_STACK_END;
/// Offset in module's main memory where the space for lookup indexes end.
pub(crate) const LOOKUP_INDEXES_END: i32 = LOOKUP_INDEXES_START + 1024;

/// Offset in module's main memory where resides the bitmap that tells if a
/// rule matches or not. This bitmap contains one bit per rule, if the N-th
/// bit is set, it indicates that the rule with RuleId = N matched.
pub(crate) const MATCHING_RULES_BITMAP_BASE: i32 = LOOKUP_INDEXES_END;

/// Table with functions and variables used by the WASM module.
///
/// The WASM module generated for evaluating rule conditions needs to
/// call back to YARA for multiple tasks. For example, it calls YARA for
/// reporting rule matches, for asking if a pattern matches at a given offset,
/// for executing functions like `uint32()`, etc.
///
/// This table contains the [`FunctionId`] for such functions, which are
/// imported by the WASM module and implemented by YARA. It also
/// contains the definition of some variables used by the module.
#[derive(Clone)]
pub(crate) struct WasmSymbols {
    /// The WASM module's main memory.
    pub main_memory: walrus::MemoryId,

    pub lookup_start: walrus::GlobalId,
    pub lookup_stack_top: walrus::GlobalId,

    /// Global variable that contains the offset within the module's main
    /// memory where resides the bitmap that indicates if a pattern matches
    /// or not.
    pub matching_patterns_bitmap_base: walrus::GlobalId,

    /// Global variable that contains the value for `filesize`.
    pub filesize: walrus::GlobalId,

    /// Called when a rule matches.
    /// Signature: (rule_id: i32) -> ()
    pub rule_match: walrus::FunctionId,

    /// Ask YARA whether a pattern matched at a specific offset.
    /// Signature: (pattern_id: i32, offset: i64) -> (i32)
    pub is_pat_match_at: walrus::FunctionId,

    /// Ask YARA whether a pattern matched within a range of offsets.
    /// Signature: (pattern_id: i32, lower_bound: i64, upper_bound: i64) -> (i32)
    pub is_pat_match_in: walrus::FunctionId,

    /// Function that returns the length of an array.
    /// Signature (host_var_index: i32) -> (i64)
    pub array_len: walrus::FunctionId,

    /// Function that returns the length of an map.
    /// Signature (host_var_index: i32) -> (i64)
    pub map_len: walrus::FunctionId,

    /// Functions that given a sequence of field indexes, lookup the fields
    /// and return their values.
    pub lookup_integer: walrus::FunctionId,
    pub lookup_float: walrus::FunctionId,
    pub lookup_bool: walrus::FunctionId,
    pub lookup_string: walrus::FunctionId,
    pub lookup_value: walrus::FunctionId,

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
    pub i32_tmp: walrus::LocalId,
}

/// Represents a [`RuntimeString`] as a `u64` that can be passed from WASM to
/// host and vice-versa.
///
/// The types that we can pass to (and receive from) WASM functions are only
/// primitive types (i64, i32, f64 and f32). In order to be able to pass a
/// [`RuntimeString`] to and from WASM, it must be represented as one of those
/// primitive types.
///
/// The `u64` value contains all the information required for uniquely
/// identifying the string. This is how the information is encoded:
///
/// * `RuntimeString:Undef`  -> `0`
///    A zero represents an undefined string.
///
/// * `RuntimeString:Literal`  -> `LiteralId << 2 | 1`
///    If the two lower bits are equal to 1, it's a literal string, where the
///    remaining bits represent the `LiteralId`.
///
/// * `RuntimeString:Owned`  -> `RuntimeStringId << 2 | 2`
///    If the two lower bits are equal to 2, it's a runtime string, where the
///    remaining bits represent the `RuntimeStringId`.
///
/// * `RuntimeString:Owned`  -> `Offset << 18 | Len << 2 | 3)`
///    If the two lower bits are 3, it's a string backed by the scanned data.
///    Bits 18:3 ar used for representing the string length (up to 64KB),
///    while bits 64:19 represents the offset (up to 70,368,744,177,663).
///
pub(crate) type RuntimeStringWasm = u64;

/// String types handled by YARA's WASM runtime.
///
/// At runtime, when the the WASM code generated for rule conditions is
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
    /// passed to WASM.
    pub(crate) fn as_wasm(&self) -> RuntimeStringWasm {
        match self {
            // Undefined strings are represented as 0.
            RuntimeString::Undef => 0,
            // Literal strings are represented as (1, LiteralId)
            RuntimeString::Literal(id) => u64::from(*id) << 2 | 1,
            // Owned strings are represented as (2, RuntimeStringId)
            RuntimeString::Owned(id) => (*id as u64) << 2 | 2,
            // Slices are represented as (length << 32 | 1, offset). This
            // implies that slice length is limited to 4GB, as it must fit
            // in the upper 32-bits of the first item in the tuple.
            RuntimeString::Slice { offset, length } => {
                if *length >= u16::MAX as usize {
                    panic!(
                        "runtime-string slices can't be larger than {}",
                        u16::MAX
                    )
                }
                (*offset as u64) << 18 | (*length as u64) << 2 | 3
            }
        }
    }

    /// Creates a [`RuntimeString`] from a [`RuntimeStringTuple`].
    pub(crate) fn from_wasm(s: RuntimeStringWasm) -> Self {
        match s & 0x3 {
            0 => Self::Undef,
            1 => Self::Literal(LiteralId::from((s >> 2) as u32)),
            2 => Self::Owned((s >> 2) as u32),
            3 => Self::Slice {
                offset: (s >> 18) as usize,
                length: ((s >> 2) & 0xffff) as usize,
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
    add_function!(linker, is_pat_match_at);
    add_function!(linker, is_pat_match_in);
    add_function!(linker, lookup_integer);
    add_function!(linker, lookup_float);
    add_function!(linker, lookup_string);
    add_function!(linker, lookup_bool);
    add_function!(linker, lookup_value);
    add_function!(linker, array_len);
    add_function!(linker, array_lookup_integer);
    add_function!(linker, array_lookup_float);
    add_function!(linker, array_lookup_bool);
    add_function!(linker, array_lookup_string);
    add_function!(linker, array_lookup_struct);
    add_function!(linker, map_len);
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

/// Invoked from WASM to notify when a rule matches.
pub(crate) fn rule_match(
    mut caller: Caller<'_, ScanContext>,
    rule_id: RuleId,
) {
    let mut store_ctx = caller.as_context_mut();

    let main_mem =
        store_ctx.data_mut().main_memory.unwrap().data_mut(store_ctx);

    let bits = BitSlice::<u8, Lsb0>::from_slice_mut(
        &mut main_mem[MATCHING_RULES_BITMAP_BASE as usize..],
    );

    // The RuleId-th bit in the `rule_matches` bit vector is set to 1.
    bits.set(rule_id as usize, true);

    caller.as_context_mut().data_mut().rules_matching.push(rule_id);
}

/// Invoked from WASM to ask whether a pattern matches at a given file
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

/// Invoked from WASM to ask whether a pattern at some offset within
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

/// Given some local variable containing an array, returns the length of the
/// array. The local variable is an index within `vars_stack`.
///
/// # Panics
///
/// If the variable doesn't exist or is not an array.
pub(crate) fn array_len(caller: Caller<'_, ScanContext>, var: i32) -> i64 {
    let len = caller
        .data()
        .vars_stack
        .get(var as usize)
        .unwrap()
        .as_array()
        .unwrap()
        .len();

    len as i64
}

/// Given some local variable containing a map, returns the length of the
/// map. The local variable is an index within `vars_stack`.
///
/// # Panics
///
/// If the variable doesn't exist or is not a map.
pub(crate) fn map_len(caller: Caller<'_, ScanContext>, var: i32) -> i64 {
    let len = caller
        .data()
        .vars_stack
        .get(var as usize)
        .unwrap()
        .as_map()
        .unwrap()
        .len();

    len as i64
}

macro_rules! lookup_common {
    ($caller:ident, $type_value:ident, $code:block) => {{
        let lookup_start = $caller
            .data()
            .lookup_start
            .unwrap()
            .get(&mut $caller.as_context_mut())
            .i32()
            .unwrap();

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

        let $type_value = if lookup_stack.len() > 0 {
            let mut structure = if let Some(current_structure) =
                &store_ctx.data().current_struct
            {
                current_structure.as_ref()
            } else if lookup_start != -1 {
                let var =
                    &store_ctx.data().vars_stack[lookup_start as usize];

                if let TypeValue::Struct(s) = var {
                    s
                } else {
                    unreachable!(
                        "expecting struct, got `{:?}` at variable with index {}",
                        var, lookup_start)
                }
            } else {
                &store_ctx.data().root_struct
            };

            let mut final_field = None;

            for field_index in lookup_stack {
                let field =
                    structure.field_by_index(*field_index as usize).unwrap();
                final_field = Some(field);
                if let TypeValue::Struct(s) = &field.type_value {
                    structure = &s
                }
            }

            &final_field.unwrap().type_value
        } else if lookup_start != -1 {
            &store_ctx.data().vars_stack[lookup_start as usize]
        } else {
            unreachable!();
        };

        let result = $code;

        $caller.data_mut().current_struct = None;

        result
    }};
}

pub(crate) fn lookup_string(
    mut caller: Caller<'_, ScanContext>,
) -> RuntimeStringWasm {
    let string = lookup_common!(caller, type_value, {
        match type_value {
            TypeValue::String(Some(value)) => {
                let value = value.to_owned();
                RuntimeString::Owned(
                    caller.data_mut().string_pool.get_or_intern(value),
                )
            }
            TypeValue::String(None) => RuntimeString::Undef,
            _ => unreachable!(),
        }
    });

    string.as_wasm()
}

pub(crate) fn lookup_value(mut caller: Caller<'_, ScanContext>, var: i32) {
    let value = lookup_common!(caller, type_value, { type_value.clone() });
    let index = var as usize;

    let vars = &mut caller.data_mut().vars_stack;

    if vars.len() <= index {
        vars.resize(index + 1, TypeValue::Unknown);
    }

    vars[index] = value;
}

macro_rules! gen_lookup_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
        ) -> possibly_undef!($return_type) {
            lookup_common!(caller, type_value, {
                if let $type(Some(value)) = type_value {
                    defined!(*value as $return_type)
                } else {
                    undefined!(_)
                }
            })
        }
    };
}

gen_lookup_fn!(lookup_integer, i64, TypeValue::Integer);
gen_lookup_fn!(lookup_float, f64, TypeValue::Float);
gen_lookup_fn!(lookup_bool, i32, TypeValue::Bool);

macro_rules! gen_array_lookup_fn {
    ($name:ident, $fn:ident, $return_type:ty) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            index: i64,
            var: i32,
        ) -> possibly_undef!($return_type) {
            // TODO: decide what to to with this. It looks like are not going to need
            // to store integer, floats nor bools in host-side variables.
            assert_eq!(var, -1);

            let array = lookup_common!(caller, type_value, {
                type_value.as_array().unwrap()
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
    var: i32,
) -> RuntimeStringWasm {
    // TODO: decide what to to with this. It looks like are not going to need
    // to store strings in host-side variables.
    assert_eq!(var, -1);

    let array =
        lookup_common!(caller, type_value, { type_value.as_array().unwrap() });

    let array = array.as_string_array();

    if let Some(string) = array.get(index as usize) {
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
    var: i32,
) -> possibly_undef!() {
    let array =
        lookup_common!(caller, type_value, { type_value.as_array().unwrap() });

    let array = array.as_struct_array();

    if let Some(s) = array.get(index as usize) {
        caller.data_mut().current_struct = Some(s.clone());

        if var != -1 {
            let index = var as usize;
            let vars = &mut caller.data_mut().vars_stack;

            if vars.len() <= index {
                vars.resize(index + 1, TypeValue::Unknown);
            }

            vars[index] = TypeValue::Struct(s.clone());
        }

        defined!()
    } else {
        undefined!()
    }
}

macro_rules! gen_map_string_key_lookup_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            key: u64,
        ) -> possibly_undef!($return_type) {
            let map = lookup_common!(caller, type_value, {
                type_value.as_map().unwrap()
            });

            let key = RuntimeString::from_wasm(key);
            let key_bstr = key.as_bstr(caller.data());

            let value = match map.borrow() {
                Map::StringKeys { map, .. } => map.get(key_bstr),
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
            let map = lookup_common!(caller, type_value, {
                type_value.as_map().unwrap()
            });

            let value = match map.borrow() {
                Map::IntegerKeys { map, .. } => map.get(&key),
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
    TypeValue::Integer
);

gen_map_integer_key_lookup_fn!(
    map_lookup_integer_integer,
    i64,
    TypeValue::Integer
);

gen_map_string_key_lookup_fn!(map_lookup_string_float, f64, TypeValue::Float);

gen_map_integer_key_lookup_fn!(
    map_lookup_integer_float,
    f64,
    TypeValue::Float
);

gen_map_string_key_lookup_fn!(map_lookup_string_bool, i32, TypeValue::Bool);

gen_map_integer_key_lookup_fn!(map_lookup_integer_bool, i32, TypeValue::Bool);

pub(crate) fn map_lookup_integer_string(
    mut caller: Caller<'_, ScanContext>,
    key: i64,
) -> RuntimeStringWasm {
    let map =
        lookup_common!(caller, type_value, { type_value.as_map().unwrap() });

    let value = match map.borrow() {
        Map::IntegerKeys { map, .. } => map.get(&key),
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
    key: u64,
) -> RuntimeStringWasm {
    let map =
        lookup_common!(caller, type_value, { type_value.as_map().unwrap() });

    let key = RuntimeString::from_wasm(key);
    let key_bstr = key.as_bstr(caller.data());

    let type_value = match map.borrow() {
        Map::StringKeys { map, .. } => map.get(key_bstr),
        _ => unreachable!(),
    };

    let string = if let Some(type_value) = type_value {
        RuntimeString::Owned(
            caller
                .data_mut()
                .string_pool
                .get_or_intern(type_value.as_bstr().unwrap()),
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
    let map = lookup_common!(caller, value, {
        match value {
            TypeValue::Map(map) => map.clone(),
            _ => unreachable!(),
        }
    });

    let value = match map.borrow() {
        Map::IntegerKeys { map, .. } => map.get(&key),
        _ => unreachable!(),
    };

    if let Some(value) = value {
        if let TypeValue::Struct(s) = value {
            caller.data_mut().current_struct = Some(s.clone());
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
    key: u64,
) -> possibly_undef!() {
    let map = lookup_common!(caller, value, {
        match value {
            TypeValue::Map(map) => map.clone(),
            _ => unreachable!(),
        }
    });

    let key = RuntimeString::from_wasm(key);
    let key_bstr = key.as_bstr(caller.data());

    let value = match map.borrow() {
        Map::StringKeys { map, .. } => map.get(key_bstr),
        _ => unreachable!(),
    };

    if let Some(value) = value {
        if let TypeValue::Struct(s) = value {
            caller.data_mut().current_struct = Some(s.clone());
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
            lhs: u64,
            rhs: u64,
        ) -> i32 {
            let lhs_str = RuntimeString::from_wasm(lhs);
            let rhs_str = RuntimeString::from_wasm(rhs);

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
            lhs: u64,
            rhs: u64,
        ) -> i32 {
            let lhs_str = RuntimeString::from_wasm(lhs);
            let rhs_str = RuntimeString::from_wasm(rhs);

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

pub(crate) fn str_len(caller: Caller<'_, ScanContext>, str: u64) -> i64 {
    let string = RuntimeString::from_wasm(str);
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
