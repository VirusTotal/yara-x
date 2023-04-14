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
`uint8(...)`, or functions implemented by YARA modules.

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
[`lookup_integer`], while the global variable `lookup_num_lookup_indexes` says how
many indexes to lookup.

See the [`lookup_field`] function.

 */
use std::any::{type_name, TypeId};
use std::mem;

use bstr::ByteSlice;
use lazy_static::lazy_static;
use linkme::distributed_slice;
use smallvec::{smallvec, SmallVec};
use wasmtime::{
    AsContextMut, Caller, Config, Engine, FuncType, Linker, ValRaw,
};

use yara_x_macros::wasm_export;
use yara_x_parser::types::TypeValue;

use crate::compiler::{PatternId, RuleId};
use crate::modules::BUILTIN_MODULES;
use crate::scanner::ScanContext;
use crate::wasm::string::{RuntimeString, RuntimeStringWasm};
use crate::LiteralId;

pub(crate) mod builder;
pub(crate) mod string;

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

/// Global slice that contains an entry for each function that is callable from
/// WASM code. Functions with attributes `#[wasm_export]` and `#[module_export]`
/// are automatically added to this slice. See https://github.com/dtolnay/linkme
/// for details about how `#[distributed_slice]` works.
#[distributed_slice]
pub(crate) static WASM_EXPORTS: [WasmExport] = [..];

/// Type of each entry in [`WASM_EXPORTS`].
pub(crate) struct WasmExport {
    /// Function's name.
    pub name: &'static str,
    /// Function's mangled name. The mangled name contains information about
    /// the function's arguments and return type. For additional details see
    /// [`yara_x_parser::types::MangledFnName`].
    pub mangled_name: &'static str,
    /// True if the function is visible from YARA rules. Functions exported by
    /// modules, as well as built-in functions like uint8, uint16, etc are
    /// public, but many other functions callable from WASM are for internal
    /// use only and therefore are not public.
    pub public: bool,
    /// Path of the module where the function resides. This an absolute path
    /// that includes the crate name (e.g: yara_x::modules::test_proto2)
    pub rust_module_path: &'static str,
    /// Reference to some type that implements the WasmExportedFn trait.
    pub func: &'static (dyn WasmExportedFn + Send + Sync),
}

impl WasmExport {
    /// Returns the fully qualified name for a #[wasm_export] function.
    ///
    /// The fully qualified name includes not only the function's name, but
    /// also the module's name (e.g: `my_module.my_struct.my_func@ii@i`)
    pub fn fully_qualified_mangled_name(&self) -> String {
        for (module_name, module) in BUILTIN_MODULES.iter() {
            if let Some(rust_module_name) = module.rust_module_name {
                if self.rust_module_path.contains(rust_module_name) {
                    return format!("{}.{}", module_name, self.mangled_name);
                }
            }
        }
        self.mangled_name.to_owned()
    }
}

/// Trait implemented for all types that represent a function exported to WASM.
///
/// Implementors of this trait are [`WasmExportedFn0`], [`WasmExportedFn1`],
/// [`WasmExportedFn2`], etc. Each of these types is a generic type that
/// represents all functions with 0, 1, and 2 arguments respectively.
pub(crate) trait WasmExportedFn {
    /// Returns the function that will be passed to [`wasmtime::Func::new`]
    /// while linking the WASM code to this function.
    fn trampoline(&'static self) -> TrampolineFn;

    /// Returns a [`Vec<wasmtime::ValType>`] with the types of the function's
    /// arguments
    fn wasmtime_args(&'static self) -> Vec<wasmtime::ValType>;

    /// Returns a [`Vec<wasmtime::ValType>`] with the types of the function's
    /// return values.
    fn wasmtime_results(&'static self) -> WasmResultArray<wasmtime::ValType>;

    /// Returns a [`Vec<walrus::ValType>`] with the types of the function's
    /// arguments
    fn walrus_args(&'static self) -> Vec<walrus::ValType> {
        self.wasmtime_args().iter().map(wasmtime_to_walrus).collect()
    }

    /// Returns a [`Vec<walrus::ValType>`] with the types of the function's
    /// return values.
    fn walrus_results(&'static self) -> WasmResultArray<walrus::ValType> {
        self.wasmtime_results().iter().map(wasmtime_to_walrus).collect()
    }
}

type TrampolineFn = Box<
    dyn Fn(Caller<'_, ScanContext>, &mut [ValRaw]) -> anyhow::Result<()>
        + Send
        + Sync
        + 'static,
>;

const MAX_RESULTS: usize = 4;
type WasmResultArray<T> = SmallVec<[T; MAX_RESULTS]>;

/// Represents an argument passed to a `#[wasm_export]` function.
///
/// The purpose of this type is converting [`wasmtime::ValRaw`] into Rust
/// types (e.g: `i64`, `i32`, `f64`, `f32`, etc)
struct WasmArg(ValRaw);

impl From<ValRaw> for WasmArg {
    fn from(value: ValRaw) -> Self {
        Self(value)
    }
}

impl From<WasmArg> for i64 {
    fn from(value: WasmArg) -> Self {
        value.0.get_i64()
    }
}

impl From<WasmArg> for i32 {
    fn from(value: WasmArg) -> Self {
        value.0.get_i32()
    }
}

impl From<WasmArg> for f64 {
    fn from(value: WasmArg) -> Self {
        f64::from_bits(value.0.get_f64())
    }
}

impl From<WasmArg> for f32 {
    fn from(value: WasmArg) -> Self {
        f32::from_bits(value.0.get_f32())
    }
}

impl From<WasmArg> for RuleId {
    fn from(value: WasmArg) -> Self {
        RuleId::from(value.0.get_i32())
    }
}

impl From<WasmArg> for PatternId {
    fn from(value: WasmArg) -> Self {
        PatternId::from(value.0.get_i32())
    }
}

impl From<WasmArg> for LiteralId {
    fn from(value: WasmArg) -> Self {
        LiteralId::from(value.0.get_i32())
    }
}

impl From<WasmArg> for RuntimeString {
    fn from(value: WasmArg) -> Self {
        Self::from_wasm(RuntimeStringWasm::from(value))
    }
}

/// A trait for converting a function result into an array of
/// [`wasmtime::ValRaw`] values suitable to be passed to WASM code.
///
/// Functions with the `#[wasm_export]` attribute must return a type that
/// implements this trait.
pub(crate) trait WasmResult {
    // Returns the WASM values representing this result.
    fn values(&self) -> WasmResultArray<ValRaw>;

    // Returns the WASM types that conform this result.
    fn types() -> WasmResultArray<wasmtime::ValType>;
}

impl WasmResult for () {
    fn values(&self) -> WasmResultArray<ValRaw> {
        smallvec![]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![]
    }
}

impl WasmResult for i32 {
    fn values(&self) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i32(*self)]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I32]
    }
}

impl WasmResult for i64 {
    fn values(&self) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i64(*self)]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I64]
    }
}

impl WasmResult for f32 {
    fn values(&self) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::f32(f32::to_bits(*self))]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::F32]
    }
}

impl WasmResult for f64 {
    fn values(&self) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::f64(f64::to_bits(*self))]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::F64]
    }
}

impl WasmResult for bool {
    fn values(&self) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i32(*self as i32)]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I32]
    }
}

impl WasmResult for RuntimeString {
    fn values(&self) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i64(self.as_wasm())]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I64]
    }
}

impl<A, B> WasmResult for (A, B)
where
    A: WasmResult,
    B: WasmResult,
{
    fn values(&self) -> WasmResultArray<ValRaw> {
        let mut result = self.0.values();
        result.extend(self.1.values());
        result
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        let mut result = A::types();
        result.extend(B::types());
        result
    }
}

impl<T> WasmResult for Option<T>
where
    T: WasmResult + Default,
{
    fn values(&self) -> WasmResultArray<ValRaw> {
        match self {
            Some(value) => {
                let mut result = value.values();
                result.push(ValRaw::i32(0));
                result
            }
            None => {
                let mut result = T::default().values();
                result.push(ValRaw::i32(1));
                result
            }
        }
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        let mut result = T::types();
        result.push(wasmtime::ValType::I32);
        result
    }
}

pub fn wasmtime_to_walrus(ty: &wasmtime::ValType) -> walrus::ValType {
    match ty {
        wasmtime::ValType::I64 => walrus::ValType::I64,
        wasmtime::ValType::I32 => walrus::ValType::I32,
        wasmtime::ValType::F64 => walrus::ValType::F64,
        wasmtime::ValType::F32 => walrus::ValType::F32,
        _ => unreachable!(),
    }
}

#[allow(clippy::if_same_then_else)]
fn type_id_to_wasmtime(
    type_id: TypeId,
    type_name: &'static str,
) -> &'static [wasmtime::ValType] {
    if type_id == TypeId::of::<i64>() {
        return &[wasmtime::ValType::I64];
    } else if type_id == TypeId::of::<i32>() {
        return &[wasmtime::ValType::I32];
    } else if type_id == TypeId::of::<f64>() {
        return &[wasmtime::ValType::F64];
    } else if type_id == TypeId::of::<f32>() {
        return &[wasmtime::ValType::F32];
    } else if type_id == TypeId::of::<bool>() {
        return &[wasmtime::ValType::I32];
    } else if type_id == TypeId::of::<LiteralId>() {
        return &[wasmtime::ValType::I32];
    } else if type_id == TypeId::of::<PatternId>() {
        return &[wasmtime::ValType::I32];
    } else if type_id == TypeId::of::<RuleId>() {
        return &[wasmtime::ValType::I32];
    } else if type_id == TypeId::of::<()>() {
        return &[];
    } else if type_id == TypeId::of::<RuntimeString>() {
        return &[wasmtime::ValType::I64];
    }
    panic!("type `{}` can't be an argument", type_name)
}

/// Macro that creates types [`WasmExportedFn0`], [`WasmExportedFn1`], etc,
/// and implements the [`WasmExportedFn`] trait for them.
macro_rules! impl_wasm_exported_fn {
    ($name:ident $($args:ident)*) => {
        pub(super) struct $name <$($args,)* R>
        where
            $($args: 'static,)*
            R: 'static,
        {
            pub target_fn: &'static (dyn Fn(Caller<'_, ScanContext>, $($args),*) -> R
                          + Send
                          + Sync
                          + 'static),
        }

        impl<$($args,)* R> WasmExportedFn for $name<$($args,)* R>
        where
            $($args: From<WasmArg>,)*
            R: WasmResult,
        {
            #[allow(unused_mut)]
            fn wasmtime_args(&'static self) -> Vec<wasmtime::ValType> {
                let mut result = Vec::new();
                $(
                    result.extend_from_slice(type_id_to_wasmtime(
                        TypeId::of::<$args>(),
                        type_name::<$args>(),
                    ));
                )*
                result
            }

            fn wasmtime_results(&'static self) -> WasmResultArray<wasmtime::ValType> {
                R::types()
            }

            #[allow(unused_assignments)]
            #[allow(unused_variables)]
            #[allow(non_snake_case)]
            #[allow(unused_mut)]
            fn trampoline(&'static self) -> TrampolineFn {
                Box::new(
                    |caller: Caller<'_, ScanContext>,
                     args_and_results: &mut [ValRaw]|
                     -> anyhow::Result<()> {
                        let mut i = 0;
                        $(
                            let $args = WasmArg::from(args_and_results[i].clone()).into();
                            i += 1;
                        )*

                        let result = (self.target_fn)(caller, $($args),*);
                        let result = result.values();

                        let result_slice = result.as_slice();
                        let num_results = result_slice.len();

                        args_and_results[0..num_results].clone_from_slice(result_slice);
                        anyhow::Ok(())
                    },
                )
            }
        }
    };
}

// Generate multiple structures implementing the WasmExportedFn trait,
// each for a different number of arguments. The WasmExportedFn0 is a generic
// type that represents all exported functions that have no arguments,
// WasmExportedFn1 represents functions with 1 argument, and so on.
impl_wasm_exported_fn!(WasmExportedFn0);
impl_wasm_exported_fn!(WasmExportedFn1 A1);
impl_wasm_exported_fn!(WasmExportedFn2 A1 A2);
impl_wasm_exported_fn!(WasmExportedFn3 A1 A2 A3);
impl_wasm_exported_fn!(WasmExportedFn4 A1 A2 A3 A4);

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

    /// Global variable that contains the offset within the module's main
    /// memory where resides the bitmap that indicates if a pattern matches
    /// or not.
    pub matching_patterns_bitmap_base: walrus::GlobalId,

    /// Global variable that contains the value for `filesize`.
    pub filesize: walrus::GlobalId,

    /// Local variable that is set to true after the pattern search phase
    /// has been executed. In this phase the data is scanned looking for
    /// all the patterns at the same time using the Aho-Corasick algorithm.
    /// However this phase is executed lazily, when rule conditions are
    /// evaluated and some of them needs to know if a pattern matched or not.
    pub pattern_search_done: walrus::LocalId,

    /// Local variables used for temporary storage.
    pub i64_tmp: walrus::LocalId,
    pub i32_tmp: walrus::LocalId,
    pub f64_tmp: walrus::LocalId,
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

pub(crate) fn new_linker<'r>() -> Linker<ScanContext<'r>> {
    let mut linker = Linker::<ScanContext<'r>>::new(&ENGINE);
    for export in WASM_EXPORTS {
        let func_type = FuncType::new(
            export.func.wasmtime_args(),
            export.func.wasmtime_results(),
        );
        // Using `func_new_unchecked` instead of `func_new` makes function
        // calls from WASM to Rust around 3x faster.
        unsafe {
            linker
                .func_new_unchecked(
                    export.rust_module_path,
                    export.fully_qualified_mangled_name().as_str(),
                    func_type,
                    export.func.trampoline(),
                )
                .unwrap();
        }
    }

    linker
}

/// Invoked from WASM for triggering the pattern search phase.
#[wasm_export]
pub(crate) fn search_for_patterns(mut caller: Caller<'_, ScanContext>) {
    caller.data_mut().search_for_patterns();
}

/// Invoked from WASM to notify when a rule matches.
#[wasm_export]
pub(crate) fn rule_match(
    mut caller: Caller<'_, ScanContext>,
    rule_id: RuleId,
) {
    caller.data_mut().track_rule_match(rule_id);
}

/// Invoked from WASM to ask whether a pattern matches at a given file
/// offset.
///
/// Returns 1 if the pattern identified by `pattern_id` matches at `offset`,
/// or 0 if otherwise.
#[wasm_export]
pub(crate) fn is_pat_match_at(
    _caller: Caller<'_, ScanContext>,
    _pattern_id: PatternId,
    _offset: i64,
) -> bool {
    // TODO
    false
}

/// Invoked from WASM to ask whether a pattern at some offset within
/// given range.
///
/// Returns 1 if the pattern identified by `pattern_id` matches at some offset
/// in the range [`lower_bound`, `upper_bound`].
#[wasm_export]
pub(crate) fn is_pat_match_in(
    _caller: Caller<'_, ScanContext>,
    _pattern_id: PatternId,
    _lower_bound: i64,
    _upper_bound: i64,
) -> bool {
    // TODO
    false
}

/// Given some local variable containing an array, returns the length of the
/// array. The local variable is an index within `vars_stack`.
///
/// # Panics
///
/// If the variable doesn't exist or is not an array.
#[wasm_export]
pub(crate) fn array_len(mut caller: Caller<'_, ScanContext>, var: i32) -> i64 {
    let ctx = caller.data_mut();
    let len = ctx.vars_stack.get(var as usize).unwrap().as_array().len();
    len as i64
}

/// Given some local variable containing a map, returns the length of the
/// map. The local variable is an index within `vars_stack`.
///
/// # Panics
///
/// If the variable doesn't exist or is not a map.
#[wasm_export]
pub(crate) fn map_len(mut caller: Caller<'_, ScanContext>, var: i32) -> i64 {
    let ctx = caller.data_mut();
    let len = ctx.vars_stack.get(var as usize).unwrap().as_map().len();
    len as i64
}

/// Given a structure and a series of fields indexes, walks the structure
/// looking for the final field.
///
/// For example, suppose that we have a structure that has two fields, the
/// first one is an integer and the second one is another struct, which in
/// turns have another integer field:
///
/// {
///   integer_field,
///   struct_field: {
///      integer_field
///   }
/// }
///
/// For locating the integer field in the inner structure, we can start at the
/// outer structure and pass the following sequence of field indexes: 1, 0. The
/// first value (1) is the index of `struct_field` within the outer structure,
/// as this field is another structure, we can continue looking for fields, and
/// the next value (0) is the index of `integer_field` within the inner
/// structure. So starting at the outer structure and following the path: 1,0 we
/// reach the inner `integer_field`.
///
/// The initial structure is the one stored in the variable `struct_var`
/// (`struct_var` is actually an index within `vars_stack`, so, the structure is
/// stored in `vars_stack[struct_var]`). If `struct_var` is -1 the initial
/// structure will be `ScanContext.current_struct`.
///
/// The sequence of indexes is stored in WASM main memory, starting at
/// `LOOKUP_INDEXES_START`, and the number of indexes is indicated by the
/// argument `num_lookup_indexes`.
fn lookup_field(
    caller: &mut Caller<'_, ScanContext>,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> TypeValue {
    let mut store_ctx = caller.as_context_mut();

    let lookup_indexes_ptr =
        store_ctx.data_mut().main_memory.unwrap().data_ptr(&mut store_ctx);

    let lookup_indexes = unsafe {
        std::slice::from_raw_parts::<i32>(
            lookup_indexes_ptr.offset(LOOKUP_INDEXES_START as isize)
                as *const i32,
            num_lookup_indexes as usize,
        )
    };

    let type_value = if !lookup_indexes.is_empty() {
        let mut structure = if let Some(current_structure) =
            &store_ctx.data().current_struct
        {
            current_structure.as_ref()
        } else if struct_var != -1 {
            let var = &store_ctx.data().vars_stack[struct_var as usize];

            if let TypeValue::Struct(s) = var {
                s
            } else {
                unreachable!(
                    "expecting struct, got `{:?}` at variable with index {}",
                    var, struct_var
                )
            }
        } else {
            &store_ctx.data().root_struct
        };

        let mut final_field = None;

        for field_index in lookup_indexes {
            let field =
                structure.field_by_index(*field_index as usize).unwrap();
            final_field = Some(field);
            if let TypeValue::Struct(s) = &field.type_value {
                structure = s
            }
        }

        &final_field.unwrap().type_value
    } else if struct_var != -1 {
        &store_ctx.data().vars_stack[struct_var as usize]
    } else {
        unreachable!();
    };

    let type_value = type_value.clone();

    caller.data_mut().current_struct = None;

    type_value
}

/// Lookup a field of string type and returns its value.
///
/// See [`lookup_field`].
#[wasm_export]
pub(crate) fn lookup_string(
    mut caller: Caller<'_, ScanContext>,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> Option<RuntimeString> {
    match lookup_field(&mut caller, num_lookup_indexes, struct_var) {
        TypeValue::String(Some(value)) => Some(RuntimeString::Owned(
            caller.data_mut().string_pool.get_or_intern(value),
        )),
        TypeValue::String(None) => None,
        _ => unreachable!(),
    }
}

/// Lookup a field of string type and returns its value.
///
/// See [`lookup_field`].
#[wasm_export]
pub(crate) fn lookup_value(
    mut caller: Caller<'_, ScanContext>,
    num_lookup_indexes: i32,
    struct_var: i32,
    dst_var: i32,
) {
    let type_value = lookup_field(&mut caller, num_lookup_indexes, struct_var);
    let index = dst_var as usize;
    let vars = &mut caller.data_mut().vars_stack;

    if vars.len() <= index {
        vars.resize(index + 1, TypeValue::Unknown);
    }

    vars[index] = type_value;
}

macro_rules! gen_lookup_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        #[wasm_export]
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            num_lookup_indexes: i32,
            struct_var: i32,
        ) -> Option<$return_type> {
            if let $type(Some(value)) =
                lookup_field(&mut caller, num_lookup_indexes, struct_var)
            {
                Some(value as $return_type)
            } else {
                None
            }
        }
    };
}

gen_lookup_fn!(lookup_integer, i64, TypeValue::Integer);
gen_lookup_fn!(lookup_float, f64, TypeValue::Float);
gen_lookup_fn!(lookup_bool, bool, TypeValue::Bool);

macro_rules! gen_array_indexing_fn {
    ($name:ident, $fn:ident, $return_type:ty) => {
        #[wasm_export]
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            index: i64,
            num_lookup_indexes: i32,
            struct_var: i32,
        ) -> Option<$return_type> {
            lookup_field(&mut caller, num_lookup_indexes, struct_var)
                .as_array()
                .$fn()
                .get(index as usize)
                .map(|value| *value as $return_type)
        }
    };
}

gen_array_indexing_fn!(array_indexing_integer, as_integer_array, i64);
gen_array_indexing_fn!(array_indexing_float, as_float_array, f64);
gen_array_indexing_fn!(array_indexing_bool, as_bool_array, bool);

#[wasm_export]
#[rustfmt::skip]
pub(crate) fn array_indexing_string(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> Option<RuntimeString> {
    lookup_field(&mut caller, num_lookup_indexes,struct_var )
        .as_array()
        .as_string_array()
        .get(index as usize)
        .map(|s| { 
            RuntimeString::from_bytes(caller.data_mut(), s.as_bstr())
        })
}

#[wasm_export]
#[rustfmt::skip]
pub(crate) fn array_indexing_struct(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
    dst_var: i32,
) -> Option<()> {
    lookup_field(&mut caller, num_lookup_indexes,struct_var )
        .as_array()
        .as_struct_array()
        .get(index as usize)
        .map(|s| {
            if dst_var != -1 {
                let index = dst_var as usize;
                let vars = &mut caller.data_mut().vars_stack;
                if vars.len() <= index {
                    vars.resize(index + 1, TypeValue::Unknown);
                }
                vars[index] = TypeValue::Struct(s.clone());
            }
            caller.data_mut().current_struct = Some(s.clone());
        })
}

macro_rules! gen_map_lookup_fn {
    ($name:ident, i64, i64) => {
        gen_map_lookup_fn!($name, i64, i64, with_integer_keys, as_integer);
    };
    ($name:ident, i64, f64) => {
        gen_map_lookup_fn!($name, i64, f64, with_integer_keys, as_float);
    };
    ($name:ident, i64, bool) => {
        gen_map_lookup_fn!($name, i64, bool, with_integer_keys, as_bool);
    };
    ($name:ident, RuntimeString, i64) => {
        gen_map_lookup_fn!(
            $name,
            RuntimeString,
            i64,
            with_string_keys,
            as_integer
        );
    };
    ($name:ident, RuntimeString, f64) => {
        gen_map_lookup_fn!(
            $name,
            RuntimeString,
            f64,
            with_string_keys,
            as_float
        );
    };
    ($name:ident, RuntimeString, bool) => {
        gen_map_lookup_fn!(
            $name,
            RuntimeString,
            bool,
            with_string_keys,
            as_bool
        );
    };
    ($name:ident, i64, $return_type:ty, $with:ident, $as:ident) => {
        #[wasm_export]
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            key: i64,
            num_lookup_indexes: i32,
            struct_var: i32,
        ) -> Option<$return_type> {
            let map =
                lookup_field(&mut caller, num_lookup_indexes, struct_var)
                    .as_map();
            map.$with().get(&key).map(|v| v.$as())
        }
    };
    ($name:ident, RuntimeString, $return_type:ty, $with:ident, $as:ident) => {
        #[wasm_export]
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            key: RuntimeString,
            num_lookup_indexes: i32,
            struct_var: i32,
        ) -> Option<$return_type> {
            let map =
                lookup_field(&mut caller, num_lookup_indexes, struct_var)
                    .as_map();
            let key = key.as_bstr(caller.data());
            map.$with().get(key).map(|v| v.$as())
        }
    };
}

#[rustfmt::skip]
gen_map_lookup_fn!(
    map_lookup_string_integer,
    RuntimeString,
    i64
);

#[rustfmt::skip]
gen_map_lookup_fn!(
    map_lookup_string_float,
    RuntimeString,
    f64
);

#[rustfmt::skip]
gen_map_lookup_fn!(
    map_lookup_string_bool,
    RuntimeString,
    bool
);

#[rustfmt::skip]
gen_map_lookup_fn!(
    map_lookup_integer_integer,
    i64,
    i64
);

#[rustfmt::skip]
gen_map_lookup_fn!(
    map_lookup_integer_float,
    i64,
    f64
);

#[rustfmt::skip]
gen_map_lookup_fn!(
    map_lookup_integer_bool,
    i64,
    bool
);

#[wasm_export]
pub(crate) fn map_lookup_integer_string(
    mut caller: Caller<'_, ScanContext>,
    key: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> Option<RuntimeString> {
    lookup_field(&mut caller, num_lookup_indexes, struct_var)
        .as_map()
        .with_integer_keys()
        .get(&key)
        .map(|v| RuntimeString::from_bytes(caller.data_mut(), v.as_bstr()))
}

#[wasm_export]
pub(crate) fn map_lookup_string_string(
    mut caller: Caller<'_, ScanContext>,
    key: RuntimeString,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> Option<RuntimeString> {
    let map =
        lookup_field(&mut caller, num_lookup_indexes, struct_var).as_map();
    let key = key.as_bstr(caller.data());
    map.with_string_keys()
        .get(key)
        .map(|v| RuntimeString::from_bytes(caller.data_mut(), v.as_bstr()))
}

#[wasm_export]
pub(crate) fn map_lookup_integer_struct(
    mut caller: Caller<'_, ScanContext>,
    key: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> Option<()> {
    lookup_field(&mut caller, num_lookup_indexes, struct_var)
        .as_map()
        .with_integer_keys()
        .get(&key)
        .map(|v| caller.data_mut().current_struct = Some(v.as_struct()))
}

#[wasm_export]
pub(crate) fn map_lookup_string_struct(
    mut caller: Caller<'_, ScanContext>,
    key: RuntimeString,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> Option<()> {
    let map =
        lookup_field(&mut caller, num_lookup_indexes, struct_var).as_map();
    let key = key.as_bstr(caller.data());
    map.with_string_keys()
        .get(key)
        .map(|v| caller.data_mut().current_struct = Some(v.as_struct()))
}

macro_rules! gen_map_lookup_by_index_fn {
    ($name:ident, RuntimeString, $val:ty, $with:ident, $as:ident) => {
        #[wasm_export]
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            index: i64,
            num_lookup_indexes: i32,
            struct_var: i32,
        ) -> (RuntimeString, $val) {
            let map =
                lookup_field(&mut caller, num_lookup_indexes, struct_var)
                    .as_map();
            let (key, value) = map.$with().get_index(index as usize).unwrap();
            let key =
                RuntimeString::from_bytes(caller.data_mut(), key.as_bstr());
            (key, value.$as())
        }
    };
    ($name:ident, $key:ty, $val:ty, $with:ident, $as:ident) => {
        #[wasm_export]
        pub(crate) fn $name(
            mut caller: Caller<'_, ScanContext>,
            index: i64,
            num_lookup_indexes: i32,
            struct_var: i32,
        ) -> ($key, $val) {
            let map =
                lookup_field(&mut caller, num_lookup_indexes, struct_var)
                    .as_map();
            let (key, value) = map.$with().get_index(index as usize).unwrap();
            (*key, value.$as())
        }
    };
}

#[rustfmt::skip]
gen_map_lookup_by_index_fn!(
    map_lookup_by_index_integer_integer,
    i64,
    i64,
    with_integer_keys,
    as_integer
);

#[rustfmt::skip]
gen_map_lookup_by_index_fn!(
    map_lookup_by_index_integer_float,
    i64,
    f64,
    with_integer_keys,
    as_float
);

#[rustfmt::skip]
gen_map_lookup_by_index_fn!(
    map_lookup_by_index_integer_bool,
    i64,
    bool,
    with_integer_keys,
    as_bool
);

#[rustfmt::skip]
gen_map_lookup_by_index_fn!(
    map_lookup_by_index_string_integer,
    RuntimeString,
    i64,
    with_string_keys,
    as_integer
);

#[rustfmt::skip]
gen_map_lookup_by_index_fn!(
    map_lookup_by_index_string_float,
    RuntimeString,
    f64,
    with_string_keys,
    as_float
);

#[rustfmt::skip]
gen_map_lookup_by_index_fn!(
    map_lookup_by_index_string_bool,
    RuntimeString,
    bool,
    with_string_keys,
    as_bool
);

#[wasm_export]
pub(crate) fn map_lookup_by_index_integer_string(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> (i64, RuntimeString) {
    let map =
        lookup_field(&mut caller, num_lookup_indexes, struct_var).as_map();
    let (key, value) =
        map.with_integer_keys().get_index(index as usize).unwrap();
    let value = RuntimeString::from_bytes(caller.data_mut(), value.as_bstr());
    (*key, value)
}

#[wasm_export]
pub(crate) fn map_lookup_by_index_string_string(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
) -> (RuntimeString, RuntimeString) {
    let map =
        lookup_field(&mut caller, num_lookup_indexes, struct_var).as_map();
    let (key, value) =
        map.with_string_keys().get_index(index as usize).unwrap();
    let key = RuntimeString::from_bytes(caller.data_mut(), key.as_bstr());
    let value = RuntimeString::from_bytes(caller.data_mut(), value.as_bstr());
    (key, value)
}

#[wasm_export]
pub(crate) fn map_lookup_by_index_integer_struct(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
    dst_var: i32,
) -> i64 {
    let map =
        lookup_field(&mut caller, num_lookup_indexes, struct_var).as_map();
    let (key, value) =
        map.with_integer_keys().get_index(index as usize).unwrap();

    let value = value.as_struct();

    if dst_var != -1 {
        let index = dst_var as usize;
        let vars = &mut caller.data_mut().vars_stack;
        if vars.len() <= index {
            vars.resize(index + 1, TypeValue::Unknown);
        }
        vars[index] = TypeValue::Struct(value.clone());
    }

    caller.data_mut().current_struct = Some(value);

    *key
}

#[wasm_export]
pub(crate) fn map_lookup_by_index_string_struct(
    mut caller: Caller<'_, ScanContext>,
    index: i64,
    num_lookup_indexes: i32,
    struct_var: i32,
    dst_var: i32,
) -> RuntimeString {
    let map =
        lookup_field(&mut caller, num_lookup_indexes, struct_var).as_map();
    let (key, value) =
        map.with_string_keys().get_index(index as usize).unwrap();

    let value = value.as_struct();

    if dst_var != -1 {
        let index = dst_var as usize;
        let vars = &mut caller.data_mut().vars_stack;
        if vars.len() <= index {
            vars.resize(index + 1, TypeValue::Unknown);
        }
        vars[index] = TypeValue::Struct(value.clone());
    }

    caller.data_mut().current_struct = Some(value);

    RuntimeString::from_bytes(caller.data_mut(), key.as_bstr())
}

macro_rules! gen_str_cmp_fn {
    ($name:ident, $op:tt) => {
        #[wasm_export]
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            lhs: RuntimeString,
            rhs: RuntimeString,
        ) -> bool {
            lhs.$op(&rhs, caller.data())
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
        #[wasm_export]
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            lhs: RuntimeString,
            rhs: RuntimeString,
        ) -> bool {
            lhs.$op(&rhs, caller.data(), $case_insensitive)
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

#[wasm_export]
pub(crate) fn str_len(
    caller: Caller<'_, ScanContext>,
    s: RuntimeString,
) -> i64 {
    s.len(caller.data()) as i64
}

macro_rules! gen_uint_fn {
    ($name:ident, $return_type:ty, $from_fn:ident) => {
        #[wasm_export(public = true)]
        pub(crate) fn $name(
            caller: Caller<'_, ScanContext>,
            offset: i64,
        ) -> Option<i64> {
            let offset = usize::try_from(offset).ok()?;
            caller
                .data()
                .scanned_data()
                .get(offset..offset + mem::size_of::<$return_type>())
                .map_or(None, |bytes| {
                    let value =
                        <$return_type>::$from_fn(bytes.try_into().unwrap());
                    Some(value as i64)
                })
        }
    };
}

gen_uint_fn!(uint8, u8, from_le_bytes);
gen_uint_fn!(uint16, u16, from_le_bytes);
gen_uint_fn!(uint32, u32, from_le_bytes);
gen_uint_fn!(uint64, u64, from_le_bytes);
gen_uint_fn!(uint8be, u8, from_be_bytes);
gen_uint_fn!(uint16be, u16, from_be_bytes);
gen_uint_fn!(uint32be, u32, from_be_bytes);
gen_uint_fn!(uint64be, u64, from_be_bytes);

#[cfg(test)]
mod tests {
    use crate::wasm::WasmResult;

    #[test]
    fn wasm_result_conversion() {
        let w = 1_i64.values();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].get_i64(), 1);

        let w = 1_i32.values();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].get_i32(), 1);

        let w = Option::<i64>::Some(2).values();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].get_i64(), 2);
        assert_eq!(w[1].get_i32(), 0);

        let w = Option::<i64>::None.values();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].get_i64(), 0);
        assert_eq!(w[1].get_i32(), 1);

        let w = Option::<i32>::Some(2).values();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].get_i64(), 2);
        assert_eq!(w[1].get_i32(), 0);

        let w = Option::<i32>::None.values();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].get_i32(), 0);
        assert_eq!(w[1].get_i32(), 1);

        let w = Option::<()>::Some(()).values();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].get_i32(), 0);

        let w = Option::<()>::None.values();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].get_i32(), 1);
    }
}
