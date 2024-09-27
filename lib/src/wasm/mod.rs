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
  │ Variable undefined flags │
  ├──────────────────────────┤ 16
  │ Variable #0              │ 24
  │ Variable #1              │ 32
  : ...                      :
  │ Variable #n              │
  : ...                      :
  │                          │
  ├──────────────────────────┤ 1032
  │ Field lookup indexes     │
  ├──────────────────────────┤ 2056
  │ Matching rules bitmap    │
  │                          │
  :                          :
  │                          │
  ├──────────────────────────┤
  │ Matching patterns bitmap │
  │                          │
  :                          :
  │                          │
  └──────────────────────────┘
```

# Variable undefined flags

The first few bytes in WASM memory contains a bitmap where each bit indicates
whether one of the variables is undefined or not. The bitmap is 128-bits long,
which is also the number of variable that follow the bitmap in memory. When
some variable is flagged as undefined (the corresponding bit in the bitmap is
set) the value of the variable is ignored.

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
[`lookup_integer`], while the global variable `lookup_num_lookup_indexes` says
how many indexes to lookup.

See the [`lookup_field`] function.

 */
use std::any::{type_name, TypeId};
use std::mem;
use std::rc::Rc;

use bstr::{BString, ByteSlice};
use lazy_static::lazy_static;
use linkme::distributed_slice;
use rustc_hash::FxHashMap;
use smallvec::{smallvec, SmallVec};
use wasmtime::{
    AsContextMut, Caller, Config, Engine, FuncType, Linker, ValRaw,
};

use yara_x_macros::wasm_export;

use crate::compiler::{LiteralId, PatternId, RegexpId, RuleId};
use crate::modules::BUILTIN_MODULES;
use crate::scanner::{RuntimeObjectHandle, ScanContext, ScanError};
use crate::types::{
    Array, Func, FuncSignature, Map, Struct, TypeValue, Value,
};
use crate::wasm::string::RuntimeString;

pub(crate) mod builder;
pub(crate) mod string;

/// Offset in module's main memory where the space for loop variables start.
pub(crate) const VARS_STACK_START: i32 = 16;
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
    /// modules, as well as built-in functions like uint8, uint16, etc, are
    /// public, but many other functions callable from WASM are for internal
    /// use only and therefore are not public.
    pub public: bool,
    /// Path of the module where the function resides. This an absolute path
    /// that includes the crate name (e.g: yara_x::modules::test_proto2)
    pub rust_module_path: &'static str,
    /// If the function is a method of some type, this contains the name of
    /// the type (i.e: `my_module.my_struct`).
    pub method_of: Option<&'static str>,
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

    /// Returns true if this export comes from YARA itself, not for a YARA
    /// module.
    pub fn builtin(&self) -> bool {
        self.rust_module_path.strip_prefix("yara_x::modules::").is_none()
    }

    /// Returns a hash map with all function exported to WASM that match the
    /// given predicate.
    ///
    /// Keys are function names and values are [`Func`] structures. Overloaded
    /// functions appear in the map as a single entry where the [`Func`] has
    /// multiple signatures.
    pub fn get_functions<P>(predicate: P) -> FxHashMap<&'static str, Func>
    where
        P: FnMut(&&WasmExport) -> bool,
    {
        let mut functions: FxHashMap<&'static str, Func> =
            FxHashMap::default();

        // Iterate over public functions in WASM_EXPORTS looking for those that
        // match the predicate. Add them to `functions` map, or update the
        // `Func` object with an additional signature if the function is
        // overloaded.
        for export in WASM_EXPORTS.iter().filter(predicate) {
            let mangled_name = export.fully_qualified_mangled_name();
            // If the function was already present in the map is because it has
            // multiple signatures. If that's the case, add more signatures to
            // the existing `Func` object.
            if let Some(function) = functions.get_mut(export.name) {
                function.add_signature(FuncSignature::from(mangled_name))
            } else {
                functions.insert(
                    export.name,
                    Func::from_mangled_name(mangled_name.as_str()),
                );
            }
        }

        functions
    }

    /// Returns the methods implemented for the type with the given name.
    ///
    /// `type_name` is one of the strings passed in the `method_of` field to
    /// the `module_export` macro. For instance, in the example below we
    /// specify that `some_method` is a method of `my_module.MyStructure`. If
    /// we call `find_methods` with `"my_module.MyStructure"` it returns
    /// a hash map that contains a [`Func`] describing `some_method`.
    ///
    /// ```text
    /// #[module_export(method_of = "my_module.MyStructure")]
    /// fn some_method(...) { ... }
    /// ```
    pub fn get_methods(type_name: &str) -> FxHashMap<&'static str, Func> {
        let mut methods = WasmExport::get_functions(|export| {
            export.method_of.is_some_and(|name| name == type_name)
        });
        for (_, func) in methods.iter_mut() {
            func.make_method_of(type_name)
        }
        methods
    }
}

/// Trait implemented for all types that represent a function exported to WASM.
///
/// Implementors of this trait are [`WasmExportedFn0`], [`WasmExportedFn1`],
/// [`WasmExportedFn2`], etc. Each of these types is a generic type that
/// represents all functions with 0, 1, and 2 arguments respectively.
pub(crate) trait WasmExportedFn {
    /// Returns the function that will be passed to
    /// [`wasmtime::Func::new_unchecked`] while linking the WASM code to this
    /// function.
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

/// A trait for converting raw values received from WASM code into Rust types.
///
/// Functions decorated with `#[wasm_export]` must have arguments of some type
/// `T` so that [`WasmArg<T>`] is implemented for [`ValRaw`].
///
/// By implementing [`WasmArg<T>`] for [`ValRaw`], the raw values received from
/// WASM code can be converted into Rust type `T`.
trait WasmArg<T> {
    fn raw_into(self, _: &mut ScanContext) -> T;
}

impl WasmArg<i64> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> i64 {
        self.get_i64()
    }
}

impl WasmArg<i32> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> i32 {
        self.get_i32()
    }
}

impl WasmArg<f64> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> f64 {
        f64::from_bits(self.get_f64())
    }
}

impl WasmArg<f32> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> f32 {
        f32::from_bits(self.get_f32())
    }
}

impl WasmArg<bool> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> bool {
        self.get_i32() == 1
    }
}

impl WasmArg<RuleId> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> RuleId {
        RuleId::from(self.get_i32())
    }
}

impl WasmArg<PatternId> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> PatternId {
        PatternId::from(self.get_i32())
    }
}

impl WasmArg<LiteralId> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> LiteralId {
        LiteralId::from(self.get_i32())
    }
}

impl WasmArg<RegexpId> for ValRaw {
    #[inline]
    fn raw_into(self, _: &mut ScanContext) -> RegexpId {
        RegexpId::from(self.get_i32())
    }
}

impl WasmArg<RuntimeString> for ValRaw {
    #[inline]
    fn raw_into(self, ctx: &mut ScanContext) -> RuntimeString {
        RuntimeString::from_wasm(ctx, self.get_i64())
    }
}

impl WasmArg<Rc<Array>> for ValRaw {
    #[inline]
    fn raw_into(self, ctx: &mut ScanContext) -> Rc<Array> {
        let handle = RuntimeObjectHandle::from(self.get_i64());
        ctx.runtime_objects.get(&handle).unwrap().as_array()
    }
}

impl WasmArg<Rc<Map>> for ValRaw {
    #[inline]
    fn raw_into(self, ctx: &mut ScanContext) -> Rc<Map> {
        let handle = RuntimeObjectHandle::from(self.get_i64());
        ctx.runtime_objects.get(&handle).unwrap().as_map()
    }
}

impl WasmArg<Rc<Struct>> for ValRaw {
    #[inline]
    fn raw_into(self, ctx: &mut ScanContext) -> Rc<Struct> {
        let handle = RuntimeObjectHandle::from(self.get_i64());
        ctx.runtime_objects.get(&handle).unwrap().as_struct()
    }
}

impl WasmArg<Option<Rc<Struct>>> for ValRaw {
    #[inline]
    fn raw_into(self, ctx: &mut ScanContext) -> Option<Rc<Struct>> {
        let handle = RuntimeObjectHandle::from(self.get_i64());
        if handle == RuntimeObjectHandle::NULL {
            return None;
        }
        Some(ctx.runtime_objects.get(&handle).unwrap().as_struct())
    }
}

/// A trait for converting a function result into an array of [`ValRaw`] values
/// suitable to be passed to WASM code.
///
/// Functions with the `#[wasm_export]` attribute must return a type that
/// implements this trait.
pub(crate) trait WasmResult {
    /// Returns the WASM values representing this result.
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw>;

    /// Returns the WASM types that conform this result.
    fn types() -> WasmResultArray<wasmtime::ValType>;
}

impl WasmResult for () {
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![]
    }
}

impl WasmResult for i32 {
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i32(self)]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I32]
    }
}

impl WasmResult for i64 {
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i64(self)]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I64]
    }
}

impl WasmResult for f32 {
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::f32(f32::to_bits(self))]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::F32]
    }
}

impl WasmResult for f64 {
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::f64(f64::to_bits(self))]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::F64]
    }
}

impl WasmResult for bool {
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i32(self as i32)]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I32]
    }
}

impl WasmResult for RuntimeString {
    fn values(self, ctx: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i64(self.into_wasm_with_ctx(ctx))]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I64]
    }
}

impl WasmResult for RuntimeObjectHandle {
    fn values(self, _: &mut ScanContext) -> WasmResultArray<ValRaw> {
        smallvec![ValRaw::i64(self.into())]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I64]
    }
}

impl WasmResult for Rc<BString> {
    fn values(self, ctx: &mut ScanContext) -> WasmResultArray<ValRaw> {
        let s = RuntimeString::Rc(self);
        smallvec![ValRaw::i64(s.into_wasm_with_ctx(ctx))]
    }

    fn types() -> WasmResultArray<wasmtime::ValType> {
        smallvec![wasmtime::ValType::I64]
    }
}

impl WasmResult for Rc<Struct> {
    fn values(self, ctx: &mut ScanContext) -> WasmResultArray<ValRaw> {
        let handle = ctx.store_struct(self);
        smallvec![ValRaw::i64(handle.into())]
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
    fn values(self, ctx: &mut ScanContext) -> WasmResultArray<ValRaw> {
        let mut result = self.0.values(ctx);
        result.extend(self.1.values(ctx));
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
    fn values(self, ctx: &mut ScanContext) -> WasmResultArray<ValRaw> {
        match self {
            Some(value) => {
                let mut result = value.values(ctx);
                result.push(ValRaw::i32(0));
                result
            }
            None => {
                let mut result = T::default().values(ctx);
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
    } else if type_id == TypeId::of::<RegexpId>() {
        return &[wasmtime::ValType::I32];
    } else if type_id == TypeId::of::<()>() {
        return &[];
    } else if type_id == TypeId::of::<RuntimeString>() {
        return &[wasmtime::ValType::I64];
    } else if type_id == TypeId::of::<Option<Rc<Struct>>>() {
        return &[wasmtime::ValType::I64];
    } else if type_id == TypeId::of::<Rc<Struct>>() {
        return &[wasmtime::ValType::I64];
    } else if type_id == TypeId::of::<Rc<Array>>() {
        return &[wasmtime::ValType::I64];
    } else if type_id == TypeId::of::<Rc<Map>>() {
        return &[wasmtime::ValType::I64];
    }
    panic!("type `{}` can't be an argument", type_name)
}

/// Macro that creates types [`WasmExportedFn0`], [`WasmExportedFn1`], etc,
/// and implements the [`WasmExportedFn`] trait for them.
macro_rules! impl_wasm_exported_fn {
    ($name:ident $($args:ident)*) => {
        #[allow(dead_code)]
        pub(super) struct $name <$($args,)* R>
        where
            $($args: 'static,)*
            R: 'static,
        {
            pub target_fn: &'static (dyn Fn(&mut Caller<'_, ScanContext>, $($args),*) -> R
                          + Send
                          + Sync
                          + 'static),
        }

        #[allow(dead_code)]
        impl<$($args,)* R> WasmExportedFn for $name<$($args,)* R>
        where
            $(ValRaw: WasmArg<$args>,)*
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
                    |mut caller: Caller<'_, ScanContext>,
                     args_and_results: &mut [ValRaw]|
                     -> anyhow::Result<()> {
                        let mut i = 0;
                        $(
                            let $args = args_and_results[i].raw_into(caller.data_mut());
                            i += 1;
                        )*

                        let result = (self.target_fn)(&mut caller, $($args),*);
                        let result = result.values(caller.data_mut());

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

/// Table with identifiers of variables and memories shared by the WASM
/// module with the host.
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

    /// Global variable that is set to true after the pattern search phase
    /// has been executed. In this phase the data is scanned looking for
    /// all the patterns at the same time using the Aho-Corasick algorithm.
    /// However, this phase is executed lazily, when rule conditions are
    /// evaluated and some of them needs to know if a pattern matched or not.
    pub pattern_search_done: walrus::GlobalId,

    /// Global variable that is set to true when a timeout during the scanning
    /// phase.
    pub timeout_occurred: walrus::GlobalId,

    /// Local variables used for temporary storage.
    pub i64_tmp_a: walrus::LocalId,
    pub i64_tmp_b: walrus::LocalId,
    pub i32_tmp: walrus::LocalId,
    pub f64_tmp: walrus::LocalId,
}

lazy_static! {
    pub(crate) static ref CONFIG: Config = {
        let mut config = Config::default();
        // Wasmtime produces a nasty warning when linked against musl. The
        // warning can be fixed by disabling native unwind information.
        //
        // More details:
        //
        // https://github.com/bytecodealliance/wasmtime/issues/8897
        // https://github.com/VirusTotal/yara-x/issues/181
        //
        #[cfg(target_env = "musl")]
        config.native_unwind_info(false);

        config.cranelift_opt_level(wasmtime::OptLevel::SpeedAndSize);
        config.epoch_interruption(true);
        config
    };
    pub(crate) static ref ENGINE: Engine = Engine::new(&CONFIG).unwrap();
    pub(crate) static ref LINKER: Linker<ScanContext<'static>> = new_linker();
}

pub(crate) fn new_linker<'r>() -> Linker<ScanContext<'r>> {
    let mut linker = Linker::<ScanContext<'r>>::new(&ENGINE);
    for export in WASM_EXPORTS {
        let func_type = FuncType::new(
            &ENGINE,
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

/// Invoked from WASM before starting the evaluation of the rule identified
/// by the given [`RuleId`]. This only happens when the "logging" feature is
/// enabled.
#[wasm_export]
#[cfg(feature = "logging")]
pub(crate) fn log_rule_eval_start(
    caller: &mut Caller<'_, ScanContext>,
    rule_id: RuleId,
) {
    caller.data_mut().log_rule_eval_start(rule_id);
}

/// Invoked from WASM for triggering the pattern search phase.
///
/// Returns `true` on success and `false` when a timeout occurs.
#[wasm_export]
pub(crate) fn search_for_patterns(
    caller: &mut Caller<'_, ScanContext>,
) -> bool {
    match caller.data_mut().search_for_patterns() {
        Ok(_) => true,
        Err(ScanError::Timeout) => false,
        Err(_) => unreachable!(),
    }
}

/// Invoked from WASM to notify when a rule matches.
#[wasm_export]
pub(crate) fn rule_match(
    caller: &mut Caller<'_, ScanContext>,
    rule_id: RuleId,
) {
    caller.data_mut().track_rule_match(rule_id);
}

/// Invoked from WASM to notify when a global rule doesn't match.
#[wasm_export]
pub(crate) fn global_rule_no_match(
    caller: &mut Caller<'_, ScanContext>,
    rule_id: RuleId,
) {
    caller.data_mut().track_global_rule_no_match(rule_id);
}

/// Invoked from WASM to ask whether a pattern matches at a given file
/// offset.
///
/// Returns true if the pattern identified by `pattern_id` matches at `offset`,
/// or false if otherwise.
#[wasm_export]
pub(crate) fn is_pat_match_at(
    caller: &mut Caller<'_, ScanContext>,
    pattern_id: PatternId,
    offset: i64,
) -> bool {
    // Matches can't occur at negative offsets.
    if offset < 0 {
        return false;
    }
    if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
        matches.search(offset.try_into().unwrap()).is_ok()
    } else {
        false
    }
}

/// Invoked from WASM to ask whether a pattern matches at some offset within
/// a given range.
///
/// Returns true if the pattern identified by `pattern_id` matches at some
/// offset in the range [`lower_bound`, `upper_bound`], both inclusive.
#[wasm_export]
pub(crate) fn is_pat_match_in(
    caller: &mut Caller<'_, ScanContext>,
    pattern_id: PatternId,
    lower_bound: i64,
    upper_bound: i64,
) -> bool {
    if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
        matches
            .matches_in_range(lower_bound as isize..=upper_bound as isize)
            .is_positive()
    } else {
        false
    }
}

/// Invoked from WASM to ask for the number of matches for a pattern.
#[wasm_export]
pub(crate) fn pat_matches(
    caller: &mut Caller<'_, ScanContext>,
    pattern_id: PatternId,
) -> i64 {
    if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
        matches.len().try_into().unwrap()
    } else {
        0
    }
}

/// Invoked from WASM to ask for the number of matches of a given pattern
/// within some offset range.
///
/// Returns the number of matches for the pattern identified by `pattern_id`
/// that start in the range [`lower_bound`, `upper_bound`], both inclusive.
#[wasm_export]
pub(crate) fn pat_matches_in(
    caller: &mut Caller<'_, ScanContext>,
    pattern_id: PatternId,
    lower_bound: i64,
    upper_bound: i64,
) -> i64 {
    if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
        matches.matches_in_range(lower_bound as isize..=upper_bound as isize)
    } else {
        0
    }
}

/// Invoked from WASM to ask for the offset where a pattern matched
///
/// Returns the length for the index-th occurrence of the pattern identified
/// by `pattern_id`. The index is 1-based. Returns `None` if the pattern
/// has not matched or there are less than `index` matches.
#[wasm_export]
pub(crate) fn pat_length(
    caller: &mut Caller<'_, ScanContext>,
    pattern_id: PatternId,
    index: i64,
) -> Option<i64> {
    if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
        let index: usize = index.try_into().ok()?;
        // Index is 1-based, convert it to 0-based before calling `matches.get`
        let m = matches.get(index.checked_sub(1)?)?;
        Some(ExactSizeIterator::len(&m.range) as i64)
    } else {
        None
    }
}

/// Invoked from WASM to ask for the length of some pattern match
///
/// Returns the offset for the index-th occurrence of the pattern identified
/// by `pattern_id`. The index is 1-based. Returns `None` if the pattern
/// has not matched or there are less than `index` matches.
#[wasm_export]
pub(crate) fn pat_offset(
    caller: &mut Caller<'_, ScanContext>,
    pattern_id: PatternId,
    index: i64,
) -> Option<i64> {
    if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
        let index: usize = index.try_into().ok()?;
        // Index is 1-based, convert it to 0-based before calling `matches.get`
        let m = matches.get(index.checked_sub(1)?)?;
        Some(m.range.start as i64)
    } else {
        None
    }
}

/// Called from WASM to obtain the length of an array.
#[wasm_export]
pub(crate) fn array_len(
    _: &mut Caller<'_, ScanContext>,
    array: Rc<Array>,
) -> i64 {
    array.len() as i64
}

/// Called from WASM to obtain the length of a map.
#[wasm_export]
pub(crate) fn map_len(_: &mut Caller<'_, ScanContext>, map: Rc<Map>) -> i64 {
    map.len() as i64
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
/// The initial structure is the one passed in the `structure` argument, or the
/// root structure if this argument is `None`.
///
/// The sequence of indexes is stored in WASM main memory, starting at
/// `LOOKUP_INDEXES_START`, and the number of indexes is indicated by the
/// argument `num_lookup_indexes`.
fn lookup_field(
    caller: &mut Caller<'_, ScanContext>,
    structure: Option<Rc<Struct>>,
    num_lookup_indexes: i32,
) -> TypeValue /* TODO: make this a &TypeValue? */ {
    assert!(num_lookup_indexes > 0);

    let mut store_ctx = caller.as_context_mut();

    let mem_ptr =
        store_ctx.data_mut().main_memory.unwrap().data_ptr(&mut store_ctx);

    let lookup_indexes_ptr =
        unsafe { mem_ptr.offset(LOOKUP_INDEXES_START as isize) };

    let lookup_indexes = unsafe {
        std::slice::from_raw_parts::<i32>(
            lookup_indexes_ptr as *const i32,
            num_lookup_indexes as usize,
        )
    };

    // If the passed structure is None, it means that we should start the
    // at the root structure.
    let mut structure =
        structure.as_deref().unwrap_or(&store_ctx.data().root_struct);

    let mut final_field = None;

    for field_index in lookup_indexes {
        // Integers in WASM memory are always stored as little-endian
        // regardless of the endianness of the host platform. If we
        // are in a big-endian platform the integers needs to be swapped
        // for obtaining the original value.
        let field_index = if cfg!(target_endian = "big") {
            field_index.swap_bytes()
        } else {
            *field_index
        };

        let field = structure
            .field_by_index(field_index as usize)
            .unwrap_or_else(|| {
                panic!(
                    "expecting field with index {} in {:#?}",
                    field_index, structure
                )
            });

        final_field = Some(field);

        if let TypeValue::Struct(s) = &field.type_value {
            structure = s
        }
    }

    final_field.unwrap().type_value.clone()
}

/// Lookup a field of string type and returns its value.
///
/// See [`lookup_field`].
#[wasm_export]
pub(crate) fn lookup_string(
    caller: &mut Caller<'_, ScanContext>,
    structure: Option<Rc<Struct>>,
    num_lookup_indexes: i32,
) -> Option<RuntimeString> {
    match lookup_field(caller, structure, num_lookup_indexes) {
        TypeValue::String(Value::Var(s)) => Some(RuntimeString::Rc(s)),
        TypeValue::String(Value::Const(s)) => Some(RuntimeString::Rc(s)),
        TypeValue::String(Value::Unknown) => None,
        _ => unreachable!(),
    }
}

/// Lookup a value in a struct, and put its value in a variable.
///
/// See [`lookup_field`].
#[wasm_export]
pub(crate) fn lookup_object(
    caller: &mut Caller<'_, ScanContext>,
    structure: Option<Rc<Struct>>,
    num_lookup_indexes: i32,
) -> RuntimeObjectHandle {
    let type_value = lookup_field(caller, structure, num_lookup_indexes);
    let ctx = caller.data_mut();
    match type_value {
        TypeValue::Struct(s) => ctx.store_struct(s),
        TypeValue::Array(a) => ctx.store_array(a),
        TypeValue::Map(m) => ctx.store_map(m),
        _ => unreachable!(),
    }
}

macro_rules! gen_lookup_fn {
    ($name:ident, $return_type:ty, $type:path) => {
        #[wasm_export]
        pub(crate) fn $name(
            caller: &mut Caller<'_, ScanContext>,
            structure: Option<Rc<Struct>>,
            num_lookup_indexes: i32,
        ) -> Option<$return_type> {
            if let $type(value) =
                lookup_field(caller, structure, num_lookup_indexes)
            {
                value.extract().cloned()
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
            _: &mut Caller<'_, ScanContext>,
            array: Rc<Array>,
            index: i64,
        ) -> Option<$return_type> {
            array.$fn().get(index as usize).map(|value| *value)
        }
    };
}

gen_array_indexing_fn!(array_indexing_integer, as_integer_array, i64);
gen_array_indexing_fn!(array_indexing_float, as_float_array, f64);
gen_array_indexing_fn!(array_indexing_bool, as_bool_array, bool);

#[wasm_export]
#[rustfmt::skip]
pub(crate) fn array_indexing_string(
    _: &mut Caller<'_, ScanContext>,
    array: Rc<Array>,
    index: i64,
) -> Option<Rc<BString>> {
    array
        .as_string_array()
        .get(index as usize)
        .cloned()
}

#[wasm_export]
#[rustfmt::skip]
pub(crate) fn array_indexing_struct(
    _: &mut Caller<'_, ScanContext>,
    array: Rc<Array>,
    index: i64,
) -> Option<Rc<Struct>> {
    array
        .as_struct_array()
        .get(index as usize)
        .cloned()
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
            _: &mut Caller<'_, ScanContext>,
            map: Rc<Map>,
            key: i64,
        ) -> Option<$return_type> {
            map.$with().get(&key).map(|v| v.$as())
        }
    };
    ($name:ident, RuntimeString, $return_type:ty, $with:ident, $as:ident) => {
        #[wasm_export]
        pub(crate) fn $name(
            caller: &mut Caller<'_, ScanContext>,
            map: Rc<Map>,
            key: RuntimeString,
        ) -> Option<$return_type> {
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
    _: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    key: i64,
) -> Option<Rc<BString>> {
    map.with_integer_keys().get(&key).map(|s| s.as_string())
}

#[wasm_export]
pub(crate) fn map_lookup_string_string(
    caller: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    key: RuntimeString,
) -> Option<Rc<BString>> {
    let key = key.as_bstr(caller.data());
    map.with_string_keys().get(key).map(|s| s.as_string())
}

#[wasm_export]
pub(crate) fn map_lookup_integer_struct(
    _: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    key: i64,
) -> Option<Rc<Struct>> {
    map.with_integer_keys().get(&key).map(|v| v.as_struct())
}

#[wasm_export]
pub(crate) fn map_lookup_string_struct(
    caller: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    key: RuntimeString,
) -> Option<Rc<Struct>> {
    let key = key.as_bstr(caller.data());
    map.with_string_keys().get(key).map(|v| v.as_struct())
}

macro_rules! gen_map_lookup_by_index_fn {
    ($name:ident, RuntimeString, $val:ty, $with:ident, $as:ident) => {
        #[wasm_export]
        pub(crate) fn $name(
            _: &mut Caller<'_, ScanContext>,
            map: Rc<Map>,
            index: i64,
        ) -> (Rc<BString>, $val) {
            map.with_string_keys()
                .get_index(index as usize)
                .map(|(key, value)| (Rc::new(key.clone()), value.$as()))
                .unwrap()
        }
    };
    ($name:ident, $key:ty, $val:ty, $with:ident, $as:ident) => {
        #[wasm_export]
        pub(crate) fn $name(
            _: &mut Caller<'_, ScanContext>,
            map: Rc<Map>,
            index: i64,
        ) -> ($key, $val) {
            map.$with()
                .get_index(index as usize)
                .map(|(key, value)| (*key, value.$as()))
                .unwrap()
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
    _: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    index: i64,
) -> (i64, Rc<BString>) {
    map.with_integer_keys()
        .get_index(index as usize)
        .map(|(key, value)| (*key, value.as_string()))
        .unwrap()
}

#[wasm_export]
pub(crate) fn map_lookup_by_index_string_string(
    _: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    index: i64,
) -> (Rc<BString>, Rc<BString>) {
    map.with_string_keys()
        .get_index(index as usize)
        .map(|(key, value)| {
            (Rc::new(key.as_bstr().to_owned()), value.as_string())
        })
        .unwrap()
}

#[wasm_export]
pub(crate) fn map_lookup_by_index_integer_struct(
    _: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    index: i64,
) -> (i64, Rc<Struct>) {
    map.with_integer_keys()
        .get_index(index as usize)
        .map(|(key, value)| (*key, value.as_struct()))
        .unwrap()
}

#[wasm_export]
pub(crate) fn map_lookup_by_index_string_struct(
    _: &mut Caller<'_, ScanContext>,
    map: Rc<Map>,
    index: i64,
) -> (Rc<BString>, Rc<Struct>) {
    map.with_string_keys()
        .get_index(index as usize)
        .map(|(key, value)| {
            (Rc::new(key.as_bstr().to_owned()), value.as_struct())
        })
        .unwrap()
}

macro_rules! gen_str_cmp_fn {
    ($name:ident, $op:tt) => {
        #[wasm_export]
        pub(crate) fn $name(
            caller: &mut Caller<'_, ScanContext>,
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
            caller: &mut Caller<'_, ScanContext>,
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
    caller: &mut Caller<'_, ScanContext>,
    s: RuntimeString,
) -> i64 {
    s.len(caller.data()) as i64
}

#[wasm_export]
pub(crate) fn str_matches(
    caller: &mut Caller<'_, ScanContext>,
    lhs: RuntimeString,
    rhs: RegexpId,
) -> bool {
    let ctx = caller.data();
    ctx.regexp_matches(rhs, lhs.as_bstr(ctx))
}

macro_rules! gen_xint_fn {
    ($name:ident, $return_type:ty, $from_fn:ident) => {
        #[wasm_export(public = true)]
        pub(crate) fn $name(
            caller: &mut Caller<'_, ScanContext>,
            offset: i64,
        ) -> Option<i64> {
            let offset = usize::try_from(offset).ok()?;
            caller
                .data()
                .scanned_data()
                .get(offset..offset + mem::size_of::<$return_type>())
                .map(|bytes| {
                    <$return_type>::$from_fn(bytes.try_into().unwrap()) as i64
                })
        }
    };
}

gen_xint_fn!(uint8, u8, from_le_bytes);
gen_xint_fn!(uint16, u16, from_le_bytes);
gen_xint_fn!(uint32, u32, from_le_bytes);
gen_xint_fn!(uint8be, u8, from_be_bytes);
gen_xint_fn!(uint16be, u16, from_be_bytes);
gen_xint_fn!(uint32be, u32, from_be_bytes);

gen_xint_fn!(int8, i8, from_le_bytes);
gen_xint_fn!(int16, i16, from_le_bytes);
gen_xint_fn!(int32, i32, from_le_bytes);
gen_xint_fn!(int8be, i8, from_be_bytes);
gen_xint_fn!(int16be, i16, from_be_bytes);
gen_xint_fn!(int32be, i32, from_be_bytes);
