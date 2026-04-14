//! Browser runtime implemented on top of the host WebAssembly API.
//!
//! This backend stores a Rust-side view of globals and memories while the
//! actual execution happens in the browser's WebAssembly runtime.

use anyhow::{Result, anyhow};
use js_sys::{
    Array, BigInt, Function, Object, Reflect, Uint8Array, WebAssembly,
};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

use super::common::{self, RuntimeBackend};

/// Browser runtime backend.
#[derive(Clone, Default)]
pub(crate) struct Backend;

pub(crate) use super::common::{
    AsContext, AsContextMut, Config, Engine, OptLevel,
};
/// Alias for [`common::Caller`] specialized for the browser backend.
pub(crate) type Caller<'a, T> = common::Caller<'a, T, Backend>;
/// Alias for [`common::Instance`] specialized for the browser backend.
pub(crate) type Instance = common::Instance<Backend>;
/// Alias for [`common::Linker`] specialized for the browser backend.
pub(crate) type Linker<T> = common::Linker<T, Backend>;
/// Alias for [`common::Memory`] specialized for the browser backend.
pub(crate) type Memory = common::Memory;
/// Alias for [`common::Module`] specialized for the browser backend.
pub(crate) type Module = common::Module<Backend>;
/// Alias for [`common::Store`] specialized for the browser backend.
pub(crate) type Store<T> = common::Store<T, Backend>;
/// Alias for [`common::TypedFunc`] specialized for the browser backend.
pub(crate) type TypedFunc<P, R> = common::TypedFunc<P, R, Backend>;

/// Shared Wasmtime-like runtime types used by the browser backend.
pub(crate) use super::common::{
    Extern, FuncType, Global, GlobalType, MemoryType, Mutability, Val, ValRaw,
    ValType,
};

pub(crate) type Trampoline<T> = common::Trampoline<T, Backend>;
pub(crate) type TrampolineResult = common::TrampolineResult;

struct GlobalInner {
    val_type: ValType,
    mutability: Mutability,
    js_global: WebAssembly::Global,
}

struct MemoryInner {
    js_memory: WebAssembly::Memory,
    cache: Vec<u8>,
}

/// Browser-specific runtime state stored alongside each [`Store`].
#[derive(Default)]
pub(crate) struct RuntimeState {
    globals: Vec<GlobalInner>,
    memories: Vec<MemoryInner>,
    import_callbacks:
        Vec<Closure<dyn FnMut(JsValue, JsValue, JsValue, JsValue) -> JsValue>>,
}

impl RuntimeState {
    fn sync_memory_from_js(&mut self) {
        // The browser runtime owns the actual linear memory. Keep the Rust-side
        // cache aligned with it before Rust reads from memory-backed state.
        for memory in &mut self.memories {
            let js = Uint8Array::new(&memory.js_memory.buffer());
            if memory.cache.len() != js.length() as usize {
                memory.cache.resize(js.length() as usize, 0);
            }
            js.copy_to(memory.cache.as_mut_slice());
        }
    }

    fn sync_memory_to_js(&mut self) {
        // Writes performed through the Rust-side cache must be copied back into
        // the browser's WebAssembly memory before guest code observes them.
        for memory in &mut self.memories {
            let js = Uint8Array::new(&memory.js_memory.buffer());
            if memory.cache.len() != js.length() as usize {
                memory.cache.resize(js.length() as usize, 0);
            }
            js.copy_from(memory.cache.as_slice());
        }
    }
}

impl RuntimeBackend for Backend {
    type RuntimeState = RuntimeState;
    type ModuleInner = Vec<u8>;
    type InstanceInner = WebAssembly::Instance;
    type TypedFuncHandle = Function;

    fn set_epoch_deadline(_runtime: &mut Self::RuntimeState, _deadline: u64) {}

    fn prepare_for_instantiation(runtime: &mut Self::RuntimeState) {
        runtime.import_callbacks.clear();
    }

    fn reset_for_store_reuse(runtime: &mut Self::RuntimeState) {
        runtime.import_callbacks.clear();
        runtime.globals.clear();
        runtime.memories.clear();
    }

    fn create_global(
        runtime: &mut Self::RuntimeState,
        ty: GlobalType,
        value: Val,
    ) -> Result<usize> {
        let descriptor = Object::new();
        Reflect::set(
            &descriptor,
            &JsValue::from_str("value"),
            &JsValue::from_str(val_type_name(ty.val_type)),
        )
        .map_err(js_error)?;
        Reflect::set(
            &descriptor,
            &JsValue::from_str("mutable"),
            &JsValue::from_bool(matches!(ty.mutability, Mutability::Var)),
        )
        .map_err(js_error)?;

        let js_global =
            WebAssembly::Global::new(&descriptor, &val_to_js(value))
                .map_err(js_error)?;

        runtime.globals.push(GlobalInner {
            val_type: ty.val_type,
            mutability: ty.mutability,
            js_global,
        });

        Ok(runtime.globals.len() - 1)
    }

    fn get_global(runtime: &mut Self::RuntimeState, id: usize) -> Val {
        let inner = &runtime.globals[id];
        js_to_val(&inner.js_global.value(), inner.val_type)
            .unwrap_or_else(|_| common::default_val(inner.val_type))
    }

    fn set_global(
        runtime: &mut Self::RuntimeState,
        id: usize,
        value: Val,
    ) -> Result<()> {
        let inner = &runtime.globals[id];
        if !matches!(inner.mutability, Mutability::Var) {
            return Err(anyhow!("attempted to set immutable global"));
        }
        inner.js_global.set_value(&val_to_js(value));
        Ok(())
    }

    fn create_memory(
        runtime: &mut Self::RuntimeState,
        ty: MemoryType,
    ) -> Result<usize> {
        let descriptor = Object::new();
        Reflect::set(
            &descriptor,
            &JsValue::from_str("initial"),
            &JsValue::from_f64(ty.initial as f64),
        )
        .map_err(js_error)?;
        if let Some(max) = ty.maximum {
            Reflect::set(
                &descriptor,
                &JsValue::from_str("maximum"),
                &JsValue::from_f64(max as f64),
            )
            .map_err(js_error)?;
        }

        let js_memory =
            WebAssembly::Memory::new(&descriptor).map_err(js_error)?;
        let cache = vec![0_u8; ty.initial as usize * 65_536];

        runtime.memories.push(MemoryInner { js_memory, cache });
        Ok(runtime.memories.len() - 1)
    }

    fn memory_data<'a>(
        runtime: &'a Self::RuntimeState,
        id: usize,
    ) -> &'a [u8] {
        runtime.memories[id].cache.as_slice()
    }

    fn memory_data_mut<'a>(
        runtime: &'a mut Self::RuntimeState,
        id: usize,
    ) -> &'a mut [u8] {
        runtime.memories[id].cache.as_mut_slice()
    }

    fn memory_data_ptr(
        runtime: &mut Self::RuntimeState,
        id: usize,
    ) -> *mut u8 {
        runtime.memories[id].cache.as_mut_ptr()
    }

    fn module_from_binary(
        _engine: &Engine,
        bytes: &[u8],
    ) -> Result<Self::ModuleInner> {
        // Validate eagerly so errors surface at compile/load time while still
        // keeping the original bytes for later instantiation and serialization.
        let wasm = Uint8Array::from(bytes);
        let _ = WebAssembly::Module::new(&wasm.into()).map_err(js_error)?;
        Ok(bytes.to_vec())
    }

    fn instantiate<T: 'static>(
        store: &mut Store<T>,
        linker: &Linker<T>,
        module: &Module,
    ) -> Result<Self::InstanceInner> {
        let imports = Object::new();

        for defined in &linker.externs {
            let ns = ensure_namespace(&imports, &defined.module)?;
            let value: JsValue = match defined.value {
                Extern::Global(global) => {
                    store.runtime.globals[global.id].js_global.clone().into()
                }
                Extern::Memory(memory) => {
                    store.runtime.memories[memory.id].js_memory.clone().into()
                }
            };

            Reflect::set(
                &ns,
                &JsValue::from_str(defined.name.as_str()),
                &value,
            )
            .map_err(js_error)?;
        }

        let store_ptr = store as *mut Store<T>;

        for import in &linker.functions {
            let ns = ensure_namespace(&imports, import.module.as_str())?;
            let params = import.ty.params.clone();
            let results = import.ty.results.clone();
            let sync_flags = import.sync_flags;
            let trampoline = std::sync::Arc::clone(&import.trampoline);

            let callback = Closure::wrap(Box::new(
                move |a0: JsValue,
                      a1: JsValue,
                      a2: JsValue,
                      a3: JsValue|
                      -> JsValue {
                    let store = unsafe { &mut *store_ptr };

                    if common::should_sync_before(sync_flags) {
                        store.runtime.sync_memory_from_js();
                    }

                    let mut args_and_results = vec![
                        ValRaw::default();
                        common::callback_storage_len(&params, &results)
                    ];

                    let incoming = [a0, a1, a2, a3];

                    for (idx, ty) in params.iter().enumerate() {
                        args_and_results[idx] =
                            js_to_valraw(&incoming[idx], *ty)
                                .unwrap_or_default();
                    }

                    let caller = Caller::new(store);

                    if trampoline(caller, &mut args_and_results).is_err() {
                        return JsValue::UNDEFINED;
                    }

                    if common::should_sync_after(sync_flags) {
                        store.runtime.sync_memory_to_js();
                    }

                    match results.len() {
                        0 => JsValue::UNDEFINED,
                        1 => valraw_to_js(args_and_results[0], results[0]),
                        _ => {
                            let js = Array::new();
                            for (idx, ty) in results.iter().enumerate() {
                                js.push(&valraw_to_js(
                                    args_and_results[idx],
                                    *ty,
                                ));
                            }
                            js.into()
                        }
                    }
                },
            )
                as Box<
                    dyn FnMut(JsValue, JsValue, JsValue, JsValue) -> JsValue,
                >);

            Reflect::set(
                &ns,
                &JsValue::from_str(import.name.as_str()),
                callback.as_ref().unchecked_ref::<Function>(),
            )
            .map_err(js_error)?;

            // Keep the closure alive for at least as long as the instance. If
            // this is dropped, the browser may garbage-collect the callback
            // even though the instantiated module still imports it.
            store.runtime.import_callbacks.push(callback);
        }

        let bytes = Uint8Array::from(module.inner.as_slice());
        let js_module =
            WebAssembly::Module::new(&bytes.into()).map_err(js_error)?;
        WebAssembly::Instance::new(&js_module, &imports).map_err(js_error)
    }

    fn get_typed_func_handle<P, R>(
        instance: &Self::InstanceInner,
        name: &str,
    ) -> Result<Self::TypedFuncHandle> {
        let exports = instance.exports();
        let value = Reflect::get(&exports, &JsValue::from_str(name))
            .map_err(js_error)?;
        value
            .dyn_into::<Function>()
            .map_err(|_| anyhow!("export `{name}` is not a function"))
    }

    fn typed_func_call_i32<T>(
        store: &mut Store<T>,
        func: &Self::TypedFuncHandle,
    ) -> Result<i32> {
        // Guest code reads and writes the browser-owned memory directly, so
        // copy the cache in before the call and back out afterwards.
        store.runtime.sync_memory_to_js();

        let value = func.call0(&JsValue::UNDEFINED).map_err(js_error)?;

        store.runtime.sync_memory_from_js();

        if let Some(v) = value.as_f64() {
            return Ok(v as i32);
        }

        Err(anyhow!("main returned a non-number"))
    }
}

fn ensure_namespace(root: &Object, module_name: &str) -> Result<Object> {
    let key = JsValue::from_str(module_name);

    let existing = Reflect::get(root, &key).map_err(js_error)?;
    if existing.is_object() {
        return Ok(existing.unchecked_into::<Object>());
    }

    let namespace = Object::new();
    Reflect::set(root, &key, &namespace).map_err(js_error)?;
    Ok(namespace)
}

fn js_to_valraw(value: &JsValue, ty: ValType) -> Result<ValRaw> {
    Ok(match ty {
        ValType::I32 => ValRaw::i32(value.as_f64().unwrap_or(0.0) as i32),
        ValType::I64 => ValRaw::i64(js_to_i64(value)?),
        ValType::F32 => {
            ValRaw::f32((value.as_f64().unwrap_or(0.0) as f32).to_bits())
        }
        ValType::F64 => ValRaw::f64(value.as_f64().unwrap_or(0.0).to_bits()),
    })
}

fn valraw_to_js(value: ValRaw, ty: ValType) -> JsValue {
    match ty {
        ValType::I32 => JsValue::from_f64(value.get_i32() as f64),
        ValType::I64 => BigInt::from(value.get_i64()).into(),
        ValType::F32 => {
            JsValue::from_f64(f32::from_bits(value.get_f32()) as f64)
        }
        ValType::F64 => JsValue::from_f64(f64::from_bits(value.get_f64())),
    }
}

fn val_to_js(value: Val) -> JsValue {
    match value {
        Val::I32(v) => JsValue::from_f64(v as f64),
        Val::I64(v) => BigInt::from(v).into(),
        Val::F32(v) => JsValue::from_f64(f32::from_bits(v) as f64),
        Val::F64(v) => JsValue::from_f64(f64::from_bits(v)),
    }
}

fn js_to_val(value: &JsValue, ty: ValType) -> Result<Val> {
    Ok(match ty {
        ValType::I32 => Val::I32(value.as_f64().unwrap_or(0.0) as i32),
        ValType::I64 => Val::I64(js_to_i64(value)?),
        ValType::F32 => {
            Val::F32((value.as_f64().unwrap_or(0.0) as f32).to_bits())
        }
        ValType::F64 => Val::F64(value.as_f64().unwrap_or(0.0).to_bits()),
    })
}

fn js_to_i64(value: &JsValue) -> Result<i64> {
    if let Some(v) = value.as_f64() {
        return Ok(v as i64);
    }

    // `wasm-bindgen` represents `i64` values as `BigInt` in JS.
    let bigint = BigInt::from(value.clone());
    let text: String =
        bigint.to_string(10).map_err(|err| js_error(err.into()))?.into();

    text.parse::<i64>()
        .map_err(|err| anyhow!("invalid i64 value `{text}`: {err}"))
}

fn val_type_name(ty: ValType) -> &'static str {
    match ty {
        ValType::I32 => "i32",
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
    }
}

fn js_error(err: JsValue) -> anyhow::Error {
    if let Some(message) = err.as_string() {
        anyhow!("{message}")
    } else {
        anyhow!("{err:?}")
    }
}
