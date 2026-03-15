//! `wasm32-wasip1` runtime implemented through the WIT host bridge.
//!
//! Generated WASM is validated and instantiated by host-provided functions,
//! while this guest-side shim keeps the rest of YARA-X talking to a
//! Wasmtime-shaped API.

use std::mem::MaybeUninit;
use std::slice;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use crate::scanner::ScanError;

use super::common::{self, RuntimeBackend};

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "runtime",
    });
}

mod host {
    pub use super::bindings::yara::runtime::host::*;
}

// Sentinel string returned by the host bridge when a call times out.
const HOST_TIMEOUT_ERROR: &str = "__yarax_timeout__";
// Sentinel used by the host bridge to indicate that no timeout is active.
const NO_TIMEOUT_NANOS: u64 = u64::MAX;

/// `wasm32-wasip1` runtime backend.
#[derive(Clone, Default)]
pub struct Backend;

pub(crate) use super::common::{
    AsContext, AsContextMut, Config, Engine, OptLevel,
};

/// Alias for [`common::Caller`] specialized for the `wasm32-wasip1` backend.
pub type Caller<'a, T> = common::Caller<'a, T, Backend>;
/// Alias for [`common::Instance`] specialized for the `wasm32-wasip1` backend.
pub type Instance = common::Instance<Backend>;
/// Alias for [`common::Linker`] specialized for the `wasm32-wasip1` backend.
pub type Linker<T> = common::Linker<T, Backend>;
/// Alias for [`common::Memory`] specialized for the `wasm32-wasip1` backend.
pub type Memory = common::Memory;
/// Alias for [`common::Module`] specialized for the `wasm32-wasip1` backend.
pub type Module = common::Module<Backend>;
/// Alias for [`common::Store`] specialized for the `wasm32-wasip1` backend.
pub type Store<T> = common::Store<T, Backend>;
/// Alias for [`common::StoreContext`] specialized for the `wasm32-wasip1`
/// backend.
pub type StoreContext<'a, T> = common::StoreContext<'a, T, Backend>;
/// Alias for [`common::StoreContextMut`] specialized for the `wasm32-wasip1`
/// backend.
pub type StoreContextMut<'a, T> = common::StoreContextMut<'a, T, Backend>;
/// Alias for [`common::TypedFunc`] specialized for the `wasm32-wasip1`
/// backend.
pub type TypedFunc<P, R> = common::TypedFunc<P, R, Backend>;

/// Shared Wasmtime-like runtime types used by the `wasm32-wasip1` backend.
pub use super::common::{
    Extern, FuncType, Global, GlobalType, MemoryType, Mutability, Val, ValRaw,
    ValType,
};

struct GlobalInner {
    val_type: ValType,
    mutability: Mutability,
    handle: u64,
}

struct MemoryInner {
    handle: u64,
    cache: Vec<u8>,
}

pub(crate) struct InstanceInner {
    session: u64,
    id: u64,
}

impl Drop for InstanceInner {
    fn drop(&mut self) {
        let _ = host::instance_destroy(self.session, self.id);
    }
}

pub(crate) struct TypedFuncHandle {
    instance: Arc<InstanceInner>,
    name: String,
}

/// `wasm32-wasip1` runtime state stored alongside each [`Store`].
#[derive(Default)]
pub struct RuntimeState {
    session_id: u64,
    timeout_deadline: Option<Instant>,
    globals: Vec<GlobalInner>,
    memories: Vec<MemoryInner>,
    import_callbacks: Vec<Box<CallbackEntry>>,
}

impl RuntimeState {
    fn remaining_timeout_nanos(&self) -> Result<u64> {
        let Some(deadline) = self.timeout_deadline else {
            return Ok(NO_TIMEOUT_NANOS);
        };

        let now = Instant::now();
        if now >= deadline {
            return Err(ScanError::Timeout.into());
        }

        let remaining = deadline.duration_since(now).as_nanos();
        Ok(remaining.min((NO_TIMEOUT_NANOS - 1) as u128) as u64)
    }

    fn register_callback<T: 'static>(
        &mut self,
        params: Vec<ValType>,
        results: Vec<ValType>,
        sync_flags: u32,
        trampoline: common::HostFunc<T, Backend>,
        store_ptr: *mut Store<T>,
    ) -> u64 {
        // Keep the callback entry boxed so its address can act as a stable
        // callback identifier for the duration of the instance.
        let mut entry = Box::new(CallbackEntry {
            session_id: self.session_id,
            invoke: Box::new(move |args: Vec<u64>| {
                let store = unsafe { &mut *store_ptr };

                if common::should_sync_before(sync_flags) {
                    store.runtime.sync_memory_from_host()?;
                }

                let mut args_and_results =
                    vec![
                        ValRaw::default();
                        common::callback_storage_len(&params, &results)
                    ];

                for (idx, ty) in params.iter().enumerate() {
                    let raw = args.get(idx).copied().unwrap_or_default();
                    let _ = ty;
                    args_and_results[idx] = ValRaw::from_raw(raw);
                }

                let caller = Caller::new(store);
                trampoline(caller, &mut args_and_results)?;

                if common::should_sync_after(sync_flags) {
                    store.runtime.sync_memory_to_host()?;
                }

                Ok(results
                    .iter()
                    .enumerate()
                    .map(|(idx, ty)| {
                        common::valraw_to_raw(args_and_results[idx], *ty)
                    })
                    .collect())
            }),
        });

        let callback_id = (&mut *entry as *mut CallbackEntry) as usize as u64;
        self.import_callbacks.push(entry);
        callback_id
    }

    fn sync_memory_from_host(&mut self) -> Result<()> {
        for memory in &mut self.memories {
            let data = host_result(host::memory_read(
                self.session_id,
                memory.handle,
            ))?;
            memory.cache = data;
        }
        Ok(())
    }

    fn sync_memory_to_host(&mut self) -> Result<()> {
        for memory in &self.memories {
            host_result(host::memory_write(
                self.session_id,
                memory.handle,
                &memory.cache,
            ))?;
        }
        Ok(())
    }
}

impl RuntimeBackend for Backend {
    type RuntimeState = RuntimeState;
    type ModuleInner = Vec<u8>;
    type InstanceInner = Arc<InstanceInner>;
    type TypedFuncHandle = TypedFuncHandle;

    fn set_epoch_deadline(runtime: &mut Self::RuntimeState, deadline: u64) {
        runtime.timeout_deadline = if deadline == 0 {
            None
        } else {
            Instant::now().checked_add(Duration::from_secs(deadline))
        };
    }

    fn set_runtime_session(runtime: &mut Self::RuntimeState, session_id: u64) {
        runtime.session_id = session_id;
    }

    fn prepare_for_instantiation(runtime: &mut Self::RuntimeState) {
        runtime.import_callbacks.clear();
    }

    fn reset_for_store_reuse(runtime: &mut Self::RuntimeState) {
        runtime.import_callbacks.clear();
        runtime.timeout_deadline = None;
        runtime.globals.clear();
        runtime.memories.clear();
    }

    fn create_global(
        runtime: &mut Self::RuntimeState,
        ty: GlobalType,
        value: Val,
    ) -> Result<usize> {
        let handle = host_result(host::global_new(
            runtime.session_id,
            val_type_to_host(ty.val_type),
            matches!(ty.mutability, Mutability::Var),
            common::val_to_raw(value),
        ))?;

        runtime.globals.push(GlobalInner {
            val_type: ty.val_type,
            mutability: ty.mutability,
            handle,
        });

        Ok(runtime.globals.len() - 1)
    }

    fn get_global(runtime: &mut Self::RuntimeState, id: usize) -> Val {
        let inner = &runtime.globals[id];
        match host::global_get(
            runtime.session_id,
            inner.handle,
            val_type_to_host(inner.val_type),
        ) {
            Ok(raw) => common::raw_to_val(raw, inner.val_type),
            Err(_) => common::default_val(inner.val_type),
        }
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
        host_result(host::global_set(
            runtime.session_id,
            inner.handle,
            val_type_to_host(inner.val_type),
            common::val_to_raw(value),
        ))
    }

    fn create_memory(
        runtime: &mut Self::RuntimeState,
        ty: MemoryType,
    ) -> Result<usize> {
        let handle = host_result(host::memory_new(
            runtime.session_id,
            ty.initial,
            ty.maximum,
        ))?;
        let cache = vec![0_u8; ty.initial as usize * 65_536];

        runtime.memories.push(MemoryInner { handle, cache });
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
        host_result(host::validate_module(bytes))?;
        Ok(bytes.to_vec())
    }

    fn module_serialize(module: &Self::ModuleInner) -> Result<Vec<u8>> {
        Ok(module.clone())
    }

    fn instantiate<T: 'static>(
        store: &mut Store<T>,
        linker: &Linker<T>,
        module: &Module,
    ) -> Result<Self::InstanceInner> {
        let store_ptr = store as *mut Store<T>;

        let mut function_imports = Vec::with_capacity(linker.functions.len());
        for import in &linker.functions {
            let callback_id = store.runtime.register_callback(
                import.ty.params.clone(),
                import.ty.results.clone(),
                import.sync_flags,
                Arc::clone(&import.trampoline),
                store_ptr,
            );

            function_imports.push(host::FunctionImport {
                module: import.module.clone(),
                name: import.name.clone(),
                params: import
                    .ty
                    .params
                    .iter()
                    .copied()
                    .map(val_type_to_host)
                    .collect(),
                results: import
                    .ty
                    .results
                    .iter()
                    .copied()
                    .map(val_type_to_host)
                    .collect(),
                callback_id,
                sync_flags: import.sync_flags,
            });
        }

        let mut extern_imports = Vec::with_capacity(linker.externs.len());
        for defined in &linker.externs {
            let value = match defined.value {
                Extern::Global(global) => host::ExternValue::Global(
                    store.runtime.globals[global.id].handle,
                ),
                Extern::Memory(memory) => host::ExternValue::Memory(
                    store.runtime.memories[memory.id].handle,
                ),
            };

            extern_imports.push(host::ExternImport {
                module: defined.module.clone(),
                name: defined.name.clone(),
                value,
            });
        }

        let id = host_result(host::instantiate(
            store.runtime.session_id,
            &module.inner,
            &function_imports,
            &extern_imports,
        ))?;

        Ok(Arc::new(InstanceInner { session: store.runtime.session_id, id }))
    }

    fn get_typed_func_handle<P, R>(
        instance: &Self::InstanceInner,
        name: &str,
    ) -> Result<Self::TypedFuncHandle> {
        Ok(TypedFuncHandle {
            instance: Arc::clone(instance),
            name: name.to_owned(),
        })
    }

    fn typed_func_call_i32<T>(
        store: &mut Store<T>,
        func: &Self::TypedFuncHandle,
    ) -> Result<i32> {
        store.runtime.sync_memory_to_host()?;
        let timeout_nanos = store.runtime.remaining_timeout_nanos()?;

        let returned = match host::call_export(
            store.runtime.session_id,
            func.instance.id,
            func.name.as_str(),
            &[],
            &[host::ValType::I32],
            timeout_nanos,
        ) {
            Ok(returned) => returned,
            Err(message) if message == HOST_TIMEOUT_ERROR => {
                return Err(ScanError::Timeout.into());
            }
            Err(message) => return Err(anyhow!(message)),
        };

        store.runtime.sync_memory_from_host()?;

        if returned.len() != 1 {
            return Err(anyhow!("main returned unexpected number of values"));
        }

        Ok(returned[0] as u32 as i32)
    }
}

/// Callback registered with the host bridge.
struct CallbackEntry {
    session_id: u64,
    invoke: Box<dyn Fn(Vec<u64>) -> Result<Vec<u64>>>,
}

fn invoke_registered_callback(
    session_id: u64,
    callback_id: u64,
    args: Vec<u64>,
) -> std::result::Result<Vec<u64>, String> {
    let callback =
        unsafe { (callback_id as usize as *const CallbackEntry).as_ref() }
            .ok_or_else(|| format!("unknown callback id `{callback_id}`"))?;

    // Callback identifiers are process-local pointers, so guard against the
    // host trying to call a callback that belongs to another session.
    if callback.session_id != session_id {
        return Err(format!(
            "callback `{callback_id}` belongs to session `{}`, not `{session_id}`",
            callback.session_id,
        ));
    }

    (callback.invoke)(args).map_err(|err| err.to_string())
}

const CALLBACK_RETURN_AREA_SIZE: usize = 3 * std::mem::size_of::<*const u8>();
const CALLBACK_RESULT_ALIGN: usize = std::mem::align_of::<u64>();

#[cfg_attr(target_pointer_width = "64", repr(align(8)))]
#[cfg_attr(target_pointer_width = "32", repr(align(4)))]
// Matches the lowered component-model return area used by the generated WIT
// bindings: tag, payload pointer, and payload length.
struct CallbackReturnArea([MaybeUninit<u8>; CALLBACK_RETURN_AREA_SIZE]);

unsafe fn write_callback_return(
    area: *mut u8,
    result: std::result::Result<Vec<u64>, String>,
) {
    match result {
        Ok(values) => {
            let boxed = values.into_boxed_slice();
            let ptr = boxed.as_ptr() as *mut u8;
            let len = boxed.len();
            std::mem::forget(boxed);

            // SAFETY: `area` points to the callback return area allocated by
            // `export_invoke_callback`, which is large enough for the tag,
            // payload pointer, and payload length fields.
            unsafe {
                *area.add(0).cast::<u8>() = 0;
                *area
                    .add(std::mem::size_of::<*const u8>())
                    .cast::<*mut u8>() = ptr;
                *area
                    .add(2 * std::mem::size_of::<*const u8>())
                    .cast::<usize>() = len;
            }
        }
        Err(message) => {
            let boxed = message.into_bytes().into_boxed_slice();
            let ptr = boxed.as_ptr() as *mut u8;
            let len = boxed.len();
            std::mem::forget(boxed);

            // SAFETY: `area` points to the callback return area allocated by
            // `export_invoke_callback`, which is large enough for the tag,
            // payload pointer, and payload length fields.
            unsafe {
                *area.add(0).cast::<u8>() = 1;
                *area
                    .add(std::mem::size_of::<*const u8>())
                    .cast::<*mut u8>() = ptr;
                *area
                    .add(2 * std::mem::size_of::<*const u8>())
                    .cast::<usize>() = len;
            }
        }
    }
}

/// Guest entry point used by the host bridge to invoke imported callbacks.
#[unsafe(export_name = "yara:runtime/callbacks#invoke-callback")]
unsafe extern "C" fn export_invoke_callback(
    session_id: i64,
    callback_id: i64,
    args_ptr: *mut u8,
    args_len: usize,
) -> *mut u8 {
    let args = if args_len == 0 {
        Vec::new()
    } else {
        // SAFETY: the host passes a valid pointer/length pair containing
        // `args_len` contiguous `u64` values for this callback invocation.
        unsafe { slice::from_raw_parts(args_ptr.cast::<u64>(), args_len) }
            .to_vec()
    };

    let result = invoke_registered_callback(
        session_id as u64,
        callback_id as u64,
        args,
    );

    let area = Box::into_raw(Box::new(CallbackReturnArea(
        [MaybeUninit::uninit(); CALLBACK_RETURN_AREA_SIZE],
    )));
    let area_ptr = area.cast::<u8>();
    // SAFETY: `area_ptr` points to the freshly allocated callback return area.
    unsafe { write_callback_return(area_ptr, result) };
    area_ptr
}

/// Guest post-return hook used by the host bridge to release callback results.
#[unsafe(export_name = "cabi_post_yara:runtime/callbacks#invoke-callback")]
unsafe extern "C" fn post_return_invoke_callback(area: *mut u8) {
    if area.is_null() {
        return;
    }

    // SAFETY: `area` points to a `CallbackReturnArea` previously allocated by
    // `export_invoke_callback`, so these field reads are within bounds.
    let (tag, payload_ptr, payload_len) = unsafe {
        (
            *area.add(0).cast::<u8>(),
            *area.add(std::mem::size_of::<*const u8>()).cast::<*mut u8>(),
            *area.add(2 * std::mem::size_of::<*const u8>()).cast::<usize>(),
        )
    };

    if !payload_ptr.is_null() && payload_len != 0 {
        let (size, align) = if tag == 0 {
            (payload_len * std::mem::size_of::<u64>(), CALLBACK_RESULT_ALIGN)
        } else {
            (payload_len, 1)
        };
        let layout = std::alloc::Layout::from_size_align(size, align)
            .expect("callback return payload layout must be valid");
        // SAFETY: `payload_ptr` was allocated from the global allocator with
        // the same layout in `write_callback_return`.
        unsafe { std::alloc::dealloc(payload_ptr, layout) };
    }

    // SAFETY: `area` was allocated with `Box::into_raw` in
    // `export_invoke_callback` and must be reclaimed exactly once here.
    unsafe { drop(Box::from_raw(area.cast::<CallbackReturnArea>())) };
}

/// Converts a host bridge result into an [`anyhow::Result`].
fn host_result<T>(result: std::result::Result<T, String>) -> Result<T> {
    result.map_err(|message| anyhow!("{message}"))
}

/// Converts a runtime value type into the host bridge representation.
fn val_type_to_host(val_type: ValType) -> host::ValType {
    match val_type {
        ValType::I64 => host::ValType::I64,
        ValType::I32 => host::ValType::I32,
        ValType::F64 => host::ValType::F64Bits,
        ValType::F32 => host::ValType::F32Bits,
    }
}
