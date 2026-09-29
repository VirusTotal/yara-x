//! Native runtime backed directly by Wasmtime.
//!
//! This adapter exists only to normalize a couple of APIs so the rest of the
//! crate can talk to native and custom runtimes through the same interface.

use std::mem::transmute;

use crate::errors::SerializationError;
use anyhow::anyhow;

pub use wasmtime::Caller;

/// Wasmtime types re-exported by the native runtime.
pub(crate) use wasmtime::{
    AsContext, AsContextMut, Config, Engine, Extern, FuncType, Global,
    GlobalType, Instance, Memory, MemoryType, Mutability, OptLevel, Store,
    TypedFunc, Val, ValRaw, ValType,
};

#[derive(Clone)]
pub(crate) struct Module(wasmtime::Module);

impl Module {
    pub fn from_binary(
        engine: &Engine,
        binary: &[u8],
    ) -> wasmtime::Result<Self> {
        if cfg!(target_env = "musl") {
            // Under musl, the default stack size for threads can be very small
            // (typically 128 KB), which is insufficient for the deep call stacks
            // required by Wasmtime/Cranelift during WebAssembly compilation.
            // To avoid stack overflow crashes, we compile the WebAssembly module
            // in a separate thread with a guaranteed 8 MB stack size.
            std::thread::scope(|s| {
                std::thread::Builder::new()
                    .name("yara-x-wasm-compiler".to_string())
                    .stack_size(8 * 1024 * 1024) // 8MB stack size
                    .spawn_scoped(s, || {
                        wasmtime::Module::from_binary(engine, binary)
                            .map(Module)
                    })
                    .unwrap()
                    .join()
                    .unwrap()
            })
        } else {
            wasmtime::Module::from_binary(engine, binary).map(Module)
        }
    }

    pub fn deserialize(
        engine: &Engine,
        bytes: impl AsRef<[u8]>,
    ) -> wasmtime::Result<Self> {
        unsafe { wasmtime::Module::deserialize(engine, bytes).map(Module) }
    }

    #[allow(dead_code)]
    pub fn serialize(&self) -> wasmtime::Result<Vec<u8>> {
        self.0.serialize()
    }
}

/// Thin wrapper around [`wasmtime::Linker`] with a backend-neutral API.
pub(crate) struct Linker<T>(wasmtime::Linker<T>);

pub(crate) type Trampoline<T> = Box<
    dyn Fn(Caller<'_, T>, &mut [ValRaw]) -> TrampolineResult
        + Send
        + Sync
        + 'static,
>;

pub(crate) type TrampolineResult = wasmtime::Result<()>;

impl<T: 'static> Linker<T> {
    /// Creates a new linker.
    pub fn new(engine: &wasmtime::Engine) -> Self {
        Self(wasmtime::Linker::new(engine))
    }

    /// Registers a function import without validating its ABI.
    ///
    /// The custom runtimes use `sync_flags` to decide when imported module
    /// state must be synchronized. Native wasmtime shares state directly, so
    /// those flags are ignored here.
    pub unsafe fn func_new_unchecked(
        &mut self,
        module: &str,
        name: &str,
        ty: FuncType,
        sync_flags: u32,
        trampoline: Trampoline<T>,
    ) -> TrampolineResult {
        let _ = sync_flags;
        unsafe {
            self.0
                .func_new_unchecked(module, name, ty, move |caller, args| {
                    trampoline(
                        caller,
                        transmute::<
                            &mut [std::mem::MaybeUninit<ValRaw>],
                            &mut [ValRaw],
                        >(args),
                    )
                })
                .map(|_| ())
        }
    }

    /// Defines an extern import.
    pub fn define(
        &mut self,
        store: impl AsContext<Data = T>,
        module: &str,
        name: &str,
        item: impl Into<Extern>,
    ) -> wasmtime::Result<&mut Self> {
        self.0.define(store, module, name, item)?;
        Ok(self)
    }

    /// Instantiates `module` with the imports currently registered.
    pub fn instantiate(
        &self,
        store: impl AsContextMut<Data = T>,
        module: &Module,
    ) -> Result<Instance, SerializationError> {
        self.0
            .instantiate(store, &module.0)
            .map_err(|e| SerializationError::InvalidWASM(anyhow!(e)))
    }
}
