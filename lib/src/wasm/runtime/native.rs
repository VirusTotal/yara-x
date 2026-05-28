//! Native runtime backed directly by Wasmtime.
//!
//! This adapter exists only to normalize a couple of APIs so the rest of the
//! crate can talk to native and custom runtimes through the same interface.

use crate::errors::SerializationError;
use anyhow::anyhow;
use std::mem::transmute;
pub use wasmtime::Caller;
/// Wasmtime types re-exported by the native runtime.
pub(crate) use wasmtime::{
    AsContext, AsContextMut, Config, Engine, Extern, FuncType, Global,
    GlobalType, Instance, Memory, MemoryType, Mutability, OptLevel, Store,
    TypedFunc, Val, ValRaw, ValType,
};

#[derive(Clone)]
pub(crate) struct Module(pub(crate) wasmtime::Module);

impl Module {
    pub fn from_binary(
        engine: &wasmtime::Engine,
        binary: &[u8],
    ) -> wasmtime::Result<Self> {
        let binary = binary.to_vec();
        let engine = engine.clone();
        std::thread::Builder::new()
            .name("yara-x-wasm-compiler".to_string())
            .stack_size(8 * 1024 * 1024) // 8MB stack size
            .spawn(move || {
                wasmtime::Module::from_binary(&engine, &binary).map(Module)
            })
            .unwrap()
            .join()
            .unwrap()
    }

    pub unsafe fn deserialize(
        engine: &wasmtime::Engine,
        bytes: impl AsRef<[u8]>,
    ) -> wasmtime::Result<Self> {
        let bytes = bytes.as_ref().to_vec();
        let engine = engine.clone();
        std::thread::Builder::new()
            .name("yara-x-wasm-deserializer".to_string())
            .stack_size(8 * 1024 * 1024) // 8MB stack size
            .spawn(move || unsafe {
                wasmtime::Module::deserialize(&engine, &bytes).map(Module)
            })
            .unwrap()
            .join()
            .unwrap()
    }

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
    pub fn new(engine: &Engine) -> Self {
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
