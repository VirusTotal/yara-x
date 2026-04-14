//! Native runtime backed directly by Wasmtime.
//!
//! This adapter exists only to normalize a couple of APIs so the rest of the
//! crate can talk to native and custom runtimes through the same interface.

use std::mem::transmute;

/// Wasmtime types re-exported by the native runtime.
pub(crate) use wasmtime::{
    AsContext, AsContextMut, Caller, Config, Engine, Extern, FuncType, Global,
    GlobalType, Instance, Memory, MemoryType, Module, Mutability, OptLevel,
    Store, TypedFunc, Val, ValRaw, ValType,
};

/// Thin wrapper around [`wasmtime::Linker`] with a backend-neutral API.
pub(crate) struct Linker<T>(wasmtime::Linker<T>);

type Trampoline<T> = dyn Fn(Caller<'_, T>, &mut [ValRaw]) -> wasmtime::Result<()>
    + Send
    + Sync
    + 'static;

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
        trampoline: Box<Trampoline<T>>,
    ) -> wasmtime::Result<()> {
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
    ) -> wasmtime::Result<Instance> {
        self.0.instantiate(store, module)
    }
}
