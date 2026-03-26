//! Common pieces shared by YARA-X's custom WASM runtimes.
//!
//! The browser backend exposes a small, Wasmtime-like API to the rest of the
//! crate. This module contains the backend-agnostic pieces of that shim so the
//! browser runtime can stay focused on the host `WebAssembly` integration.

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;

/// Synchronize imported module state before invoking a callback.
pub(crate) const CALLBACK_SYNC_BEFORE: u32 = 1 << 0;
/// Synchronize imported module state after invoking a callback.
pub(crate) const CALLBACK_SYNC_AFTER: u32 = 1 << 1;

/// Returns true if callback state must be synchronized before the call.
pub(crate) fn should_sync_before(sync_flags: u32) -> bool {
    sync_flags & CALLBACK_SYNC_BEFORE != 0
}

/// Returns true if callback state must be synchronized after the call.
pub(crate) fn should_sync_after(sync_flags: u32) -> bool {
    sync_flags & CALLBACK_SYNC_AFTER != 0
}

/// Returns the scratch storage needed for callback parameters and results.
///
/// Custom runtimes reuse a single buffer for both directions, matching the
/// way the generated trampolines pass arguments in and read results back out.
pub(crate) fn callback_storage_len(
    params: &[ValType],
    results: &[ValType],
) -> usize {
    params.len().max(results.len())
}

/// Immutable view over a [`Store`].
pub(crate) type StoreContext<'a, T, B> = &'a Store<T, B>;
/// Mutable view over a [`Store`].
pub(crate) type StoreContextMut<'a, T, B> = &'a mut Store<T, B>;

/// Backend contract implemented by each custom runtime.
pub(crate) trait RuntimeBackend:
    Clone + Default + Sized + 'static
{
    /// Per-store runtime state owned by the backend.
    type RuntimeState: Default;
    /// Backend-specific representation of a compiled module.
    type ModuleInner;
    /// Backend-specific representation of an instantiated module.
    type InstanceInner;
    /// Backend-specific representation of a typed function handle.
    type TypedFuncHandle;

    /// Updates the deadline used for interrupting long-running scans.
    fn set_epoch_deadline(runtime: &mut Self::RuntimeState, deadline: u64);
    /// Associates the runtime state with the current host session.
    fn set_runtime_session(runtime: &mut Self::RuntimeState, session_id: u64);
    /// Resets any per-instantiation state before creating a new instance.
    fn prepare_for_instantiation(runtime: &mut Self::RuntimeState);
    /// Clears any runtime state that should not survive store reuse.
    fn reset_for_store_reuse(runtime: &mut Self::RuntimeState);

    /// Creates a global and returns its backend-specific identifier.
    fn create_global(
        runtime: &mut Self::RuntimeState,
        ty: GlobalType,
        value: Val,
    ) -> Result<usize>;

    /// Returns the current value for the global identified by `id`.
    fn get_global(runtime: &mut Self::RuntimeState, id: usize) -> Val;

    /// Updates the global identified by `id`.
    fn set_global(
        runtime: &mut Self::RuntimeState,
        id: usize,
        value: Val,
    ) -> Result<()>;

    /// Creates a memory and returns its backend-specific identifier.
    fn create_memory(
        runtime: &mut Self::RuntimeState,
        ty: MemoryType,
    ) -> Result<usize>;

    /// Returns the current memory contents for the memory identified by `id`.
    fn memory_data<'a>(runtime: &'a Self::RuntimeState, id: usize)
    -> &'a [u8];

    /// Returns mutable access to the memory identified by `id`.
    fn memory_data_mut<'a>(
        runtime: &'a mut Self::RuntimeState,
        id: usize,
    ) -> &'a mut [u8];

    /// Returns a raw pointer to the memory identified by `id`.
    fn memory_data_ptr(runtime: &mut Self::RuntimeState, id: usize)
    -> *mut u8;

    /// Creates a module from raw WASM bytes.
    fn module_from_binary(
        engine: &Engine,
        bytes: &[u8],
    ) -> Result<Self::ModuleInner>;

    /// Instantiates `module` with the functions and externs in `linker`.
    fn instantiate<T: 'static>(
        store: &mut Store<T, Self>,
        linker: &Linker<T, Self>,
        module: &Module<Self>,
    ) -> Result<Self::InstanceInner>;

    /// Returns a handle to the typed function named `name`.
    fn get_typed_func_handle<P, R>(
        instance: &Self::InstanceInner,
        name: &str,
    ) -> Result<Self::TypedFuncHandle>;

    /// Calls a `() -> i32` typed function.
    fn typed_func_call_i32<T>(
        store: &mut Store<T, Self>,
        func: &Self::TypedFuncHandle,
    ) -> Result<i32>;
}

/// Trait for types that can yield an immutable [`StoreContext`].
pub(crate) trait AsContext {
    /// User data stored in the underlying [`Store`].
    type Data;
    /// Runtime backend associated with the underlying [`Store`].
    type Backend: RuntimeBackend;

    /// Returns an immutable store context.
    fn as_context(&self) -> StoreContext<'_, Self::Data, Self::Backend>;
}

/// Trait for types that can yield a mutable [`StoreContextMut`].
pub(crate) trait AsContextMut: AsContext {
    /// Returns a mutable store context.
    fn as_context_mut(
        &mut self,
    ) -> StoreContextMut<'_, Self::Data, Self::Backend>;
}

/// Storage for user data plus backend-specific runtime state.
pub(crate) struct Store<T, B: RuntimeBackend> {
    /// User data associated with the store.
    data: T,
    /// Backend-specific runtime state for globals, memories and callbacks.
    pub(crate) runtime: B::RuntimeState,
    _engine: Engine,
    _backend: PhantomData<B>,
}

impl<T, B: RuntimeBackend> Store<T, B> {
    /// Creates a new store associated with `engine`.
    pub fn new(engine: &Engine, data: T) -> Self {
        Self {
            data,
            runtime: B::RuntimeState::default(),
            _engine: engine.clone(),
            _backend: PhantomData,
        }
    }

    /// Returns the store's user data.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Returns mutable access to the store's user data.
    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Sets the deadline used by the backend for interrupting execution.
    pub fn set_epoch_deadline(&mut self, deadline: u64) {
        B::set_epoch_deadline(&mut self.runtime, deadline);
    }

    /// Registers a callback for deadline expiration.
    ///
    /// Custom runtimes poll the deadline from their runtime state instead of
    /// using a backend callback, so this method is a no-op kept for API
    /// compatibility with Wasmtime.
    pub fn epoch_deadline_callback<F>(&mut self, _callback: F)
    where
        F: FnMut(StoreContextMut<'_, T, B>) -> Result<()> + 'static,
    {
    }

    /// Associates the store with a backend-specific runtime session.
    pub(crate) fn set_runtime_session(&mut self, session_id: u64) {
        B::set_runtime_session(&mut self.runtime, session_id);
    }
}

impl<T, B: RuntimeBackend> Drop for Store<T, B> {
    fn drop(&mut self) {
        B::reset_for_store_reuse(&mut self.runtime);
    }
}

impl<T, B: RuntimeBackend> AsContext for Store<T, B> {
    type Data = T;
    type Backend = B;

    fn as_context(&self) -> StoreContext<'_, T, B> {
        self
    }
}

impl<T, B: RuntimeBackend> AsContextMut for Store<T, B> {
    fn as_context_mut(&mut self) -> StoreContextMut<'_, T, B> {
        self
    }
}

impl<T, B: RuntimeBackend> AsContext for &Store<T, B> {
    type Data = T;
    type Backend = B;

    fn as_context(&self) -> StoreContext<'_, T, B> {
        self
    }
}

impl<T, B: RuntimeBackend> AsContext for &mut Store<T, B> {
    type Data = T;
    type Backend = B;

    fn as_context(&self) -> StoreContext<'_, T, B> {
        self
    }
}

impl<T, B: RuntimeBackend> AsContextMut for &mut Store<T, B> {
    fn as_context_mut(&mut self) -> StoreContextMut<'_, T, B> {
        self
    }
}

impl<T, B: RuntimeBackend> AsContext for Pin<Box<Store<T, B>>> {
    type Data = T;
    type Backend = B;

    fn as_context(&self) -> StoreContext<'_, T, B> {
        self.as_ref().get_ref()
    }
}

impl<T, B: RuntimeBackend> AsContextMut for Pin<Box<Store<T, B>>> {
    fn as_context_mut(&mut self) -> StoreContextMut<'_, T, B> {
        // SAFETY: `Store<T, B>` is not self-referential, and callers rely on
        // mutable access to the pinned store.
        unsafe { self.as_mut().get_unchecked_mut() }
    }
}

/// View passed to host callbacks.
pub(crate) struct Caller<'a, T, B: RuntimeBackend> {
    /// Store being used for the callback.
    pub(crate) store: &'a mut Store<T, B>,
}

impl<'a, T, B: RuntimeBackend> Caller<'a, T, B> {
    /// Creates a caller from a mutable store reference.
    pub(crate) fn new(store: &'a mut Store<T, B>) -> Self {
        Self { store }
    }

    /// Returns the store's user data.
    pub fn data(&self) -> &T {
        self.store.data()
    }

    /// Returns mutable access to the store's user data.
    pub fn data_mut(&mut self) -> &mut T {
        self.store.data_mut()
    }
}

impl<T, B: RuntimeBackend> AsContext for Caller<'_, T, B> {
    type Data = T;
    type Backend = B;

    fn as_context(&self) -> StoreContext<'_, T, B> {
        self.store
    }
}

impl<T, B: RuntimeBackend> AsContextMut for Caller<'_, T, B> {
    fn as_context_mut(&mut self) -> StoreContextMut<'_, T, B> {
        self.store
    }
}

/// Minimal configuration object matching the Wasmtime API used by YARA-X.
///
/// All methods are no-ops for the custom runtimes.
#[derive(Clone, Default)]
pub(crate) struct Config;

impl Config {
    /// Matches Wasmtime's `native_unwind_info` option.
    #[cfg(target_env = "musl")]
    pub fn native_unwind_info(&mut self, _enabled: bool) -> &mut Self {
        self
    }

    /// Matches Wasmtime's `cranelift_opt_level` option.
    pub fn cranelift_opt_level(&mut self, _level: OptLevel) -> &mut Self {
        self
    }

    /// Matches Wasmtime's `epoch_interruption` option.
    pub fn epoch_interruption(&mut self, _enabled: bool) -> &mut Self {
        self
    }

    /// Matches Wasmtime's `memory_reservation` option.
    pub fn memory_reservation(&mut self, _bytes: u64) -> &mut Self {
        self
    }

    /// Matches Wasmtime's `memory_reservation_for_growth` option.
    pub fn memory_reservation_for_growth(&mut self, _bytes: u64) -> &mut Self {
        self
    }

    /// Matches Wasmtime's `memory_may_move` option.
    pub fn memory_may_move(&mut self, _enabled: bool) -> &mut Self {
        self
    }
}

/// Optimization level accepted by [`Config::cranelift_opt_level`].
#[derive(Clone, Copy)]
pub(crate) enum OptLevel {
    /// Optimize for both speed and code size.
    SpeedAndSize,
}

/// Minimal engine object matching the Wasmtime API used by YARA-X.
#[derive(Clone, Default)]
pub(crate) struct Engine;

impl Engine {
    /// Creates a new engine from `config`.
    pub fn new(_config: &Config) -> Result<Self> {
        Ok(Self)
    }

    /// Increments the engine epoch.
    ///
    /// Custom runtimes track deadlines without an engine-level epoch counter,
    /// so this is a no-op kept for API compatibility.
    #[allow(dead_code)]
    pub fn increment_epoch(&self) {}

    /// Unloads process-wide handlers owned by the engine.
    ///
    /// Custom runtimes do not install such handlers.
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "s390x",
    ))]
    pub fn unload_process_handlers(self) {}
}

/// Value types supported by generated WASM code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValType {
    /// A 64-bit integer.
    I64,
    /// A 32-bit integer.
    I32,
    /// A 64-bit floating-point value.
    F64,
    /// A 32-bit floating-point value.
    F32,
}

/// Raw value passed across host callback trampolines.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ValRaw(u64);

impl ValRaw {
    /// Creates a raw value from an `i64`.
    #[inline]
    pub fn i64(value: i64) -> Self {
        Self(value as u64)
    }

    /// Creates a raw value from an `i32`.
    #[inline]
    pub fn i32(value: i32) -> Self {
        Self((value as u32) as u64)
    }

    /// Creates a raw value from the bit pattern of an `f64`.
    #[inline]
    pub fn f64(value: u64) -> Self {
        Self(value)
    }

    /// Creates a raw value from the bit pattern of an `f32`.
    #[inline]
    pub fn f32(value: u32) -> Self {
        Self(value as u64)
    }

    /// Returns the value interpreted as an `i64`.
    #[inline]
    pub fn get_i64(self) -> i64 {
        self.0 as i64
    }

    /// Returns the value interpreted as an `i32`.
    #[inline]
    pub fn get_i32(self) -> i32 {
        self.0 as u32 as i32
    }

    /// Returns the raw bit pattern for an `f64`.
    #[inline]
    pub fn get_f64(self) -> u64 {
        self.0
    }

    /// Returns the raw bit pattern for an `f32`.
    #[inline]
    pub fn get_f32(self) -> u32 {
        self.0 as u32
    }
}

/// Function signature used when wiring imports.
#[derive(Clone)]
pub(crate) struct FuncType {
    /// Function parameter types.
    pub(crate) params: Vec<ValType>,
    /// Function result types.
    pub(crate) results: Vec<ValType>,
}

impl FuncType {
    /// Creates a new function signature.
    ///
    /// The `engine` argument is unused by the custom runtimes and is kept only
    /// for compatibility with Wasmtime's API.
    pub fn new(
        _engine: &Engine,
        params: Vec<ValType>,
        results: impl IntoIterator<Item = ValType>,
    ) -> Self {
        Self { params, results: results.into_iter().collect() }
    }
}

/// Host callback invoked from generated WASM code.
///
/// The callback receives raw parameter storage and writes any results back into
/// that same storage.
pub(crate) type HostFunc<T, B> =
    Arc<dyn Fn(Caller<'_, T, B>, &mut [ValRaw]) -> Result<()> + Send + Sync>;

/// Function registered in a [`Linker`].
pub(crate) struct RegisteredFunc<T, B: RuntimeBackend> {
    /// Module namespace for the import.
    pub(crate) module: String,
    /// Name of the imported function.
    pub(crate) name: String,
    /// Function signature.
    pub(crate) ty: FuncType,
    /// Callback synchronization flags.
    pub(crate) sync_flags: u32,
    /// Host trampoline invoked when the import is called.
    pub(crate) trampoline: HostFunc<T, B>,
}

/// Handle to a global defined in the store.
#[derive(Clone, Copy)]
pub(crate) struct Global {
    /// Backend-specific global identifier.
    pub(crate) id: usize,
}

/// Handle to a memory defined in the store.
#[derive(Clone, Copy)]
pub(crate) struct Memory {
    /// Backend-specific memory identifier.
    pub(crate) id: usize,
}

/// Extern item that can be defined in a [`Linker`].
pub(crate) enum Extern {
    /// A global variable.
    Global(Global),
    /// A linear memory.
    Memory(Memory),
}

impl From<Global> for Extern {
    fn from(value: Global) -> Self {
        Self::Global(value)
    }
}

impl From<Memory> for Extern {
    fn from(value: Memory) -> Self {
        Self::Memory(value)
    }
}

/// Extern registered in a [`Linker`].
pub(crate) struct DefinedExtern {
    /// Module namespace for the import.
    pub(crate) module: String,
    /// Name of the imported extern.
    pub(crate) name: String,
    /// Extern value to be defined.
    pub(crate) value: Extern,
}

/// Linker used for registering imports and instantiating modules.
pub(crate) struct Linker<T, B: RuntimeBackend> {
    /// Functions registered in the linker.
    pub(crate) functions: Vec<RegisteredFunc<T, B>>,
    /// Externs registered in the linker.
    pub(crate) externs: Vec<DefinedExtern>,
    _phantom: PhantomData<T>,
}

impl<T: 'static, B: RuntimeBackend> Linker<T, B> {
    /// Creates an empty linker.
    ///
    /// The `engine` argument is unused by the custom runtimes and is kept only
    /// for compatibility with Wasmtime's API.
    pub fn new(_engine: &Engine) -> Self {
        Self {
            functions: Vec::new(),
            externs: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Registers a function import without validating its ABI.
    ///
    /// The generated WASM determines the function signature, so custom
    /// runtimes only need to record the metadata and trampoline here.
    pub unsafe fn func_new_unchecked(
        &mut self,
        module: &str,
        name: &str,
        ty: FuncType,
        sync_flags: u32,
        trampoline: Box<
            dyn Fn(Caller<'_, T, B>, &mut [ValRaw]) -> Result<()>
                + Send
                + Sync
                + 'static,
        >,
    ) -> Result<()> {
        // This mirrors Wasmtime's unchecked registration API. The generated
        // WASM determines the ABI, so the runtime only needs to record the
        // metadata and trampoline here.
        // Store the trampoline and metadata; the backend turns these into
        // actual imports when the module is instantiated.
        self.functions.push(RegisteredFunc {
            module: module.to_owned(),
            name: name.to_owned(),
            ty,
            sync_flags,
            trampoline: Arc::from(trampoline),
        });
        Ok(())
    }

    /// Defines an extern import.
    ///
    /// The `store` argument is unused by the custom runtimes and is kept only
    /// for compatibility with Wasmtime's API.
    pub fn define(
        &mut self,
        _store: StoreContext<'_, T, B>,
        module: &str,
        name: &str,
        value: impl Into<Extern>,
    ) -> Result<&mut Self> {
        self.externs.push(DefinedExtern {
            module: module.to_owned(),
            name: name.to_owned(),
            value: value.into(),
        });
        Ok(self)
    }

    /// Instantiates `module` with the imports currently registered.
    pub fn instantiate(
        &self,
        store: StoreContextMut<'_, T, B>,
        module: &Module<B>,
    ) -> Result<Instance<B>> {
        // Clear any instance-local state before wiring a fresh set of imports.
        B::prepare_for_instantiation(&mut store.runtime);
        Ok(Instance {
            inner: B::instantiate(store, self, module)?,
            _backend: PhantomData,
        })
    }
}

/// Whether a global can be mutated after creation.
#[derive(Clone, Copy)]
pub(crate) enum Mutability {
    /// Immutable global.
    Const,
    /// Mutable global.
    Var,
}

/// Type information for a global.
pub(crate) struct GlobalType {
    /// Value type stored in the global.
    pub(crate) val_type: ValType,
    /// Whether the global can be mutated.
    pub(crate) mutability: Mutability,
}

impl GlobalType {
    /// Creates a new global type.
    pub fn new(val_type: ValType, mutability: Mutability) -> Self {
        Self { val_type, mutability }
    }
}

/// Runtime value stored in globals and returned from typed functions.
#[derive(Clone, Copy)]
pub(crate) enum Val {
    /// A 32-bit integer.
    I32(i32),
    /// A 64-bit integer.
    I64(i64),
    /// Raw bits for a 32-bit floating-point value.
    F32(u32),
    /// Raw bits for a 64-bit floating-point value.
    F64(u64),
}

impl Val {
    /// Returns the value as an `i64`, if applicable.
    pub fn i64(self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(v),
            _ => None,
        }
    }
}

impl Global {
    /// Creates a new global in `store`.
    pub fn new<T, B: RuntimeBackend>(
        store: StoreContextMut<'_, T, B>,
        ty: GlobalType,
        value: Val,
    ) -> Result<Self> {
        Ok(Self { id: B::create_global(&mut store.runtime, ty, value)? })
    }

    /// Returns the current value of the global.
    pub fn get<T, B: RuntimeBackend>(
        &self,
        store: StoreContextMut<'_, T, B>,
    ) -> Val {
        B::get_global(&mut store.runtime, self.id)
    }

    /// Updates the value stored in the global.
    pub fn set<T, B: RuntimeBackend>(
        &self,
        store: StoreContextMut<'_, T, B>,
        value: Val,
    ) -> Result<()> {
        B::set_global(&mut store.runtime, self.id, value)
    }
}

/// Type information for a memory.
pub(crate) struct MemoryType {
    /// Initial size in WASM pages.
    pub(crate) initial: u32,
    /// Maximum size in WASM pages, if any.
    pub(crate) maximum: Option<u32>,
}

impl MemoryType {
    /// Creates a new memory type.
    pub fn new(initial: u32, maximum: Option<u32>) -> Self {
        Self { initial, maximum }
    }
}

impl Memory {
    /// Creates a new memory in `store`.
    pub fn new<T, B: RuntimeBackend>(
        store: StoreContextMut<'_, T, B>,
        ty: MemoryType,
    ) -> Result<Self> {
        Ok(Self { id: B::create_memory(&mut store.runtime, ty)? })
    }

    /// Returns the current contents of the memory.
    pub fn data<'a, T, B: RuntimeBackend>(
        &self,
        store: StoreContext<'a, T, B>,
    ) -> &'a [u8] {
        B::memory_data(&store.runtime, self.id)
    }

    /// Returns mutable access to the memory contents.
    pub fn data_mut<'a, T, B: RuntimeBackend>(
        &self,
        store: StoreContextMut<'a, T, B>,
    ) -> &'a mut [u8] {
        B::memory_data_mut(&mut store.runtime, self.id)
    }

    /// Returns a raw pointer to the memory contents.
    pub fn data_ptr<T, B: RuntimeBackend>(
        &self,
        store: StoreContextMut<'_, T, B>,
    ) -> *mut u8 {
        B::memory_data_ptr(&mut store.runtime, self.id)
    }
}

/// Compiled WASM module.
pub(crate) struct Module<B: RuntimeBackend> {
    /// Backend-specific module representation.
    pub(crate) inner: B::ModuleInner,
    _backend: PhantomData<B>,
}

impl<B: RuntimeBackend> Module<B> {
    /// Compiles a module from raw WASM bytes.
    pub fn from_binary(engine: &Engine, bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: B::module_from_binary(engine, bytes)?,
            _backend: PhantomData,
        })
    }

    /// Deserializes a module from bytes previously returned by [`serialize`].
    ///
    /// Custom runtimes simply rebuild the module from raw WASM bytes, while
    /// the native runtime preserves Wasmtime's unsafe deserialization API.
    pub unsafe fn deserialize(engine: &Engine, bytes: &[u8]) -> Result<Self> {
        Self::from_binary(engine, bytes)
    }
}

#[cfg(feature = "native-code-serialization")]
impl<B> Module<B>
where
    B: RuntimeBackend<ModuleInner = Vec<u8>>,
{
    /// Serializes a module into bytes that can later be passed to
    /// [`Module::deserialize`].
    ///
    /// Custom runtimes keep the original validated WASM bytes as their module
    /// representation, so serialization simply returns those bytes.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.inner.clone())
    }
}

/// Instantiated module.
pub(crate) struct Instance<B: RuntimeBackend> {
    /// Backend-specific instance representation.
    pub(crate) inner: B::InstanceInner,
    _backend: PhantomData<B>,
}

impl<B: RuntimeBackend> Instance<B> {
    /// Returns a typed function exported by this instance.
    ///
    /// The `store` argument is unused by the custom runtimes and is kept only
    /// for compatibility with Wasmtime's API.
    pub fn get_typed_func<P, R>(
        &self,
        _store: impl AsContextMut<Backend = B>,
        name: &str,
    ) -> Result<TypedFunc<P, R, B>> {
        Ok(TypedFunc {
            inner: B::get_typed_func_handle::<P, R>(&self.inner, name)?,
            _params: PhantomData,
            _results: PhantomData,
            _backend: PhantomData,
        })
    }
}

/// Typed function exported by an [`Instance`].
pub(crate) struct TypedFunc<P, R, B: RuntimeBackend> {
    inner: B::TypedFuncHandle,
    _params: PhantomData<P>,
    _results: PhantomData<R>,
    _backend: PhantomData<B>,
}

impl<B: RuntimeBackend> TypedFunc<(), i32, B> {
    /// Calls a `() -> i32` function.
    pub fn call<T>(
        &self,
        store: StoreContextMut<'_, T, B>,
        _params: (),
    ) -> Result<i32> {
        B::typed_func_call_i32(store, &self.inner)
    }
}

/// Returns the zero value for `ty`.
pub(crate) fn default_val(ty: ValType) -> Val {
    match ty {
        ValType::I32 => Val::I32(0),
        ValType::I64 => Val::I64(0),
        ValType::F32 => Val::F32(0),
        ValType::F64 => Val::F64(0),
    }
}
