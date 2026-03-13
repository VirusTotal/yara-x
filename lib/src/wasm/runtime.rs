#[cfg(not(target_family = "wasm"))]
pub use wasmtime::*;

#[cfg(target_family = "wasm")]
#[allow(missing_docs)]
mod browser_runtime {
    use std::cmp;
    use std::marker::PhantomData;
    use std::pin::Pin;
    use std::sync::Arc;

    use anyhow::{Result, anyhow};
    use js_sys::{
        Array, BigInt, Function, Object, Reflect, Uint8Array, WebAssembly,
    };
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};

    pub type StoreContext<'a, T> = &'a Store<T>;
    pub type StoreContextMut<'a, T> = &'a mut Store<T>;

    pub trait AsContext {
        type Data;
        fn as_context(&self) -> StoreContext<'_, Self::Data>;
    }

    pub trait AsContextMut: AsContext {
        fn as_context_mut(&mut self) -> StoreContextMut<'_, Self::Data>;
    }

    pub struct Store<T> {
        data: T,
        runtime: RuntimeState,
        _engine: Engine,
    }

    impl<T> Store<T> {
        pub fn new(engine: &Engine, data: T) -> Self {
            Self {
                data,
                runtime: RuntimeState::default(),
                _engine: engine.clone(),
            }
        }

        pub fn data(&self) -> &T {
            &self.data
        }

        pub fn data_mut(&mut self) -> &mut T {
            &mut self.data
        }

        pub fn set_epoch_deadline(&mut self, _deadline: u64) {}

        pub fn epoch_deadline_callback<F>(&mut self, _callback: F)
        where
            F: FnMut(StoreContextMut<'_, T>) -> Result<()> + 'static,
        {
        }
    }

    impl<T> AsContext for Store<T> {
        type Data = T;

        fn as_context(&self) -> StoreContext<'_, T> {
            self
        }
    }

    impl<T> AsContextMut for Store<T> {
        fn as_context_mut(&mut self) -> StoreContextMut<'_, T> {
            self
        }
    }

    impl<T> AsContext for &Store<T> {
        type Data = T;

        fn as_context(&self) -> StoreContext<'_, T> {
            self
        }
    }

    impl<T> AsContext for &mut Store<T> {
        type Data = T;

        fn as_context(&self) -> StoreContext<'_, T> {
            self
        }
    }

    impl<T> AsContextMut for &mut Store<T> {
        fn as_context_mut(&mut self) -> StoreContextMut<'_, T> {
            self
        }
    }

    impl<T> AsContext for Pin<Box<Store<T>>> {
        type Data = T;

        fn as_context(&self) -> StoreContext<'_, T> {
            self.as_ref().get_ref()
        }
    }

    impl<T> AsContextMut for Pin<Box<Store<T>>> {
        fn as_context_mut(&mut self) -> StoreContextMut<'_, T> {
            // SAFETY: `Store<T>` is not self-referential, and the existing
            // code expects mutable access to the pinned store.
            unsafe { self.as_mut().get_unchecked_mut() }
        }
    }

    pub struct Caller<'a, T> {
        store: &'a mut Store<T>,
    }

    impl<'a, T> Caller<'a, T> {
        pub fn data(&self) -> &T {
            self.store.data()
        }

        pub fn data_mut(&mut self) -> &mut T {
            self.store.data_mut()
        }
    }

    impl<T> AsContext for Caller<'_, T> {
        type Data = T;

        fn as_context(&self) -> StoreContext<'_, T> {
            self.store
        }
    }

    impl<T> AsContextMut for Caller<'_, T> {
        fn as_context_mut(&mut self) -> StoreContextMut<'_, T> {
            self.store
        }
    }

    #[derive(Clone, Default)]
    pub struct Config;

    impl Config {
        pub fn cranelift_opt_level(&mut self, _level: OptLevel) -> &mut Self {
            self
        }

        pub fn epoch_interruption(&mut self, _enabled: bool) -> &mut Self {
            self
        }

        pub fn memory_reservation(&mut self, _bytes: u64) -> &mut Self {
            self
        }

        pub fn memory_reservation_for_growth(
            &mut self,
            _bytes: u64,
        ) -> &mut Self {
            self
        }

        pub fn memory_may_move(&mut self, _enabled: bool) -> &mut Self {
            self
        }
    }

    #[derive(Clone, Copy)]
    pub enum OptLevel {
        SpeedAndSize,
    }

    #[derive(Clone, Default)]
    pub struct Engine;

    impl Engine {
        pub fn new(_config: &Config) -> Result<Self> {
            Ok(Self)
        }

        pub fn increment_epoch(&self) {}
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ValType {
        I64,
        I32,
        F64,
        F32,
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct ValRaw(u64);

    impl ValRaw {
        #[inline]
        pub fn i64(value: i64) -> Self {
            Self(value as u64)
        }

        #[inline]
        pub fn i32(value: i32) -> Self {
            Self((value as u32) as u64)
        }

        #[inline]
        pub fn f64(value: u64) -> Self {
            Self(value)
        }

        #[inline]
        pub fn f32(value: u32) -> Self {
            Self(value as u64)
        }

        #[inline]
        pub fn get_i64(self) -> i64 {
            self.0 as i64
        }

        #[inline]
        pub fn get_i32(self) -> i32 {
            self.0 as u32 as i32
        }

        #[inline]
        pub fn get_f64(self) -> u64 {
            self.0
        }

        #[inline]
        pub fn get_f32(self) -> u32 {
            self.0 as u32
        }
    }

    #[derive(Clone)]
    pub struct FuncType {
        params: Vec<ValType>,
        results: Vec<ValType>,
    }

    impl FuncType {
        pub fn new(
            _engine: &Engine,
            params: Vec<ValType>,
            results: impl IntoIterator<Item = ValType>,
        ) -> Self {
            Self { params, results: results.into_iter().collect() }
        }
    }

    pub type HostFunc<T> =
        Arc<dyn Fn(Caller<'_, T>, &mut [ValRaw]) -> Result<()> + Send + Sync>;

    struct RegisteredFunc<T> {
        module: String,
        name: String,
        ty: FuncType,
        trampoline: HostFunc<T>,
    }

    #[derive(Clone, Copy)]
    pub struct Global {
        id: usize,
    }

    #[derive(Clone, Copy)]
    pub struct Memory {
        id: usize,
    }

    pub enum Extern {
        Global(Global),
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

    struct DefinedExtern {
        module: String,
        name: String,
        value: Extern,
    }

    pub struct Linker<T> {
        functions: Vec<RegisteredFunc<T>>,
        externs: Vec<DefinedExtern>,
        _phantom: PhantomData<T>,
    }

    impl<T: 'static> Linker<T> {
        pub fn new(_engine: &Engine) -> Self {
            Self {
                functions: Vec::new(),
                externs: Vec::new(),
                _phantom: PhantomData,
            }
        }

        pub unsafe fn func_new_unchecked(
            &mut self,
            module: &str,
            name: &str,
            ty: FuncType,
            trampoline: Box<
                dyn Fn(Caller<'_, T>, &mut [ValRaw]) -> Result<()>
                    + Send
                    + Sync
                    + 'static,
            >,
        ) -> Result<()> {
            self.functions.push(RegisteredFunc {
                module: module.to_owned(),
                name: name.to_owned(),
                ty,
                trampoline: Arc::from(trampoline),
            });
            Ok(())
        }

        pub fn define(
            &mut self,
            _store: StoreContext<'_, T>,
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

        pub fn instantiate(
            &self,
            store: StoreContextMut<'_, T>,
            module: &Module,
        ) -> Result<Instance> {
            // If this store is reused across instantiations, ensure host
            // callback closures from prior instances are dropped.
            store.runtime.prepare_for_instantiation();

            let imports = Object::new();

            for defined in &self.externs {
                let ns = ensure_namespace(&imports, &defined.module)?;
                let value: JsValue = match defined.value {
                    Extern::Global(g) => {
                        store.runtime.globals[g.id].js_global.clone().into()
                    }
                    Extern::Memory(m) => {
                        store.runtime.memories[m.id].js_memory.clone().into()
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

            for import in &self.functions {
                let ns = ensure_namespace(&imports, import.module.as_str())?;
                let params = import.ty.params.clone();
                let results = import.ty.results.clone();
                let trampoline = Arc::clone(&import.trampoline);

                let callback = Closure::wrap(Box::new(
                    move |a0: JsValue,
                          a1: JsValue,
                          a2: JsValue,
                          a3: JsValue|
                          -> JsValue {
                        let store = unsafe { &mut *store_ptr };

                        store.runtime.sync_memory_from_js();

                        let mut args_and_results =
                            vec![
                                ValRaw::default();
                                cmp::max(params.len(), results.len())
                            ];

                        let incoming = [a0, a1, a2, a3];

                        for (idx, ty) in params.iter().enumerate() {
                            args_and_results[idx] =
                                js_to_valraw(&incoming[idx], *ty)
                                    .unwrap_or_default();
                        }

                        let caller = Caller { store };

                        if trampoline(caller, &mut args_and_results).is_err() {
                            return JsValue::UNDEFINED;
                        }

                        store.runtime.sync_memory_to_js();

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
                        dyn FnMut(
                            JsValue,
                            JsValue,
                            JsValue,
                            JsValue,
                        ) -> JsValue,
                    >);

                Reflect::set(
                    &ns,
                    &JsValue::from_str(import.name.as_str()),
                    callback.as_ref().unchecked_ref::<Function>(),
                )
                .map_err(js_error)?;

                store.runtime.import_callbacks.push(callback);
            }

            let bytes = Uint8Array::from(module.bytes.as_slice());
            let js_module =
                WebAssembly::Module::new(&bytes.into()).map_err(js_error)?;
            let js_instance = WebAssembly::Instance::new(&js_module, &imports)
                .map_err(js_error)?;

            Ok(Instance { inner: js_instance })
        }
    }

    #[derive(Clone, Copy)]
    pub enum Mutability {
        Const,
        Var,
    }

    pub struct GlobalType {
        val_type: ValType,
        mutability: Mutability,
    }

    impl GlobalType {
        pub fn new(val_type: ValType, mutability: Mutability) -> Self {
            Self { val_type, mutability }
        }
    }

    #[derive(Clone, Copy)]
    pub enum Val {
        I32(i32),
        I64(i64),
        F32(u32),
        F64(u64),
    }

    impl Val {
        pub fn i64(self) -> Option<i64> {
            match self {
                Val::I64(v) => Some(v),
                _ => None,
            }
        }
    }

    struct GlobalInner {
        val_type: ValType,
        mutability: Mutability,
        js_global: WebAssembly::Global,
    }

    impl Global {
        pub fn new<T>(
            store: StoreContextMut<'_, T>,
            ty: GlobalType,
            value: Val,
        ) -> Result<Self> {
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

            store.runtime.globals.push(GlobalInner {
                val_type: ty.val_type,
                mutability: ty.mutability,
                js_global,
            });

            Ok(Self { id: store.runtime.globals.len() - 1 })
        }

        pub fn get<T>(&self, store: StoreContextMut<'_, T>) -> Val {
            let inner = &store.runtime.globals[self.id];
            js_to_val(&inner.js_global.value(), inner.val_type).unwrap_or(
                match inner.val_type {
                    ValType::I32 => Val::I32(0),
                    ValType::I64 => Val::I64(0),
                    ValType::F32 => Val::F32(0),
                    ValType::F64 => Val::F64(0),
                },
            )
        }

        pub fn set<T>(
            &self,
            store: StoreContextMut<'_, T>,
            value: Val,
        ) -> Result<()> {
            let inner = &store.runtime.globals[self.id];
            if !matches!(inner.mutability, Mutability::Var) {
                return Err(anyhow!("attempted to set immutable global"));
            }
            inner.js_global.set_value(&val_to_js(value));
            Ok(())
        }
    }

    pub struct MemoryType {
        initial: u32,
        maximum: Option<u32>,
    }

    impl MemoryType {
        pub fn new(initial: u32, maximum: Option<u32>) -> Self {
            Self { initial, maximum }
        }
    }

    struct MemoryInner {
        js_memory: WebAssembly::Memory,
        cache: Vec<u8>,
    }

    impl Memory {
        pub fn new<T>(
            store: StoreContextMut<'_, T>,
            ty: MemoryType,
        ) -> Result<Self> {
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

            store.runtime.memories.push(MemoryInner { js_memory, cache });

            Ok(Self { id: store.runtime.memories.len() - 1 })
        }

        pub fn data<'a, T>(&self, store: StoreContext<'a, T>) -> &'a [u8] {
            store.runtime.memories[self.id].cache.as_slice()
        }

        pub fn data_mut<'a, T>(
            &self,
            store: StoreContextMut<'a, T>,
        ) -> &'a mut [u8] {
            store.runtime.memories[self.id].cache.as_mut_slice()
        }

        pub fn data_ptr<T>(&self, store: StoreContextMut<'_, T>) -> *mut u8 {
            store.runtime.memories[self.id].cache.as_mut_ptr()
        }
    }

    pub struct Module {
        bytes: Vec<u8>,
    }

    impl Module {
        pub fn from_binary(_engine: &Engine, bytes: &[u8]) -> Result<Self> {
            let wasm = Uint8Array::from(bytes);
            let _ =
                WebAssembly::Module::new(&wasm.into()).map_err(js_error)?;
            Ok(Self { bytes: bytes.to_vec() })
        }

        pub unsafe fn deserialize(
            _engine: &Engine,
            bytes: &[u8],
        ) -> Result<Self> {
            Self::from_binary(_engine, bytes)
        }
    }

    pub struct Instance {
        inner: WebAssembly::Instance,
    }

    impl Instance {
        pub fn get_typed_func<P, R>(
            &self,
            _store: impl AsContextMut,
            name: &str,
        ) -> Result<TypedFunc<P, R>> {
            let exports = self.inner.exports();
            let value = Reflect::get(&exports, &JsValue::from_str(name))
                .map_err(js_error)?;
            let function = value
                .dyn_into::<Function>()
                .map_err(|_| anyhow!("export `{name}` is not a function"))?;
            Ok(TypedFunc {
                function,
                _params: PhantomData,
                _results: PhantomData,
            })
        }
    }

    pub struct TypedFunc<P, R> {
        function: Function,
        _params: PhantomData<P>,
        _results: PhantomData<R>,
    }

    impl TypedFunc<(), i32> {
        pub fn call<T>(
            &self,
            store: StoreContextMut<'_, T>,
            _params: (),
        ) -> Result<i32> {
            store.runtime.sync_memory_to_js();

            let value =
                self.function.call0(&JsValue::UNDEFINED).map_err(js_error)?;

            store.runtime.sync_memory_from_js();

            if let Some(v) = value.as_f64() {
                return Ok(v as i32);
            }

            Err(anyhow!("main returned a non-number"))
        }
    }

    #[derive(Default)]
    struct RuntimeState {
        globals: Vec<GlobalInner>,
        memories: Vec<MemoryInner>,
        import_callbacks: Vec<
            Closure<dyn FnMut(JsValue, JsValue, JsValue, JsValue) -> JsValue>,
        >,
    }

    impl RuntimeState {
        fn prepare_for_instantiation(&mut self) {
            self.import_callbacks.clear();
        }

        fn sync_memory_from_js(&mut self) {
            for memory in &mut self.memories {
                let js = Uint8Array::new(&memory.js_memory.buffer());
                if memory.cache.len() != js.length() as usize {
                    memory.cache.resize(js.length() as usize, 0);
                }
                js.copy_to(memory.cache.as_mut_slice());
            }
        }

        fn sync_memory_to_js(&mut self) {
            for memory in &mut self.memories {
                let js = Uint8Array::new(&memory.js_memory.buffer());
                if memory.cache.len() != js.length() as usize {
                    memory.cache.resize(js.length() as usize, 0);
                }
                js.copy_from(memory.cache.as_slice());
            }
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
            ValType::F64 => {
                ValRaw::f64(value.as_f64().unwrap_or(0.0).to_bits())
            }
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
}

#[cfg(target_family = "wasm")]
pub use browser_runtime::*;
