//! Runtime backend selection for generated WASM code.
//!
//! Native builds use Wasmtime directly, while `wasm32` builds select one of
//! YARA-X's custom runtimes depending on the target environment.

#[cfg(all(
    target_family = "wasm",
    target_os = "wasi",
    not(all(target_arch = "wasm32", target_env = "p1"))
))]
compile_error!(
    "only `wasm32-wasip1` is currently supported for WASI builds; the browser runtime is only supported on non-WASI wasm targets"
);

#[cfg(target_family = "wasm")]
mod common;

// Native builds execute generated WASM through Wasmtime.
#[cfg(not(target_family = "wasm"))]
mod native;

// Browser builds execute generated WASM through the host WebAssembly runtime.
#[cfg(all(target_family = "wasm", not(target_os = "wasi")))]
mod browser;

#[cfg(all(target_arch = "wasm32", target_os = "wasi", target_env = "p1"))]
mod wasip1;

#[cfg(not(target_family = "wasm"))]
pub(crate) use native::*;

#[cfg(all(target_family = "wasm", not(target_os = "wasi")))]
pub(crate) use browser::*;

#[cfg(all(
    target_arch = "wasm32",
    target_os = "wasi",
    target_env = "p1"
))]
pub(crate) use wasip1::*;
