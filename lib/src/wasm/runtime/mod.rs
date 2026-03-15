//! Runtime backend selection for generated WASM code.
//!
//! Native builds use Wasmtime directly, while `wasm32` builds select one of
//! YARA-X's custom runtimes depending on the target environment.

// Fail early for unsupported `wasm` targets instead of falling through to a
// missing backend implementation.
#[cfg(all(
    target_family = "wasm",
    feature = "wasip1-runtime",
    not(all(target_arch = "wasm32", target_os = "wasi", target_env = "p1"))
))]
compile_error!("`wasip1-runtime` is only supported for wasm32-wasip1 targets");

#[cfg(target_family = "wasm")]
mod common;

// Native builds execute generated WASM through Wasmtime.
#[cfg(not(target_family = "wasm"))]
mod native;

// Browser builds execute generated WASM through the host WebAssembly runtime.
#[cfg(all(target_family = "wasm", not(feature = "wasip1-runtime")))]
mod browser;

// `wasm32-wasip1` builds delegate execution to the host bridge defined in WIT.
#[cfg(all(
    target_arch = "wasm32",
    target_os = "wasi",
    target_env = "p1",
    feature = "wasip1-runtime"
))]
mod wasip1;

#[cfg(not(target_family = "wasm"))]
pub(crate) use native::*;

#[cfg(all(target_family = "wasm", not(feature = "wasip1-runtime")))]
pub(crate) use browser::*;

#[cfg(all(
    target_arch = "wasm32",
    target_os = "wasi",
    target_env = "p1",
    feature = "wasip1-runtime"
))]
pub(crate) use wasip1::*;
