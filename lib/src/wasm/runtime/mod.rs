//! Runtime backend selection for generated WASM code.
//!
//! Native builds use Wasmtime directly, while `wasm32` builds use YARA-X's
//! browser-oriented custom runtime.

#[cfg(target_family = "wasm")]
mod common;

// Native builds execute generated WASM through Wasmtime.
#[cfg(not(target_family = "wasm"))]
mod native;

// Browser builds execute generated WASM through the host WebAssembly runtime.
#[cfg(target_family = "wasm")]
mod browser;

#[cfg(not(target_family = "wasm"))]
pub(crate) use native::*;

#[cfg(target_family = "wasm")]
pub(crate) use browser::*;
