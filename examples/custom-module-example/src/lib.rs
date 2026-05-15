//! Example of registering a custom YARA-X module from an external crate.
//!
//! The `foobar` module defined here is registered at link time via
//! [`inventory::submit!`]. Any binary that links against this crate can then
//! use `import "foobar"` in YARA rules and read `foobar.count`, `foobar.label`,
//! `foobar.tags`, and call `foobar.add(a, b)`.
//!
//! The module's main function populates the protobuf from the scanned data.
//! Callers can also override the output for a specific scan by calling
//! [`yara_x::Scanner::set_module_output`] before [`yara_x::Scanner::scan`].
use protobuf::MessageDyn;
use protobuf::MessageFull;

use yara_x::errors::ModuleError;
use yara_x::mods::prelude::*;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

pub use proto::foobar::Foobar;

fn foobar_main(
    data: &[u8],
    _meta: Option<&[u8]>,
) -> Result<Box<dyn MessageDyn>, ModuleError> {
    let mut out = Foobar::new();
    out.count = Some(data.len() as u64);
    out.label = Some("foobar".to_owned());
    Ok(Box::new(out))
}

/// Returns the sum of two integers. Callable from rules as `foobar.add(a, b)`.
#[module_export]
pub fn add(_ctx: &ScanContext, a: i64, b: i64) -> i64 {
    a + b
}

register_module! {
    Module {
        name: "foobar",
        root_descriptor: Foobar::descriptor,
        main_fn: Some(foobar_main),
        rust_module_name: Some("custom_module_example"),
    }
}
