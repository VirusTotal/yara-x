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
use yara_x::YaraModule;
use yara_x::errors::ModuleError;

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

/// Functions exported to YARA rules as callable functions of the `foobar` module.
pub mod fns {
    use yara_x::ScanContext;

    /// Returns the sum of two integers. Callable from rules as `foobar.add(a, b)`.
    #[yara_x::module_export(yara_x_crate = "yara_x")]
    pub fn add(_ctx: &ScanContext, a: i64, b: i64) -> i64 {
        a + b
    }
}

yara_x::inventory::submit! {
    YaraModule {
        name: "foobar",
        root_descriptor: Foobar::descriptor,
        main_fn: Some(foobar_main),
        rust_module_name: Some("custom_module_example::fns"),
    }
}

/// Forces the linker to keep this crate's `inventory::submit!` initializer.
/// Call this from any entry point that must see the `foobar` module.
pub fn ensure_registered() {}
