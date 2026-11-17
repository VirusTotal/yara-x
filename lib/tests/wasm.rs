//! Tests a module registered by a crate whose name matches a Rust module
//! inside `yara-x`.
//!
//! The name of this file matters: Cargo names the integration test crate
//! after it, so `register_module!` below sets `rust_module_name` to `"wasm"`,
//! while YARA's built-in functions (like `uint8`) live in `yara_x::wasm`. A
//! module must not claim functions from a different crate just because the
//! end of their Rust path matches its `rust_module_name`.

use protobuf::well_known_types::empty::Empty;
use yara_x::mods::prelude::*;

register_module!("named_wasm", Empty, main);

fn main(_: &mut ModuleContext, _: &[u8]) -> Result<Empty, ModuleError> {
    Ok(Empty::new())
}

#[test]
fn builtin_functions_still_work() {
    let rules =
        yara_x::compile(r#"rule test { condition: uint8(0) == 0x41 }"#)
            .unwrap();
    let mut scanner = yara_x::Scanner::new(&rules);
    assert_eq!(scanner.scan(b"A").unwrap().matching_rules().len(), 1);
}

#[test]
fn builtin_functions_are_not_module_fields() {
    let err = yara_x::compile(
        r#"import "named_wasm" rule test { condition: named_wasm.uint8(0) == 0x41 }"#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("unknown field or method `uint8`"),
        "unexpected error: {err}"
    );
}
