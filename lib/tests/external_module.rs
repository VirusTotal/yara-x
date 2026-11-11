//! Tests for YARA modules defined outside the `yara-x` crate.
//!
//! These tests live in an integration test because they need modules whose
//! functions are defined outside `yara_x::modules`, just like the functions
//! of a module registered by a third-party crate.

use protobuf::well_known_types::empty::Empty;
use yara_x::mods::prelude::*;

register_module!("external", Empty, main);

fn main(_: &mut ModuleContext, _: &[u8]) -> Result<Empty, ModuleError> {
    Ok(Empty::new())
}

#[module_export]
fn str_lt(
    ctx: &ScanContext,
    a: RuntimeString,
    b: RuntimeString,
) -> Option<bool> {
    Some(a.to_str(ctx).ok()? < b.to_str(ctx).ok()?)
}

#[module_export(method_of = "external.DummyType")]
fn dummy_method(_ctx: &ScanContext, _x: i64) -> bool {
    true
}

// Functions belong to a module only if they are defined in the same Rust
// module where `register_module!` was invoked. These aren't, and no module
// is registered here, so they don't belong to any module.
mod misplaced {
    use yara_x::mods::prelude::*;

    #[module_export]
    fn add_one(_ctx: &ScanContext, a: i64) -> i64 {
        a + 1
    }

    // Shares the exact name, argument name, and WASM signature with YARA's
    // built-in `uint8`. Because it is an orphaned `WasmExportKind::Module`,
    // it must be ignored rather than shadowing the real built-in `uint8`.
    #[module_export]
    fn uint8(_ctx: &ScanContext, _offset: i64) -> Option<u8> {
        Some(0xFF)
    }
}

// A module registered in a Rust module nested inside the one where `external`
// is registered.
mod nested {
    use protobuf::well_known_types::empty::Empty;
    use yara_x::mods::prelude::*;

    register_module!("nested", Empty, main);

    fn main(_: &mut ModuleContext, _: &[u8]) -> Result<Empty, ModuleError> {
        Ok(Empty::new())
    }

    #[module_export]
    fn double(_ctx: &ScanContext, a: i64) -> i64 {
        a * 2
    }
}

// A data-only module, which has no `rust_module_name`, next to a function.
mod data_only {
    use protobuf::well_known_types::empty::Empty;
    use yara_x::mods::prelude::*;

    register_module!("data_only", Empty);

    #[module_export]
    fn identity(_ctx: &ScanContext, a: i64) -> i64 {
        a
    }
}

// A module built by hand whose `rust_module_name` is only the last segment
// of the functions' Rust path (`external_module::partial`), instead of the
// value of `module_path!()`.
mod partial {
    use protobuf::well_known_types::empty::Empty;
    use yara_x::mods::prelude::*;

    inventory::submit! {
        &Module::<Empty> {
            name: "partial",
            main_fn: None,
            rust_module_name: Some("partial"),
        } as &dyn RegisteredModule
    }

    #[module_export]
    fn negate(_ctx: &ScanContext, a: i64) -> i64 {
        -a
    }
}

// Two distinct Rust modules registering the same YARA module name (`"dup"`).
// Whichever registration wins lookup must not inherit the other's functions.
mod dup_one {
    use protobuf::well_known_types::empty::Empty;
    use yara_x::mods::prelude::*;

    register_module!("dup", Empty, main);

    fn main(_: &mut ModuleContext, _: &[u8]) -> Result<Empty, ModuleError> {
        Ok(Empty::new())
    }

    #[module_export]
    fn from_one(_ctx: &ScanContext) -> i64 {
        1
    }
}

mod dup_two {
    use protobuf::well_known_types::empty::Empty;
    use yara_x::mods::prelude::*;

    register_module!("dup", Empty, main);

    fn main(_: &mut ModuleContext, _: &[u8]) -> Result<Empty, ModuleError> {
        Ok(Empty::new())
    }

    #[module_export]
    fn from_two(_ctx: &ScanContext) -> i64 {
        2
    }
}

fn assert_matches_data(src: &str, data: &[u8]) {
    let rules = yara_x::compile(src).unwrap();
    let mut scanner = yara_x::Scanner::new(&rules);
    assert_eq!(scanner.scan(data).unwrap().matching_rules().len(), 1);
}

fn assert_matches(src: &str) {
    assert_matches_data(src, b"");
}

fn assert_compile_error(src: &str, expected: &str) {
    let err = yara_x::compile(src).unwrap_err().to_string();
    assert!(err.contains(expected), "unexpected error: {err}");
}

#[test]
fn qualified_call() {
    assert_matches(
        r#"
        import "external"
        rule test { condition: external.str_lt("a", "b") }
        "#,
    );
}

#[test]
fn unqualified_call_is_unknown_identifier() {
    // Functions exported by a module must not be reachable without the
    // module's prefix, with or without importing the module.
    for src in [
        r#"import "external" rule test { condition: str_lt("a", "b") }"#,
        r#"rule test { condition: str_lt("a", "b") }"#,
    ] {
        assert_compile_error(src, "unknown identifier `str_lt`");
    }
}

#[test]
fn external_method_is_neither_global_nor_module_function() {
    assert_compile_error(
        r#"rule test { condition: dummy_method(1) }"#,
        "unknown identifier `dummy_method`",
    );
    assert_compile_error(
        r#"import "external" rule test { condition: external.dummy_method(1) }"#,
        "unknown field or method `dummy_method`",
    );
}

#[test]
fn orphaned_exports_are_not_global_and_do_not_shadow_builtins() {
    // A function that doesn't belong to any module must not become a global
    // function.
    assert_compile_error(
        r#"rule test { condition: add_one(1) == 2 }"#,
        "unknown identifier `add_one`",
    );

    // And an orphaned `#[module_export]` named `uint8` must not shadow YARA's
    // built-in `uint8` (`0x41 == b'A'`, whereas `misplaced::uint8` returns
    // `0xFF`).
    assert_matches_data(r#"rule test { condition: uint8(0) == 0x41 }"#, b"A");
}

#[test]
fn nested_module() {
    // `double` belongs to `nested`, not to `external`, even though its Rust
    // path (`external_module::nested`) starts with the Rust module of
    // `external` (`external_module`).
    assert_matches(
        r#"
        import "nested"
        rule test { condition: nested.double(2) == 4 }
        "#,
    );
    assert_compile_error(
        r#"import "external" rule test { condition: external.double(2) == 4 }"#,
        "unknown field or method `double`",
    );
    assert_compile_error(
        r#"rule test { condition: double(2) == 4 }"#,
        "unknown identifier `double`",
    );
}

#[test]
fn data_only_module() {
    // A data-only module has no `rust_module_name`, so it has no functions,
    // and functions next to it are not global either.
    assert_compile_error(
        r#"import "data_only" rule test { condition: data_only.identity(1) == 1 }"#,
        "unknown field or method `identity`",
    );
    assert_compile_error(
        r#"rule test { condition: identity(1) == 1 }"#,
        "unknown identifier `identity`",
    );
}

#[test]
fn rust_module_name_must_match_exactly() {
    // `rust_module_name` must be the value of `module_path!()` where the
    // functions are defined. A partial path doesn't match.
    assert_compile_error(
        r#"import "partial" rule test { condition: partial.negate(1) == -1 }"#,
        "unknown field or method `negate`",
    );
    assert_compile_error(
        r#"rule test { condition: negate(1) == -1 }"#,
        "unknown identifier `negate`",
    );
}

#[test]
fn same_named_modules_do_not_cross_attach_functions() {
    let one_ok = yara_x::compile(
        r#"import "dup" rule test { condition: dup.from_one() == 1 }"#,
    )
    .is_ok();
    let two_ok = yara_x::compile(
        r#"import "dup" rule test { condition: dup.from_two() == 2 }"#,
    )
    .is_ok();

    // Exactly one of the two `"dup"` registrations wins `module_by_name`, and
    // it must expose only its own function, not both.
    assert_ne!(
        one_ok, two_ok,
        "expected exactly one `dup` registration's function to be attached"
    );
}
