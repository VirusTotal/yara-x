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

// Functions belong to a module only if they are defined in the same Rust
// module where `register_module!` was invoked. This one isn't, and no module
// is registered here, so it doesn't belong to any module.
mod misplaced {
    use yara_x::mods::prelude::*;

    #[module_export]
    fn add_one(_ctx: &ScanContext, a: i64) -> i64 {
        a + 1
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

fn assert_matches(src: &str) {
    let rules = yara_x::compile(src).unwrap();
    let mut scanner = yara_x::Scanner::new(&rules);
    assert_eq!(scanner.scan(b"").unwrap().matching_rules().len(), 1);
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
fn functions_outside_yara_x_are_never_global() {
    // A function that doesn't belong to any module must not become a global
    // function either.
    assert_compile_error(
        r#"rule test { condition: add_one(1) == 2 }"#,
        "unknown identifier `add_one`",
    );
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
