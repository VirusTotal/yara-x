use crate::mods::api::prelude::*;
use crate::modules::protos::time::*;

#[module_main]
fn main(_data: &[u8], _meta: Option<&[u8]>) -> Result<Time, ModuleError> {
    // Nothing to do, but we have to return our protobuf
    Ok(Time::new())
}

/// Returns the current time as the number of seconds since January 1, 1970 (UTC).
#[module_export]
fn now(_ctx: &ScanContext) -> Option<i64> {
    current_unix_timestamp()
}

#[cfg(all(target_family = "wasm", not(target_os = "wasi")))]
fn current_unix_timestamp() -> Option<i64> {
    // `SystemTime::now` is unavailable on `wasm32-unknown-unknown`, but the
    // browser and Node runtimes both expose `Date.now()`.
    Some((js_sys::Date::now() / 1000.0).floor() as i64)
}

#[cfg(not(all(target_family = "wasm", not(target_os = "wasi"))))]
fn current_unix_timestamp() -> Option<i64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use crate::tests::rule_true;
    use crate::tests::test_rule;

    #[test]
    fn now() {
        rule_true!(
            r#"
            import "time"
            rule test { condition: time.now() >= 0 }"#,
            &[]
        );
    }
}

register_module! {
    Module {
        name: "time",
        root_descriptor: Time::descriptor,
        main_fn: Some(__main__ as ModuleMainFn),
        rust_module_name: Some(module_path!()),
    }
}
