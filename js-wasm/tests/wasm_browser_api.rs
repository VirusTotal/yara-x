#![cfg(target_arch = "wasm32")]

#[path = "support/mod.rs"]
mod support;

use js_sys::Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;
use yara_x_js::WasmCompiler;

use crate::support::{ScanResult, parse_scan_result};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(inline_js = r#"
let __yaraConsoleOriginalLog;
let __yaraConsoleMessages = [];

export function beginConsoleCapture() {
  __yaraConsoleMessages = [];
  __yaraConsoleOriginalLog = console.log;
  console.log = (...args) => {
    __yaraConsoleMessages.push(args.join(""));
  };
}

export function endConsoleCapture() {
  if (__yaraConsoleOriginalLog) {
    console.log = __yaraConsoleOriginalLog;
    __yaraConsoleOriginalLog = undefined;
  }
}

export function takeConsoleCapture() {
  return __yaraConsoleMessages.slice();
}
"#)]
extern "C" {
    fn beginConsoleCapture();
    fn endConsoleCapture();
    fn takeConsoleCapture() -> Array;
}

fn scan_rule(rule: &str, payload: &[u8]) -> ScanResult {
    let mut compiler = WasmCompiler::new();
    compiler.add_source(rule).expect("rule should compile");
    let rules = compiler.build().expect("rules should build");
    parse_scan_result(rules.scan(payload).expect("scan should succeed"))
}

#[wasm_bindgen_test]
fn console_module_logs_expected_messages_in_browser() {
    beginConsoleCapture();

    let parsed = scan_rule(
        r#"
            import "console"
            rule test {
                condition:
                    console.log("foo") and
                    console.log("bar: ", 1) and
                    console.log("baz: ", 3.14) and
                    console.log(10) and
                    console.log(6.28) and
                    console.log(true) and
                    console.log("bool: ", true) and
                    console.hex(10) and
                    console.hex("qux: ", 255) and
                    console.log("hello ", "world!")
            }
            "#,
        b"",
    );

    endConsoleCapture();

    assert!(parsed.valid);
    assert_eq!(parsed.matches.len(), 1);

    let captured = takeConsoleCapture()
        .iter()
        .map(|value| value.as_string().expect("console output should be text"))
        .collect::<Vec<_>>();

    assert_eq!(
        captured,
        vec![
            "foo",
            "bar: 1",
            "baz: 3.14",
            "10",
            "6.28",
            "true",
            "bool: true",
            "0xa",
            "qux: 0xff",
            "hello world!",
        ]
    );
}

#[wasm_bindgen_test]
fn time_module_uses_browser_clock() {
    let parsed = scan_rule(
        r#"
            import "time"
            rule test {
                condition:
                    time.now() > 1_600_000_000
            }
            "#,
        b"",
    );

    assert!(parsed.valid);
    assert_eq!(parsed.matches.len(), 1);
}
