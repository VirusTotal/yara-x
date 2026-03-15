#![cfg(target_arch = "wasm32")]

#[path = "support/mod.rs"]
mod support;

use serde_wasm_bindgen::to_value;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;
use yara_wasm::{
    scan_rules_js, validate_rules_js, MetadataValue, ScanResult,
    ValidationResult, WasmCompiler, WasmScanner,
};

use crate::support::{
    assert_match_identifiers, js_error_message, parse_scan_result,
    parse_validation_result,
};

fn test_rule() -> &'static str {
    r#"
    rule api_rule : alpha beta {
        meta:
            author = "linus"
            score = 7
            active = true
        strings:
            $a = "abc"
        condition:
            $a
    }
    "#
}

fn compiler_with_single_global_rule() -> WasmCompiler {
    let mut compiler = WasmCompiler::new();
    compiler
        .define_global("tenant", JsValue::from_str("unset"))
        .expect("global should be defined");
    compiler
        .add_source(
            r#"
            rule tenant_a {
                condition:
                    tenant == "a"
            }
            "#,
        )
        .expect("rule should compile");
    compiler
        .add_source(
            r#"
            rule tenant_b {
                condition:
                    tenant == "b"
            }
            "#,
        )
        .expect("rule should compile");
    compiler
}

#[wasm_bindgen_test]
fn validate_rules_accepts_single_rule() {
    let result = validate_rules_js(JsValue::from_str(test_rule()))
        .expect("validateRules should return a result object");

    let parsed: ValidationResult = parse_validation_result(result);
    assert!(parsed.valid);
    assert!(parsed.errors.is_empty());
}

#[wasm_bindgen_test]
fn validate_rules_accepts_rule_array() {
    let input = to_value(&vec![
        "rule a { condition: true }".to_owned(),
        "rule b { condition: true }".to_owned(),
    ])
    .expect("rule array should serialize");

    let result =
        validate_rules_js(input).expect("validateRules should succeed");
    let parsed: ValidationResult = parse_validation_result(result);
    assert!(parsed.valid);
    assert!(parsed.errors.is_empty());
}

#[wasm_bindgen_test]
fn validate_rules_rejects_empty_rule_array() {
    let input = to_value(&Vec::<String>::new()).expect("empty array");
    let error = validate_rules_js(input).expect_err("empty array must fail");

    assert!(
        js_error_message(error).contains("at least one rule must be provided")
    );
}

#[wasm_bindgen_test]
fn validate_rules_rejects_invalid_input_type() {
    let error = validate_rules_js(JsValue::from_bool(true))
        .expect_err("bool must fail");

    assert!(js_error_message(error).contains("string or array of strings"));
}

#[wasm_bindgen_test]
fn validate_rules_reports_syntax_errors() {
    let bad_rule = "rule bad { condition: and }";
    let result = validate_rules_js(JsValue::from_str(bad_rule))
        .expect("validateRules should not throw on syntax errors");

    let parsed: ValidationResult = parse_validation_result(result);
    assert!(!parsed.valid);
    assert!(!parsed.errors.is_empty());
}

#[wasm_bindgen_test]
fn scan_rules_returns_matches_and_metadata() {
    let result = scan_rules_js(JsValue::from_str(test_rule()), b"zzabczz")
        .expect("scanRules should return a result object");

    let parsed: ScanResult = parse_scan_result(result);
    assert!(parsed.valid);
    assert_eq!(parsed.matches.len(), 1);

    let matched_rule = &parsed.matches[0];
    assert_eq!(matched_rule.identifier, "api_rule");
    assert_eq!(matched_rule.tags, vec!["alpha".to_owned(), "beta".to_owned()]);

    let score_meta = matched_rule
        .metadata
        .iter()
        .find(|m| m.identifier == "score")
        .expect("score metadata present");

    assert_eq!(score_meta.value, MetadataValue::Integer(7));

    let pattern = matched_rule
        .patterns
        .iter()
        .find(|p| p.identifier == "$a")
        .expect("$a pattern present");
    assert_eq!(pattern.matches.len(), 1);
    assert_eq!(pattern.matches[0].offset, 2);
}

#[wasm_bindgen_test]
fn scan_rules_returns_compile_errors_without_throwing() {
    let result = scan_rules_js(
        JsValue::from_str("rule invalid { condition: and }"),
        b"x",
    )
    .expect("scanRules should return compile diagnostics");

    let parsed: ScanResult = parse_scan_result(result);
    assert!(!parsed.valid);
    assert!(!parsed.errors.is_empty());
    assert!(parsed.matches.is_empty());
}

#[wasm_bindgen_test]
fn compiler_builds_namespaced_rules_and_is_consumed() {
    let mut compiler = WasmCompiler::new();
    compiler.new_namespace("tenant").expect("namespace switch should succeed");
    compiler
        .add_source("rule namespaced { condition: true }")
        .expect("rule should compile");

    assert!(compiler.errors().expect("errors getter").is_empty());
    compiler.warnings().expect("warnings getter should succeed");

    let rules = compiler.build().expect("build should succeed");

    let scan =
        parse_scan_result(rules.scan(b"").expect("scan should succeed"));
    assert!(scan.valid);
    assert_eq!(scan.matches.len(), 1);
    assert_eq!(scan.matches[0].identifier, "namespaced");
    assert_eq!(scan.matches[0].namespace, "tenant");

    let error = compiler
        .add_source("rule later { condition: true }")
        .expect_err("consumed compiler should reject more rules");
    assert!(
        js_error_message(error).contains("compiler has already been consumed")
    );
}

#[wasm_bindgen_test]
fn scanner_globals_are_isolated_between_instances() {
    let mut compiler = compiler_with_single_global_rule();
    let rules = compiler.build().expect("rules should build");
    let mut scanner_a = WasmScanner::new(&rules);
    let mut scanner_b = rules.scanner();

    scanner_a
        .set_global("tenant", JsValue::from_str("a"))
        .expect("scanner A should accept global");
    scanner_b
        .set_global("tenant", JsValue::from_str("b"))
        .expect("scanner B should accept global");

    for _ in 0..4 {
        let scan_a = parse_scan_result(scanner_a.scan(b"").expect("scan A"));
        let scan_b = parse_scan_result(scanner_b.scan(b"").expect("scan B"));

        assert!(scan_a.valid);
        assert!(scan_b.valid);
        assert_match_identifiers(&scan_a, &["tenant_a"]);
        assert_match_identifiers(&scan_b, &["tenant_b"]);
    }

    scanner_a
        .set_global("tenant", JsValue::from_str("b"))
        .expect("scanner A global should be replaceable");

    let flipped = parse_scan_result(scanner_a.scan(b"").expect("scan A"));
    let unchanged = parse_scan_result(scanner_b.scan(b"").expect("scan B"));
    assert_match_identifiers(&flipped, &["tenant_b"]);
    assert_match_identifiers(&unchanged, &["tenant_b"]);
}

#[wasm_bindgen_test]
fn scanner_rejects_unknown_and_mismatched_globals() {
    let mut compiler = WasmCompiler::new();
    compiler
        .define_global("enabled", JsValue::from_bool(false))
        .expect("bool global should be defined");
    compiler
        .add_source("rule uses_global { condition: enabled }")
        .expect("rule should compile");

    let rules = compiler.build().expect("rules should build");
    let mut scanner = rules.scanner();

    let missing = scanner
        .set_global("missing", JsValue::from_bool(true))
        .expect_err("unknown globals must fail");
    assert!(js_error_message(missing).contains("not defined"));

    let mismatch = scanner
        .set_global("enabled", JsValue::from_f64(1.0))
        .expect_err("type mismatch must fail");
    assert!(js_error_message(mismatch).contains("invalid type"));
}

#[wasm_bindgen_test]
fn scanner_max_matches_per_pattern_limits_results() {
    let rule = r#"
        rule repeated {
            strings:
                $a = "aa"
            condition:
                $a
        }
    "#;

    let mut compiler = WasmCompiler::new();
    compiler.add_source(rule).expect("rule should compile");
    let rules = compiler.build().expect("rules should build");

    let baseline =
        parse_scan_result(rules.scan(b"aaaaaa").expect("baseline scan"));
    let baseline_matches = &baseline.matches[0].patterns[0].matches;
    assert!(baseline_matches.len() > 1);

    let mut scanner = rules.scanner();
    scanner.set_max_matches_per_pattern(1);
    let limited =
        parse_scan_result(scanner.scan(b"aaaaaa").expect("limited scan"));
    assert_eq!(limited.matches.len(), 1);
    assert_eq!(limited.matches[0].patterns[0].matches.len(), 1);
}

#[wasm_bindgen_test]
fn repeated_compile_and_scan_rounds_are_isolated() {
    for i in 0..20 {
        let rule_name = format!("round_{i}_rule");
        let marker = format!("marker_{i}_abc");
        let rule = format!(
            r#"
            rule {rule_name} {{
              strings:
                $a = "{marker}"
              condition:
                $a
            }}
            "#
        );
        let payload = format!("xx{marker}yy");

        let result = scan_rules_js(
            JsValue::from_str(rule.as_str()),
            payload.as_bytes(),
        )
        .expect("scanRules should return a result object");
        let parsed: ScanResult = parse_scan_result(result);

        assert!(parsed.valid, "round {i} must remain valid");
        assert_eq!(parsed.matches.len(), 1, "round {i} must match once");
        assert_eq!(parsed.matches[0].identifier, rule_name);
    }
}

#[wasm_bindgen_test]
fn repeated_scans_with_same_rules_do_not_retain_stale_matches() {
    let rules = r#"
        rule alpha_hit {
          strings:
            $a = "alpha"
          condition:
            $a
        }
        rule beta_hit {
          strings:
            $b = "beta"
          condition:
            $b
        }
    "#;

    let scenarios: [(&[u8], &[&str]); 5] = [
        (b"prefix alpha suffix", &["alpha_hit"]),
        (b"no markers here", &[]),
        (b"prefix beta suffix", &["beta_hit"]),
        (b"alpha and beta", &["alpha_hit", "beta_hit"]),
        (b"still no markers", &[]),
    ];

    for (payload, expected) in scenarios {
        let result = scan_rules_js(JsValue::from_str(rules), payload)
            .expect("scanRules should return a result object");
        let parsed: ScanResult = parse_scan_result(result);

        assert!(parsed.valid);
        assert_match_identifiers(&parsed, expected);
    }
}
