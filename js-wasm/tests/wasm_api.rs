#![cfg(target_arch = "wasm32")]

#[path = "support/mod.rs"]
mod support;

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;
use yara_x_wasm::{WasmCompiler, WasmScanner};

use crate::support::{
    MetadataValue, ScanResult, assert_match_identifiers, js_error_message,
    parse_scan_result,
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

fn compiler_with_sources(rule_sources: &[&str]) -> WasmCompiler {
    let mut compiler = WasmCompiler::new();
    for source in rule_sources {
        compiler.add_source(source).expect("rule source should be accepted");
    }
    compiler
}

fn scan_rule_sources(rule_sources: &[&str], payload: &[u8]) -> ScanResult {
    let mut compiler = compiler_with_sources(rule_sources);
    let rules = compiler.build().expect("rules should build");
    parse_scan_result(rules.scan(payload).expect("scan should succeed"))
}

#[wasm_bindgen_test]
fn compiler_accepts_single_rule_source() {
    let compiler = compiler_with_sources(&[test_rule()]);
    assert!(compiler.errors().expect("errors getter").is_empty());
}

#[wasm_bindgen_test]
fn compiler_accepts_multiple_rule_sources() {
    let compiler = compiler_with_sources(&[
        "rule a { condition: true }",
        "rule b { condition: true }",
    ]);
    assert!(compiler.errors().expect("errors getter").is_empty());
}

#[wasm_bindgen_test]
fn compiler_reports_syntax_errors() {
    let mut compiler = WasmCompiler::new();
    let error = compiler
        .add_source("rule bad { condition: and }")
        .expect_err("syntax error must be surfaced");

    assert!(js_error_message(error).contains("error"));
    assert!(!compiler.errors().expect("errors getter").is_empty());
}

#[wasm_bindgen_test]
fn compiler_build_rejects_accumulated_errors() {
    let mut compiler = WasmCompiler::new();
    let add_error = compiler
        .add_source("rule bad { condition: and }")
        .expect_err("syntax error must be surfaced");

    assert!(js_error_message(add_error).contains("syntax error"));

    let build_error = match compiler.build() {
        Ok(_) => panic!("build must reject accumulated compiler errors"),
        Err(err) => err,
    };
    assert!(js_error_message(build_error).contains("syntax error"));
    assert!(!compiler.errors().expect("errors getter").is_empty());
}

#[wasm_bindgen_test]
fn rules_scan_returns_matches_and_metadata() {
    let parsed = scan_rule_sources(&[test_rule()], b"zzabczz");
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
fn scan_results_include_compiler_warnings() {
    let mut compiler = WasmCompiler::new();
    compiler
        .add_source(
            r#"
            rule slow_loop {
                condition:
                    for any i in (0..filesize) : ( true )
            }
            "#,
        )
        .expect("rule should compile");

    let compiler_warnings = compiler.warnings().expect("warnings getter");
    assert!(!compiler_warnings.is_empty());
    assert!(compiler_warnings[0].contains("potentially slow loop"));

    let rules = compiler.build().expect("rules should build");
    let rules_warnings = rules.warnings();
    assert_eq!(rules_warnings, compiler_warnings);

    let rules_scan = parse_scan_result(rules.scan(b"").expect("rules scan"));
    assert_eq!(rules_scan.warnings, rules_warnings);

    let scanner = rules.scanner();
    let scanner_scan =
        parse_scan_result(scanner.scan(b"").expect("scanner scan"));
    assert_eq!(scanner_scan.warnings, rules_warnings);
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

        let parsed = scan_rule_sources(&[rule.as_str()], payload.as_bytes());

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

    let mut compiler = compiler_with_sources(&[rules]);
    let rules = compiler.build().expect("rules should build");

    for (payload, expected) in scenarios {
        let parsed = parse_scan_result(rules.scan(payload).expect("scan"));

        assert!(parsed.valid);
        assert_match_identifiers(&parsed, expected);
    }
}
