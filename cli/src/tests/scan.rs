use std::ffi::OsString;

use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;
use serde_json;

#[test]
fn always_true() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "warning[invariant_expr]: invariant boolean expression",
        ))
        .stdout(predicate::str::contains(
            "always_true src/tests/testdata/dummy.file",
        ));
}

#[test]
fn negate() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--negate")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("");
}

#[test]
fn scan_list_from_stdin() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--count")
        .arg("--scan-list")
        .arg("--threads=1")
        .arg("src/tests/testdata/foo.yar")
        .arg("-")
        .write_stdin("src/tests/testdata/dummy.file\n")
        .assert()
        .success()
        .stdout("src/tests/testdata/dummy.file: 1\n");
}

#[test]
fn filter_by_tag() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--tag=foo")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("");

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--tag=bar")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(predicate::str::contains("foo src/tests/testdata/dummy.file"));

    let temp_dir = TempDir::new().unwrap();
    let rules_file = temp_dir.child("rules.yar");
    rules_file
        .write_str(
            r#"
            rule rule_a : tag_a { condition: true }
            rule rule_b : tag_b { condition: true }
            "#,
        )
        .unwrap();

    // NDJSON: only rule_a should be returned when filtering by tag_a.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("--tag=tag_a")
        .arg(rules_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("{\"path\":\"src/tests/testdata/dummy.file\",\"rules\":[{\"identifier\":\"rule_a\"}]}\n");

    // NDJSON: nothing should be returned when filtering by a non-matching tag.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("--tag=tag_c")
        .arg(rules_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("");

    // JSON: only rule_a should be in `matches` when filtering by tag_a.
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("--tag=tag_a")
        .arg(rules_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("valid JSON output");
    let matches = json["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["rule"], "rule_a");

    // JSON: `matches` should be empty when filtering by a non-matching tag.
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("--tag=tag_c")
        .arg(rules_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("valid JSON output");
    let matches = json["matches"].as_array().unwrap();
    assert!(matches.is_empty());
}

#[test]
fn disable_warning() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--disable-warnings=invariant_expr")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(
            predicate::str::contains(
                "warning[invariant_expr]: invariant boolean expression",
            )
            .not(),
        )
        .stdout(predicate::str::contains(
            "always_true src/tests/testdata/dummy.file",
        ));
}

#[test]
fn disable_warning_config_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.child("config.toml");

    config_file
        .write_str(
            r#"
            [warnings]
            invariant_expr = { disabled = true }
            "#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("--config")
        .arg(config_file.path())
        .arg("scan")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(
            predicate::str::contains(
                "warning[invariant_expr]: invariant boolean expression",
            )
            .not(),
        )
        .stdout(predicate::str::contains(
            "always_true src/tests/testdata/dummy.file",
        ));
}

#[test]
fn print_strings() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-strings")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(
            "foo src/tests/testdata/dummy.file
0x0:3:$foo: foo
0x0:3:$foo_hex: 66 6f 6f
",
        );
}

#[test]
fn print_strings_n() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-strings=2")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(
            "foo src/tests/testdata/dummy.file
0x0:3:$foo: fo ... 1 more bytes
0x0:3:$foo_hex: 66 6f ... 1 more bytes
",
        );
}

#[test]
fn print_namespace() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-namespace")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("default:foo src/tests/testdata/dummy.file\n");
}

#[test]
fn print_meta() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-meta")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("foo [string=\"foo\",bool=true,int=1,float=3.14,regexp=\"foo\"] src/tests/testdata/dummy.file\n");
}

#[test]
fn print_tags() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-tags")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("foo [bar,baz] src/tests/testdata/dummy.file\n");
}

#[test]
fn path_as_namespace() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-namespace")
        .arg("--path-as-namespace")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(
            "src/tests/testdata/foo.yar:foo src/tests/testdata/dummy.file\n",
        );
}

#[test]
fn format_ndjson() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("{\"path\":\"src/tests/testdata/dummy.file\",\"rules\":[{\"identifier\":\"foo\"}]}\n");
}

#[test]
fn define() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--define=float=3.14")
        .arg("--define=int=1")
        .arg("--define=bool=true")
        .arg("src/tests/testdata/variables.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("test src/tests/testdata/dummy.file\n");
}

#[test]
fn console() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/console.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr("src/tests/testdata/dummy.file: hello\n");

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--disable-console-logs")
        .arg("src/tests/testdata/console.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr("");
}

#[test]
fn ignore_module() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--ignore-module=unknown")
        .arg("src/tests/testdata/unknown_module.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(
            r#"warning[unsupported_module]: module `unknown` is not supported
 --> src/tests/testdata/unknown_module.yar:1:1
  |
1 | import "unknown"
  | ---------------- module `unknown` used here
warning[unsupported_module]: module `unknown` is not supported
 --> src/tests/testdata/unknown_module.yar:5:6
  |
5 |      unknown.foo()
  |      ------- module `unknown` used here
  |
  = note: the whole rule `test` will be ignored
"#,
        );
}

#[test]
fn ignore_supported_module() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--ignore-module=math")
        .arg("src/tests/testdata/known_module.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(
            r#"warning[unsupported_module]: module `math` is not supported
 --> src/tests/testdata/known_module.yar:1:1
  |
1 | import "math"
  | ------------- module `math` used here
warning[unsupported_module]: module `math` is not supported
 --> src/tests/testdata/known_module.yar:5:6
  |
5 |      math.entropy(0, filesize) >= 0
  |      ---- module `math` used here
  |
  = note: the whole rule `test` will be ignored
"#,
        );
}

#[test]
fn recursive() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--recursive")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure()
        .code(1)
        .stderr(
            "error: can\'t use \'--recursive\' when <TARGET_PATH> is a file\n",
        );
}

#[test]
fn compiled_rules() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--compiled-rules")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure()
        .code(1)
        .stderr("error: can\'t use \'--compiled-rules\' with more than one RULES_PATH\n");

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--compiled-rules")
        .arg("namespace:src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure()
        .code(1)
        .stderr("error: can\'t use namespace with \'--compiled-rules\'\n");

    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("compile")
        .arg("-o")
        .arg(input_file.with_extension("yarc"))
        .arg(input_file.path())
        .assert()
        .success();

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--compiled-rules")
        .arg(input_file.with_extension("yarc"))
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success();
}

#[test]
fn issue_280() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg("./src/tests/testdata/")
        .assert()
        .success();

    // Handle special case of just . for path argument.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg(".")
        .assert()
        .success();

    // Handle special case of just ./ for path argument.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg("./")
        .assert()
        .success();

    // Handle special case of just .\ for path argument.
    #[cfg(target_os = "windows")]
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg(r#".\"#)
        .assert()
        .success();
}

#[test]
fn json_output_duplicate_meta_keys() {
    // Test that duplicate metadata keys are preserved as arrays in JSON output
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("--print-meta")
        .arg("src/tests/testdata/duplicate_meta.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("valid JSON output");

    // Navigate to the meta object
    let meta = &json["matches"][0]["meta"];

    // Single-value keys should remain as single values
    assert_eq!(meta["author"], "Test Author");
    assert_eq!(meta["description"], "Rule with duplicate metadata keys");

    // Duplicate keys should become arrays
    let hash = &meta["hash"];
    assert!(hash.is_array(), "hash should be an array");
    let hash_array = hash.as_array().unwrap();
    assert_eq!(hash_array.len(), 3);
    assert!(hash_array.contains(&serde_json::json!("aaa111")));
    assert!(hash_array.contains(&serde_json::json!("bbb222")));
    assert!(hash_array.contains(&serde_json::json!("ccc333")));
}

#[test]
fn json_output_single_meta_not_array() {
    // Test that single metadata values are NOT wrapped in arrays
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("--print-meta")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("valid JSON output");

    let meta = &json["matches"][0]["meta"];

    // All values should be single values, not arrays
    assert!(meta["string"].is_string());
    assert!(meta["bool"].is_boolean());
    assert!(meta["int"].is_i64());
    assert!(meta["float"].is_f64());
}

#[test]
fn fast_scan() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--fast-scan")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(predicate::str::contains("foo src/tests/testdata/dummy.file"));

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("-f")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(predicate::str::contains("foo src/tests/testdata/dummy.file"));
}

#[test]
fn cpu_limit() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--cpu-limit=50")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success();
}

#[test]
fn ignore_invalid_rules() {
    let temp_dir = TempDir::new().unwrap();
    let yar_file = temp_dir.child("test.yar");

    yar_file
        .write_str(
            r#"
            rule valid_rule {
                condition: true
            }
            rule invalid_rule {
                condition: undefined_var == 1
            }
            "#,
        )
        .unwrap();

    // Without --ignore-invalid-rules, scan should fail on compile error.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg(yar_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure()
        .stderr(predicate::str::contains("1 error(s) found"));

    // With --ignore-invalid-rules, scan should succeed and match valid_rule.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--ignore-invalid-rules")
        .arg(yar_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(predicate::str::contains("valid_rule"));
}

#[test]
fn format_ndjson_omits_non_matching_files() {
    let temp_dir = TempDir::new().unwrap();
    let matching_file = temp_dir.child("matching.file");
    let non_matching_file = temp_dir.child("non_matching.file");

    matching_file.write_str("foo").unwrap();
    non_matching_file.write_str("bar").unwrap();

    let expected_path = matching_file.path().to_str().unwrap();

    // Non-matching files should not appear in ndjson output.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout(format!(
            "{{\"path\":{},\"rules\":[{{\"identifier\":\"foo\"}}]}}\n",
            serde_json::to_string(expected_path).unwrap()
        ));

    // When --tag filters out all matching rules, nothing should be emitted.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("--tag=non_existent_tag")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout("");

    // With --count, only files with count > 0 should be emitted.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("--count")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout(format!(
            "{{\"path\":{},\"count\":1}}\n",
            serde_json::to_string(expected_path).unwrap()
        ));

    // With --count and --tag filtering out matches, nothing should be emitted.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("--count")
        .arg("--tag=non_existent_tag")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout("");
}

#[cfg(target_os = "linux")]
#[test]
fn format_ndjson_non_utf8_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();
    let matching_file = temp_dir.child(OsStr::from_bytes(b"foo_\xff.file"));
    let non_matching_file =
        temp_dir.child(OsStr::from_bytes(b"bar_\xff.file"));

    matching_file.write_str("foo").unwrap();
    non_matching_file.write_str("bar").unwrap();

    // File names that are not valid UTF-8 must not abort the scan; invalid
    // byte sequences are replaced with U+FFFD in the output.
    let expected_path = matching_file.path().to_string_lossy();

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout(format!(
            "{{\"path\":{},\"rules\":[{{\"identifier\":\"foo\"}}]}}\n",
            serde_json::to_string(expected_path.as_ref()).unwrap()
        ));

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("--count")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout(format!(
            "{{\"path\":{},\"count\":1}}\n",
            serde_json::to_string(expected_path.as_ref()).unwrap()
        ));
}

#[cfg(target_os = "linux")]
#[test]
fn format_json_non_utf8_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();
    let file_fe = temp_dir.child(OsStr::from_bytes(b"odd_\xfe.file"));
    let file_ff = temp_dir.child(OsStr::from_bytes(b"odd_\xff.file"));

    file_fe.write_str("foo").unwrap();
    file_ff.write_str("foo").unwrap();

    let expected_path = dunce::canonicalize(file_fe.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();

    // Matches must report the lossy path instead of "".
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let matches = json["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().all(|m| m["file"] == expected_path));

    // With --count, distinct files whose lossy names collide must not be
    // merged into a single entry.
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("--count")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let counts: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let entries = counts.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().all(|e| e["path"] == expected_path && e["count"] == 1)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn rules_non_utf8_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();

    temp_dir
        .child(OsStr::from_bytes(b"foo_\xff.yar"))
        .write_str("rule foo { strings: $foo = \"foo\" condition: $foo }")
        .unwrap();

    // Rule files with names that are not valid UTF-8 must be compiled
    // without panicking.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg(temp_dir.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("foo src/tests/testdata/dummy.file\n");
}

#[test]
fn count_omits_non_matching_files() {
    let temp_dir = TempDir::new().unwrap();
    let matching_file = temp_dir.child("matching.file");
    let non_matching_file = temp_dir.child("non_matching.file");

    matching_file.write_str("foo").unwrap();
    non_matching_file.write_str("bar").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--count")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout(format!("{}: 1\n", matching_file.path().display()));

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--count")
        .arg("--tag=non_existent_tag")
        .arg("src/tests/testdata/foo.yar")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout("");
}

// When the timeout expires all worker threads exit, and the walker thread
// must stop instead of blocking forever trying to enqueue more paths into a
// full bounded channel. The file count must exceed the thread count plus the
// bounded channel capacity (128).
#[test]
fn timeout_with_pending_files() {
    let temp_dir = TempDir::new().unwrap();
    let rules_file = temp_dir.child("rules.yar");
    let scan_dir = temp_dir.child("files");

    rules_file
        .write_str(
            r#"rule slow {
                condition:
                    for all i in (0..9223372036854775806) : (i >= 0)
            }"#,
        )
        .unwrap();

    for i in 0..200 {
        scan_dir.child(format!("{i}.file")).write_str("foo").unwrap();
    }

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--timeout=1")
        .arg("--threads=2")
        .arg(rules_file.path())
        .arg(scan_dir.path())
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .success()
        .stderr(
            predicate::str::contains("timeout").and(
                predicate::str::contains("sending on a disconnected channel")
                    .not(),
            ),
        );
}

// Regression test for https://github.com/VirusTotal/yara-x/issues/785.
//
// When `yr scan` runs in an interactive terminal (both `stdout` and `stderr`
// are TTYs), `ParWalker` uses `Console` to display the scan progress.
// Previously, output lines were printed via `MultiProgress::println`, which
// padded lines with spaces up to the terminal width instead of writing `\n`
// characters.
//
// Standard `Command` tests pipe `stdout` and `stderr`, so `is_tty()` is `false`
// and the interactive console code path is not exercised. To test the
// interactive terminal behavior, we allocate a pseudo-terminal (PTY) pair via
// `openpty` and attach the child process's `stdin`, `stdout`, and `stderr` to
// the `slave` end of the PTY while reading the combined terminal stream from
// the `master` end.
#[cfg(unix)]
#[test]
fn issue_785() {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::process::Stdio;
    use std::ptr;

    #[repr(C)]
    struct Winsize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }

    unsafe extern "C" {
        fn openpty(
            amaster: *mut std::ffi::c_int,
            aslave: *mut std::ffi::c_int,
            name: *mut std::ffi::c_char,
            termp: *const std::ffi::c_void,
            winp: *const Winsize,
        ) -> std::ffi::c_int;
    }

    let mut master_fd = -1;
    let mut slave_fd = -1;

    // Set a non-zero terminal window size (80x24) so `Console` detects valid
    // terminal dimensions when querying `TIOCGWINSZ`.
    let ws = Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };

    let ret = unsafe {
        openpty(
            &mut master_fd,
            &mut slave_fd,
            ptr::null_mut(),
            ptr::null(),
            &ws,
        )
    };
    assert_eq!(ret, 0);

    let mut master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };

    let mut cmd = std::process::Command::new(cargo_bin!("yr"));

    cmd.arg("scan")
        .arg("--print-strings")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        // `TERM` must be set to a value other than `"dumb"` because `Console`
        // disables live rendering on Unix when `TERM` is unset or `"dumb"` (as
        // is common in CI environments).
        .env("TERM", "xterm-256color")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));

    let mut child = cmd.spawn().unwrap();

    // `cmd` holds the `Stdio` file descriptors duplicated from `slave`. Drop
    // `cmd` immediately after spawning so no `slave` file descriptors remain
    // open in the parent process; otherwise, reading from `master` below would
    // block forever after the child exits.
    drop(cmd);

    // Read all output produced by the child from the PTY master until the
    // slave side is closed. Once the child exits and all slave descriptors are
    // closed, `read` returns `Ok(0)` on macOS/BSD or `Err(EIO)` on Linux.
    let mut output = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match master.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => output.extend_from_slice(&buf[..n]),
        }
    }

    assert!(child.wait().unwrap().success());

    // The PTY line discipline translates `\n` into `\r\n` (`ONLCR`). Verify
    // that each output line is terminated by `\r\n` rather than padded with
    // spaces to the 80-column terminal width.
    let output = String::from_utf8(output).unwrap();
    assert!(
        output.contains("0x0:3:$foo: foo\r\n0x0:3:$foo_hex: 66 6f 6f\r\n"),
        "unexpected terminal output: {output:?}"
    );
}

#[test]
fn excludes_literal_files_and_directory_trees() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();

    for path in [
        "target/keep.bin",
        "target/skip.bin",
        "target/skip.bin.more",
        "target/skip[1]/deep/excluded.bin",
        "target/skip1/keep-too.bin",
    ] {
        temp.child(path).write_str("test").unwrap();
    }

    let mut exclude_arg = OsString::from("--exclude=");
    exclude_arg
        .push(temp.path().canonicalize().unwrap().join("target/skip[1]"));

    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "--recursive", "--threads=1"])
        .args(["--exclude", "target/skip.bin"])
        .arg(exclude_arg)
        .args(["rules.yar", "./target"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keep.bin"))
        .stdout(predicate::str::contains("keep-too.bin"))
        .stdout(predicate::str::contains("excluded.bin").not())
        .stdout(predicate::str::contains("skip.bin.more"))
        .stdout(predicate::str::contains("skip.bin\n").not());
}

#[test]
fn excluded_paths_are_skipped_before_metadata_in_scan_lists() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("keep.bin").write_str("test").unwrap();
    temp.child("paths.txt")
        .write_str("missing/deep/file.bin\nkeep.bin\n")
        .unwrap();

    for stdin in [false, true] {
        let mut cmd = Command::new(cargo_bin!("yr"));
        cmd.current_dir(temp.path()).args([
            "scan",
            "--scan-list",
            "--exclude",
            "./unused/../missing",
            "rules.yar",
            if stdin { "-" } else { "paths.txt" },
        ]);
        if stdin {
            cmd.write_stdin("missing/deep/file.bin\nkeep.bin\n");
        }
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("keep.bin"))
            .stdout(predicate::str::contains("missing").not())
            .stderr("");
    }
}

#[test]
fn excluded_explicit_targets_including_missing_paths_are_not_opened() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();

    for target in ["skip/file.bin", "skip/missing.bin", "skip"] {
        Command::new(cargo_bin!("yr"))
            .current_dir(temp.path())
            .args(["scan", "--exclude", "skip", "rules.yar", target])
            .assert()
            .success()
            .stdout("")
            .stderr("");
    }
}

#[cfg(unix)]
#[test]
fn excluded_directories_are_not_descended_into() {
    use std::fs::{Permissions, set_permissions};
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("target/keep.bin").write_str("test").unwrap();
    temp.child("target/private/nested/file.bin").write_str("test").unwrap();

    let private = temp.path().join("target/private");
    set_permissions(&private, Permissions::from_mode(0o000)).unwrap();

    let result = Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--recursive",
            "--exclude",
            "target/private",
            "rules.yar",
            "target",
        ])
        .output();

    set_permissions(&private, Permissions::from_mode(0o700)).unwrap();

    let result = result.unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty(), "{:?}", result.stderr);
    assert!(String::from_utf8_lossy(&result.stdout).contains("keep.bin"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("file.bin"));
}

#[cfg(target_os = "linux")]
#[test]
fn excludes_non_utf8_directory_names() {
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("target/keep.bin").write_str("test").unwrap();

    let excluded = temp
        .path()
        .join("target")
        .join(OsString::from_vec(b"skip-\xff".to_vec()));
    std::fs::create_dir(&excluded).unwrap();
    std::fs::write(excluded.join("excluded.bin"), b"test").unwrap();

    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "--recursive", "--exclude"])
        .arg(&excluded)
        .args(["rules.yar", "target"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keep.bin"))
        .stdout(predicate::str::contains("excluded.bin").not())
        .stderr("");
}

#[test]
fn empty_exclusion_is_rejected_before_compiling_rules() {
    Command::new(cargo_bin!("yr"))
        .args([
            "scan",
            "--exclude",
            "",
            "src/tests/testdata/missing.yar",
            "src/tests/testdata/dummy.file",
        ])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("--exclude"))
        .stderr(predicate::str::contains("missing.yar").not());
}

#[test]
fn invalid_scan_list_lines_do_not_abort_the_scan() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();
    temp.child("keep.bin").write_str("test").unwrap();
    temp.child("paths.txt")
        .write_str("\nskip/file.bin\n\nkeep.bin\n")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--scan-list",
            "--exclude",
            "skip",
            "rules.yar",
            "paths.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("keep.bin"))
        .stdout(predicate::str::contains("skip").not());
}

#[test]
fn recursive_scan_of_excluded_file_target_is_not_an_error() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();

    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--recursive",
            "--exclude",
            "skip",
            "rules.yar",
            "skip/file.bin",
        ])
        .assert()
        .success()
        .stdout("")
        .stderr("");
}

#[test]
fn equivalent_spellings_of_the_current_directory_are_walked() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("keep/file.bin").write_str("test").unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();

    let dot_slash = if cfg!(windows) { r".\\" } else { ".//" };
    let dot_dot = if cfg!(windows) { r".\." } else { "./." };

    for target in [dot_slash, dot_dot] {
        Command::new(cargo_bin!("yr"))
            .current_dir(temp.path())
            .args(["scan", "--recursive", "--exclude", "skip", "rules.yar"])
            .arg(target)
            .assert()
            .success()
            .stdout(predicate::str::contains("keep"))
            .stdout(predicate::str::contains("skip").not())
            .stderr("");
    }
}

#[cfg(unix)]
#[test]
fn exclusions_match_through_symlinked_parent_directories() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("real/work/keep/file.bin").write_str("test").unwrap();
    temp.child("real/work/skip/file.bin").write_str("test").unwrap();

    let real = temp.path().canonicalize().unwrap().join("real");
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let rules = temp.path().join("rules.yar");

    // Exclusion uses the symlinked spelling while `.` resolves to `real/work`.
    Command::new(cargo_bin!("yr"))
        .current_dir(link.join("work"))
        .args(["scan", "--recursive", "--exclude"])
        .arg(link.join("work/skip"))
        .arg(&rules)
        .arg(".")
        .assert()
        .success()
        .stdout(predicate::str::contains("keep"))
        .stdout(predicate::str::contains("skip").not());

    // Target uses the symlinked spelling while exclusion is relative to `real/work`.
    Command::new(cargo_bin!("yr"))
        .current_dir(real.join("work"))
        .args(["scan", "--recursive", "--exclude", "skip"])
        .arg(&rules)
        .arg(link.join("work"))
        .assert()
        .success()
        .stdout(predicate::str::contains("keep"))
        .stdout(predicate::str::contains("skip").not());

    // Missing intermediate directories under a symlinked ancestor still match.
    temp.child("real/work/paths.txt")
        .write_str("missing/sub/file.bin\nkeep/file.bin\n")
        .unwrap();
    Command::new(cargo_bin!("yr"))
        .current_dir(link.join("work"))
        .args(["scan", "--scan-list", "--exclude"])
        .arg(link.join("work/missing/sub"))
        .arg(&rules)
        .arg("paths.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("keep"))
        .stdout(predicate::str::contains("missing").not())
        .stderr("");

    // Target reached through a symlink with a missing intermediate dir inside
    // an excluded relative path also matches without trying to open it.
    Command::new(cargo_bin!("yr"))
        .current_dir(real.join("work"))
        .args(["scan", "--exclude", "skip"])
        .arg(&rules)
        .arg(link.join("work/skip/missing/file.bin"))
        .assert()
        .success()
        .stdout("")
        .stderr("");
}

#[cfg(windows)]
#[test]
fn exclusions_are_case_insensitive_on_windows() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("target/Keep/file.bin").write_str("test").unwrap();
    temp.child("target/OneDrive/file.bin").write_str("test").unwrap();

    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--recursive",
            "--exclude",
            r"TARGET\onedrive",
            "rules.yar",
            "target",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Keep"))
        .stdout(predicate::str::contains("OneDrive").not());
}

#[cfg(unix)]
#[test]
fn symlinks_to_files_are_followed() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str(r#"rule marker { strings: $a = "MARKER" condition: $a }"#)
        .unwrap();

    let real_sample = temp.child("real/sample.txt");
    real_sample.write_str("hello MARKER").unwrap();

    let real_large = temp.child("real/large.txt");
    real_large.write_str(&format!("MARKER{}", "x".repeat(200))).unwrap();

    let real_nested = temp.child("real/nested/hidden.txt");
    real_nested.write_str("nested MARKER").unwrap();

    let links_dir = temp.child("links");
    links_dir.create_dir_all().unwrap();
    links_dir.child("regular.txt").write_str("regular MARKER").unwrap();

    std::os::unix::fs::symlink(
        real_sample.path(),
        links_dir.child("sample.txt").path(),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        real_large.path(),
        links_dir.child("large.txt").path(),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        temp.child("real/nested").path(),
        links_dir.child("subdir_link").path(),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        temp.child("real/nonexistent.txt").path(),
        links_dir.child("dangling.txt").path(),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        links_dir.child("loop_b.txt").path(),
        links_dir.child("loop_a.txt").path(),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        links_dir.child("loop_a.txt").path(),
        links_dir.child("loop_b.txt").path(),
    )
    .unwrap();

    // Non-recursive scan follows file symlinks and silently skips directory,
    // dangling, and cyclic symlinks.
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "rules.yar", "links"])
        .assert()
        .success()
        .stdout(predicate::str::contains("links/sample.txt"))
        .stdout(predicate::str::contains("links/large.txt"))
        .stdout(predicate::str::contains("links/regular.txt"))
        .stdout(predicate::str::contains("hidden.txt").not())
        .stderr("");

    // Recursive scan also follows file symlinks without descending into
    // symlinked directories.
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "-r", "rules.yar", "links"])
        .assert()
        .success()
        .stdout(predicate::str::contains("links/sample.txt"))
        .stdout(predicate::str::contains("links/large.txt"))
        .stdout(predicate::str::contains("links/regular.txt"))
        .stdout(predicate::str::contains("hidden.txt").not())
        .stderr("");

    // `--skip-larger` checks the target file's size, not the symlink size.
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "--skip-larger", "50", "rules.yar", "links"])
        .assert()
        .success()
        .stdout(predicate::str::contains("links/sample.txt"))
        .stdout(predicate::str::contains("links/regular.txt"))
        .stdout(predicate::str::contains("links/large.txt").not())
        .stderr("");

    // Excluding a symlink path skips it without affecting sibling entries.
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "--exclude", "links/sample.txt", "rules.yar", "links"])
        .assert()
        .success()
        .stdout(predicate::str::contains("links/regular.txt"))
        .stdout(predicate::str::contains("links/large.txt"))
        .stdout(predicate::str::contains("links/sample.txt").not())
        .stderr("");
}

#[cfg(unix)]
#[test]
fn symlinked_rules_in_directory_are_compiled() {
    let temp = TempDir::new().unwrap();

    let real_rule = temp.child("real_rules/marker.yar");
    real_rule
        .write_str(r#"rule marker { strings: $a = "MARKER" condition: $a }"#)
        .unwrap();

    let sample = temp.child("sample.txt");
    sample.write_str("hello MARKER").unwrap();

    let rules_dir = temp.child("rules_dir");
    rules_dir.create_dir_all().unwrap();

    std::os::unix::fs::symlink(
        real_rule.path(),
        rules_dir.child("marker.yar").path(),
    )
    .unwrap();
    // Dangling rule symlink should be silently skipped rather than aborting.
    std::os::unix::fs::symlink(
        temp.child("real_rules/missing.yar").path(),
        rules_dir.child("dangling.yar").path(),
    )
    .unwrap();
    // Symlinked directory should not be descended into (otherwise `marker`
    // would be compiled twice and fail with a duplicate rule error).
    std::os::unix::fs::symlink(
        temp.child("real_rules").path(),
        rules_dir.child("sub_link").path(),
    )
    .unwrap();

    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "rules_dir", "sample.txt"])
        .assert()
        .success()
        .stdout(predicate::str::contains("marker sample.txt"))
        .stderr("");
}
