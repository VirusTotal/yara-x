use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn fix_warnings() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("test.yar");

    input_file
        .write_str(
            r#"
rule test {
  strings:
    $a = "dummy"
  condition:
    0 of them
}
"#,
        )
        .unwrap();

    // Run the "fix warnings" command.
    Command::new(cargo_bin!("yr"))
        .arg("fix")
        .arg("warnings")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains(
            "1 out of 1 warning(s) fixed, 1 file(s) modified",
        ))
        .success();

    // Check that the file was modified.
    input_file.assert(
        r#"
rule test {
  strings:
    $a = "dummy"
  condition:
    none of them
}
"#,
    );
}

#[test]
fn fix_warnings_nested_overlapping() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("nested.yar");

    // Both rules contain nested fixable warnings:
    // - `r1` has `math.in_range(pe.number_of_sections, 0, 1) == 1` where the
    //   outer `BooleanIntegerComparison` span starts before the inner
    //   `DeprecatedField` span (`start_outer < start_inner`).
    // - `r2` has `pe.is_dll() == 1 == 1` where the outer and inner
    //   `BooleanIntegerComparison` spans start at the exact same byte offset
    //   (`start_outer == start_inner`).
    input_file
        .write_str(
            r#"import "math"
import "pe"

rule r1 {
  condition:
    math.in_range(pe.number_of_sections, 0, 1) == 1
}

rule r2 {
  condition:
    pe.is_dll() == 1 == 1
}
"#,
        )
        .unwrap();

    // First pass applies the two outer `BooleanIntegerComparison` patches
    // without panicking or truncating the file.
    Command::new(cargo_bin!("yr"))
        .arg("fix")
        .arg("warnings")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains(
            "2 out of 4 warning(s) fixed, 1 file(s) modified",
        ))
        .success();

    input_file.assert(
        r#"import "math"
import "pe"

rule r1 {
  condition:
    math.in_range(pe.number_of_sections, 0, 1)
}

rule r2 {
  condition:
    pe.is_dll() == 1
}
"#,
    );

    // Second pass fixes the two remaining inner warnings.
    Command::new(cargo_bin!("yr"))
        .arg("fix")
        .arg("warnings")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains(
            "2 out of 2 warning(s) fixed, 1 file(s) modified",
        ))
        .success();

    input_file.assert(
        r#"import "math"
import "pe"

rule r1 {
  condition:
    math.in_range(pe.sections.len(), 0, 1)
}

rule r2 {
  condition:
    pe.is_dll()
}
"#,
    );
}

#[test]
fn fix_warnings_shared_include() {
    let temp_dir = TempDir::new().unwrap();
    let shared_file = temp_dir.child("shared.yar");
    let ns1_file = temp_dir.child("ns1.yar");
    let ns2_file = temp_dir.child("ns2.yar");

    shared_file
        .write_str(
            r#"
rule shared {
  strings:
    $a = "dummy"
  condition:
    0 of them
}
"#,
        )
        .unwrap();

    ns1_file.write_str("include \"shared.yar\"\n").unwrap();
    ns2_file.write_str("include \"shared.yar\"\n").unwrap();

    let ns1_arg = format!("ns1:{}", ns1_file.path().display());
    let ns2_arg = format!("ns2:{}", ns2_file.path().display());

    Command::new(cargo_bin!("yr"))
        .arg("fix")
        .arg("warnings")
        .arg("--include-dir")
        .arg(temp_dir.path())
        .arg(ns1_arg)
        .arg(ns2_arg)
        .assert()
        .stdout(predicate::str::contains(
            "2 out of 2 warning(s) fixed, 1 file(s) modified",
        ))
        .success();

    shared_file.assert(
        r#"
rule shared {
  strings:
    $a = "dummy"
  condition:
    none of them
}
"#,
    );
}
