use assert_cmd::{cargo_bin, Command};
use assert_fs::prelude::*;
use assert_fs::TempDir;

#[test]
fn basic_rule() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule a { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
}

"#,
        )
        .success();
}

#[test]
fn duplicate_rule() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: true } rule a { condition: true }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .failure()
        .code(1)
        .stderr("error: Duplicate rule \"a\" found\n");
}

#[test]
fn rule_does_not_exist() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule a { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("does_not_exist")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
}

"#,
        )
        .success();
}

#[test]
fn unknown_identifier() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule a { condition: x }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
}

"#,
        )
        .success();
}

#[test]
fn module_identifier() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule a { condition: pe.is_dll() }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  a -> pe;
}

"#,
        )
        .success();
}

#[test]
fn dependency_and_module() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str(
            r#"rule a { condition: pe.is_dll() }
    rule b { condition: a } "#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("b")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  b [fillcolor=paleturquoise, style="filled"];
  a [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  a -> pe;
  b -> a;
}

"#,
        )
        .success();
}

#[test]
fn for_in_variable_module_name() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: for 1 pe in (1): (pe > 0) }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
}

"#,
        )
        .success();
}

#[test]
fn nested_variables() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str(
            r#"rule a {
        condition:
          for 1 pe in (1): (
            for 1 elf in (2): (
              pe + elf > 0
            )
          )
        }"#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
}

"#,
        )
        .success();
}

#[test]
fn with_variables() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str(
            r#"rule a {
        condition:
          with pe = 1, elf = 2: (
            pe + elf > 0
          )
        }"#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
}

"#,
        )
        .success();
}

#[test]
fn with_variables_and_unknown() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str(
            r#"rule a {
        condition:
          with pe = 1, elf = 2: (
            pe + elf + x > 0
          )
        }"#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
}

"#,
        )
        .success();
}

#[test]
fn with_variables_and_previous_rule() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: true } rule b { condition: with a = 1: (a > 0) }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("b")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  b [fillcolor=paleturquoise, style="filled"];
}

"#,
        )
        .success();
}
#[test]
fn with_module_in_expression() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str(
            "rule a { condition: with a = pe: ( a.number_of_signatures > 0) }",
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  a -> pe;
}

"#,
        )
        .success();
}

#[test]
fn for_in_variable_module_name_other_module() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: for 1 pe in (1): (pe + elf.number_of_sections > 0) }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  elf [fillcolor=palegreen, style="filled"];
  a -> elf;
}

"#,
        )
        .success();
}

#[test]
fn field_access() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: pe.number_of_sections > 0 }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  a -> pe;
}

"#,
        )
        .success();
}

#[test]
fn field_access_expression() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: (pe).number_of_signatures > 0 }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  a -> pe;
}

"#,
        )
        .success();
}

#[test]
fn field_access_with_unknown_lookup() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: pe.signatures[i].issuer == \"foo\" }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  a -> pe;
}

"#,
        )
        .success();
}

#[test]
fn field_access_with_variable() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: for any i in (1..pe.number_of_signatures): (pe.signatures[i].issuer == \"foo\") }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  a -> pe;
}

"#,
        )
        .success();
}

#[test]
fn field_access_hidding_ident() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str(
            r#"
        import "pe"

        rule a {
        condition:
          true
        }

        rule b {
        condition:
            pe.a
        }
        "#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-r")
        .arg("b")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  b [fillcolor=paleturquoise, style="filled"];
  pe [fillcolor=palegreen, style="filled"];
  b -> pe;
}

"#,
        )
        .success();
}

#[test]
fn reverse_deps() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str("rule a { condition: true } rule b { condition: a }")
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("deps")
        .arg("-R")
        .arg("-r")
        .arg("a")
        .arg(input_file.path())
        .assert()
        .stdout(
            r#"digraph {
  a [fillcolor=paleturquoise, style="filled"];
  b [fillcolor=paleturquoise, style="filled"];
  b -> a;
}

"#,
        )
        .success();
}
