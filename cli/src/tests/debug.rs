use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;

#[test]
fn ast() {
    Command::new(cargo_bin!("yr"))
        .arg("debug")
        .arg("ast")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .success();
}

#[test]
fn cst() {
    Command::new(cargo_bin!("yr"))
        .arg("debug")
        .arg("cst")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .success();
}

#[test]
fn wasm() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("debug")
        .arg("wasm")
        .arg(input_file.path())
        .assert()
        .success();

    if !input_file.with_extension("wasm").exists() {
        panic!("`yr debug wasm` didn't create .wasm file")
    }
}

#[test]
fn atoms() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file
        .write_str(
            r#"
rule test {
    strings:
        $a = "ABCD"
        $b = { 01 02 03 04 }
        $c = { 30 ( 30 | 31 | 32 | 33 | 34 | 35 | 36 | 37 | 38 | 39 ) }

    condition:
        any of them
}
"#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("debug")
        .arg("atoms")
        .arg(input_file.path())
        .assert()
        .success()
        .stdout(
            "\
rule test
  $a
    41424344 (ABCD)
  $b
    01020304
  $c
    3030..3039 (00..09)
",
        );

    Command::new(cargo_bin!("yr"))
        .arg("debug")
        .arg("atoms")
        .arg("--json")
        .arg(input_file.path())
        .assert()
        .success()
        .stdout(
            "\
[
  {
    \"rule\": \"test\",
    \"pattern\": \"$a\",
    \"atoms\": [
      \"41424344\"
    ]
  },
  {
    \"rule\": \"test\",
    \"pattern\": \"$b\",
    \"atoms\": [
      \"01020304\"
    ]
  },
  {
    \"rule\": \"test\",
    \"pattern\": \"$c\",
    \"atoms\": [
      \"3030\",
      \"3031\",
      \"3032\",
      \"3033\",
      \"3034\",
      \"3035\",
      \"3036\",
      \"3037\",
      \"3038\",
      \"3039\"
    ]
  }
]
",
        );
}
