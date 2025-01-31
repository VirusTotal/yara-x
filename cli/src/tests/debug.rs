use assert_cmd::Command;
use assert_fs::prelude::*;
use assert_fs::TempDir;

#[test]
fn ast() {
    Command::cargo_bin("yr")
        .unwrap()
        .arg("debug")
        .arg("ast")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .success();
}

#[test]
fn cst() {
    Command::cargo_bin("yr")
        .unwrap()
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

    Command::cargo_bin("yr")
        .unwrap()
        .arg("debug")
        .arg("wasm")
        .arg(input_file.path())
        .assert()
        .success();

    if !input_file.with_extension("wasm").exists() {
        panic!("`yr debug wasm` didn't create .wasm file")
    }
}
