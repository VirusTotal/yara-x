use assert_cmd::{cargo::cargo_bin, Command};
use assert_fs::prelude::*;
use assert_fs::TempDir;

#[test]
fn ast() {
    Command::new(cargo_bin!("yr"))
        .unwrap()
        .arg("debug")
        .arg("ast")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .success();
}

#[test]
fn cst() {
    Command::new(cargo_bin!("yr"))
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

    Command::new(cargo_bin!("yr"))
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
