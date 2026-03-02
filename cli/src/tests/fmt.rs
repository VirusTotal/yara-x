use assert_cmd::{cargo_bin, Command};
use assert_fs::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;

#[test]
fn fmt() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .code(1); // Exit code 1 indicates that the file was modified.

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .code(0); // Second time that we format the same file, no expected changes.
}

#[test]
fn fmt_check_shows_filenames() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(input_file.path())
        .assert()
        .stderr(predicate::str::contains("rule.yar"))
        .code(1);
}

#[test]
fn utf8_error() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_binary(&[0xff, 0xff]).unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .stderr("error: invalid UTF-8 at [0..1]\n")
        .code(1);
}
