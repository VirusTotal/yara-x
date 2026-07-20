use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
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

#[test]
fn fmt_directory() {
    let temp_dir = TempDir::new().unwrap();
    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();

    let file1 = temp_dir.child("rule1.yar");
    let file2 = subdir.child("rule2.yar");

    file1.write_str("rule test1 { condition: true }").unwrap();
    file2.write_str("rule test2 { condition: true }").unwrap();

    // By default without -r/--recursive, only the top-level directory files are formatted.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .code(1); // file1 should be modified.

    // So now file1 is formatted, but file2 should still be unformatted.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .code(0); // Top-level files are already formatted, so no changes.

    // With -r/--recursive, the subdirectories are also processed, so file2 will be formatted.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("-r")
        .arg(temp_dir.path())
        .assert()
        .code(1); // file2 in subdir should be modified.

    // Subsequent format runs should find no modified files.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("-r")
        .arg(temp_dir.path())
        .assert()
        .code(0);
}
