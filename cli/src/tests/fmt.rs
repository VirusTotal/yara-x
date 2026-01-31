use assert_cmd::{cargo_bin, Command};
use assert_fs::prelude::*;
use assert_fs::TempDir;

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
fn fmt_directory() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.child("rule1.yar");
    let file2 = temp_dir.child("rule2.yar");

    file1.write_str("rule test1 { condition: true }").unwrap();
    file2.write_str("rule test2 { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .code(1); // Files were modified

    // Verify files are now formatted
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(temp_dir.path())
        .assert()
        .code(0); // No changes needed
}

#[test]
fn fmt_directory_recursive() {
    let temp_dir = TempDir::new().unwrap();
    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();
    let file = subdir.child("rule.yar");
    file.write_str("rule test { condition: true }").unwrap();

    // Without --recursive, subdir file should not be formatted
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(temp_dir.path())
        .assert()
        .code(0);

    // With --recursive, subdir file should be found and needs formatting
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg("--recursive")
        .arg(temp_dir.path())
        .assert()
        .code(1);
}

#[test]
fn fmt_directory_filter() {
    let temp_dir = TempDir::new().unwrap();
    let yar_file = temp_dir.child("rule.yar");
    let txt_file = temp_dir.child("rule.txt");

    yar_file.write_str("rule test1 { condition: true }").unwrap();
    txt_file.write_str("rule test2 { condition: true }").unwrap();

    // With default filters, only .yar file should be formatted
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .code(1);

    // .txt file should still need formatting (was not touched)
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--filter")
        .arg("**/*.txt")
        .arg(temp_dir.path())
        .assert()
        .code(1);
}

#[test]
fn fmt_directory_threads() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.child("rule1.yar");
    let file2 = temp_dir.child("rule2.yar");

    file1.write_str("rule test1 { condition: true }").unwrap();
    file2.write_str("rule test2 { condition: true }").unwrap();

    // Test that --threads option is accepted and works
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--threads")
        .arg("2")
        .arg(temp_dir.path())
        .assert()
        .code(1); // Files were modified

    // Verify files are now formatted
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(temp_dir.path())
        .assert()
        .code(0);
}

#[test]
fn fmt_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.child("rule1.yar");
    let file2 = temp_dir.child("rule2.yar");

    file1.write_str("rule test1 { condition: true }").unwrap();
    file2.write_str("rule test2 { condition: true }").unwrap();

    // Format multiple files (original backward-compatible behavior)
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(file1.path())
        .arg(file2.path())
        .assert()
        .code(1);

    // Verify both files are now formatted
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(file1.path())
        .arg(file2.path())
        .assert()
        .code(0);
}

#[test]
fn fmt_mixed_files_and_directories() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.child("rule1.yar");
    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();
    let file2 = subdir.child("rule2.yar");

    file1.write_str("rule test1 { condition: true }").unwrap();
    file2.write_str("rule test2 { condition: true }").unwrap();

    // Format a file and a directory together
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(file1.path())
        .arg(subdir.path())
        .assert()
        .code(1);

    // Verify both are now formatted
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(file1.path())
        .arg(subdir.path())
        .assert()
        .code(0);
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
