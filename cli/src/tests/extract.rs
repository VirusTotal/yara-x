use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use std::fs;

#[test]
fn test_extract_command() {
    let temp = TempDir::new().unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("extract")
        .arg(
            "../lib/src/modules/zip/tests/testdata/stored_and_deflated.in.zip",
        )
        .arg(temp.path())
        .assert()
        .success();

    let entries: Vec<_> =
        fs::read_dir(temp.path()).unwrap().filter_map(|e| e.ok()).collect();

    assert!(!entries.is_empty(), "expected extracted files in output dir");
}
