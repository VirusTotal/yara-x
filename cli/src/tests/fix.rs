use assert_cmd::{cargo_bin, Command};
use assert_fs::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;

#[test]
fn fix_warnings() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("test.yar");

    input_file.write_str(
        r#"
rule test {
  strings:
    $a = "dummy"
  condition:
    0 of them
}
"#).unwrap();

    // Run the "fix warnings" command.
    Command::new(cargo_bin!("yr"))
        .arg("fix")
        .arg("warnings")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains("1 out of 1 warnings fixed, 1 file(s) modified"))
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
"#);
}
