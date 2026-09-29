use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn ignore_invalid_rules() {
    let temp_dir = TempDir::new().unwrap();
    let yar_file = temp_dir.child("test.yar");
    let yarc_file = temp_dir.child("test.yarc");

    yar_file
        .write_str(
            r#"
            rule valid_rule {
                condition: true
            }
            rule invalid_rule {
                condition: undefined_var == 1
            }
            "#,
        )
        .unwrap();

    // Without --ignore-invalid-rules, compilation should fail early.
    Command::new(cargo_bin!("yr"))
        .arg("compile")
        .arg("-o")
        .arg(yarc_file.path())
        .arg(yar_file.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("1 error(s) found"));

    // With --ignore-invalid-rules, valid rules are compiled to destination file
    // and ignored rules are listed in the message, completing with success.
    Command::new(cargo_bin!("yr"))
        .arg("compile")
        .arg("--ignore-invalid-rules")
        .arg("-o")
        .arg(yarc_file.path())
        .arg(yar_file.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("the following rules were ignored:"))
        .stderr(predicate::str::contains("invalid_rule"));

    // Verify that the compiled rules file was created and contains the valid rule.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--compiled-rules")
        .arg(yarc_file.path())
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(predicate::str::contains("valid_rule"));
}
