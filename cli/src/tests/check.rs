use assert_cmd::Command;
use assert_fs::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;

#[test]
fn metadata() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.child("config.toml");

    config_file
        .write_str(
            r#"
            [check.metadata]
            string = { type = "string"  }
            bool = { type = "bool" }
            int = { type = "integer" }
            float = { type = "float" }
            md5 = { type = "md5" }
            sha1 = { type = "sha1" }
            sha256 = { type = "sha256" }
            required = { type = "string", required = true }
            optional = { type = "string" }
            "#,
        )
        .unwrap();

    Command::cargo_bin("yr")
        .unwrap()
        .arg("--config")
        .arg(config_file.path())
        .arg("check")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .success()
        .stdout("[ WARN ] src/tests/testdata/foo.yar\n")
        .stderr(
            r#"warning[missing_metadata]: required metadata is missing
 --> src/tests/testdata/foo.yar:1:6
  |
1 | rule foo : bar baz {
  |      --- required metadata `required` not found
  |
warning[text_as_hex]: hex pattern could be written as text literal
 --> src/tests/testdata/foo.yar:9:5
  |
9 |     $foo_hex = { 66 6f 6f }
  |     ---------------------
  |     |
  |     this pattern can be written as a text literal
  |     help: replace with "foo"
  |
"#,
        );

    let yar_file = temp_dir.child("test.yar");

    yar_file
        .write_str(
            r#"rule test {
              meta:
                md5 = "not a md5"
                sha1 = "not a sha1"
                sha256 = "not a sha256"
                bool = 1
                int = 3.14
                float = "not a float"
                string = true
              condition:
                true
            }"#,
        )
        .unwrap();

    Command::cargo_bin("yr")
        .unwrap()
        .arg("--config")
        .arg(config_file.path())
        .arg("check")
        .arg(yar_file.path())
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "warning[invalid_metadata]: metadata `md5` is not valid",
        ))
        .stderr(predicate::str::contains(
            "warning[invalid_metadata]: metadata `sha1` is not valid",
        ))
        .stderr(predicate::str::contains(
            "warning[invalid_metadata]: metadata `sha256` is not valid",
        ))
        .stderr(predicate::str::contains(
            "warning[invalid_metadata]: metadata `bool` is not valid",
        ))
        .stderr(predicate::str::contains(
            "warning[invalid_metadata]: metadata `int` is not valid",
        ))
        .stderr(predicate::str::contains(
            "warning[invalid_metadata]: metadata `float` is not valid",
        ))
        .stderr(predicate::str::contains(
            "warning[invalid_metadata]: metadata `string` is not valid",
        ));
}

#[test]
fn check_rule_name_warning() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.child("config.toml");

    config_file
        .write_str(
            r#"
            [check.rule_name]
            regexp = "APT_.+"
            "#,
        )
        .unwrap();

    Command::cargo_bin("yr")
        .unwrap()
        .arg("--config")
        .arg(config_file.path())
        .arg("check")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .success()
        .stdout("[ WARN ] src/tests/testdata/foo.yar\n");
}

#[test]
fn check_rule_name_error() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.child("config.toml");

    config_file
        .write_str(
            r#"
            [check.rule_name]
            regexp = "APT_.+"
            error = true
            "#,
        )
        .unwrap();

    Command::cargo_bin("yr")
        .unwrap()
        .arg("--config")
        .arg(config_file.path())
        .arg("check")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .success()
        .stdout(
            r#"[ FAIL ] src/tests/testdata/foo.yar
error[E039]: rule name does not match regex `APT_.+`
 --> src/tests/testdata/foo.yar:1:6
  |
1 | rule foo : bar baz {
  |      ^^^ this rule name does not match regex `APT_.+`
  |
"#,
        );
}

#[test]
fn config_error() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.child("config.toml");

    config_file
        .write_str(
            r#"
    [check.foo]
    author = { type = "string"  }
    "#,
        )
        .unwrap();

    Command::cargo_bin("yr")
        .unwrap()
        .arg("--config")
        .arg(config_file.path())
        .arg("check")
        .arg("src/tests/testdata/foo.yar")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains(
                r#"error: unknown field: found `foo`, expected `one of `metadata`, `rule_name`, `tags`` for key "default.check.foo""#,
            )
        );
}
