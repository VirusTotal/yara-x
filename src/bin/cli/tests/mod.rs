use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_check_file_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("yr")?;

    cmd.arg("check").arg("test/file/doesnt/exist");
    cmd.assert().failure().stderr(predicate::str::contains(
        "can not read `test/file/doesnt/exist`",
    ));

    Ok(())
}

#[test]
fn test_help() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("yr")?;

    let prog = if cfg!(target_os = "windows") { "yr.exe" } else { "yr" };

    cmd.arg("help");
    cmd.assert().success().stdout(format!(
        r#"An experimental implementation of YARA in Rust

Victor M. Alvarez <vmalvarez@virustotal.com>

Usage:
    {} [COMMAND]

Commands:
  scan   Scans a file with some YARA
  ast    Print Abstract Syntax Tree (AST) for a YARA source file
  wasm   Emits a .wasm file with the code generated for a YARA source file
  check  Check if YARA source files are syntactically correct
  fmt    Format YARA source files
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
"#,
        prog
    ));

    Ok(())
}
