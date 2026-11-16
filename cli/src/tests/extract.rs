use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use predicates::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_extract_command() {
    let temp = TempDir::new().unwrap();

    let output = Command::new(cargo_bin!("yr"))
        .arg("extract")
        .arg(
            "../lib/src/modules/zip/tests/testdata/stored_and_deflated.in.zip",
        )
        .arg(temp.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let printed_paths: HashSet<PathBuf> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(PathBuf::from)
        .collect();

    let entries: HashSet<PathBuf> = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();

    assert!(!entries.is_empty(), "expected extracted files in output dir");
    assert_eq!(printed_paths, entries);
}

#[test]
fn test_extract_command_zip_max_extracted_files() {
    let temp = TempDir::new().unwrap();

    let output = Command::new(cargo_bin!("yr"))
        .arg("extract")
        .arg("--zip-max-extracted-files")
        .arg("1")
        .arg(
            "../lib/src/modules/zip/tests/testdata/stored_and_deflated.in.zip",
        )
        .arg(temp.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let entries: Vec<_> =
        fs::read_dir(temp.path()).unwrap().filter_map(|e| e.ok()).collect();

    assert_eq!(entries.len(), 1);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("{}\n", entries[0].path().display()),
    );
}

fn decode_zipped_ihex(zip_path: &str) -> Vec<u8> {
    let zip_bytes = fs::read(zip_path).unwrap();
    let mut ihex_text = String::new();
    let _ = yara_x::Extractor::new().extract(&zip_bytes, |_m, _p, bytes| {
        ihex_text = String::from_utf8(bytes.to_vec()).unwrap();
        std::ops::ControlFlow::Break(())
    });

    let mut out = Vec::new();
    for line in ihex_text.lines() {
        let Some(rest) = line.strip_prefix(':') else {
            continue;
        };
        if rest.len() < 8 {
            continue;
        }
        let byte_count = usize::from_str_radix(&rest[0..2], 16).unwrap();
        let record_type = u8::from_str_radix(&rest[6..8], 16).unwrap();
        if record_type == 0x00 {
            let data_hex = &rest[8..8 + byte_count * 2];
            for i in 0..byte_count {
                out.push(
                    u8::from_str_radix(&data_hex[i * 2..i * 2 + 2], 16)
                        .unwrap(),
                );
            }
        }
    }
    out
}

#[test]
fn test_extract_command_vba() {
    let temp = TempDir::new().unwrap();
    let input_dir = TempDir::new().unwrap();
    let doc_path = input_dir.path().join("macro.doc");
    fs::write(
        &doc_path,
        decode_zipped_ihex(
            "../lib/src/modules/vba/tests/testdata/7972ee9287cfcce00dc23098dce4ea8ed32e2dff629342e5364a48cd9c01bcb8.in.zip",
        ),
    )
    .unwrap();

    let output = Command::new(cargo_bin!("yr"))
        .arg("extract")
        .arg(&doc_path)
        .arg(temp.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let printed_lines: Vec<_> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(PathBuf::from)
        .collect();
    assert_eq!(printed_lines.len(), 2);
    assert!(printed_lines.contains(&temp.path().join("ThisDocument")));

    let entries: Vec<_> =
        fs::read_dir(temp.path()).unwrap().filter_map(|e| e.ok()).collect();

    assert_eq!(entries.len(), 2);
    let this_doc =
        fs::read_to_string(temp.path().join("ThisDocument")).unwrap();
    assert!(this_doc.contains("Attribute VB_Name = \"ThisDocument\""));
}

#[test]
fn test_extract_command_vba_max_extracted_files() {
    let temp = TempDir::new().unwrap();
    let input_dir = TempDir::new().unwrap();
    let doc_path = input_dir.path().join("macro.doc");
    fs::write(
        &doc_path,
        decode_zipped_ihex(
            "../lib/src/modules/vba/tests/testdata/7972ee9287cfcce00dc23098dce4ea8ed32e2dff629342e5364a48cd9c01bcb8.in.zip",
        ),
    )
    .unwrap();

    let output = Command::new(cargo_bin!("yr"))
        .arg("extract")
        .arg("--vba-max-extracted-files")
        .arg("1")
        .arg(&doc_path)
        .arg(temp.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let entries: Vec<_> =
        fs::read_dir(temp.path()).unwrap().filter_map(|e| e.ok()).collect();

    assert_eq!(entries.len(), 1);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("{}\n", entries[0].path().display()),
    );
}

#[test]
fn test_extract_command_nested_companion_dir() {
    let temp = TempDir::new().unwrap();
    let input_dir = TempDir::new().unwrap();
    let docm_path = input_dir.path().join("macro.docm");
    fs::write(
        &docm_path,
        decode_zipped_ihex(
            "../lib/src/modules/vba/tests/testdata/643d1e3b68c1e31aef5779eb28ac3b0aaa284c91c47c26cfc2dbb3bc7f569103.in.zip",
        ),
    )
    .unwrap();

    let expected_vba_bin = format!(
        "{}\n",
        temp.path().join("word").join("vbaProject.bin").display()
    );
    let expected_this_doc = format!(
        "{}\n",
        temp.path()
            .join("word")
            .join("vbaProject.bin_")
            .join("ThisDocument")
            .display()
    );

    // Run twice into the same output directory to verify both initial creation
    // of `<name>_/` and idempotent re-extraction.
    for _ in 0..2 {
        Command::new(cargo_bin!("yr"))
            .arg("extract")
            .arg("--max-depth")
            .arg("2")
            .arg(&docm_path)
            .arg(temp.path())
            .assert()
            .success()
            .stdout(predicate::str::contains(&expected_vba_bin))
            .stdout(predicate::str::contains(&expected_this_doc));
    }

    assert!(temp.path().join("word/vbaProject.bin").is_file());

    let this_doc = fs::read_to_string(
        temp.path().join("word/vbaProject.bin_/ThisDocument"),
    )
    .unwrap();
    assert!(this_doc.contains("MsgBox \"Hello, world!\""));
}
