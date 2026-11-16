use std::ffi::OsString;

use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn excludes_literal_files_and_directory_trees() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    for path in [
        "target/keep.bin",
        "target/skip.bin",
        "target/skip.bin.more",
        "target/skip[1]/deep/excluded.bin",
        "target/skip1/keep-too.bin",
    ] {
        temp.child(path).write_str("test").unwrap();
    }
    let mut exclude_arg = OsString::from("--exclude=");
    exclude_arg
        .push(temp.path().canonicalize().unwrap().join("target/skip[1]"));
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "--recursive", "--threads=1"])
        .args(["--exclude", "target/skip.bin"])
        .arg(exclude_arg)
        .args(["rules.yar", "./target"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keep.bin"))
        .stdout(predicate::str::contains("keep-too.bin"))
        .stdout(predicate::str::contains("excluded.bin").not())
        .stdout(predicate::str::contains("skip.bin.more"))
        .stdout(predicate::str::contains("skip.bin\n").not());
}

#[test]
fn excluded_paths_are_skipped_before_metadata_in_scan_lists() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("keep.bin").write_str("test").unwrap();
    for stdin in [false, true] {
        temp.child("paths.txt")
            .write_str("missing/deep/file.bin\nkeep.bin\n")
            .unwrap();
        let mut cmd = Command::new(cargo_bin!("yr"));
        cmd.current_dir(temp.path()).args([
            "scan",
            "--scan-list",
            "--exclude",
            "./unused/../missing",
            "rules.yar",
            if stdin { "-" } else { "paths.txt" },
        ]);
        if stdin {
            cmd.write_stdin("missing/deep/file.bin\nkeep.bin\n");
        }
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("keep.bin"))
            .stdout(predicate::str::contains("missing").not())
            .stderr("");
    }
}

#[test]
fn excluded_explicit_targets_including_missing_paths_are_not_opened() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();
    for target in ["skip/file.bin", "skip/missing.bin", "skip"] {
        Command::new(cargo_bin!("yr"))
            .current_dir(temp.path())
            .args(["scan", "--exclude", "skip", "rules.yar", target])
            .assert()
            .success()
            .stdout("")
            .stderr("");
    }
}

#[cfg(unix)]
#[test]
fn excluded_directories_are_not_descended_into() {
    use std::fs::{Permissions, set_permissions};
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("target/keep.bin").write_str("test").unwrap();
    temp.child("target/private/nested/file.bin").write_str("test").unwrap();
    let private = temp.path().join("target/private");
    set_permissions(&private, Permissions::from_mode(0)).unwrap();
    let result = Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--recursive",
            "--exclude",
            "target/private",
            "rules.yar",
            "target",
        ])
        .output();
    set_permissions(&private, Permissions::from_mode(0o700)).unwrap();
    let result = result.unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty(), "{:?}", result.stderr);
    assert!(String::from_utf8_lossy(&result.stdout).contains("keep.bin"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("file.bin"));
}

#[cfg(target_os = "linux")]
#[test]
fn excludes_non_utf8_directory_names() {
    use std::os::unix::ffi::OsStringExt;
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("target/keep.bin").write_str("test").unwrap();
    let excluded = temp
        .path()
        .join("target")
        .join(OsString::from_vec(b"skip-\xff".to_vec()));
    std::fs::create_dir(&excluded).unwrap();
    std::fs::write(excluded.join("excluded.bin"), b"test").unwrap();
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args(["scan", "--recursive", "--exclude"])
        .arg(&excluded)
        .args(["rules.yar", "target"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keep.bin"))
        .stdout(predicate::str::contains("excluded.bin").not())
        .stderr("");
}

#[test]
fn empty_exclusion_is_rejected_before_compiling_rules() {
    // The rules path doesn't exist: the error must be about the empty
    // exclusion, which is checked before the rules are compiled.
    Command::new(cargo_bin!("yr"))
        .args([
            "scan",
            "--exclude",
            "",
            "src/tests/testdata/missing.yar",
            "src/tests/testdata/dummy.file",
        ])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("--exclude"))
        .stderr(predicate::str::contains("missing.yar").not());
}

#[test]
fn invalid_scan_list_lines_do_not_abort_the_scan() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();
    temp.child("keep.bin").write_str("test").unwrap();
    temp.child("paths.txt")
        .write_str("\nskip/file.bin\n\nkeep.bin\n")
        .unwrap();
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--scan-list",
            "--exclude",
            "skip",
            "rules.yar",
            "paths.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("keep.bin"))
        .stdout(predicate::str::contains("skip").not());
}

#[test]
fn recursive_scan_of_excluded_file_target_is_not_an_error() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--recursive",
            "--exclude",
            "skip",
            "rules.yar",
            "skip/file.bin",
        ])
        .assert()
        .success()
        .stdout("")
        .stderr("");
}

#[test]
fn equivalent_spellings_of_the_current_directory_are_walked() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("keep/file.bin").write_str("test").unwrap();
    temp.child("skip/file.bin").write_str("test").unwrap();
    let dot_slash = if cfg!(windows) { r".\\" } else { ".//" };
    let dot_dot = if cfg!(windows) { r".\." } else { "./." };
    for target in [dot_slash, dot_dot] {
        Command::new(cargo_bin!("yr"))
            .current_dir(temp.path())
            .args(["scan", "--recursive", "--exclude", "skip", "rules.yar"])
            .arg(target)
            .assert()
            .success()
            .stdout(predicate::str::contains("keep"))
            .stdout(predicate::str::contains("skip").not())
            .stderr("");
    }
}

/// An exclusion written through a symbolic link matches entries reached
/// through the resolved path, and the other way around.
#[cfg(unix)]
#[test]
fn exclusions_match_through_symlinked_parent_directories() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("real/work/keep/file.bin").write_str("test").unwrap();
    temp.child("real/work/skip/file.bin").write_str("test").unwrap();
    let real = temp.path().canonicalize().unwrap().join("real");
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let rules = temp.path().join("rules.yar");

    // The working directory is entered through the link, but the process
    // sees the resolved path; the exclusion uses the link spelling.
    Command::new(cargo_bin!("yr"))
        .current_dir(link.join("work"))
        .args(["scan", "--recursive", "--exclude"])
        .arg(link.join("work/skip"))
        .arg(&rules)
        .arg(".")
        .assert()
        .success()
        .stdout(predicate::str::contains("keep"))
        .stdout(predicate::str::contains("skip").not());

    // The target uses the link spelling, the exclusion is relative to the
    // resolved working directory.
    Command::new(cargo_bin!("yr"))
        .current_dir(real.join("work"))
        .args(["scan", "--recursive", "--exclude", "skip"])
        .arg(&rules)
        .arg(link.join("work"))
        .assert()
        .success()
        .stdout(predicate::str::contains("keep"))
        .stdout(predicate::str::contains("skip").not());
}

#[cfg(windows)]
#[test]
fn exclusions_are_case_insensitive_on_windows() {
    let temp = TempDir::new().unwrap();
    temp.child("rules.yar")
        .write_str("rule test { condition: filesize > 0 }")
        .unwrap();
    temp.child("target/Keep/file.bin").write_str("test").unwrap();
    temp.child("target/OneDrive/file.bin").write_str("test").unwrap();
    Command::new(cargo_bin!("yr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--recursive",
            "--exclude",
            r"TARGET\onedrive",
            "rules.yar",
            "target",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Keep"))
        .stdout(predicate::str::contains("OneDrive").not());
}
