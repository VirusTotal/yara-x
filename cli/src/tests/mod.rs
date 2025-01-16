use std::fs;
use std::io::Write;

use assert_cmd::Command;

#[test]
fn test_cli() {
    let mut mint = goldenfile::Mint::new(".");

    for entry in globwalk::glob("src/tests/testdata/*.in").unwrap().flatten() {
        // Path to the .in file.
        let in_path = entry.into_path();
        let stderr_path = in_path.with_extension("stderr");
        let stdout_path = in_path.with_extension("stdout");

        let args = fs::read_to_string(&in_path).expect("unable to read");

        let mut cmd = Command::cargo_bin("yr").unwrap();

        cmd.args(args.split(" "));

        let mut stderr_file = mint.new_goldenfile(stderr_path).unwrap();
        let mut stdout_file = mint.new_goldenfile(stdout_path).unwrap();

        stderr_file
            .write_all(&*cmd.output().unwrap().stderr)
            .expect("unable to write .stderr file");

        stdout_file
            .write_all(&*cmd.output().unwrap().stdout)
            .expect("unable to write .stdout file");
    }
}
