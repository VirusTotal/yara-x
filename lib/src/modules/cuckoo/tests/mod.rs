use std::fs;
use std::io::Write;

#[test]
fn cuckoo() {
    // Create goldenfile mint.
    let files: Vec<_> =
        globwalk::glob("src/modules/cuckoo/tests/testdata/*.json")
            .unwrap()
            .flatten()
            .map(|entry| entry.into_path())
            .collect();

    files.iter().for_each(|path| {
        let mut mint = goldenfile::Mint::new(".");

        let yar_path = path.with_extension("yar");
        let out_path = path.with_extension("out");

        let cuckoo_report = fs::read_to_string(path).unwrap();
        let rule = fs::read_to_string(yar_path).unwrap();

        let rules = crate::compile(rule.as_str()).unwrap();

        let options = crate::ScanOptions::default()
            .set_module_metadata("cuckoo", cuckoo_report.as_bytes());

        let mut scanner = crate::scanner::Scanner::new(&rules);

        let scan_results = scanner
            .scan_with_options(&[], options)
            .expect("scan should not fail");

        let mut output_file = mint.new_goldenfile(out_path).unwrap();

        writeln!(&mut output_file, "MATCHING RULES").unwrap();
        writeln!(&mut output_file, "--------------\n").unwrap();

        for r in scan_results.matching_rules() {
            writeln!(&mut output_file, "{}", r.identifier()).unwrap();
        }

        writeln!(&mut output_file, "\nNON-MATCHING RULES").unwrap();
        writeln!(&mut output_file, "------------------\n").unwrap();

        for r in scan_results.non_matching_rules() {
            writeln!(&mut output_file, "{}", r.identifier()).unwrap();
        }
    });
}
