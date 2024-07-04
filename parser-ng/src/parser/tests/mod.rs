use rayon::prelude::*;
use std::fs;
use std::io::BufWriter;
use std::io::Write;

use crate::parser::cst::CST;
use crate::Parser;

#[test]
fn cst() {
    let files: Vec<_> = globwalk::glob("src/parser/tests/testdata/*.in")
        .unwrap()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    files.into_par_iter().for_each(|path| {
        let mut mint = goldenfile::Mint::new(".");
        // Path to the .out file, replace the .in extension with .out.
        let output_path = path.with_extension("out");
        let output_file = mint.new_goldenfile(output_path).unwrap();

        let source = fs::read_to_string(path).unwrap();
        let cst = CST::from(Parser::new(source.as_bytes()));
        let mut w = BufWriter::new(output_file);
        write!(&mut w, "{:?}", cst).unwrap();
    });
}

#[test]
fn test() {
    let cst = CST::from(Parser::new(
        r#"
rule test : = {
  condition:
	  true
}
"#
        .as_bytes(),
    ));

    println!("{:#?}", cst);
}
