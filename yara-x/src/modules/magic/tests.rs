use pretty_assertions::assert_eq;

#[test]
fn get_filetype() {
    let data = b"Maestro\r";
    let expected = "RISC OS music file";
    assert_eq!(expected, crate::modules::magic::get_type(data))
}

#[test]
fn get_mimetype() {
    let expected = "text/plain";
    assert_eq!(
        expected,
        crate::modules::magic::get_mime_type(expected.as_bytes())
    )
}

#[test]
fn e2e_test() {
    let mut src = String::new();
    src.push_str(r#"import "magic""#);
    src.push_str(
        r#"rule t {condition: magic.type() == "RISC OS music file"}"#,
    );

    let rules = crate::compiler::Compiler::new()
        .add_source(src.as_str())
        .unwrap()
        .build()
        .unwrap();

    let data = b"Maestro\r";

    let mut scanner = crate::scanner::Scanner::new(&rules);
    let results = scanner.scan(data);

    assert_eq!(results.num_matching_rules(), 1);
}
