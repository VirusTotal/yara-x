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
    let rules = crate::compile(
        r#"
    import "magic"
    rule t { 
      condition: 
        magic.type() == "RISC OS music file" and 
        magic.mime_type() == "text/plain" and 
        // Call the functions twice, in order to excercise the caching
        // mechanism.
        magic.type() == "RISC OS music file" and 
        magic.mime_type() == "text/plain"
    }"#,
    )
    .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);
    let results = scanner.scan(b"Maestro\r").unwrap();

    assert_eq!(results.matching_rules().len(), 1);
}
