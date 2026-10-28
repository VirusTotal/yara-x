use pretty_assertions::assert_eq;

#[test]
fn get_filetype() {
    assert!(
        crate::modules::magic::get_type(b"Maestro\r")
            .unwrap()
            .starts_with("RISC OS music file")
    )
}

#[test]
fn get_mimetype() {
    assert_eq!(
        "text/plain",
        crate::modules::magic::get_mime_type(b"foobar").unwrap()
    )
}

#[test]
fn e2e_test() {
    let rules = crate::compile(
        r#"
    import "magic"
    rule t { 
      condition: 
        magic.type() startswith "RISC OS music file" and 
        magic.mime_type() == "text/plain" and 
        // Call the functions twice, in order to exercise the caching
        // mechanism.
        magic.type() startswith "RISC OS music file" and 
        magic.mime_type() == "text/plain"
    }"#,
    )
    .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);
    let results = scanner.scan(b"Maestro\r").unwrap();

    assert_eq!(results.matching_rules().len(), 1);
}

// Test case that covers the following issue:
// https://github.com/robo9k/rust-magic/issues/358
#[test]
fn magic_crash() {
    let rules = crate::compile(
        r#"
    import "magic"
    rule t {
      condition:
        magic.mime_type() == "foo"
    }"#,
    )
    .unwrap();

    let mut scanner = crate::scanner::Scanner::new(&rules);
    let results = scanner
        .scan(&[0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x2a, 0x08])
        .unwrap();

    assert_eq!(results.matching_rules().len(), 0);
}
