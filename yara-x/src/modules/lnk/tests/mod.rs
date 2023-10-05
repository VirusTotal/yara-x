#[test]
fn lnk_module() {
    let rules = crate::compile(
        r#"
           import "lnk"
           rule test {
              condition: 
                lnk.is_lnk and
                lnk.creation_time == 1221251237 and
                lnk.access_time == 1221251237 and 
                lnk.write_time == 1221251237 and
                lnk.link_flags & lnk.HAS_LINK_TARGET_ID_LIST and
                lnk.link_target_id_list[0].size == 0x12 and
                lnk.link_target_id_list[0].data == "\x1fP\xe0O\xd0 \xea:i\x10\xa2\xd8\x08\x00+00\x9d" and
                lnk.local_base_path == "C:\\test\\a.txt" and
                lnk.volume_label == ""
           }
        "#,
    )
    .unwrap();

    let mut scanner = crate::Scanner::new(&rules);
    let data = include_bytes!("testdata/lnk-network");
    let scan_results = scanner.scan(data).unwrap();

    assert_eq!(scan_results.matching_rules().len(), 1);
}
