use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_false;
use crate::tests::rule_true;
use crate::tests::test_rule;

// Test files in `testdata` are named after the SHA-256 of their content.

/// Minimal DOCX: `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`
/// (deflated) and `word/media/image1.png` (stored).
const MINIMAL_DOCX: &str =
    "75e336586bf3df0d4ef0506d1d323b9f3a85bdbecf86b1fc1f9bb9e37f843e8a";

/// ZIP archive (not OOXML) created on FAT, with a file comment.
const PLAIN_ZIP_WITH_COMMENT: &str =
    "b8f07c13d544b3477c6b4b80c90a13624186298e843e5bb3ed07bb037de49101";

/// ZIP archive declaring 5 entries but containing 3: one with an empty
/// name, one with a non-UTF-8 name and one with an unknown compression
/// method and host OS.
const EDGE_CASES: &str =
    "f96f0decf5ad2178e995a1b63a623008c06c2e7aa46458bf0cdacc19ddf9f668";

/// ZIP archive whose end of central directory record declares no entries.
const NO_ENTRIES: &str =
    "437acdb7788e7a730b6049899a2f8e860f29e8418cedd001348e5663aac0e072";

/// Plain text file.
const NOT_ZIP: &str =
    "c371cf6873aa8ab54e1b3bfa0275a1d0c36ee271f61ce07c2c22a4f5038d0ae9";

fn testdata(sha256: &str) -> Vec<u8> {
    create_binary_from_zipped_ihex(format!(
        "src/modules/ooxml/tests/testdata/{sha256}.in.zip"
    ))
}

#[test]
fn ooxml_document() {
    let docx = testdata(MINIMAL_DOCX);

    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            ooxml.is_ooxml
            and ooxml.number_of_total_entries == 4
            and ooxml.number_of_on_disk_entries == ooxml.number_of_total_entries
            and ooxml.entries[0].name_string == "[Content_Types].xml"
            and ooxml.entries[0].name_length == 19
            and ooxml.zip_comment_len == 0
            and not defined ooxml.zip_comment_str
        }
        "#,
        &docx
    );

    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            for any e in ooxml.entries : (
              e.name_string == "word/media/image1.png"
              and e.compression_method_name == "Store"
              and e.compressed_size == e.uncompressed_size
            )
            and for any e in ooxml.entries : (
              e.name_string == "word/document.xml"
              and e.compression_method_value == 8
              and e.compression_method_name == "Deflate"
              and e.uncompressed_size > e.compressed_size
            )
        }
        "#,
        &docx
    );

    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            for all e in ooxml.entries : (
              e.os_name == "Unix"
              and e.spec_version == e.version_made_by & 0xff
              and e.mod_date_raw == 0x5a22
            )
        }
        "#,
        &docx
    );
}

#[test]
fn plain_zip() {
    let zip = testdata(PLAIN_ZIP_WITH_COMMENT);

    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            not ooxml.is_ooxml
            and ooxml.number_of_total_entries == 2
            and ooxml.zip_comment_len == 23
            and ooxml.zip_comment_str == "Some Random Zip Comment"
            and ooxml.entries[0].os_name == "FAT"
            and ooxml.entries[1].crc32_checksum == 0x29058c73
        }
        "#,
        &zip
    );
}

#[test]
fn edge_cases() {
    let zip = testdata(EDGE_CASES);

    // The archive declares 5 entries but only 3 can be parsed. The first one
    // has an empty name, the second a name that isn't valid UTF-8.
    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            not ooxml.is_ooxml
            and ooxml.number_of_total_entries == 5
            and not defined ooxml.entries[3].flags
            and not defined ooxml.entries[0].name_string
            and not defined ooxml.entries[0].name_length
            and defined ooxml.entries[0].flags
            and ooxml.entries[1].name_string == "\x80\xfename.txt"
            and ooxml.entries[2].compression_method_value == 93
            and ooxml.entries[2].compression_method_name == "Unknown"
            and ooxml.entries[2].os_name == "Unknown"
            and ooxml.entries[2].spec_version == 20
        }
        "#,
        &zip
    );
}

/// Builds a ZIP archive with a single stored entry ("a.txt") and the given
/// file comment.
fn zip_with_comment(comment: &[u8]) -> Vec<u8> {
    let name = b"a.txt";
    let content = b"a";
    let crc32 = 0xe8b7be43_u32.to_le_bytes(); // CRC-32 of "a"
    let size = (content.len() as u32).to_le_bytes();
    let name_len = (name.len() as u16).to_le_bytes();

    // Local file header: signature, version needed, flags, method, time,
    // date, CRC-32, sizes, name length, extra field length.
    let mut zip = 0x04034b50_u32.to_le_bytes().to_vec();
    zip.extend(20_u16.to_le_bytes());
    zip.extend([0; 8]);
    zip.extend(crc32);
    zip.extend(size);
    zip.extend(size);
    zip.extend(name_len);
    zip.extend([0; 2]);
    zip.extend(name);
    zip.extend(content);

    // Central directory header: signature, version made by (Unix, 2.0),
    // version needed, flags, method, time, date, CRC-32, sizes, name length,
    // then extra field length, comment length, disk number, attributes and
    // local header offset, all zero.
    let cd_offset = (zip.len() as u32).to_le_bytes();
    let cd_start = zip.len();
    zip.extend(0x02014b50_u32.to_le_bytes());
    zip.extend(0x0314_u16.to_le_bytes());
    zip.extend(20_u16.to_le_bytes());
    zip.extend([0; 8]);
    zip.extend(crc32);
    zip.extend(size);
    zip.extend(size);
    zip.extend(name_len);
    zip.extend([0; 16]);
    zip.extend(name);
    let cd_size = ((zip.len() - cd_start) as u32).to_le_bytes();

    // End of central directory record.
    zip.extend(0x06054b50_u32.to_le_bytes());
    zip.extend([0; 4]);
    zip.extend(1_u16.to_le_bytes());
    zip.extend(1_u16.to_le_bytes());
    zip.extend(cd_size);
    zip.extend(cd_offset);
    zip.extend((comment.len() as u16).to_le_bytes());
    zip.extend(comment);
    zip
}

#[test]
fn zip_comment() {
    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            ooxml.zip_comment_len == 0
            and not defined ooxml.zip_comment_str
            and ooxml.entries[0].name_string == "a.txt"
            and ooxml.entries[0].crc32_checksum == 0xe8b7be43
        }
        "#,
        &zip_with_comment(b"")
    );

    // A comment of the maximum length (65535 bytes) puts the end of central
    // directory record as far as possible from the end of the file.
    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            ooxml.zip_comment_len == 65535
            and ooxml.zip_comment_str startswith "CCCC"
            and ooxml.number_of_total_entries == 1
            and ooxml.entries[0].name_string == "a.txt"
        }
        "#,
        &zip_with_comment(&[b'C'; 0xffff])
    );

    // If the comment length in the end of central directory record doesn't
    // match the actual end of the file, the archive is not recognized.
    let mut trailing_data = zip_with_comment(b"comment");
    trailing_data.extend(b"trailing data");

    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            not defined ooxml.is_ooxml
        }
        "#,
        &trailing_data
    );
}

#[test]
fn no_entries() {
    // A valid archive whose central directory declares no entries: the
    // module knows it's a ZIP file, but not an OOXML document.
    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            defined ooxml.is_ooxml
            and not ooxml.is_ooxml
            and ooxml.number_of_total_entries == 0
            and not defined ooxml.entries[0].flags
        }
        "#,
        &testdata(NO_ENTRIES)
    );
}

#[test]
fn not_zip() {
    let data = testdata(NOT_ZIP);

    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            not defined ooxml.is_ooxml
            and not defined ooxml.number_of_total_entries
        }
        "#,
        &data
    );

    rule_false!(
        r#"
        import "ooxml"
        rule test {
          condition:
            ooxml.is_ooxml
        }
        "#,
        &data
    );

    // A file must start with a local file header to be parsed.
    let mut prefixed = b"MZ".to_vec();
    prefixed.extend(testdata(MINIMAL_DOCX));

    rule_true!(
        r#"
        import "ooxml"
        rule test {
          condition:
            not defined ooxml.is_ooxml
        }
        "#,
        &prefixed
    );
}
