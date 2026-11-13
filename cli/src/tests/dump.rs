use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use std::fs;

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

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Builds a valid uncompressed (Stored) ZIP archive from `(name, data)` pairs.
fn create_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut central_dir = Vec::new();

    for &(name, data) in entries {
        let local_header_offset = buf.len() as u32;
        let name_bytes = name.as_bytes();
        let crc = crc32(data);
        let size = data.len() as u32;

        // Local file header
        buf.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression: Stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes()); // compressed size
        buf.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(data);

        // Central directory file header
        central_dir.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central_dir.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central_dir.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // flags
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // compression: Stored
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central_dir.extend_from_slice(&crc.to_le_bytes());
        central_dir.extend_from_slice(&size.to_le_bytes()); // compressed size
        central_dir.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        central_dir
            .extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central_dir.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central_dir.extend_from_slice(&local_header_offset.to_le_bytes());
        central_dir.extend_from_slice(name_bytes);
    }

    let cd_offset = buf.len() as u32;
    let cd_size = central_dir.len() as u32;
    buf.extend_from_slice(&central_dir);

    // End of central directory record
    let count = entries.len() as u16;
    buf.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
    buf.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len

    buf
}

#[test]
fn test_dump_default_depth_zero() {
    let temp = TempDir::new().unwrap();
    let docm_path = temp.path().join("macro.docm");
    fs::write(
        &docm_path,
        decode_zipped_ihex(
            "../lib/src/modules/vba/tests/testdata/643d1e3b68c1e31aef5779eb28ac3b0aaa284c91c47c26cfc2dbb3bc7f569103.in.zip",
        ),
    )
    .unwrap();

    // Default (max_depth = 0) dumps only the root file without file path keys.
    let yaml_default = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg(&docm_path)
        .output()
        .unwrap();
    assert!(yaml_default.status.success());
    let yaml_str = String::from_utf8(yaml_default.stdout).unwrap();
    assert!(yaml_str.starts_with("zip:\n"));
    assert!(!yaml_str.contains("vba:"));

    // Explicit `--max-depth 0` behaves identically to default.
    let yaml_zero = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("0")
        .arg(&docm_path)
        .output()
        .unwrap();
    assert!(yaml_zero.status.success());
    assert_eq!(String::from_utf8(yaml_zero.stdout).unwrap(), yaml_str);

    // JSON at depth 0 has module names directly at the top level.
    let json_default = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("-o")
        .arg("json")
        .arg(&docm_path)
        .output()
        .unwrap();
    assert!(json_default.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_default.stdout).unwrap();
    assert_eq!(parsed["zip"]["is_zip"], true);
    assert!(parsed.get("vba").is_none());
}

#[test]
fn test_dump_max_depth_one() {
    let temp = TempDir::new().unwrap();
    let docm_path = temp.path().join("macro.docm");
    fs::write(
        &docm_path,
        decode_zipped_ihex(
            "../lib/src/modules/vba/tests/testdata/643d1e3b68c1e31aef5779eb28ac3b0aaa284c91c47c26cfc2dbb3bc7f569103.in.zip",
        ),
    )
    .unwrap();

    let root_key = docm_path.to_string_lossy().into_owned();
    let vba_key = docm_path
        .join("word")
        .join("vbaProject.bin")
        .to_string_lossy()
        .into_owned();

    // JSON output with --max-depth 1
    let json_out = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("1")
        .arg("-o")
        .arg("json")
        .arg(&docm_path)
        .output()
        .unwrap();
    assert!(json_out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).unwrap();
    let obj = parsed.as_object().unwrap();

    // Non-matching inner XML files in the .docm are omitted; only the root ZIP
    // and word/vbaProject.bin appear.
    assert_eq!(obj.len(), 2);
    assert_eq!(obj[&root_key]["zip"]["is_zip"], true);
    assert_eq!(obj[&vba_key]["olecf"]["is_olecf"], true);
    assert_eq!(obj[&vba_key]["vba"]["has_macros"], true);

    // YAML output with --max-depth 1
    let yaml_out = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("1")
        .arg(&docm_path)
        .output()
        .unwrap();
    assert!(yaml_out.status.success());
    let yaml_str = String::from_utf8(yaml_out.stdout).unwrap();
    assert!(yaml_str.contains(&root_key.replace('\\', "\\\\")));
    assert!(yaml_str.contains(&vba_key.replace('\\', "\\\\")));
    assert!(yaml_str.contains("    zip:\n"));
    assert!(yaml_str.contains("    olecf:\n"));
    assert!(yaml_str.contains("    vba:\n"));
    assert!(!yaml_str.contains("[Content_Types].xml\":"));
}

#[test]
fn test_dump_max_depth_nested_and_module_filter() {
    let temp = TempDir::new().unwrap();
    let docm_bytes = decode_zipped_ihex(
        "../lib/src/modules/vba/tests/testdata/643d1e3b68c1e31aef5779eb28ac3b0aaa284c91c47c26cfc2dbb3bc7f569103.in.zip",
    );
    let outer_zip_bytes = create_stored_zip(&[
        ("readme.txt", b"just plain text"),
        ("macro.docm", &docm_bytes),
    ]);
    let outer_path = temp.path().join("outer.zip");
    fs::write(&outer_path, outer_zip_bytes).unwrap();

    let outer_key = outer_path.to_string_lossy().into_owned();
    let docm_key =
        outer_path.join("macro.docm").to_string_lossy().into_owned();
    let vba_key = outer_path
        .join("macro.docm_")
        .join("word")
        .join("vbaProject.bin")
        .to_string_lossy()
        .into_owned();

    // At depth 1: outer.zip and outer.zip/macro.docm (readme.txt omitted,
    // vbaProject.bin not yet extracted).
    let depth1_out = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("1")
        .arg("-o")
        .arg("json")
        .arg(&outer_path)
        .output()
        .unwrap();
    assert!(depth1_out.status.success());
    let depth1: serde_json::Value =
        serde_json::from_slice(&depth1_out.stdout).unwrap();
    let depth1_obj = depth1.as_object().unwrap();
    assert_eq!(depth1_obj.len(), 2);
    assert_eq!(depth1_obj[&outer_key]["zip"]["is_zip"], true);
    assert_eq!(depth1_obj[&docm_key]["zip"]["is_zip"], true);

    // At depth 2: vbaProject.bin inside macro.docm is also extracted and dumped.
    let depth2_out = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("2")
        .arg("-o")
        .arg("json")
        .arg(&outer_path)
        .output()
        .unwrap();
    assert!(depth2_out.status.success());
    let depth2: serde_json::Value =
        serde_json::from_slice(&depth2_out.stdout).unwrap();
    let depth2_obj = depth2.as_object().unwrap();
    assert_eq!(depth2_obj.len(), 3);
    assert_eq!(depth2_obj[&outer_key]["zip"]["is_zip"], true);
    assert_eq!(depth2_obj[&docm_key]["zip"]["is_zip"], true);
    assert_eq!(depth2_obj[&vba_key]["vba"]["has_macros"], true);

    // Filtering with `--module vba` at depth 2 omits non-VBA containers/files
    // and omits `olecf` on vbaProject.bin.
    let filtered_out = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("2")
        .arg("-m")
        .arg("vba")
        .arg("-o")
        .arg("json")
        .arg(&outer_path)
        .output()
        .unwrap();
    assert!(filtered_out.status.success());
    let filtered: serde_json::Value =
        serde_json::from_slice(&filtered_out.stdout).unwrap();
    let filtered_obj = filtered.as_object().unwrap();
    assert_eq!(filtered_obj.len(), 1);
    assert_eq!(filtered_obj[&vba_key]["vba"]["has_macros"], true);
    assert!(filtered_obj[&vba_key].get("olecf").is_none());
}

#[test]
fn test_dump_max_depth_no_matching_modules() {
    let json_out = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("1")
        .arg("-o")
        .arg("json")
        .arg("src/tests/testdata/dummy.file")
        .output()
        .unwrap();
    assert!(json_out.status.success());
    assert_eq!(String::from_utf8(json_out.stdout).unwrap(), "{}\n");

    let yaml_out = Command::new(cargo_bin!("yr"))
        .arg("dump")
        .arg("--max-depth")
        .arg("1")
        .arg("src/tests/testdata/dummy.file")
        .output()
        .unwrap();
    assert!(yaml_out.status.success());
    assert_eq!(String::from_utf8(yaml_out.stdout).unwrap(), "\n");
}
