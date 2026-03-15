#![allow(dead_code)]

use std::io::{Cursor, Read};

use js_sys::Reflect;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::JsValue;
use yara_wasm::{ScanResult, ValidationResult};
use zip::ZipArchive;

pub fn parse_validation_result(value: JsValue) -> ValidationResult {
    from_value(value)
        .expect("validation result should have the expected shape")
}

pub fn parse_scan_result(value: JsValue) -> ScanResult {
    from_value(value).expect("scan result should have the expected shape")
}

pub fn js_error_message(error: JsValue) -> String {
    Reflect::get(&error, &JsValue::from_str("message"))
        .ok()
        .and_then(|value| value.as_string())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| format!("{error:?}"))
}

pub fn decode_zipped_ihex_fixture(
    zip_bytes: &[u8],
    inner_name: &str,
) -> Vec<u8> {
    let mut archive = ZipArchive::new(Cursor::new(zip_bytes))
        .expect("fixture archive should be readable");

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .expect("fixture archive entry should open");

        if file.name() != inner_name {
            continue;
        }

        let mut ihex = String::new();
        file.read_to_string(&mut ihex)
            .expect("fixture payload should be valid UTF-8");
        return decode_ihex(&ihex);
    }

    panic!("fixture archive does not contain {inner_name}");
}

pub fn assert_match_identifiers(result: &ScanResult, expected: &[&str]) {
    let mut got = result
        .matches
        .iter()
        .map(|m| m.identifier.as_str())
        .collect::<Vec<_>>();
    got.sort_unstable();

    let mut expected = expected.to_vec();
    expected.sort_unstable();

    assert_eq!(got, expected);
}

fn decode_ihex(ihex: &str) -> Vec<u8> {
    let mut data = Vec::new();

    for raw_line in ihex.lines() {
        let line = raw_line.trim();

        if line.is_empty() {
            continue;
        }

        assert!(line.starts_with(':'), "fixture line must start with ':'");
        assert!(line.len() >= 11, "fixture line is too short: {line}");

        let byte_count = parse_hex_byte(&line[1..3]) as usize;
        let record_type = parse_hex_byte(&line[7..9]);
        let payload_end = 9 + byte_count * 2;

        assert!(
            line.len() >= payload_end,
            "fixture line payload is truncated: {line}"
        );

        if record_type != 0x00 {
            continue;
        }

        let payload = &line[9..payload_end];

        for i in (0..payload.len()).step_by(2) {
            data.push(parse_hex_byte(&payload[i..i + 2]));
        }
    }

    data
}

fn parse_hex_byte(hex: &str) -> u8 {
    u8::from_str_radix(hex, 16).expect("fixture byte should be valid hex")
}
