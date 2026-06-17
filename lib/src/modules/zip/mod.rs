use flate2::read::DeflateDecoder;
use std::io::Read;
use tinyzip::{Archive, Compression};

use crate::modules::protos::zip::{Compression as ProtoCompression, Entry, Zip};
use crate::modules::{ExtractedFile, ModuleError};
use crate::register_module;
use crate::scanner::ScannedData;
use protobuf::EnumOrUnknown;

pub fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Zip, ModuleError> {
    let mut zip = Zip::new();

    let archive = match Archive::open(data) {
        Ok(arch) => arch,
        Err(_) => {
            zip.set_is_zip(false);
            return Ok(zip);
        }
    };

    zip.set_is_zip(true);

    let mut entries = Vec::new();
    let max_entries = 100000; // Guardrail: prevent DoS with huge entry counts

    let mut path_buf = vec![0u8; 65536];

    for entry_res in archive.entries() {
        if entries.len() >= max_entries {
            break;
        }

        let entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path_bytes = match entry.read_path(&mut path_buf) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let filename = String::from_utf8_lossy(path_bytes).to_string();

        let raw_method = match entry.compression() {
            Ok(Compression::Stored) => 0,
            Ok(Compression::Deflated) => 8,
            Err(tinyzip::Error::UnsupportedCompression(raw)) => raw,
            Err(_) => 255,
        };

        let mut proto_entry = Entry::new();
        proto_entry.set_filename(filename);
        proto_entry.compression =
            Some(EnumOrUnknown::<ProtoCompression>::from_i32(raw_method as i32));
        proto_entry.set_uncompressed_size(entry.uncompressed_size());
        proto_entry.set_compressed_size(entry.compressed_size());

        entries.push(proto_entry);
    }

    zip.entries = entries;

    Ok(zip)
}

/// Extracts internal items from a ZIP archive.
pub fn extract_zip<'a>(
    data: &ScannedData<'a>,
) -> Result<Vec<ExtractedFile<'a>>, ModuleError> {
    let slice = data.as_ref();
    let archive = match Archive::open(slice) {
        Ok(arch) => arch,
        Err(err) => {
            return Err(ModuleError::InternalError { err: err.to_string() });
        }
    };

    let mut results = Vec::new();
    let max_files = 1000; // Guardrail: prevent file extraction DoS
    let max_file_size = 50 * 1024 * 1024; // Guardrail: 50MB extraction limit per file

    let mut path_buf = vec![0u8; 65536];

    for entry in archive.entries().filter_map(|entry| entry.ok()) {
        if results.len() >= max_files {
            break;
        }

        let path_bytes = match entry.read_path(&mut path_buf) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if path_bytes.is_empty() || path_bytes.ends_with(b"/") {
            continue;
        }

        let path_str = String::from_utf8_lossy(path_bytes);
        let mut path = std::path::PathBuf::new();

        for component in std::path::Path::new(path_str.as_ref()).components() {
            if let std::path::Component::Normal(c) = component {
                path.push(c);
            }
        }

        if path.as_os_str().is_empty() {
            continue;
        }

        let data_range = match entry.data_range() {
            Ok(r) => r.data_range,
            Err(_) => continue,
        };

        let start = match usize::try_from(data_range.start) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let end = match usize::try_from(data_range.end) {
            Ok(e) => e,
            Err(_) => continue,
        };

        match entry.compression() {
            Ok(Compression::Stored) => {
                if let Some(sub_data) = data.slice(start..end) {
                    results.push(ExtractedFile { path, data: sub_data });
                }
            }
            Ok(Compression::Deflated) => {
                if let Some(compressed_bytes) = slice.get(start..end) {
                    let decoder = DeflateDecoder::new(compressed_bytes);
                    let mut buffer = Vec::with_capacity(
                        (entry.uncompressed_size() as usize)
                            .min(max_file_size),
                    );
                    if decoder
                        .take(max_file_size as u64)
                        .read_to_end(&mut buffer)
                        .is_ok()
                    {
                        results.push(ExtractedFile {
                            path,
                            data: ScannedData::from_vec(buffer),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    Ok(results)
}

register_module!("zip", Zip, main, extract_zip);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_zip_invalid() {
        let data = ScannedData::Slice(b"not a valid zip archive");
        assert!(extract_zip(&data).is_err());
    }

    #[test]
    fn test_main_invalid() {
        let zip = main(b"not a valid zip", None).unwrap();
        assert_eq!(zip.is_zip(), false);
        assert_eq!(zip.entries.len(), 0);
    }

    #[test]
    fn test_main_valid() {
        let zip_data = [
            0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33,
            0x63, 0xd0, 0x5c, 0xe7, 0xb0, 0x5a, 0x76, 0x35, 0x00, 0x00, 0x00,
            0x36, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x73, 0x75, 0x73,
            0x70, 0x69, 0x63, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x70, 0x61, 0x79,
            0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x0b, 0xc9, 0xc8,
            0x2c, 0x56, 0x00, 0xa2, 0x44, 0x85, 0xe2, 0xd2, 0xe2, 0x82, 0xcc,
            0xe4, 0xcc, 0xfc, 0xd2, 0x62, 0x85, 0x48, 0xc7, 0x20, 0x47, 0x85,
            0x82, 0xc4, 0xca, 0x9c, 0xfc, 0xc4, 0x14, 0x85, 0xcc, 0xbc, 0xe2,
            0xcc, 0x94, 0x54, 0xa0, 0x82, 0x28, 0xcf, 0x00, 0x85, 0xc4, 0xa2,
            0xe4, 0x8c, 0xcc, 0xb2, 0x54, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14,
            0x03, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x63, 0xd0, 0x5c,
            0xe7, 0xb0, 0x5a, 0x76, 0x35, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00,
            0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73, 0x75, 0x73,
            0x70, 0x69, 0x63, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x70, 0x61, 0x79,
            0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x50, 0x4b, 0x05,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x44, 0x00,
            0x00, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let zip = main(&zip_data, None).unwrap();
        assert_eq!(zip.is_zip(), true);
        assert_eq!(zip.entries.len(), 1);
        assert_eq!(zip.entries[0].filename(), "suspicious_payload.exe");
        assert_eq!(zip.entries[0].compression(), ProtoCompression::DEFLATED);
    }
}
