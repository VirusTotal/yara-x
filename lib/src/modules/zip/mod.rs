use flate2::read::DeflateDecoder;
use std::io::Read;
use tinyzip::{Archive, Compression};

use crate::modules::protos::zip::Zip;
use crate::modules::{ExtractedFile, ModuleError};
use crate::register_module;
use crate::scanner::ScannedData;

pub fn main(_data: &[u8], _meta: Option<&[u8]>) -> Result<Zip, ModuleError> {
    Ok(Zip::new())
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
}
