use std::io::Read;
use std::ops::Deref;
use std::path::PathBuf;

use crate::mods::prelude::*;
use crate::modules::protos::zip::Zip;
use crate::modules::utils::zip::ZipCache;
use crate::modules::{ModuleError, ScannedDataWithPath};
use crate::register_module;
use crate::scanner::ScannedData;

pub fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Zip, ModuleError> {
    match ctx.zip_cache.get_or_insert_with(|| ZipCache::new(data)) {
        ZipCache::Cached(zip) => Ok(zip.deref().into()),
        ZipCache::NotZip => {
            let mut zip = Zip::new();
            zip.set_is_zip(false);
            Ok(zip)
        }
    }
}

/// Extracts internal items from a ZIP archive.
pub fn extract_zip<'a>(
    data: &ScannedData<'a>,
) -> Result<Vec<ScannedDataWithPath<'a>>, ModuleError> {
    let archive = match tinyzip::Archive::open(data.as_ref()) {
        Ok(arch) => arch,
        Err(_) => return Ok(Vec::new()),
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

        // Skip entries that are empty or represent a directory.
        if entry.uncompressed_size() == 0
            || path_bytes.is_empty()
            || path_bytes.ends_with(b"/")
        {
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

        let decompressed_data = match entry.compression() {
            Ok(tinyzip::Compression::Stored) => match data {
                ScannedData::Slice(s) => {
                    s.get(start..end).map(ScannedData::from_slice)
                }
                _ => data
                    .as_ref()
                    .get(start..end)
                    .map(|bytes| ScannedData::from_vec(bytes.to_vec())),
            },
            Ok(tinyzip::Compression::Deflated) => {
                data.as_ref().get(start..end).and_then(|compressed_data| {
                    let decoder =
                        flate2::read::DeflateDecoder::new(compressed_data);
                    let mut decompressed = Vec::with_capacity(
                        (entry.uncompressed_size() as usize)
                            .min(max_file_size),
                    );
                    match decoder
                        .take(max_file_size as u64)
                        .read_to_end(&mut decompressed)
                    {
                        Ok(_) => Some(ScannedData::from_vec(decompressed)),
                        Err(_) => None,
                    }
                })
            }
            _ => None,
        };

        if let Some(extracted_data) = decompressed_data {
            let path_str = String::from_utf8_lossy(path_bytes);
            let mut path = PathBuf::new();

            for component in
                std::path::Path::new(path_str.as_ref()).components()
            {
                if let std::path::Component::Normal(c) = component {
                    path.push(c);
                }
            }

            if path.as_os_str().is_empty() {
                continue;
            }

            results.push(ScannedDataWithPath { path, data: extracted_data });
        }
    }

    Ok(results)
}

register_module!("zip", Zip, main, extract_zip);
