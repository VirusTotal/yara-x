use std::io::Read;
use std::ops::{Deref, Range};
use std::path::PathBuf;

use crate::mods::prelude::*;
use crate::modules::ModuleError;
use crate::modules::ScannedDataWithPath;
use crate::modules::protos::zip::Zip;
use crate::modules::utils::zip::CachedZip;
use crate::register_module;
use crate::scanner::ScannedData;

pub fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Zip, ModuleError> {
    match ctx.zip_cache.get_or_insert_with(|| CachedZip::new(data)) {
        CachedZip::Zip(zip) => Ok(zip.deref().into()),
        CachedZip::NotZip => {
            let mut zip = Zip::new();
            zip.set_is_zip(false);
            Ok(zip)
        }
    }
}

struct ZipEntry {
    path: PathBuf,
    data_range: Range<usize>,
    uncompressed_size: usize,
    compression: tinyzip::Compression,
}

/// Iterator that lazily extracts files from a ZIP archive one at a time.
pub struct ZipExtractor<'a> {
    data: ScannedData<'a>,
    entries: std::vec::IntoIter<ZipEntry>,
}

impl<'a> ZipExtractor<'a> {
    fn new(data: &ScannedData<'a>) -> Option<Self> {
        const MAX_FILES: usize = 1000; // Guardrail: prevent file extraction DoS

        let archive = tinyzip::Archive::open(data.as_ref()).ok()?;
        if archive.entry_count() == 0 {
            return None;
        }

        let mut entries = Vec::new();
        let mut path_buf = vec![0u8; 65536];

        for entry in archive.entries().flatten() {
            if entries.len() >= MAX_FILES {
                break;
            }

            let Ok(path_bytes) = entry.read_path(&mut path_buf) else {
                continue;
            };

            // Skip entries that are empty or represent a directory.
            if entry.uncompressed_size() == 0
                || path_bytes.is_empty()
                || path_bytes.ends_with(b"/")
            {
                continue;
            }

            let Ok(compression) = entry.compression() else {
                continue;
            };

            let Ok(data_range) = entry.data_range() else {
                continue;
            };

            let Ok(start) = usize::try_from(data_range.data_range.start)
            else {
                continue;
            };

            let Ok(end) = usize::try_from(data_range.data_range.end) else {
                continue;
            };

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

            entries.push(ZipEntry {
                path,
                data_range: start..end,
                uncompressed_size: entry.uncompressed_size() as usize,
                compression,
            });
        }

        if entries.is_empty() {
            return None;
        }

        Some(Self { data: data.clone(), entries: entries.into_iter() })
    }
}

impl<'a> Iterator for ZipExtractor<'a> {
    type Item = ScannedDataWithPath<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Guardrail: 128MB extraction limit per file.
        const MAX_FILE_SIZE: usize = 128 * 1024 * 1024;

        for entry in self.entries.by_ref() {
            let decompressed_data = match entry.compression {
                tinyzip::Compression::Stored => {
                    self.data.slice(entry.data_range)
                }
                tinyzip::Compression::Deflated => self
                    .data
                    .as_ref()
                    .get(entry.data_range)
                    .and_then(|compressed_data| {
                        let decoder =
                            flate2::read::DeflateDecoder::new(compressed_data);
                        let mut decompressed = Vec::with_capacity(
                            entry.uncompressed_size.min(MAX_FILE_SIZE),
                        );
                        match decoder
                            .take(MAX_FILE_SIZE as u64)
                            .read_to_end(&mut decompressed)
                        {
                            Ok(_) => Some(ScannedData::from_vec(decompressed)),
                            Err(_) => None,
                        }
                    }),
            };

            if let Some(data) = decompressed_data {
                return Some(ScannedDataWithPath { path: entry.path, data });
            }
        }

        None
    }
}

/// Extracts internal items from a ZIP archive.
pub fn extract_zip<'a>(data: &ScannedData<'a>) -> Option<ZipExtractor<'a>> {
    ZipExtractor::new(data)
}

register_module!("zip", Zip, main, extract_zip);
