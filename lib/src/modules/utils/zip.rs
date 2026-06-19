use std::borrow::Cow;
use std::io::Read;

use protobuf::Enum;
use rustc_hash::FxHashMap;
use tinyzip::Archive;

use crate::modules::protos::zip::{Compression, Entry, Zip};

pub(crate) enum ZipCache<'a> {
    NotZip,
    Cached(CachedZip<'a>),
}

pub(crate) struct CachedZip<'a> {
    pub data: &'a [u8],
    pub archive: Archive<&'a [u8]>,
    pub cached_contents: FxHashMap<String, Cow<'a, [u8]>>,
}

impl<'a> ZipCache<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let archive = match Archive::open(data) {
            Ok(arch) => arch,
            Err(_) => return ZipCache::NotZip,
        };

        ZipCache::Cached(CachedZip {
            data,
            archive,
            cached_contents: FxHashMap::default(),
        })
    }
}

impl<'a> CachedZip<'a> {
    pub(crate) fn get_file_content<'b>(
        &'b mut self,
        path: &str,
    ) -> Option<&'b [u8]> {
        if !self.cached_contents.contains_key(path) {
            let entry = self.archive.find_file(path).ok()?;
            let uncompressed_size = entry.uncompressed_size();
            let data_range = entry.data_range().ok()?.data_range;
            let start = data_range.start as usize;
            let end = data_range.end as usize;
            let raw_bytes = self.data.get(start..end)?;

            let content = match entry.compression() {
                Ok(tinyzip::Compression::Stored) => Cow::Borrowed(raw_bytes),
                Ok(tinyzip::Compression::Deflated) => {
                    let mut decoder =
                        flate2::read::DeflateDecoder::new(raw_bytes);
                    let mut buf =
                        Vec::with_capacity(uncompressed_size as usize);
                    decoder.read_to_end(&mut buf).ok()?;
                    Cow::Owned(buf)
                }
                _ => return None,
            };

            self.cached_contents.insert(path.to_string(), content);
        }

        Some(self.cached_contents.get(path).unwrap().as_ref())
    }
}

impl<'a> From<&CachedZip<'a>> for Zip {
    fn from(cached: &CachedZip<'a>) -> Self {
        let mut zip = Zip::new();
        zip.set_is_zip(true);

        let mut entries = Vec::new();
        let max_entries = 100000; // Guardrail: prevent DoS with huge entry counts

        let mut path_buf = vec![0u8; 65536];

        for entry in cached.archive.entries().filter_map(|entry| entry.ok()) {
            if entries.len() >= max_entries {
                break;
            }

            let path_bytes = match entry.read_path(&mut path_buf) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let file_path = String::from_utf8_lossy(path_bytes).to_string();

            let mut proto_entry = Entry::new();
            proto_entry.set_file_path(file_path);
            proto_entry.set_uncompressed_size(entry.uncompressed_size());
            proto_entry.set_compressed_size(entry.compressed_size());

            let compression = match entry.compression() {
                Ok(tinyzip::Compression::Stored) => Compression::STORED,
                Ok(tinyzip::Compression::Deflated) => Compression::DEFLATED,
                Err(tinyzip::Error::UnsupportedCompression(raw)) => {
                    Compression::from_i32(raw as i32)
                        .unwrap_or(Compression::UNKNOWN)
                }
                Err(_) => Compression::UNKNOWN,
            };

            proto_entry.compression = Some(compression.into());
            entries.push(proto_entry);
        }

        zip.entries = entries;
        zip
    }
}
