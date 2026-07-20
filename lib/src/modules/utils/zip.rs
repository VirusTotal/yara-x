use std::cell::RefCell;
use std::io::Read;
use std::rc::Rc;

use protobuf::Enum;
use rustc_hash::FxHashMap;
use tinyzip::Archive;

use crate::modules::protos::zip::{Compression, Entry, Zip as ZipProto};

pub(crate) enum CachedZip<'a> {
    NotZip,
    Zip(Zip<'a>),
}

pub(crate) struct Zip<'a> {
    pub data: &'a [u8],
    pub archive: Archive<&'a [u8]>,
    pub cached_contents: RefCell<FxHashMap<Vec<u8>, Rc<[u8]>>>,
}

impl<'a> CachedZip<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let archive = match Archive::open(data) {
            Ok(arch) => arch,
            Err(_) => return CachedZip::NotZip,
        };

        CachedZip::Zip(Zip {
            data,
            archive,
            cached_contents: RefCell::new(FxHashMap::default()),
        })
    }
}

impl<'a> Zip<'a> {
    pub(crate) fn get_file_content<P: AsRef<[u8]>>(
        &self,
        path: P,
    ) -> Option<Rc<[u8]>> {
        let path_bytes = path.as_ref();

        if let Some(content) = self.cached_contents.borrow().get(path_bytes) {
            return Some(Rc::clone(content));
        }

        let entry = self.archive.find_file(&path).ok()?;
        let data_range = entry.data_range().ok()?.data_range;
        let start = data_range.start as usize;
        let end = data_range.end as usize;
        let raw_bytes = self.data.get(start..end)?;

        let content: Rc<[u8]> = match entry.compression() {
            Ok(tinyzip::Compression::Stored) => Rc::from(raw_bytes),
            Ok(tinyzip::Compression::Deflated) => {
                let mut decoder =
                    flate2::read::DeflateDecoder::new(raw_bytes);
                // Pre-allocate based on the compressed data we actually
                // have, not the entry's `uncompressed_size` header field,
                // which is attacker-controlled (up to u64::MAX via a Zip64
                // extra field) and unvalidated -- trusting it makes
                // `Vec::with_capacity` panic with "capacity overflow" or
                // request a huge allocation. `read_to_end` grows the
                // buffer as needed.
                let mut buf = Vec::with_capacity(raw_bytes.len());
                decoder.read_to_end(&mut buf).ok()?;
                Rc::from(buf.into_boxed_slice())
            }
            _ => return None,
        };

        self.cached_contents
            .borrow_mut()
            .insert(path_bytes.to_vec(), Rc::clone(&content));

        Some(content)
    }
}

impl<'a> From<&Zip<'a>> for ZipProto {
    fn from(cached: &Zip<'a>) -> Self {
        let mut zip = ZipProto::new();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_cache() {
        assert!(matches!(
            CachedZip::new(b"invalid zip data"),
            CachedZip::NotZip
        ));

        let eocd = [
            0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        if let CachedZip::Zip(cached) = CachedZip::new(&eocd) {
            assert!(cached.get_file_content("missing.txt").is_none());
            let zip_proto: ZipProto = (&cached).into();
            assert!(zip_proto.is_zip());
            assert_eq!(zip_proto.entries.len(), 0);
        }
    }
}
