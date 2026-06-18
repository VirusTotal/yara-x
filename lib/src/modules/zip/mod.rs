use protobuf::Enum;
use tinyzip::Archive;

use crate::mods::prelude::*;
use crate::modules::ModuleError;
use crate::modules::protos::zip::{Compression, Entry, Zip};
use crate::register_module;

pub fn main(
    _ctx: &mut ModuleContext,
    data: &[u8],
) -> Result<Zip, ModuleError> {
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

    for entry in archive.entries().filter_map(|entry| entry.ok()) {
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

    Ok(zip)
}

register_module!("zip", Zip, main);
