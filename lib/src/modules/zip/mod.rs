use std::io::{Cursor, Read};
use crate::modules::{ExtractedFile, ModuleError};
use crate::modules::protos::zip::Zip;
use crate::register_module;

pub fn main(_data: &[u8], _meta: Option<&[u8]>) -> Result<Zip, ModuleError> {
    Ok(Zip::new())
}

/// Extracts internal items from a ZIP archive.
pub fn extract_zip(data: &[u8]) -> Result<Vec<ExtractedFile>, ModuleError> {
    let cursor = Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(arch) => arch,
        Err(_) => return Ok(Vec::new()),
    };

    let mut results = Vec::new();
    let max_files = 1000;             // Guardrail: prevent file extraction DoS
    let max_file_size = 50 * 1024 * 1024; // Guardrail: 50MB extraction limit per file

    for i in 0..archive.len() {
        if results.len() >= max_files { break; }

        let file = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };

        if file.is_dir() { continue; }

        let sanitized_name = match file.enclosed_name() {
            Some(p) => p.to_path_buf(),
            None => std::path::Path::new(file.name()).to_path_buf(),
        };

        let mut buffer = Vec::with_capacity(file.size().min(max_file_size as u64) as usize);
        let mut handle = file.take(max_file_size);
        if handle.read_to_end(&mut buffer).is_ok() {
            results.push(ExtractedFile {
                path: sanitized_name,
                data: buffer,
            });
        }
    }

    Ok(results)
}

register_module!("zip", Zip, main, extract_zip);
