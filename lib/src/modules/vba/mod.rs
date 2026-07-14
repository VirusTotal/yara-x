/*! YARA module that extracts VBA (Visual Basic for Applications) macros
from Office documents.

Read more about the VBA file format specification here:
https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc
*/

use crate::modules::vba::parser::decompress_stream;
use rustc_hash::FxHashMap as HashMap;
use std::borrow::Cow;

use crate::mods::prelude::*;
use crate::modules::olecf::parser::Olecf;
use crate::modules::protos::vba::*;
use crate::modules::utils::olecf::CachedOlecf;
use crate::modules::utils::zip::{CachedZip, Zip};

mod parser;

struct VbaExtractor;

impl VbaExtractor {
    fn read_stream_data<'a>(
        olecf: &Olecf<'a>,
        name: &str,
    ) -> Result<Cow<'a, [u8]>, &'static str> {
        let size = olecf.get_stream_size(name)? as usize;
        if size == 0 {
            return Err("Stream is empty");
        }
        olecf.get_stream_data(name)
    }

    fn extract_from_olecf<'a>(olecf: &Olecf<'a>) -> Result<Vba, &'static str> {
        let stream_names = olecf.stream_names()?;

        let mut vba_dir = None;
        let mut modules = HashMap::default();

        // First process the dir stream
        if let Some(dir_name) =
            stream_names.iter().find(|n| n.trim().eq_ignore_ascii_case("dir"))
            && let Ok(data) = Self::read_stream_data(olecf, dir_name)
        {
            vba_dir = Some(data);
        }

        // Then process other streams
        for name in &stream_names {
            if !name.trim().eq_ignore_ascii_case("dir")
                && let Ok(data) = Self::read_stream_data(olecf, name)
                && !data.is_empty()
            {
                let lowercase_name = name.to_lowercase();
                modules.insert(parser::normalize_name(&lowercase_name), data);
            }
        }

        // Always try the dir stream if we found it
        if let Some(dir_data) = vba_dir {
            let dir_stream = decompress_stream(&dir_data)?;
            parser::parse(&dir_stream, &modules)
                .map_err(|_| "Failed to parse VBA stream")
        } else {
            Err("No VBA directory stream found")
        }
    }

    fn extract_from_zip<'a>(zip: &mut Zip<'a>) -> Result<Vba, &'static str> {
        let vba_project_names = [
            "word/vbaProject.bin",
            "xl/vbaProject.bin",
            "ppt/vbaProject.bin",
            "vbaProject.bin",
        ];

        for name in &vba_project_names {
            if let Some(contents) = zip.get_file_content(name) {
                let olecf = Olecf::parse(contents)?;
                return Self::extract_from_olecf(&olecf);
            }
        }

        Err("no VBA project found in ZIP")
    }
}

fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Vba, ModuleError> {
    let is_zip = data.starts_with(&[0x50, 0x4B, 0x03, 0x04]);

    let project = if is_zip {
        match ctx.zip_cache.get_or_insert_with(|| CachedZip::new(data)) {
            CachedZip::Zip(z) => VbaExtractor::extract_from_zip(z),
            CachedZip::NotZip => Err("not a valid ZIP archive"),
        }
    } else {
        match ctx.olecf_cache.get_or_insert_with(|| CachedOlecf::new(data)) {
            CachedOlecf::Olecf(o) => VbaExtractor::extract_from_olecf(o),
            CachedOlecf::NotOlecf => Err("not a valid OLECF file"),
        }
    };

    let vba = match project {
        Ok(mut vba) => {
            vba.has_macros = Some(true);
            vba
        }
        Err(_) => {
            let mut vba = Vba::new();
            vba.has_macros = Some(false);
            vba
        }
    };

    Ok(vba)
}

register_module!("vba", Vba, main);
