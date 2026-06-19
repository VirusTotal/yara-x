/*! YARA module that extracts VBA (Visual Basic for Applications) macros
from Office documents.

Read more about the VBA file format specification here:
https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc
*/

use crate::modules::vba::parser::decompress_stream;
use std::collections::HashMap;

use crate::mods::prelude::*;
use crate::modules::olecf::parser::OLECFParser;
use crate::modules::protos::vba::*;
use crate::modules::utils::zip::ZipCache;

mod parser;

#[derive(Debug)]
struct VbaExtractor<'a> {
    data: &'a [u8],
}

impl<'a> VbaExtractor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn read_stream_data(
        ole_parser: &OLECFParser,
        name: &str,
    ) -> Result<Vec<u8>, &'static str> {
        let size = ole_parser.get_stream_size(name)? as usize;
        if size == 0 {
            return Err("Stream is empty");
        }
        ole_parser.get_stream_data(name)
    }

    fn extract_from_ole_bytes(ole_data: &[u8]) -> Result<Vba, &'static str> {
        let ole_parser = OLECFParser::new(ole_data)?;
        let stream_names = ole_parser.get_stream_names()?;

        let mut vba_dir = None;
        let mut modules = HashMap::new();

        // First process the dir stream
        if let Some(dir_name) =
            stream_names.iter().find(|n| n.to_lowercase().trim() == "dir")
            && let Ok(data) = Self::read_stream_data(&ole_parser, dir_name)
        {
            vba_dir = Some(data);
        }

        // Then process other streams
        for name in &stream_names {
            let lowercase_name = name.to_lowercase();

            if lowercase_name != "dir"
                && let Ok(data) = Self::read_stream_data(&ole_parser, name)
                && !data.is_empty()
            {
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

    fn extract_from_ole(&self) -> Result<Vba, &'static str> {
        Self::extract_from_ole_bytes(self.data)
    }
}

fn extract_from_zip<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Vba, &'static str> {
    let zip_cache = ctx.zip_cache.get_or_insert_with(|| ZipCache::new(data));

    let ZipCache::Cached(cached_zip) = zip_cache else {
        return Err("no VBA project found in ZIP");
    };

    let vba_project_names = [
        "word/vbaProject.bin",
        "xl/vbaProject.bin",
        "ppt/vbaProject.bin",
        "vbaProject.bin",
    ];

    for name in &vba_project_names {
        if let Some(contents) = cached_zip.get_file_content(name) {
            return VbaExtractor::extract_from_ole_bytes(contents);
        }
    }

    Err("no VBA project found in ZIP")
}

fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Vba, ModuleError> {
    let is_zip = data.starts_with(&[0x50, 0x4B, 0x03, 0x04]);

    let project = if is_zip {
        extract_from_zip(ctx, data)
    } else {
        VbaExtractor::new(data).extract_from_ole()
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
