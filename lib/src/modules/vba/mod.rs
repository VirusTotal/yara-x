/*! YARA module that extracts VBA (Visual Basic for Applications) macros
from Office documents.

Read more about the VBA file format specification here:
https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc
*/

use crate::modules::vba::parser::decompress_stream;
use std::collections::HashMap;
use std::io::Cursor;
use std::io::Read;
use zip::ZipArchive;

use crate::mods::prelude::*;
use crate::modules::olecf::parser::OLECFParser;
use crate::modules::protos::vba::*;

mod parser;

#[derive(Debug)]
struct VbaExtractor<'a> {
    data: &'a [u8],
}


impl<'a> VbaExtractor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn is_zip(&self) -> bool {
        self.data.starts_with(&[0x50, 0x4B, 0x03, 0x04])
    }

    fn read_stream_data(
        ole_parser: &crate::modules::olecf::parser::OLECFParser,
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

    fn extract_from_zip(&self) -> Result<Vba, &'static str> {
        let reader = Cursor::new(&self.data);
        let mut archive = ZipArchive::new(reader)
            .map_err(|_| "Failed to read ZIP archive")?;

        // Search for potential VBA project files
        let vba_project_names = [
            "word/vbaProject.bin",
            "xl/vbaProject.bin",
            "ppt/vbaProject.bin",
            "vbaProject.bin",
        ];

        for name in &vba_project_names {
            match archive.by_name(name) {
                Ok(mut file) => {
                    let mut contents = Vec::new();
                    file.read_to_end(&mut contents)
                        .map_err(|_| "Failed to read vbaProject.bin")?;

                    return Self::extract_from_ole_bytes(&contents);
                }
                Err(_) => continue,
            }
        }

        Err("no VBA project found in ZIP")
    }
}

fn main(_ctx: &mut ModuleContext, data: &[u8]) -> Result<Vba, ModuleError> {
    let extractor = VbaExtractor::new(data);

    let project = if extractor.is_zip() {
        extractor.extract_from_zip()
    } else {
        extractor.extract_from_ole()
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
