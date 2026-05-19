/*! YARA module that extracts VBA (Visual Basic for Applications) macros from Office documents.

Read more about the VBA file format specification here:
 https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc
*/

use crate::mods::prelude::*;
use crate::modules::protos::vba::vba::ProjectInfo;
use crate::modules::protos::vba::*;
use protobuf::MessageField;
use std::collections::HashMap;
use std::io::Cursor;
use std::io::Read;
use zip::ZipArchive;

mod parser;
use parser::{ModuleType, VbaProject};

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

    fn extract_from_ole_bytes(ole_data: &[u8]) -> Result<VbaProject, &'static str> {
        let ole_parser =
            crate::modules::olecf::parser::OLECFParser::new(ole_data)?;
        let stream_names = ole_parser.get_stream_names()?;

        let mut vba_dir = None;
        let mut modules = HashMap::new();

        // First process the dir stream
        if let Some(dir_name) =
            stream_names.iter().find(|n| n.to_lowercase().trim() == "dir")
            && let Ok(data) = Self::read_stream_data(&ole_parser, dir_name) {
                vba_dir = Some(data);
            }

        // Then process other streams
        for name in &stream_names {
            let lowercase_name = name.to_lowercase();

            if lowercase_name != "dir"
                && (lowercase_name.contains("module")
                    || lowercase_name.contains("thisdocument")
                    || lowercase_name.ends_with(".bas")
                    || lowercase_name.ends_with(".cls")
                    || lowercase_name.ends_with(".frm"))
                    && let Ok(data) = Self::read_stream_data(&ole_parser, name)
                        && !data.is_empty() {
                            modules.insert(name.clone(), data);
                        }
        }

        // Always try the dir stream if we found it
        if let Some(dir_data) = vba_dir {
            parser::VbaProject::parse(&dir_data, modules)
        } else {
            Err("No VBA directory stream found")
        }
    }

    fn extract_from_ole(&self) -> Result<VbaProject, &'static str> {
        Self::extract_from_ole_bytes(self.data)
    }

    fn extract_from_zip(&self) -> Result<VbaProject, &'static str> {
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

        Err("No VBA project found in ZIP")
    }
}

fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Vba, ModuleError> {
    let mut vba = Vba::new();
    vba.has_macros = Some(false);

    let extractor = VbaExtractor::new(data);

    let project_result = if extractor.is_zip() {
        extractor.extract_from_zip()
    } else {
        extractor.extract_from_ole()
    };

    match project_result {
        Ok(project) => {
            vba.has_macros = Some(true);

            let mut project_info = ProjectInfo::new();
            project_info.name = Some(project.info.name.clone());
            project_info.version = Some(project.info.version.clone());
            project_info.references.clone_from(&project.info.references);

            // Add metadata
            let module_count = project.modules.len() as i32;
            project_info.module_count = Some(module_count);
            project_info.is_compressed = Some(true);

            vba.project_info = MessageField::some(project_info);

            // Process modules
            for module in project.modules.values() {
                vba.module_names.push(module.name.clone());
                vba.module_types.push(match module.module_type {
                    ModuleType::Standard => "Standard".to_string(),
                    ModuleType::Class => "Class".to_string(),
                    ModuleType::Unknown => "Unknown".to_string(),
                });
                vba.module_codes.push(module.code.clone());
            }
        }
        Err(_) => {
            vba.has_macros = Some(false);
        }
    }

    Ok(vba)
}

register_module!("vba", Vba, main);
