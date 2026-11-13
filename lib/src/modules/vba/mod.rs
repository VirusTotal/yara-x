/*! YARA module that extracts VBA (Visual Basic for Applications) macros
from Office documents.

Read more about the VBA file format specification here:
<https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc>
*/

use std::path::PathBuf;

use rustc_hash::FxHashMap;

use crate::extractor::{ExtractOptions, VbaOptions};
use crate::mods::prelude::*;
use crate::modules::ScannedDataWithPath;
use crate::modules::olecf::parser::Olecf;
use crate::modules::protos::vba::*;
use crate::modules::utils::olecf::CachedOlecf;
use crate::modules::vba::parser::{ParsedProject, decompress_stream};
use crate::scanner::ScannedData;

mod parser;

fn parse_project<D: AsRef<[u8]>>(
    olecf: &Olecf<D>,
) -> Result<ParsedProject, &'static str> {
    let (dir_name, _) = olecf
        .streams()
        .find(|(name, entry)| {
            entry.size > 0 && name.trim().eq_ignore_ascii_case("dir")
        })
        .ok_or("No VBA directory stream found")?;

    let dir_data = olecf.get_stream_data(dir_name)?;
    let dir_stream = decompress_stream(&dir_data)?;

    parser::parse_dir(&dir_stream).map_err(|_| "Failed to parse VBA stream")
}

struct VbaEntry {
    path: PathBuf,
    stream_name: String,
    offset: u32,
}

/// Iterator that lazily extracts VB code modules from a VBA document one at a
/// time.
pub struct VbaExtractor<'a> {
    olecf: Olecf<ScannedData<'a>>,
    entries: std::vec::IntoIter<VbaEntry>,
    codepage: u16,
    extracted: usize,
    max_files: usize,
}

fn sanitize_module_path(name: &str) -> Option<PathBuf> {
    let cleaned: String = name
        .chars()
        .filter(|&c| c != '\0')
        .map(|c| if c == '\\' { '/' } else { c })
        .collect();

    let mut path = PathBuf::new();

    for component in std::path::Path::new(&cleaned).components() {
        if let std::path::Component::Normal(c) = component {
            path.push(c);
        }
    }

    if path.as_os_str().is_empty() { None } else { Some(path) }
}

impl<'a> VbaExtractor<'a> {
    fn new(data: &ScannedData<'a>, options: &VbaOptions) -> Option<Self> {
        let max_files = options.max_extracted_files;
        if max_files == 0 {
            return None;
        }

        let olecf = Olecf::parse(data.clone()).ok()?;
        let project = parse_project(&olecf).ok()?;

        if project.modules.is_empty() {
            return None;
        }

        let mut stream_names = FxHashMap::default();
        for (name, entry) in olecf.streams() {
            if entry.size > 0 && !name.trim().eq_ignore_ascii_case("dir") {
                stream_names
                    .insert(parser::normalize_name(name), name.to_string());
            }
        }

        let mut entries = Vec::new();

        for module in project.modules {
            let Some(path) = sanitize_module_path(&module.name) else {
                continue;
            };

            let stream_name = module
                .stream_name
                .as_deref()
                .and_then(|s| stream_names.get(&parser::normalize_name(s)))
                .or_else(|| {
                    stream_names.get(&parser::normalize_name(&module.name))
                })
                .cloned();

            let Some(stream_name) = stream_name else {
                continue;
            };

            entries.push(VbaEntry {
                path,
                stream_name,
                offset: module.offset,
            });
        }

        if entries.is_empty() {
            return None;
        }

        Some(Self {
            olecf,
            entries: entries.into_iter(),
            codepage: project.codepage,
            extracted: 0,
            max_files,
        })
    }
}

impl<'a> Iterator for VbaExtractor<'a> {
    type Item = ScannedDataWithPath<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.extracted >= self.max_files {
            return None;
        }

        for entry in self.entries.by_ref() {
            let Ok(module_data) = self.olecf.get_stream_data(&entry.stream_name)
            else {
                continue;
            };

            let Some(code) = parser::extract_module_code(
                &module_data,
                entry.offset,
                self.codepage,
            ) else {
                continue;
            };

            if code.is_empty() {
                continue;
            }

            self.extracted += 1;
            return Some(ScannedDataWithPath {
                path: entry.path,
                data: ScannedData::from_vec(code.into_bytes()),
            });
        }

        None
    }
}

/// Extracts VBA macro modules from an OLECF document.
pub fn extract_vba<'a>(
    data: &ScannedData<'a>,
    options: &ExtractOptions,
) -> Option<VbaExtractor<'a>> {
    VbaExtractor::new(data, &options.vba)
}

fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Vba, ModuleError> {
    let project =
        match ctx.olecf_cache.get_or_insert_with(|| CachedOlecf::new(data)) {
            CachedOlecf::Olecf(o) => parse_project(o),
            CachedOlecf::NotOlecf => Err("not a valid OLECF file"),
        };

    let vba = match project {
        Ok(project) => project.into(),
        Err(_) => {
            let mut vba = Vba::new();
            vba.has_macros = Some(false);
            vba
        }
    };

    Ok(vba)
}

register_module!("vba", Vba, main, extract_vba);

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;
    use std::path::{Path, PathBuf};

    use super::sanitize_module_path;
    use crate::extractor::{Extractor, VbaOptions};
    use crate::modules::tests::create_binary_from_zipped_ihex;

    #[test]
    fn test_sanitize_module_path() {
        assert_eq!(
            sanitize_module_path("ThisDocument"),
            Some(PathBuf::from("ThisDocument"))
        );
        assert_eq!(sanitize_module_path("模块1"), Some(PathBuf::from("模块1")));
        assert_eq!(
            sanitize_module_path("Mod\0ule1"),
            Some(PathBuf::from("Module1"))
        );
        assert_eq!(
            sanitize_module_path("../../evil"),
            Some(PathBuf::from("evil"))
        );
        assert_eq!(
            sanitize_module_path("..\\..\\evil"),
            Some(PathBuf::from("evil"))
        );
        assert_eq!(
            sanitize_module_path("/abs/Module1"),
            Some(PathBuf::from("abs").join("Module1"))
        );
        assert_eq!(sanitize_module_path(""), None);
        assert_eq!(sanitize_module_path("."), None);
        assert_eq!(sanitize_module_path(".."), None);
        assert_eq!(sanitize_module_path("///"), None);
    }

    #[test]
    fn test_vba_extractor_olecf() {
        let data = create_binary_from_zipped_ihex(
            "src/modules/vba/tests/testdata/c62c12501055319db152f092e263f65da037c4a6f7ec0112832b95916ac8a1fb.in.zip",
        );

        let extractor = Extractor::new();
        let mut extracted = Vec::new();

        let _ = extractor.extract(&data, |module, path, bytes| {
            extracted.push((
                module.name().to_string(),
                path.to_path_buf(),
                String::from_utf8_lossy(bytes).into_owned(),
            ));
            ControlFlow::<()>::Continue(())
        });

        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].0, "vba");
        assert_eq!(extracted[0].1, Path::new("ThisDocument"));
        assert!(extracted[0].2.contains("Attribute VB_Name = \"ThisDocument\""));
        assert!(extracted[0].2.contains("MsgBox \"Hello, world!\""));
    }

    #[test]
    fn test_vba_extractor_unicode_module_name() {
        let data = create_binary_from_zipped_ihex(
            "src/modules/vba/tests/testdata/7972ee9287cfcce00dc23098dce4ea8ed32e2dff629342e5364a48cd9c01bcb8.in.zip",
        );

        let extractor = Extractor::new();
        let mut extracted = Vec::new();

        let _ = extractor.extract(&data, |_module, path, bytes| {
            extracted.push((
                path.to_path_buf(),
                String::from_utf8_lossy(bytes).into_owned(),
            ));
            ControlFlow::<()>::Continue(())
        });

        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].0, Path::new("ThisDocument"));
        assert_eq!(extracted[1].0, Path::new("模块1"));
        assert!(extracted[1].1.contains("Sub Auto_Open()"));
    }

    #[test]
    fn test_vba_extractor_max_extracted_files() {
        let data = create_binary_from_zipped_ihex(
            "src/modules/vba/tests/testdata/1450fa0c4f5973ebf3efa06fb03259105065baba29690362014926583bc85f48.in.zip",
        );

        let mut all_paths = Vec::new();
        let _ = Extractor::new().extract(&data, |_module, path, _bytes| {
            all_paths.push(path.to_path_buf());
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(all_paths.len(), 4);

        let mut limited_extractor = Extractor::new();
        limited_extractor.vba_options(VbaOptions::new().max_extracted_files(2));
        let mut limited_paths = Vec::new();
        let _ = limited_extractor.extract(&data, |_module, path, _bytes| {
            limited_paths.push(path.to_path_buf());
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(
            limited_paths,
            vec![PathBuf::from("ThisDocument"), PathBuf::from("UserForm1")]
        );

        let mut zero_extractor = Extractor::new();
        zero_extractor.vba_options(VbaOptions::new().max_extracted_files(0));
        let mut zero_paths = Vec::new();
        let _ = zero_extractor.extract(&data, |_module, path, _bytes| {
            zero_paths.push(path.to_path_buf());
            ControlFlow::<()>::Continue(())
        });
        assert!(zero_paths.is_empty());
    }

    #[test]
    fn test_vba_extractor_no_macros_and_invalid() {
        let no_macros = create_binary_from_zipped_ihex(
            "src/modules/vba/tests/testdata/8de0e0bba84e2f80c2e2b58b66224f0d3a780f44fbb04fcf7caae34b973eb766.in.zip",
        );

        let extractor = Extractor::new();
        let mut count = 0;
        let _ = extractor.extract(&no_macros, |_module, _path, _bytes| {
            count += 1;
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(count, 0);

        let _ = extractor.extract(b"not an olecf file", |_m, _p, _b| {
            count += 1;
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(count, 0);
    }
}
