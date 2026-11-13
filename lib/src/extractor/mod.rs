/*! Container extractor.

This module provides the [`Extractor`] type, which extracts archive and container
formats (e.g., ZIP archives) supported by YARA modules.
*/

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::modules::{
    RegisteredModule, ScannedDataWithPath, registered_modules,
};
use crate::scanner::ScannedData;

/// Options for the ZIP archive extractor.
///
/// Passed to [`crate::deep::Scanner::zip_options`] or
/// [`Extractor::zip_options`] to configure how ZIP archives are unpacked.
///
/// # Example
///
/// ```
/// # use yara_x::{compile, deep};
/// let rules = compile("rule test { condition: true }").unwrap();
/// let mut scanner = deep::Scanner::new(&rules);
/// scanner.zip_options(deep::ZipOptions::new().max_extracted_files(2000));
/// ```
#[derive(Debug, Clone)]
pub struct ZipOptions {
    #[cfg_attr(not(feature = "zip-module"), allow(dead_code))]
    pub(crate) max_extracted_files: usize,
}

impl Default for ZipOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ZipOptions {
    const DEFAULT_MAX_EXTRACTED_FILES: usize = 1000;

    /// Creates a new [`ZipOptions`] with default settings.
    pub const fn new() -> Self {
        Self { max_extracted_files: Self::DEFAULT_MAX_EXTRACTED_FILES }
    }

    /// Sets the maximum number of files extracted per ZIP archive.
    ///
    /// If set to 0, no files are extracted from ZIP archives. Once a ZIP
    /// archive yields `n` extracted files, any remaining files in that
    /// archive are skipped.
    ///
    /// Default value is 1000.
    pub const fn max_extracted_files(mut self, n: usize) -> Self {
        self.max_extracted_files = n;
        self
    }
}

/// Options for the VBA macro extractor.
///
/// Passed to [`crate::deep::Scanner::vba_options`] or
/// [`Extractor::vba_options`] to configure how VBA documents are unpacked.
///
/// # Example
///
/// ```
/// # use yara_x::{compile, deep};
/// let rules = compile("rule test { condition: true }").unwrap();
/// let mut scanner = deep::Scanner::new(&rules);
/// scanner.vba_options(deep::VbaOptions::new().max_extracted_files(2000));
/// ```
#[derive(Debug, Clone)]
pub struct VbaOptions {
    #[cfg_attr(not(feature = "vba-module"), allow(dead_code))]
    pub(crate) max_extracted_files: usize,
}

impl Default for VbaOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl VbaOptions {
    const DEFAULT_MAX_EXTRACTED_FILES: usize = 1000;

    /// Creates a new [`VbaOptions`] with default settings.
    pub const fn new() -> Self {
        Self { max_extracted_files: Self::DEFAULT_MAX_EXTRACTED_FILES }
    }

    /// Sets the maximum number of files extracted per VBA document.
    ///
    /// If set to 0, no files are extracted from VBA documents. Once a VBA
    /// document yields `n` extracted files, any remaining files in that
    /// document are skipped.
    ///
    /// Default value is 1000.
    pub const fn max_extracted_files(mut self, n: usize) -> Self {
        self.max_extracted_files = n;
        self
    }
}

/// Bundle of configuration structures for all supported extractors.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    #[cfg_attr(not(feature = "vba-module"), allow(dead_code))]
    pub(crate) vba: VbaOptions,
    #[cfg_attr(not(feature = "zip-module"), allow(dead_code))]
    pub(crate) zip: ZipOptions,
}

pub(crate) enum ExtractEvent<'a> {
    Extracted(&'a dyn RegisteredModule, &'a Path, &'a [u8]),
    Finished(&'a Path),
}

enum StackItem<'a> {
    Iterator {
        iter: Box<dyn Iterator<Item = ScannedDataWithPath<'a>> + 'a>,
        module: &'static dyn RegisteredModule,
        parent_path: Option<PathBuf>,
        depth: usize,
    },
    Finished(PathBuf),
}

/// Extracts archive and container formats (e.g., ZIP archives) supported by
/// YARA modules.
#[derive(Debug, Clone)]
pub struct Extractor {
    max_depth: usize,
    options: ExtractOptions,
}

impl Default for Extractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor {
    const DEFAULT_MAX_DEPTH: usize = 1;

    /// Creates a new extractor.
    pub fn new() -> Self {
        Self {
            max_depth: Self::DEFAULT_MAX_DEPTH,
            options: ExtractOptions::default(),
        }
    }

    /// Sets the maximum container extraction depth.
    ///
    /// If set to 0 extracts nothing.
    /// If set to 1 extracts immediate inner files.
    ///
    /// Default value is 1.
    pub fn max_depth(&mut self, depth: usize) -> &mut Self {
        self.max_depth = depth;
        self
    }

    /// Sets options for the VBA macro extractor.
    pub fn vba_options(&mut self, options: VbaOptions) -> &mut Self {
        self.options.vba = options;
        self
    }

    /// Sets options for the ZIP archive extractor.
    pub fn zip_options(&mut self, options: ZipOptions) -> &mut Self {
        self.options.zip = options;
        self
    }

    /// Extracts files from container data recursively, executing `callback`
    /// for each actually extracted buffer.
    ///
    /// The `callback` closure is invoked exclusively for files unpacked from
    /// containers. It receives three arguments:
    ///
    /// 1. The registered YARA module that produced the extracted data.
    /// 2. The relative file path within the container (e.g.,
    ///    `Path::new("dir/file.txt")`). When files are unpacked from a nested
    ///    container (`max_depth >= 2`), a trailing `_` is appended to the
    ///    parent container's name (e.g., `Path::new("dir/inner.zip_/file.txt")`)
    ///    so container files do not collide with directory names on disk.
    /// 3. The raw extracted data as a byte slice (`&[u8]`).
    ///
    /// # Flow Control
    ///
    /// The callback closure returns [`std::ops::ControlFlow<B>`], giving explicit
    /// control over extraction traversal and early termination:
    ///
    /// - Returning [`std::ops::ControlFlow::Continue(())`] instructs the extractor
    ///   to proceed normally to the next file.
    ///
    /// - Returning [`std::ops::ControlFlow::Break(b)`] immediately halts further
    ///   extraction, returning `ControlFlow::Break(b)`.
    pub fn extract<F, B>(&self, data: &[u8], mut callback: F) -> ControlFlow<B>
    where
        F: FnMut(&dyn RegisteredModule, &Path, &[u8]) -> ControlFlow<B>,
    {
        self.extract_dfs(data, |event| match event {
            ExtractEvent::Extracted(module, path, bytes) => {
                callback(module, path, bytes)
            }
            ExtractEvent::Finished(_) => ControlFlow::Continue(()),
        })
    }

    /// Extracts files from container data recursively in depth-first search (DFS)
    /// order, invoking `callback` with [`ExtractEvent`] notifications.
    ///
    /// For each extracted file, `callback` is invoked twice:
    /// 1. With [`ExtractEvent::Extracted`] when the file is extracted.
    /// 2. With [`ExtractEvent::Finished`] after all sub-files extracted from it
    ///    (if any) have been processed.
    pub(crate) fn extract_dfs<F, B>(
        &self,
        data: &[u8],
        mut callback: F,
    ) -> ControlFlow<B>
    where
        F: FnMut(ExtractEvent) -> ControlFlow<B>,
    {
        if self.max_depth == 0 {
            return ControlFlow::Continue(());
        }

        let mut stack = Vec::new();

        self.extract_children(&ScannedData::Slice(data), None, 1, &mut stack);

        while let Some(item) = stack.last_mut() {
            match item {
                StackItem::Iterator { iter, module, parent_path, depth } => {
                    let Some(ScannedDataWithPath { mut path, data }) =
                        iter.next()
                    else {
                        stack.pop();
                        continue;
                    };

                    let module = *module;
                    let depth = *depth;

                    if let Some(parent) = parent_path
                        && !parent.as_os_str().is_empty()
                    {
                        path = parent.join(path);
                    }

                    // Notify the caller that this file has been extracted.
                    callback(ExtractEvent::Extracted(
                        module,
                        &path,
                        data.as_ref(),
                    ))?;

                    // Reserve a `Finished` slot on the stack *before* pushing
                    // any child extractors for `data`. Because `stack` is LIFO,
                    // any child iterators pushed by `extract_children` below
                    // will sit on top of this `Finished` marker and will be
                    // exhausted first. Once all descendants of `path` have been
                    // processed, this `Finished` marker will reach the top of
                    // the stack and `ExtractEvent::Finished` will be emitted.
                    let finished_idx = stack.len();
                    stack.push(StackItem::Finished(PathBuf::new()));

                    if depth < self.max_depth {
                        // Append `_` to the parent container's file name (e.g.,
                        // `dir/inner.zip` -> `dir/inner.zip_`) so extracted
                        // children do not collide with the parent container
                        // file when materialized on a filesystem.
                        let mut child_parent = path.clone();
                        if let Some(name) = child_parent.file_name() {
                            let mut dir_name = name.to_os_string();
                            dir_name.push("_");
                            child_parent.set_file_name(dir_name);
                        }
                        self.extract_children(
                            &data,
                            Some(&child_parent),
                            depth + 1,
                            &mut stack,
                        );
                    }

                    stack[finished_idx] = StackItem::Finished(path);
                }
                StackItem::Finished(_) => {
                    if let Some(StackItem::Finished(path)) = stack.pop() {
                        callback(ExtractEvent::Finished(&path))?;
                    }
                }
            }
        }

        ControlFlow::Continue(())
    }

    fn extract_children<'a>(
        &self,
        data: &ScannedData<'a>,
        parent_path: Option<&Path>,
        depth: usize,
        stack: &mut Vec<StackItem<'a>>,
    ) {
        for module in registered_modules() {
            let Some(extract_fn) = module.extract_fn() else {
                continue;
            };
            if let Some(children) = extract_fn(data, &self.options) {
                stack.push(StackItem::Iterator {
                    iter: children,
                    module,
                    parent_path: parent_path.map(Path::to_path_buf),
                    depth,
                });
            }
        }
    }
}

#[cfg(all(test, feature = "zip-module"))]
mod tests {
    use std::io::{Cursor, Write};
    use std::ops::ControlFlow;
    use std::path::PathBuf;

    use super::{ExtractEvent, Extractor};

    fn create_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = Vec::new();
        let mut zip = zip::ZipWriter::new(Cursor::new(buf));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in files {
            zip.start_file(*name, options).unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn test_extractor_dfs_nested() {
        let inner_zip =
            create_zip(&[("sub1.txt", b"sub1"), ("sub2.txt", b"sub2")]);
        let outer_zip = create_zip(&[
            ("inner.zip", &inner_zip),
            ("top1.txt", b"top1"),
            ("top2.txt", b"top2"),
        ]);

        let mut extractor = Extractor::new();
        extractor.max_depth(2);

        let mut events = Vec::new();
        let _ = extractor.extract_dfs(&outer_zip, |event| {
            match event {
                ExtractEvent::Extracted(_module, path, bytes) => {
                    events.push(format!(
                        "extracted:{}:{}",
                        path.to_string_lossy().replace('\\', "/"),
                        bytes.len()
                    ));
                }
                ExtractEvent::Finished(path) => {
                    events.push(format!(
                        "finished:{}",
                        path.to_string_lossy().replace('\\', "/")
                    ));
                }
            }
            ControlFlow::<()>::Continue(())
        });

        let inner_zip_extracted =
            format!("extracted:inner.zip:{}", inner_zip.len());
        assert_eq!(
            events,
            vec![
                inner_zip_extracted.as_str(),
                "extracted:inner.zip_/sub1.txt:4",
                "finished:inner.zip_/sub1.txt",
                "extracted:inner.zip_/sub2.txt:4",
                "finished:inner.zip_/sub2.txt",
                "finished:inner.zip",
                "extracted:top1.txt:4",
                "finished:top1.txt",
                "extracted:top2.txt:4",
                "finished:top2.txt",
            ]
        );
    }

    #[test]
    fn test_extractor_break_stops_further_extraction() {
        let zip_data = create_zip(&[
            ("file1.txt", b"content1"),
            ("file2.txt", b"content2"),
            ("file3.txt", b"content3"),
        ]);

        let extractor = Extractor::new();
        let mut extracted_paths = Vec::new();
        let res = extractor.extract(&zip_data, |_module, path, _bytes| {
            extracted_paths.push(path.to_path_buf());
            if extracted_paths.len() == 2 {
                ControlFlow::Break("stopped")
            } else {
                ControlFlow::Continue(())
            }
        });

        assert_eq!(res, ControlFlow::Break("stopped"));
        assert_eq!(
            extracted_paths,
            vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt")]
        );
    }
}
