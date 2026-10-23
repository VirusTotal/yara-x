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
}

impl Default for Extractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor {
    /// Creates a new extractor.
    pub fn new() -> Self {
        Self { max_depth: 1 }
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

    /// Extracts files from container data recursively, executing `callback`
    /// for each actually extracted buffer.
    ///
    /// The `callback` closure is invoked exclusively for files unpacked from
    /// containers. It receives three arguments:
    ///
    /// 1. The registered YARA module that produced the extracted data.
    /// 2. The relative file path within the container (e.g., `Path::new("dir/file.txt")`).
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
                        self.extract_children(
                            &data,
                            Some(&path),
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
            if let Some(children) = extract_fn(data) {
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
                "extracted:inner.zip/sub1.txt:4",
                "finished:inner.zip/sub1.txt",
                "extracted:inner.zip/sub2.txt:4",
                "finished:inner.zip/sub2.txt",
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
