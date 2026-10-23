/*! Container extractor.

This module provides the [`Extractor`] type, which extracts archive and container
formats (e.g., ZIP archives) supported by YARA modules.
*/

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
#[cfg(any(feature = "logging", test))]
use std::rc::Rc;

#[cfg(any(feature = "logging", test))]
use rustc_hash::FxHashSet;

use crate::modules::{
    RegisteredModule, ScannedDataWithPath, registered_modules,
};
use crate::scanner::ScannedData;

pub(crate) enum ExtractEvent<'a> {
    Extracted(&'a dyn RegisteredModule, &'a Path, &'a [u8]),
    Finished(&'a Path),
}

enum StackItem<'a> {
    Extracted(ScannedDataWithPath<'a>, &'static dyn RegisteredModule, usize),
    Finished(PathBuf),
}

/// Tracks extraction statistics and heap memory usage during DFS extraction.
#[cfg(any(feature = "logging", test))]
#[derive(Default, Debug)]
struct ExtractionStats {
    extracted_files: usize,
    total_extracted_bytes: usize,
    current_memory: usize,
    peak_memory: usize,
    live_allocations: FxHashSet<*const Vec<u8>>,
}

#[cfg(any(feature = "logging", test))]
impl ExtractionStats {
    fn on_item_extracted(&mut self, item: &ScannedDataWithPath) {
        self.extracted_files += 1;
        self.total_extracted_bytes += item.data.len();

        if let ScannedData::Vec { data, .. } = &item.data
            && self.live_allocations.insert(Rc::as_ptr(data))
        {
            self.current_memory += data.capacity();
            self.peak_memory = self.peak_memory.max(self.current_memory);
        }
    }

    fn on_item_dropped(&mut self, item: &ScannedDataWithPath) {
        if let ScannedData::Vec { data, .. } = &item.data
            && Rc::strong_count(data) == 1
            && self.live_allocations.remove(&Rc::as_ptr(data))
        {
            self.current_memory -= data.capacity();
        }
    }
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
        crate::init_logger();
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
    /// 1. With [`ExtractEvent::Extracted`] when the file is popped from the stack.
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
        #[cfg(feature = "logging")]
        let mut stats = ExtractionStats::default();

        // Extract top-level sub-files from the original data and push them
        // onto the LIFO stack (in reverse order so the first extracted file is
        // popped first).
        self.extract_children(
            &ScannedData::Slice(data),
            None,
            1,
            &mut stack,
            #[cfg(feature = "logging")]
            &mut stats,
        );

        let mut result = ControlFlow::Continue(());

        while let Some(item) = stack.pop() {
            match item {
                StackItem::Extracted(item, module, depth) => {
                    // Notify the caller that this file has been extracted.
                    if let ControlFlow::Break(b) =
                        callback(ExtractEvent::Extracted(
                            module,
                            &item.path,
                            item.data.as_ref(),
                        ))
                    {
                        result = ControlFlow::Break(b);
                        break;
                    }

                    // Push a `Finished` marker onto the stack *before* extracting
                    // any children from `item.data`. Because `stack` is LIFO, any
                    // children pushed by `extract_children` below will sit on top
                    // of this `Finished` marker and will be popped and processed
                    // first. Once all descendants of `item` have been processed,
                    // this `Finished` marker will be popped and
                    // `ExtractEvent::Finished` will be emitted for `item.path`.
                    stack.push(StackItem::Finished(item.path.clone()));

                    if depth < self.max_depth {
                        self.extract_children(
                            &item.data,
                            Some(&item.path),
                            depth + 1,
                            &mut stack,
                            #[cfg(feature = "logging")]
                            &mut stats,
                        );
                    }

                    #[cfg(feature = "logging")]
                    stats.on_item_dropped(&item);
                }
                StackItem::Finished(path) => {
                    if let ControlFlow::Break(b) =
                        callback(ExtractEvent::Finished(&path))
                    {
                        result = ControlFlow::Break(b);
                        break;
                    }
                }
            }
        }

        #[cfg(feature = "logging")]
        if stats.extracted_files > 0 {
            log::info!("Extracted files: {}", stats.extracted_files);
            log::info!(
                "Total extracted bytes: {}",
                stats.total_extracted_bytes
            );
            log::info!("Peak extraction memory: {} bytes", stats.peak_memory);
        }

        result
    }

    fn extract_children<'a>(
        &self,
        data: &ScannedData<'a>,
        parent_path: Option<&Path>,
        depth: usize,
        stack: &mut Vec<StackItem<'a>>,
        #[cfg(feature = "logging")] stats: &mut ExtractionStats,
    ) {
        for module in registered_modules() {
            let extract_fn = match module.extract_fn() {
                Some(f) => f,
                None => continue,
            };
            if let Ok(mut children) = extract_fn(data) {
                if let Some(path) = parent_path
                    && !path.as_os_str().is_empty()
                {
                    for child in children.iter_mut() {
                        child.path = path.join(&child.path);
                    }
                }
                stack.extend(children.into_iter().rev().map(|child| {
                    #[cfg(feature = "logging")]
                    stats.on_item_extracted(&child);
                    StackItem::Extracted(child, module, depth)
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ExtractionStats;
    use crate::modules::ScannedDataWithPath;
    use crate::scanner::ScannedData;

    #[test]
    fn test_extraction_stats_memory_tracking() {
        let mut stats = ExtractionStats::default();

        // A zero-copy slice should count towards extracted files and bytes,
        // but not heap memory.
        let slice_item = ScannedDataWithPath {
            path: PathBuf::from("slice.bin"),
            data: ScannedData::from_slice(&[0u8; 64]),
        };
        stats.on_item_extracted(&slice_item);
        assert_eq!(stats.extracted_files, 1);
        assert_eq!(stats.total_extracted_bytes, 64);
        assert_eq!(stats.current_memory, 0);
        assert_eq!(stats.peak_memory, 0);
        stats.on_item_dropped(&slice_item);
        drop(slice_item);

        // A heap-allocated Vec buffer should be tracked in current and peak memory.
        let mut buf1 = Vec::with_capacity(256);
        buf1.resize(100, 0xaa);
        let cap1 = buf1.capacity();
        let parent_item = ScannedDataWithPath {
            path: PathBuf::from("inner.zip"),
            data: ScannedData::from_vec(buf1),
        };
        stats.on_item_extracted(&parent_item);
        assert_eq!(stats.extracted_files, 2);
        assert_eq!(stats.total_extracted_bytes, 164);
        assert_eq!(stats.current_memory, cap1);
        assert_eq!(stats.peak_memory, cap1);

        // Two sub-slices sharing the parent's `Rc<Vec<u8>>` should not double-count
        // the underlying heap allocation.
        let child_slice1 = ScannedDataWithPath {
            path: PathBuf::from("inner.zip/a.bin"),
            data: parent_item.data.slice(0..40).unwrap(),
        };
        let child_slice2 = ScannedDataWithPath {
            path: PathBuf::from("inner.zip/b.bin"),
            data: parent_item.data.slice(40..100).unwrap(),
        };
        stats.on_item_extracted(&child_slice1);
        stats.on_item_extracted(&child_slice2);
        assert_eq!(stats.extracted_files, 4);
        assert_eq!(stats.total_extracted_bytes, 264);
        assert_eq!(stats.current_memory, cap1);
        assert_eq!(stats.peak_memory, cap1);

        // A newly decompressed child buffer adds to current and peak memory.
        let mut buf2 = Vec::with_capacity(512);
        buf2.resize(300, 0xbb);
        let cap2 = buf2.capacity();
        let child_vec = ScannedDataWithPath {
            path: PathBuf::from("inner.zip/c.bin"),
            data: ScannedData::from_vec(buf2),
        };
        stats.on_item_extracted(&child_vec);
        assert_eq!(stats.extracted_files, 5);
        assert_eq!(stats.total_extracted_bytes, 564);
        assert_eq!(stats.current_memory, cap1 + cap2);
        assert_eq!(stats.peak_memory, cap1 + cap2);

        // Dropping the parent while child slices still hold the `Rc<Vec<u8>>`
        // keeps `cap1` live in `current_memory`.
        stats.on_item_dropped(&parent_item);
        drop(parent_item);
        assert_eq!(stats.current_memory, cap1 + cap2);

        // Dropping the first child slice still leaves one reference (`child_slice2`).
        stats.on_item_dropped(&child_slice1);
        drop(child_slice1);
        assert_eq!(stats.current_memory, cap1 + cap2);

        // Dropping the last child slice releases `cap1`.
        stats.on_item_dropped(&child_slice2);
        drop(child_slice2);
        assert_eq!(stats.current_memory, cap2);

        // Dropping the independent `child_vec` releases `cap2`, returning live
        // memory to 0 while preserving `peak_memory`.
        stats.on_item_dropped(&child_vec);
        drop(child_vec);
        assert_eq!(stats.current_memory, 0);
        assert_eq!(stats.peak_memory, cap1 + cap2);
        assert!(stats.live_allocations.is_empty());
    }
}
