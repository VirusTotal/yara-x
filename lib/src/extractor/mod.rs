/*! Container extractor.

This module provides the [`Extractor`] type, which unpacks archive and container
formats (e.g., ZIP archives) recursively using registered YARA modules.
*/

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::path::Path;

use crate::modules::{
    RegisteredModule, ScannedDataWithPath, registered_modules,
};
use crate::scanner::ScannedData;

/// The `callback` function is invoked for every file extracted from the main input buffer.
/// The function receives three arguments:
///
/// 1. The registered YARA module that produced the extracted data (`&dyn RegisteredModule`).
///
/// 2. The file path within the container (e.g., `Path::new("dir/file.txt")`).
///
/// 3. The extracted data as a byte slice (`&[u8]`).
///
/// # Flow Control
///
/// The callback closure returns [`std::ops::ControlFlow<B>`], giving explicit
/// control over extraction traversal and early termination:
///
/// - Returning [`std::ops::ControlFlow::Continue(())`] instructs the extractor
///   to proceed normally to the next file in the queue.
///
/// - Returning [`std::ops::ControlFlow::Break(b)`] immediately halts further
///   extraction recursion, returning `Ok(ControlFlow::Break(b))`.
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
    pub fn extract<F, B>(&self, data: &[u8], mut callback: F) -> ControlFlow<B>
    where
        F: FnMut(&dyn RegisteredModule, &Path, &[u8]) -> ControlFlow<B>,
    {
        if self.max_depth == 0 {
            return ControlFlow::Continue(());
        }

        let mut queue = VecDeque::new();
        self.extract_children(&ScannedData::Slice(data), None, 1, &mut queue);

        while let Some((item, module, depth)) = queue.pop_front() {
            if let ControlFlow::Break(b) =
                callback(module, &item.path, item.data.as_ref())
            {
                return ControlFlow::Break(b);
            }

            if depth < self.max_depth {
                self.extract_children(
                    &item.data,
                    Some(&item.path),
                    depth + 1,
                    &mut queue,
                );
            }
        }

        ControlFlow::Continue(())
    }

    fn extract_children<'a>(
        &self,
        data: &ScannedData<'a>,
        parent_path: Option<&Path>,
        depth: usize,
        queue: &mut VecDeque<(
            ScannedDataWithPath<'a>,
            &'static dyn RegisteredModule,
            usize,
        )>,
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
                queue.extend(
                    children.into_iter().map(|child| (child, module, depth)),
                );
            }
        }
    }
}
