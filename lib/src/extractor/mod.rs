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
    #[cfg(feature = "logging")]
    clock: quanta::Clock,
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

        Self {
            max_depth: 1,
            #[cfg(feature = "logging")]
            clock: quanta::Clock::new(),
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

        #[cfg(feature = "logging")]
        let extract_start = self.clock.raw();
        #[cfg(feature = "logging")]
        let mut excluded_time = 0_u64;
        #[cfg(feature = "logging")]
        let mut extracted_files = 0_usize;

        let mut stack = Vec::new();
        let mut result = ControlFlow::Continue(());

        self.extract_children(&ScannedData::Slice(data), None, 1, &mut stack);

        while let Some(item) = stack.last_mut() {
            match item {
                StackItem::Iterator { iter, module, parent_path, depth } => {
                    #[cfg(feature = "logging")]
                    let file_start = self.clock.raw();

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

                    #[cfg(feature = "logging")]
                    let file_end = self.clock.raw();

                    #[cfg(feature = "logging")]
                    {
                        extracted_files += 1;
                        log::debug!(
                            "Extracted {:?} (module: `{}`, size: {} bytes) in {:?}",
                            path,
                            module.name(),
                            data.as_ref().len(),
                            self.clock.delta(file_start, file_end),
                        );
                    }

                    // Notify the caller that this file has been extracted.
                    let flow = callback(ExtractEvent::Extracted(
                        module,
                        &path,
                        data.as_ref(),
                    ));

                    // Exclude time spent logging and inside `callback` (e.g.,
                    // scanning the extracted data) from total extraction time.
                    #[cfg(feature = "logging")]
                    {
                        excluded_time = excluded_time.saturating_add(
                            self.clock.raw().saturating_sub(file_end),
                        );
                    }

                    if let ControlFlow::Break(b) = flow {
                        result = ControlFlow::Break(b);
                        break;
                    }

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
                        #[cfg(feature = "logging")]
                        let cb_start = self.clock.raw();

                        let flow = callback(ExtractEvent::Finished(&path));

                        #[cfg(feature = "logging")]
                        {
                            excluded_time = excluded_time.saturating_add(
                                self.clock.raw().saturating_sub(cb_start),
                            );
                        }

                        if let ControlFlow::Break(b) = flow {
                            result = ControlFlow::Break(b);
                            break;
                        }
                    }
                }
            }
        }

        drop(stack);

        #[cfg(feature = "logging")]
        if extracted_files > 0 {
            let extract_end = self.clock.raw();
            log::info!(
                "Extraction time: {:?} (files: {})",
                self.clock.delta(
                    extract_start.saturating_add(excluded_time),
                    extract_end,
                ),
                extracted_files,
            );
        }

        result
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

    #[cfg(all(feature = "logging", not(feature = "stderr-logs")))]
    mod logging_tests {
        use std::cell::RefCell;
        use std::ops::ControlFlow;
        use std::sync::Once;
        use std::time::Duration;

        use super::{Extractor, create_zip};

        struct ThreadLocalLogger;

        thread_local! {
            static LOGS: RefCell<Vec<(log::Level, String)>> =
                const { RefCell::new(Vec::new()) };
        }

        impl log::Log for ThreadLocalLogger {
            fn enabled(&self, metadata: &log::Metadata) -> bool {
                metadata.target().starts_with("yara_x::extractor")
            }

            fn log(&self, record: &log::Record) {
                if self.enabled(record.metadata()) {
                    LOGS.with(|logs| {
                        logs.borrow_mut()
                            .push((record.level(), record.args().to_string()));
                    });
                }
            }

            fn flush(&self) {}
        }

        static LOGGER: ThreadLocalLogger = ThreadLocalLogger;
        static INIT: Once = Once::new();

        fn init_test_logger() {
            INIT.call_once(|| {
                log::set_logger(&LOGGER).unwrap();
                log::set_max_level(log::LevelFilter::Debug);
            });
            LOGS.with(|logs| logs.borrow_mut().clear());
        }

        fn take_logs() -> Vec<(log::Level, String)> {
            LOGS.with(|logs| std::mem::take(&mut *logs.borrow_mut()))
        }

        fn parse_debug_duration(s: &str) -> Duration {
            if let Some(ns) = s.strip_suffix("ns") {
                Duration::from_secs_f64(ns.parse::<f64>().unwrap() * 1e-9)
            } else if let Some(us) = s.strip_suffix("µs") {
                Duration::from_secs_f64(us.parse::<f64>().unwrap() * 1e-6)
            } else if let Some(ms) = s.strip_suffix("ms") {
                Duration::from_secs_f64(ms.parse::<f64>().unwrap() * 1e-3)
            } else if let Some(secs) = s.strip_suffix('s') {
                Duration::from_secs_f64(secs.parse::<f64>().unwrap())
            } else {
                panic!("unexpected duration format: {s}");
            }
        }

        #[test]
        fn test_extractor_logs_nothing_when_no_files_extracted() {
            init_test_logger();

            let extractor = Extractor::new();
            let _ = extractor.extract(b"not a container", |_, _, _| {
                ControlFlow::<()>::Continue(())
            });

            assert!(take_logs().is_empty());
        }

        #[test]
        fn test_extractor_logs_per_file_and_total_excluding_callback() {
            init_test_logger();

            let inner_zip = create_zip(&[("sub.txt", b"hello")]);
            let outer_zip = create_zip(&[
                ("inner.zip", &inner_zip),
                ("top.txt", b"world"),
            ]);

            let mut extractor = Extractor::new();
            extractor.max_depth(2);

            let _ = extractor.extract(&outer_zip, |_module, _path, _bytes| {
                // Simulate 80ms of scan work per extracted file (240ms total).
                std::thread::sleep(Duration::from_millis(80));
                ControlFlow::<()>::Continue(())
            });

            let logs = take_logs();
            assert_eq!(logs.len(), 4);

            // First 3 logs are per-file DEBUG logs.
            for (level, msg) in &logs[..3] {
                assert_eq!(*level, log::Level::Debug);
                assert!(msg.starts_with("Extracted "), "unexpected: {msg}");
                assert!(msg.contains("module: `zip`"), "unexpected: {msg}");
            }

            // Final log is the INFO summary with total extraction time.
            let (level, summary) = &logs[3];
            assert_eq!(*level, log::Level::Info);
            let rest = summary
                .strip_prefix("Extraction time: ")
                .expect("missing prefix");
            let dur_str = rest
                .strip_suffix(" (files: 3)")
                .expect("missing files count suffix");

            let logged_duration = parse_debug_duration(dur_str);
            assert!(
                logged_duration < Duration::from_millis(150),
                "callback sleep leaked into extraction time: {logged_duration:?}",
            );
        }

        #[test]
        fn test_extractor_logs_total_on_early_break() {
            init_test_logger();

            let zip_data = create_zip(&[
                ("file1.txt", b"one"),
                ("file2.txt", b"two"),
                ("file3.txt", b"three"),
            ]);

            let extractor = Extractor::new();
            let res = extractor
                .extract(&zip_data, |_module, _path, _bytes| {
                    ControlFlow::Break("stop")
                });

            assert_eq!(res, ControlFlow::Break("stop"));

            let logs = take_logs();
            assert_eq!(logs.len(), 2);
            assert_eq!(logs[0].0, log::Level::Debug);
            assert_eq!(logs[1].0, log::Level::Info);
            assert!(
                logs[1].1.ends_with(" (files: 1)"),
                "unexpected summary: {}",
                logs[1].1
            );
        }
    }
}
