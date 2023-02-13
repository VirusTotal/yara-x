use anyhow::Context;
use globset::{GlobBuilder, GlobMatcher};
use std::fs::metadata;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Walks a path recursively and runs a given function for each file.
///
/// Multiple files are processed in parallel by different threads. Glob filters
/// can be used for processing only those files whose path matches certain
/// patterns.
///
/// A custom initialization function is executed when each thread is started,
/// and the result of that function is passed to the function that processes
/// individual files.
///
/// # Examples
///
/// ```text
/// let mut walker = ParallelWalk::new(".");
///
/// walker.run(
///     || {
///         // A scanner is created for each thread.
///         scanner.Scanner::new(rules)
///     },
///     |scanner, file_path| {
///         // This is called for each file, `scanner` is a mutable reference
///         // to the
///         scanner.scan_file(file_path)?;
///         Ok(())
///     }
/// )
/// ```
pub(crate) struct ParallelWalk {
    path: PathBuf,
    patterns: Vec<GlobMatcher>,
    num_threads: Option<u8>,
    max_depth: Option<usize>,
}

impl ParallelWalk {
    /// Creates a [`ParallelWalk`] that walks the given `path`.
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            patterns: Vec::new(),
            num_threads: None,
            max_depth: None,
        }
    }

    /// Sets the number of threads used.
    ///
    /// By default the number of threads is determined by the number of CPUs
    /// in the current host.
    pub fn num_threads(mut self, n: u8) -> Self {
        self.num_threads = Some(n);
        self
    }

    /// Sets a maximum depth while traversing the directory tree.
    ///
    /// When the maximum depth is 0 only the files that reside in the given
    /// directory are processed, subdirectories are not processed. By default
    /// subdirectories are traversed without depth limits.
    pub fn max_depth(mut self, n: usize) -> Self {
        self.max_depth = Some(n);
        self
    }

    /// Adds a glob pattern that controls which files will be processed.
    ///
    /// When one or more filters are added, only those files with a path that
    /// matches at least one of the filters will be processed. By default all
    /// files are processed.
    ///
    /// Patterns can contains the following wildcards:
    ///
    /// - `?`      matches any single character.
    ///
    /// - `*`      matches any sequence of characters, except the path separator.
    ///
    /// - `**`     matches any sequence of characters, including the path separator.
    ///
    /// - `[...]`  matches any character inside the brackets. Can also specify ranges of
    ///          characters (e.g. `[0-9]`, `[a-z]`)
    ///
    /// - `[!...]` is the negation of `[...]`
    ///
    /// # Examples
    ///
    /// - `**/*.yara`: Files with `.yara` extension, on any directory.
    ///
    /// - `**/my_dir/*.yara`: Files directly contained in a dir named `my_dir`.
    ///
    pub fn filter(mut self, filter: &str) -> Self {
        self.patterns.push(
            GlobBuilder::new(filter)
                .literal_separator(true)
                .build()
                .unwrap()
                .compile_matcher(),
        );
        self
    }

    fn should_process(&self, path: &Path) -> bool {
        if self.patterns.is_empty() {
            true
        } else {
            self.patterns.iter().any(|pattern| pattern.is_match(path))
        }
    }

    /// Runs `func` on every file.
    ///
    /// `func` receives a `&mut T` and the file's path. `T` is the type returned
    /// by `init`, a function that is called at the start of each thread.
    pub fn run<T, I, F>(&mut self, init: I, func: F) -> anyhow::Result<()>
    where
        I: Fn() -> T + Send + Copy,
        F: Fn(&mut T, PathBuf) -> anyhow::Result<()> + Send + Sync + Copy,
    {
        // Use the given num_threads or compute it based on available
        // parallelism.
        let num_threads = if let Some(num_threads) = self.num_threads {
            num_threads as usize
        } else {
            std::thread::available_parallelism().map(usize::from).unwrap_or(32)
        };

        let metadata = metadata(&self.path).with_context(|| {
            format!("can not read `{}`", self.path.display())
        })?;

        if metadata.is_dir() {
            let (sender, receiver) =
                crossbeam::channel::bounded::<PathBuf>(128);

            crossbeam::scope(|s| {
                let mut threads = Vec::with_capacity(num_threads);

                // Spawn the threads. Each thread will enter in a loop that takes
                // a path from the channel and call `func` until the channel is
                // closed.
                for _ in 0..num_threads {
                    let receiver = receiver.clone();
                    threads.push(s.spawn(move |_| {
                        let mut ctx = init();
                        while let Ok(path) = receiver.recv() {
                            func(&mut ctx, path.to_path_buf())?;
                        }
                        Ok::<(), anyhow::Error>(())
                    }));
                }

                let mut entries = WalkDir::new(&self.path);

                if let Some(max_depth) = self.max_depth {
                    entries = entries.max_depth(max_depth + 1);
                }

                // Walk the directory and put file paths in the channel.
                for entry in entries.into_iter().filter_map(|e| e.ok()) {
                    // Call `func` only with paths that matches at least one
                    // pattern, if any.
                    if self.should_process(entry.path()) {
                        // The call to metadata can fail, for example when the
                        // directory contains a symbolic link to a file that
                        // doesn't exist. We simple ignore those error and
                        // continue.
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.is_file() {
                                sender.send(entry.path().to_path_buf())?;
                            }
                        }
                    }
                }

                // Drop the sender in order to close the channel.
                drop(sender);

                // Wait for the threads to finish.
                for thread in threads {
                    thread.join().unwrap()?
                }

                Ok::<(), anyhow::Error>(())
            })
            .unwrap()?
        } else if self.should_process(&self.path) {
            let mut ctx = init();
            func(&mut ctx, self.path.to_path_buf())?;
        }

        Ok(())
    }
}
