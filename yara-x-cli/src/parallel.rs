use anyhow::Context;
use clap::parser::ValuesRef;
use globset::GlobBuilder;
use std::fs::metadata;
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Walks the given `path` recursively and runs `func` for every file.
///
/// Multiple files will be processed in parallel, the `threads` argument
/// specified how many threads are used. If `threads` is `None` the number of
/// threads will be computed based on the number of CPUs.
///
/// `max_depth` controls how deep it goes when traversing a directory, where
/// 0 means that only the files directly in the directory will be processed,
/// without entering in subdirectories.
///
/// `filters` are a set of glob patterns that indicate which files should be
/// processed, based on their path and file names. For a file to be scanned
/// its path must match at least one of the filters.
pub fn for_each_file<F>(
    path: &Path,
    num_threads: Option<NonZeroU8>,
    max_depth: Option<usize>,
    filters: Option<ValuesRef<String>>,
    func: F,
) -> anyhow::Result<()>
where
    F: Fn(PathBuf) -> anyhow::Result<()> + Send + Sync + Copy,
{
    // Use the given num_threads if not None, or compute it based on available
    // parallelism.
    let num_threads = u8::from(if let Some(num_threads) = num_threads {
        num_threads
    } else {
        std::thread::available_parallelism()
            .map(|n| NonZeroU8::try_from(n).unwrap())
            .unwrap_or(NonZeroU8::new(32).unwrap())
    });

    let mut patterns = Vec::new();

    // Build the provided glob filters, or use the default ones which are
    // `**/*.yar` and `**/*.yar`
    if let Some(filters) = filters {
        for f in filters {
            patterns.push(
                GlobBuilder::new(f)
                    .literal_separator(true)
                    .build()?
                    .compile_matcher(),
            )
        }
    } else {
        patterns.push(
            GlobBuilder::new("**/*.yar")
                .literal_separator(true)
                .build()
                .unwrap()
                .compile_matcher(),
        );
        patterns.push(
            GlobBuilder::new("**/*.yara")
                .literal_separator(true)
                .build()
                .unwrap()
                .compile_matcher(),
        );
    }

    let metadata = metadata(path)
        .with_context(|| format!("can not read `{}`", path.display()))?;

    if metadata.is_dir() {
        let (sender, receiver) = crossbeam::channel::bounded::<PathBuf>(128);

        crossbeam::scope(|s| {
            let mut threads = Vec::with_capacity(num_threads as usize);

            // Spawn the threads. Each thread will enter in a loop that takes
            // a path from the channel and call `func` until the channel is
            // closed.
            for _ in 0..num_threads {
                let receiver = receiver.clone();
                threads.push(s.spawn(move |_| {
                    while let Ok(path) = receiver.recv() {
                        func(path.to_path_buf())?;
                    }
                    Ok::<(), anyhow::Error>(())
                }));
            }

            let mut entries = WalkDir::new(path);

            if let Some(max_depth) = max_depth {
                entries = entries.max_depth(max_depth + 1);
            }

            // Walk the directory and put file paths in the channel.
            for entry in entries.into_iter().filter_map(|e| e.ok()) {
                // Call `func` only with paths that matches at least one pattern.
                if patterns
                    .iter()
                    .any(|pattern| pattern.is_match(entry.path()))
                {
                    // The call to metadata can fail, for example when the directory
                    // contains a symbolic link to a file that doesn't exist. We
                    // simple ignore those error and continue.
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
    } else if patterns.iter().any(|pattern| pattern.is_match(path)) {
        func(path.to_path_buf())?;
    }

    Ok(())
}
