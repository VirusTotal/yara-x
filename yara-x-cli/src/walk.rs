use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{io, thread};

use anyhow::Context;
use crossbeam::channel::{Sender, TryRecvError};
use crossterm::tty::IsTty;
use globwalk::FileType;
use superconsole::{Component, Lines, SuperConsole};

/// Walks a path recursively and runs a given function for each file.
///
/// ```text
/// let mut walker = DirWalker::new();
///
/// walker.walk(
///     // This is the path to walk.
///     ".",
///     // This function is called for each file.
///     |file_path| {
///         // ... do something with the file
///         Ok(())
///     },
///     // This function is called with any error found during the walk.
///     |err| {
///         Ok(())
///     }
/// ).unwrap();
/// ```
pub struct DirWalker<'a> {
    filters: Vec<String>,
    max_depth: Option<usize>,
    metadata_filter: Option<Box<dyn Fn(Metadata) -> bool + Send + 'a>>,
}

impl<'a> DirWalker<'a> {
    pub fn new() -> Self {
        Self { filters: Vec::new(), max_depth: None, metadata_filter: None }
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
    pub fn filter(&mut self, filter: &str) -> &mut Self {
        self.filters.push(filter.to_string());
        self
    }

    /// Sets a filter based in file metadata.
    ///
    /// The specified function receives the file metadata associated with a
    /// file and must return `false` if the file should be ignored or `true``
    /// if otherwise.
    pub fn metadata_filter(
        &mut self,
        filter: impl Fn(Metadata) -> bool + Send + 'a,
    ) -> &mut Self {
        self.metadata_filter = Some(Box::new(filter));
        self
    }

    /// Sets a maximum depth while traversing the directory tree.
    ///
    /// When the maximum depth is 0 only the files that reside in the given
    /// directory are processed, subdirectories are not processed. By default
    /// subdirectories are traversed without depth limits.
    pub fn max_depth(&mut self, n: usize) -> &mut Self {
        self.max_depth = Some(n);
        self
    }

    /// Walk the given path recursively, calling `f` for every file.
    ///
    /// The `e` function is called with any error that occurs during the walk,
    /// including errors returned by `f` itself. `e` must return `Ok(())` for
    /// continuing the walk or `Err` for aborting.
    pub fn walk<F, E>(&self, path: &Path, mut f: F, mut e: E)
    where
        F: FnMut(&Path) -> anyhow::Result<()>,
        E: FnMut(anyhow::Error) -> anyhow::Result<()>,
    {
        if path.is_file() {
            match path
                .metadata()
                .with_context(|| format!("can't open {}", path.display()))
            {
                Ok(metadata) => {
                    if self.pass_metadata_filter(metadata) {
                        if let Err(err) = f(path) {
                            let _ = e(err);
                        }
                    }
                }
                Err(err) => {
                    let _ = e(err);
                }
            };
            return;
        }

        let path = match path
            .canonicalize()
            .with_context(|| format!("can't open {}", path.display()))
        {
            Ok(path) => path,
            Err(err) => {
                let _ = e(err);
                return;
            }
        };

        let mut builder = if self.filters.is_empty() {
            globwalk::GlobWalkerBuilder::from_patterns(path, &["**"])
        } else {
            globwalk::GlobWalkerBuilder::from_patterns(
                path,
                self.filters.iter().as_ref(),
            )
        };

        builder = builder.file_type(FileType::FILE);

        if let Some(max_depth) = self.max_depth {
            builder = builder.max_depth(max_depth + 1);
        }

        for entry in builder.build().unwrap() {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    if matches!(e(err.into()), Err(_)) {
                        return;
                    } else {
                        continue;
                    }
                }
            };

            match entry.metadata() {
                Ok(metadata) => {
                    if self.pass_metadata_filter(metadata) {
                        if let Err(err) = f(entry.path()) {
                            if matches!(e(err), Err(_)) {
                                return;
                            }
                        }
                    }
                }
                Err(err) => {
                    if matches!(e(err.into()), Err(_)) {
                        return;
                    }
                }
            }
        }
    }

    fn pass_metadata_filter(&self, metadata: Metadata) -> bool {
        self.metadata_filter.as_ref().map(|f| f(metadata)).unwrap_or(true)
    }
}

/// Walks a path recursively and runs a given function for each file.
///
/// <br>
///
/// The function receives four arguments: the file's path, a state of some
/// type `S` that implements the [`Component`] trait, an output channel that
/// the function can use for writing messages to the console (its type is
/// &[`Sender<Message>`]), and a mutable reference to some type `T` returned
/// by the thread initialization function.
///
/// <br>
///
/// Multiple files are processed in parallel by different threads. Glob filters
/// can be used for processing only those files whose path matches certain
/// patterns. The thread initialization function is executed when each thread
/// is started, and the value of type `T` returned by the initialization
/// function is owned by the thread and dropped when the thread finishes.
///
/// <br>
///
/// The function should not write directly to `stdout` or `stderr`, it should
/// use the output channel instead. The state object is shared by all the
/// threads and can be used for storing global stats like number of files
/// processed.
///
/// # Examples
///
/// ```text
/// let mut walker = ParDirWalker::new();
///
/// walker.run(
///     // The path to be walked.
///     "."
///     // The first argument is the initial state. This must have some type
///     // `S` that implements the `Component` trait.
///     state
///     // This is the thread initialization function. This is called once
///     // per thread, and each thread will own the value returned by this
///     // function. A mutable reference to this value is passed as the
///     // last argument to the next function.
///     || {
///         scanner.Scanner::new(rules)
///     },
///     // This function is called for each file, `state` is a reference to
///     // the initial state (it's type is `&S`), `output` is of type
///     // `Sender<Message>`.
///     |file_path, state, output, scanner| {
///         scanner.scan_file(file_path);
///     }
/// ).unwrap();
/// ```
pub(crate) struct ParDirWalker<'a> {
    num_threads: Option<u8>,
    walker: DirWalker<'a>,
}

impl<'a> ParDirWalker<'a> {
    /// Creates a [`ParallelWalk`].
    pub fn new() -> Self {
        Self { walker: DirWalker::new(), num_threads: None }
    }

    /// Sets the number of threads used.
    ///
    /// By default the number of threads is determined by the number of CPUs
    /// in the current host.
    pub fn num_threads(&mut self, n: u8) -> &mut Self {
        self.num_threads = Some(n);
        self
    }

    /// Sets a maximum depth while traversing the directory tree.
    ///
    /// When the maximum depth is 0 only the files that reside in the given
    /// directory are processed, subdirectories are not processed. By default
    /// subdirectories are traversed without depth limits.
    pub fn max_depth(&mut self, n: usize) -> &mut Self {
        self.walker.max_depth(n);
        self
    }

    /// Adds a glob pattern that controls which files will be processed.
    ///
    /// See [`DirWalker::filter`] for details.
    pub fn filter(&mut self, filter: &str) -> &mut Self {
        self.walker.filter(filter);
        self
    }

    pub fn metadata_filter(
        &mut self,
        filter: impl Fn(Metadata) -> bool + Send + 'a,
    ) -> &mut Self {
        self.walker.metadata_filter(filter);
        self
    }

    /// Runs `func` on every file.
    ///
    /// See [`ParDirWalk`] for details.
    pub fn walk<S, T, I, F, E>(
        &mut self,
        path: &Path,
        state: S,
        init: I,
        func: F,
        e: E,
    ) -> thread::Result<()>
    where
        S: Component + Send + Sync,
        I: Fn() -> T + Send + Copy + Sync,
        F: Fn(PathBuf, &S, &Sender<Message>, &mut T) -> anyhow::Result<()>
            + Send
            + Sync
            + Copy,
        E: Fn(anyhow::Error, &Sender<Message>) -> anyhow::Result<()>
            + Send
            + Copy,
    {
        // Use the given num_threads or compute it based on available
        // parallelism.
        let num_threads = if let Some(num_threads) = self.num_threads {
            num_threads as usize
        } else {
            thread::available_parallelism().map(usize::from).unwrap_or(32)
        };

        crossbeam::scope(|s| {
            let mut threads = Vec::with_capacity(num_threads);

            // Channel that will contain the paths of the files that need to
            // be processed by `func`.
            let (paths_send, paths_recv) =
                crossbeam::channel::bounded::<PathBuf>(128);

            // Channel where `func` will put the lines that it wants to show
            // in the console.
            let (msg_send, msg_recv) =
                crossbeam::channel::unbounded::<Message>();

            let state = Arc::new(state);

            // Spawn the threads that will do the actual job. These threads
            // will obtain file paths from the paths channel and call `func`.
            for _ in 0..num_threads {
                let paths_recv = paths_recv.clone();
                let msg_sender = msg_send.clone();
                let state = state.clone();
                threads.push(s.spawn(move |_| {
                    let mut per_thread_obj = init();
                    for path in paths_recv {
                        let res = func(
                            path.to_path_buf(),
                            &state,
                            &msg_sender,
                            &mut per_thread_obj,
                        );
                        if let Err(err) = res {
                            if matches!(e(err, &msg_sender), Err(_)) {
                                let _ = msg_sender.send(Message::Abort);
                            }
                        }
                    }
                }));
            }

            // Span a thread that walks the directory and puts file paths in
            // the channel.
            threads.push(s.spawn(move |_| {
                self.walker.walk(
                    path,
                    |file_path| Ok(paths_send.send(file_path.to_path_buf())?),
                    |err| {
                        if let Err(err) = e(err, &msg_send) {
                            Err(err)
                        } else {
                            Ok(())
                        }
                    },
                );
            }));

            let mut console = if cfg!(feature = "logging") {
                None
            } else {
                // `console` will be `None` if either stdout or stderr is not a tty
                // (for example when any of them are redirected to a file).
                if io::stdout().is_tty() {
                    SuperConsole::new()
                } else {
                    None
                }
            };

            loop {
                match msg_recv.try_recv() {
                    Ok(Message::Abort) => {
                        break;
                    }
                    Ok(Message::Info(s)) => {
                        if let Some(console) = console.as_mut() {
                            console.emit(
                                Lines::from_colored_multiline_string(
                                    s.as_str(),
                                ),
                            );
                        } else {
                            println!("{}", s)
                        }
                    }
                    Ok(Message::Error(s)) => {
                        if let Some(console) = console.as_mut() {
                            console.emit(
                                Lines::from_colored_multiline_string(
                                    s.as_str(),
                                ),
                            );
                        } else {
                            eprintln!("{}", s)
                        }
                    }
                    Err(TryRecvError::Empty) => {
                        sleep(Duration::from_secs_f64(0.3));
                    }
                    Err(TryRecvError::Disconnected) => {
                        break;
                    }
                }

                if let Some(console) = console.as_mut() {
                    console.render(state.as_ref()).unwrap();
                }
            }

            if let Some(console) = console {
                console.finalize(state.as_ref()).unwrap();
            }
        })
    }
}

pub enum Message {
    Info(String),
    Error(String),
    Abort,
}

impl Message {
    pub fn as_str(&self) -> &str {
        match self {
            Message::Info(s) => s,
            Message::Error(s) => s,
            Message::Abort => "abort",
        }
    }
}
