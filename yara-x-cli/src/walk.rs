use crossbeam::channel::{Sender, TryRecvError};
use crossterm::tty::IsTty;
use globset::{GlobBuilder, GlobMatcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{io, thread};
use superconsole::{Component, Lines, SuperConsole};
use walkdir::WalkDir;
use yansi::Color::Red;

/// Walks a path recursively and runs a given function for each file.
///
/// <br>
///
/// The function receives four arguments: the file's path, a state of some type
/// `S` that implements the [`Component`] trait, an output channel that the
/// function can use for writing messages to the console (its type is
/// &[`Sender<Message>`]), and a mutable reference to some type `T` returned by
/// the thread initialization function.
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
/// let mut walker = ParallelWalk::new(".");
///
/// walker.run(
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
pub(crate) struct ParallelWalk {
    path: PathBuf,
    filters: Vec<GlobMatcher>,
    num_threads: Option<u8>,
    max_depth: Option<usize>,
}

impl ParallelWalk {
    /// Creates a [`ParallelWalk`] that walks the given `path`.
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            filters: Vec::new(),
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
        self.filters.push(
            GlobBuilder::new(filter)
                .literal_separator(true)
                .build()
                .unwrap()
                .compile_matcher(),
        );
        self
    }

    fn should_process(&self, path: &Path) -> bool {
        if self.filters.is_empty() {
            true
        } else {
            self.filters.iter().any(|pattern| pattern.is_match(path))
        }
    }

    /// Runs `func` on every file.
    ///
    /// See [`ParallelWalk`] for details.
    pub fn run<S, T, I, F>(
        &mut self,
        state: S,
        init: I,
        func: F,
    ) -> thread::Result<()>
    where
        S: Component + Send + Sync,
        I: Fn() -> T + Send + Copy,
        F: Fn(PathBuf, &S, &Sender<Message>, &mut T) + Send + Sync + Copy,
    {
        // Use the given num_threads or compute it based on available
        // parallelism.
        let num_threads = if let Some(num_threads) = self.num_threads {
            num_threads as usize
        } else {
            std::thread::available_parallelism().map(usize::from).unwrap_or(32)
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
                        func(
                            path.to_path_buf(),
                            &state,
                            &msg_sender,
                            &mut per_thread_obj,
                        );
                    }
                }));
            }

            // Span a thread that walks the directory and puts file paths in
            // the channel.
            threads.push(s.spawn(move |_| {
                let mut entries = WalkDir::new(&self.path);

                if let Some(max_depth) = self.max_depth {
                    entries = entries.max_depth(max_depth + 1);
                }

                // Walk the directory and put file paths in the channel.
                for entry in entries.into_iter() {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(err) => {
                            msg_send
                                .send(Message::Error(format!(
                                    "{} {}",
                                    Red.paint("error:").bold(),
                                    err
                                )))
                                .unwrap();
                            continue;
                        }
                    };

                    // Call `func` only with paths that matches at least one
                    // pattern, if any.
                    if self.should_process(entry.path()) {
                        // The call to metadata can fail, for example when the
                        // directory contains a symbolic link to a file that
                        // doesn't exist. We simple ignore those error and
                        // continue.
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.is_file() {
                                paths_send
                                    .send(entry.path().to_path_buf())
                                    .unwrap();
                            }
                        }
                    }
                }
            }));

            // `console` will be `None` if either stdout or stderr is not a tty
            // (for example when any of them are redirected to a file).
            let mut console =
                if io::stdout().is_tty() { SuperConsole::new() } else { None };

            loop {
                match msg_recv.try_recv() {
                    Ok(message) => {
                        if let Some(console) = console.as_mut() {
                            console.emit(
                                Lines::from_colored_multiline_string(
                                    message.as_str(),
                                ),
                            );
                        } else {
                            match message {
                                Message::Info(m) => println!("{}", m),
                                Message::Error(m) => eprintln!("{}", m),
                            }
                        }
                    }
                    Err(TryRecvError::Empty) => {
                        sleep(Duration::from_secs_f64(0.2));
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
}

impl Message {
    pub fn as_str(&self) -> &str {
        match self {
            Message::Info(s) => &s,
            Message::Error(s) => &s,
        }
    }
}
