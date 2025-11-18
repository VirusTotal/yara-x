use std::fmt::Debug;
use std::fs::{File, Metadata};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, thread};

use anyhow::{bail, Context};
use crossbeam::channel::{RecvTimeoutError, SendError, Sender};
use crossterm::tty::IsTty;
use globwalk::FileType;
use superconsole::{Component, Lines, SuperConsole};

/// Walks the files in a directory or a text file containing file paths,
/// running a given function for each file.
///
/// ```text
/// let mut walker = Walker::path(".");
///
/// walker.walk(
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
pub struct Walker<'a> {
    /// Path to the directory that will be walked, or the text file
    /// containing a list of paths.
    path: &'a Path,
    /// If true, `path` is a file containing a list of paths, one per line.
    file_list: bool,
    /// A list of filters applied to the files being walked, those that don't
    /// match at least one of the filters are ignored.
    filters: Vec<String>,
    /// When walking a directory, the maximum recursion depth. `None` means
    /// no limit.
    max_depth: Option<usize>,
    /// An optional function that allows filtering the walked files based on
    /// their metadata.
    metadata_filter: Option<Box<dyn Fn(Metadata) -> bool + Send + 'a>>,
}

impl<'a> Walker<'a> {
    /// Creates a [`Walker`] that walks a directory.
    ///
    /// `path` can also point to an individual file instead of a directory.
    pub fn path(path: &'a Path) -> Self {
        Self {
            path,
            filters: Vec::new(),
            file_list: false,
            max_depth: None,
            metadata_filter: None,
        }
    }

    /// Creates a [`Walker`] that walks the files listed in a text file
    /// containing one path per line.
    ///
    /// `path` points to the text file that contains the paths to be walked.
    pub fn file_list(path: &'a Path) -> Self {
        Self {
            path,
            filters: Vec::new(),
            file_list: true,
            max_depth: None,
            metadata_filter: None,
        }
    }

    /// Adds a glob pattern that controls which files will be processed.
    ///
    /// When one or more filters are added, only those files with a path that
    /// matches at least one of the filters will be processed. By default, all
    /// files are processed.
    ///
    /// Patterns can contain the following wildcards:
    ///
    /// - `?` matches any single character.
    ///
    /// - `*` matches any sequence of characters, except the path separator.
    ///
    /// - `**` matches any sequence of characters, including the path separator.
    ///
    /// - `[...]` matches any character inside the brackets. Can also specify ranges of
    ///   characters (e.g. `[0-9]`, `[a-z]`)
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
    /// directory are processed, subdirectories are not processed. By default,
    /// subdirectories are traversed without depth limits.
    pub fn max_depth(&mut self, n: usize) -> &mut Self {
        self.max_depth = Some(n);
        self
    }

    /// Walks the directory or list of files, calling `f` for every file.
    ///
    /// The `e` function is called with any error that occurs during the walk,
    /// including errors returned by `f` itself. `e` must return `Ok(())` for
    /// continuing the walk or `Err` for aborting.
    pub fn walk<F, E>(self, mut f: F, mut e: E) -> anyhow::Result<()>
    where
        F: FnMut(&Path) -> anyhow::Result<()>,
        E: FnMut(anyhow::Error) -> anyhow::Result<()>,
    {
        let metadata =
            match self.path.metadata().with_context(|| {
                format!("can't open `{}`", self.path.display())
            }) {
                Ok(metadata) => metadata,
                Err(err) => {
                    return e(err);
                }
            };

        if self.file_list {
            if !metadata.is_file() {
                bail!("`{}` is not a file", self.path.display())
            }
            self.walk_file_list(f, e)
        } else {
            if metadata.is_file() {
                if self.pass_metadata_filter(metadata) {
                    if let Err(err) = f(self.path) {
                        return e(err);
                    }
                };
                return Ok(());
            }
            self.walk_dir(f, e)
        }
    }

    fn walk_file_list<F, E>(self, mut f: F, mut e: E) -> anyhow::Result<()>
    where
        F: FnMut(&Path) -> anyhow::Result<()>,
        E: FnMut(anyhow::Error) -> anyhow::Result<()>,
    {
        let file = File::open(self.path)?;

        for line in io::BufReader::new(file).lines() {
            let path = PathBuf::from(line?);
            let metadata = match path
                .metadata()
                .with_context(|| format!("can't open `{}`", path.display()))
            {
                Ok(metadata) => metadata,
                Err(err) => match e(err) {
                    Ok(_) => continue,
                    Err(err) => return Err(err),
                },
            };
            if self.pass_metadata_filter(metadata) {
                if let Err(err) = f(&path) {
                    e(err)?
                }
            }
        }

        Ok(())
    }

    fn walk_dir<F, E>(&self, mut f: F, mut e: E) -> anyhow::Result<()>
    where
        F: FnMut(&Path) -> anyhow::Result<()>,
        E: FnMut(anyhow::Error) -> anyhow::Result<()>,
    {
        // Strip the ./ prefix (.\ in Windows), if present. Except for ".",
        // "./" and ".\". This is a workaround for a bug in globwalk that
        // causes a panic.
        // https://github.com/VirusTotal/yara-x/issues/280
        // https://github.com/Gilnaa/globwalk/issues/28
        let path = if self.path.as_os_str().len() > 2 {
            self.path
                .strip_prefix(if cfg!(target_os = "windows") {
                    r#".\"#
                } else {
                    "./"
                })
                .unwrap_or(self.path)
        } else {
            self.path
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

        for entry in builder.build()? {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    if let Err(err) = e(err.into()) {
                        return Err(err);
                    } else {
                        continue;
                    }
                }
            };

            match entry.metadata() {
                Ok(metadata) => {
                    if self.pass_metadata_filter(metadata) {
                        if let Err(err) = f(entry.path()) {
                            e(err)?
                        }
                    }
                }
                Err(err) => e(err.into())?,
            }
        }

        Ok(())
    }

    fn pass_metadata_filter(&self, metadata: Metadata) -> bool {
        self.metadata_filter.as_ref().map(|f| f(metadata)).unwrap_or(true)
    }
}

/// Walks a directory or a text file containing file paths, calling a given
/// function for each file.
///
/// This is similar to [`Walker`] but uses multiple threads for processing
/// multiple files simultaneously.
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
/// <br>
///
/// When an error occurs, both while walking the directory tree, or when the
/// user-provided function returns an error, the error is passed to an error
/// handling function that can decide whether the walk should continue or be
/// aborted. The walk continues if the error handling function returns `Ok`
/// and aborts if it returns `Err`.
///
/// # Examples
///
/// ```text
/// let mut walker = ParWalker::path(".");
///
/// walker.walk(
///     // The initial state. This must have some type `S` that implements the
///     // `Component` trait.
///     state
///     // This is the thread initialization function. This is called once
///     // per thread, and each thread will own the value returned by this
///     // function. A mutable reference to this value is passed as the
///     // last argument to the next function.
///     |state, output| {
///         scanner.Scanner::new(rules)
///     },
///     // This function is called for each file, `state` is a reference to
///     // the initial state (it's type is `&S`), `output` is of type
///     // `Sender<Message>`.
///     |state, output, file_path, scanner| {
///         scanner.scan_file(file_path);
///     }
///     // This function is called by each thread after every file is
///     // scanned.
///     |scanner| {
///         // Do some final action with the scanner before it is released.
///     }
///     // This function is called with every error that occurs during the
///     // walk.
///     |err, output| {
///         // Do something with `err`, like sending it to `output`.
///         // The walk aborts if this returns `Err`.
///     }
/// ).unwrap();
/// ```
pub(crate) struct ParWalker<'a> {
    num_threads: Option<u8>,
    walker: Walker<'a>,
}

impl<'a> ParWalker<'a> {
    /// Creates a [`ParWalker`] that walks a directory.
    ///
    /// `path` can also point to an individual file instead of a directory.
    pub fn path(path: &'a Path) -> Self {
        Self { walker: Walker::path(path), num_threads: None }
    }

    /// Creates a [`ParWalker`] that walks the files listed in a text file
    /// containing one path per line.
    ///
    /// `path` points to the text file that contains the paths to be walked.
    pub fn file_list(path: &'a Path) -> Self {
        Self { walker: Walker::file_list(path), num_threads: None }
    }

    /// Sets the number of threads used.
    ///
    /// By default, the number of threads is determined by the number of CPUs
    /// in the current host.
    pub fn num_threads(&mut self, n: u8) -> &mut Self {
        self.num_threads = Some(n);
        self
    }

    /// Sets a maximum depth while traversing the directory tree.
    ///
    /// When the maximum depth is 0 only the files that reside in the given
    /// directory are processed, subdirectories are not processed. By default,
    /// subdirectories are traversed without depth limits.
    pub fn max_depth(&mut self, n: usize) -> &mut Self {
        self.walker.max_depth(n);
        self
    }

    /// Adds a glob pattern that controls which files will be processed.
    ///
    /// See [`Walker::filter`] for details.
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

    /// Runs `action` on every file.
    ///
    /// See [`ParWalker`] for details.
    pub fn walk<S, T, I, A, F, D, E>(
        self,
        state: S,
        init: I,
        action: A,
        finalize: F,
        on_walk_done: D,
        error: E,
    ) -> thread::Result<S>
    where
        S: Component + Debug + Send + Sync + 'static,
        I: Fn(&S, &Sender<Message>) -> T + Send + Copy + Sync,
        A: Fn(&S, &Sender<Message>, PathBuf, &mut T) -> anyhow::Result<()>
            + Send
            + Sync
            + Copy,
        F: Fn(&T, &Sender<Message>) + Send + Copy + Sync,
        D: Fn(&Sender<Message>),
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
                let msg_send = msg_send.clone();
                let state = state.clone();
                threads.push(s.spawn(move |_| {
                    let mut per_thread_obj = init(&state, &msg_send);
                    for path in paths_recv {
                        let res = action(
                            &state,
                            &msg_send,
                            path.to_path_buf(),
                            &mut per_thread_obj,
                        );
                        if let Err(err) = res {
                            if error(err, &msg_send).is_err() {
                                let _ = msg_send.send(Message::Abort);
                                break;
                            }
                        }
                    }
                    finalize(&per_thread_obj, &msg_send);
                }));
            }

            // Span a thread that walks the directory and puts file paths in
            // the channel.
            threads.push(s.spawn(move |_| {
                let res = self.walker.walk(
                    |file_path| Ok(paths_send.send(file_path.to_path_buf())?),
                    |err| {
                        // If an error occurs while sending the file path
                        // through the channel, abort the walk.
                        if err.is::<SendError<PathBuf>>() {
                            return Err(err);
                        }

                        // Invoke the error callback and abort the walk if the
                        // callback returns error.
                        if let Err(err) = error(err, &msg_send) {
                            let _ = msg_send.send(Message::Abort);
                            return Err(err);
                        }

                        // Keep walking the directory tree.
                        Ok(())
                    },
                );

                if let Err(err) = res {
                    if error(err, &msg_send).is_err() {
                        let _ = msg_send.send(Message::Abort);
                    }
                }
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

            // The console is rendered once every `render_period`.
            let render_period = Duration::from_secs_f64(0.150);

            output_messages(
                render_period,
                Instant::now(),
                msg_recv,
                console.as_mut(),
                state.clone(),
            );

            threads.into_iter().for_each(|thread| thread.join().unwrap());

            let (msg_send, msg_recv) =
                crossbeam::channel::bounded::<Message>(32);

            let handle = {
                let state = state.clone();
                thread::spawn(move || {
                    output_messages(
                        render_period,
                        Instant::now(),
                        msg_recv,
                        console.as_mut(),
                        state.clone(),
                    );

                    if let Some(console) = console {
                        console.finalize(state.as_ref()).unwrap();
                    }
                })
            };

            // let `on_walk_done` send messages to the console
            on_walk_done(&msg_send);

            // close the channel *before* joining the thread (`handle.join()`)
            // this sends a signal through the channel to the listening threads to disconnect
            // otherwise, trying to `handle.join()` will cause a deadlock
            std::mem::drop(msg_send);

            handle.join().unwrap();

            Arc::<S>::try_unwrap(state).unwrap()
        })
    }
}

fn output_messages<S>(
    render_period: Duration,
    last_render: Instant,
    msg_recv: crossbeam::channel::Receiver<Message>,
    console: Option<&mut SuperConsole>,
    state: Arc<S>,
) where
    S: Component,
{
    let mut console = console;
    let mut last_render = last_render;

    loop {
        match msg_recv.recv_timeout(render_period) {
            Ok(Message::Info(s)) => {
                if let Some(console) = console.as_mut() {
                    console.emit(Lines::from_colored_multiline_string(
                        s.as_str(),
                    ));
                } else {
                    println!("{s}")
                }
            }
            Ok(Message::Error(s)) => {
                if let Some(console) = console.as_mut() {
                    console.emit(Lines::from_colored_multiline_string(
                        s.as_str(),
                    ));
                } else {
                    eprintln!("{s}")
                }
            }
            Ok(Message::Abort) => {
                break;
            }
            Err(RecvTimeoutError::Disconnected) => {
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        if let Some(console) = console.as_mut() {
            if Instant::elapsed(&last_render) > render_period {
                console.render(state.as_ref()).unwrap();
                last_render = Instant::now();
            }
        }
    }
}

pub enum Message {
    Info(String),
    Error(String),
    Abort,
}
