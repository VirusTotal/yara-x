use std::borrow::Cow;
use std::cmp::min;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Error};
use clap::{
    arg, value_parser, Arg, ArgAction, ArgMatches, Command, ValueEnum,
};
use crossbeam::channel::Sender;
use itertools::Itertools;
use superconsole::style::Stylize;
use superconsole::{Component, Line, Lines, Span};
#[cfg(feature = "rules-profiling")]
use yansi::Color::Green;
use yansi::Color::{Cyan, Red, Yellow};
use yansi::Paint;

use yara_x::errors::ScanError;
use yara_x::{MetaValue, Patterns, Rule, Rules, ScanOptions, Scanner};

use crate::commands::{
    compilation_args, compile_rules, get_external_vars,
    meta_file_value_parser, path_with_namespace_parser,
    truncate_with_ellipsis,
};
use crate::walk::Message;
use crate::{help, walk};

#[derive(Clone, ValueEnum)]
enum OutputFormats {
    /// Default output format.
    Text,
    /// Newline delimited JSON (i.e: one JSON object per line).
    Ndjson,
    /// JSON output (i.e: one JSON object for all results, only printed out at the end).
    Json,
}

#[rustfmt::skip]
pub fn scan() -> Command {
    super::command("scan")
        .about("Scan a file or directory")
        .long_about(help::SCAN_LONG_HELP)
        .arg(
            Arg::new("[NAMESPACE:]RULES_PATH")
                .required(true)
                .help("Path to a YARA source file or directory (optionally prefixed with a namespace)")
                .value_parser(path_with_namespace_parser)
                .action(ArgAction::Append)
        )
        .arg(
            arg!(<TARGET_PATH>)
                .help("Path to the file or directory that will be scanned")
                .value_parser(value_parser!(PathBuf))
        )
        .args(itertools::merge(compilation_args(), [
            arg!(-C --"compiled-rules")
                .help("Indicate that RULES_PATH is a file with compiled rules")
                .long_help(help::COMPILED_RULES_LONG_HELP),
            arg!(-c --"count")
                .help("Print only the number of matches per file"),
            arg!(--"disable-console-logs")
                .help("Disable printing console log messages"),
            arg!(--"max-matches-per-pattern" <MATCHES>)
                .help("Maximum number of matches per pattern")
                .long_help(help::MAX_MATCHES_PER_PATTERN_LONG_HELP)
                .value_parser(value_parser!(usize)),
            arg!(-x --"module-data")
                .help("Pass FILE's content as extra data to MODULE")
                .long_help(help::MODULE_DATA_LONG_HELP)
                .required(false)
                .value_name("MODULE=FILE")
                .value_parser(meta_file_value_parser)
                .action(ArgAction::Append),
            arg!(-n --"negate")
                .help("Print non-satisfied rules only"),
            arg!(--"no-mmap")
                .help("Don't use memory-mapped files")
                .long_help(help::NO_MMAP_LONG_HELP),
            arg!(-o --"output-format" <FORMAT>)
                .help("Output format for results")
                .long_help(help::OUTPUT_FORMAT_LONG_HELP)
                .value_parser(value_parser!(OutputFormats)),
            arg!(-m --"print-meta")
                .help("Print rule metadata"),
            arg!(-e --"print-namespace")
                .help("Print rule namespace"),
            arg!(-s --"print-strings" [N])
                .help("Print matching patterns")
                .long_help(help::SCAN_PRINT_STRING_LONG_HELP)
                .default_missing_value("120")
                .require_equals(true)
                .value_parser(value_parser!(usize)),
            arg!(-g --"print-tags")
                .help("Print rule tags"),
            arg!(--"profiling")
                .help("Show profiling information"),
            arg!(-r --"recursive" [MAX_DEPTH])
                .help("Scan directories recursively")
                .long_help(help::SCAN_RECURSIVE_LONG_HELP)
                .default_missing_value("1000")
                .require_equals(true)
                .value_parser(value_parser!(usize)),
            arg!(--"scan-list")
                .help("Indicate that TARGET_PATH is a file containing the paths to be scanned")
                .long_help(help::SCAN_LIST_LONG_HELP),
            arg!(-z --"skip-larger" <FILE_SIZE>)
                .help("Skip files larger than the given size")
                .value_parser(value_parser!(u64)),
            arg!(-t --"tag" <TAG>)
                .help("Print only rules tagged as TAG")
                .value_parser(value_parser!(String)),
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .value_parser(value_parser!(u8).range(1..)),
            arg!(-a --"timeout" <SECONDS>)
                .help("Abort scanning after the given number of seconds")
                .value_parser(value_parser!(u64).range(1..))

    ]))
}

#[cfg(feature = "rules-profiling")]
struct ProfilingData {
    pub namespace: String,
    pub rule: String,
    pub condition_exec_time: Duration,
    pub pattern_matching_time: Duration,
    pub total_time: Duration,
}

#[cfg(feature = "rules-profiling")]
impl From<yara_x::ProfilingData<'_>> for ProfilingData {
    fn from(value: yara_x::ProfilingData) -> Self {
        Self {
            namespace: value.namespace.to_string(),
            rule: value.rule.to_string(),
            condition_exec_time: value.condition_exec_time,
            pattern_matching_time: value.pattern_matching_time,
            total_time: value.condition_exec_time
                + value.pattern_matching_time,
        }
    }
}

struct OutputOptions {
    count_only: bool,
    include_namespace: bool,
    include_meta: bool,
    include_tags: bool,
    include_strings: Option<usize>,
    only_tag: Option<String>,
}

impl From<&ArgMatches> for OutputOptions {
    fn from(args: &ArgMatches) -> Self {
        Self {
            count_only: args.get_flag("count"),
            include_namespace: args.get_flag("print-namespace"),
            include_meta: args.get_flag("print-meta"),
            include_tags: args.get_flag("print-tags"),
            include_strings: args.get_one::<usize>("print-strings").cloned(),
            only_tag: args.get_one::<String>("tag").cloned(),
        }
    }
}

pub fn exec_scan(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let mut rules_path = args
        .get_many::<(Option<String>, PathBuf)>("[NAMESPACE:]RULES_PATH")
        .unwrap();

    let target_path = args.get_one::<PathBuf>("TARGET_PATH").unwrap();
    let compiled_rules = args.get_flag("compiled-rules");
    let profiling = args.get_flag("profiling");
    let num_threads = args.get_one::<u8>("threads");
    let skip_larger = args.get_one::<u64>("skip-larger");
    let disable_console_logs = args.get_flag("disable-console-logs");
    let scan_list = args.get_flag("scan-list");
    let recursive = args.get_one::<usize>("recursive");
    let no_mmap = args.get_flag("no-mmap");
    let max_matches_per_pattern =
        args.get_one::<usize>("max-matches-per-pattern");

    let timeout =
        args.get_one::<u64>("timeout").map(|t| Duration::from_secs(*t));

    let external_vars = get_external_vars(args);

    let metadata = args
        .get_many::<(String, PathBuf)>("module-data")
        .into_iter()
        .flatten()
        // collect to eagerly call the parser on each element
        .collect::<Vec<_>>();

    if profiling && !cfg!(feature = "rules-profiling") {
        bail!(
            "{} requires that YARA-X is built with profiling support.\n\nUse {}.",
            Paint::bold("--profiling"),
            Paint::cyan("`cargo build --release --features=rules-profiling`")
        );
    }

    if recursive.is_some() && target_path.is_file() {
        bail!(
            "can't use '{}' when <TARGET_PATH> is a file",
            Paint::bold("--recursive")
        );
    }

    let rules = if compiled_rules {
        if rules_path.len() > 1 {
            bail!(
                "can't use '{}' with more than one RULES_PATH",
                Paint::bold("--compiled-rules")
            );
        }

        let (namespace, rules_path) = rules_path.next().unwrap();

        if namespace.is_some() {
            bail!(
                "can't use namespace with '{}'",
                Paint::bold("--compiled-rules")
            );
        }

        let file = File::open(rules_path)
            .with_context(|| format!("can not open {:?}", &rules_path))?;

        let rules = Rules::deserialize_from(file)?;

        // If the user is defining external variables, make sure that these
        // variables are valid. A scanner is created only with the purpose
        // of validating the variables.
        if let Some(ref vars) = external_vars {
            let mut scanner = Scanner::new(&rules);
            for (ident, value) in vars {
                scanner.set_global(ident.as_str(), value)?;
            }
        }

        rules
    } else {
        // With `take()` we pass the external variables to `compile_rules`,
        // while leaving a `None` in `external_vars`. This way external
        // variables are not set again in the scanner.
        compile_rules(rules_path, args, config)?
    };

    let rules_ref = &rules;

    let mut w = if scan_list {
        walk::ParWalker::file_list(target_path)
    } else {
        walk::ParWalker::path(target_path)
    };

    if let Some(num_threads) = num_threads {
        w.num_threads(*num_threads);
    }

    if let Some(max_file_size) = skip_larger {
        w.metadata_filter(|metadata| metadata.len() <= *max_file_size);
    }

    w.max_depth(*recursive.unwrap_or(&0));

    let start_time = Instant::now();
    let state = ScanState::new(start_time);

    let all_metadata = metadata
        .into_iter()
        .map(|(module_full_name, metadata_path)| {
            std::fs::read(Path::new(metadata_path))
                .map(|meta| (module_full_name.to_string(), meta))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let output_handler = match args.get_one::<OutputFormats>("output-format") {
        Some(OutputFormats::Json) => {
            Box::new(JsonOutputHandler::new(args.into()))
                as Box<dyn OutputHandler>
        }
        Some(OutputFormats::Ndjson) => {
            Box::new(NdjsonOutputHandler::new(args.into()))
        }
        None | Some(OutputFormats::Text) => {
            Box::new(TextOutputHandler::new(args.into()))
        }
    };

    #[cfg(feature = "rules-profiling")]
    let slowest_rules: Mutex<Vec<ProfilingData>> = Mutex::new(Vec::new());

    w.walk(
        state,
        // Initialization
        |_, _| {
            let mut scanner = Scanner::new(rules_ref);

            if let Some(ref vars) = external_vars {
                for (ident, value) in vars {
                    // It's ok to use `unwrap()`, this can not fail because
                    // we already verified that external variables are correct.
                    scanner.set_global(ident.as_str(), value).unwrap();
                }
            }

            if no_mmap {
                scanner.use_mmap(false);
            }

            if let Some(max_matches_per_pattern) = max_matches_per_pattern {
                scanner.max_matches_per_pattern(*max_matches_per_pattern);
            }

            scanner
        },
        // File handler. Called for every file found while walking the path.
        |state, output, file_path, scanner| {
            if !disable_console_logs {
                let output = output.clone();
                let path = file_path.display().to_string();
                scanner.console_log(move |msg| {
                    output
                        .send(Message::Error(format!("{}: {}", &path.paint(Yellow), msg.paint(Yellow))))
                        .unwrap();
                });
            }

            let elapsed_time = Instant::elapsed(&start_time);

            if let Some(timeout) = timeout {
                // Discount the already elapsed time from the timeout passed to
                // the scanner.
                if let Some(timeout) = timeout.checked_sub(elapsed_time) {
                    scanner.set_timeout(timeout);
                } else {
                    return Err(Error::from(ScanError::Timeout));
                }
            }

            let now = Instant::now();

            state
                .files_in_progress
                .lock()
                .unwrap()
                .push((file_path.to_path_buf(), now));

            let scan_options = all_metadata.iter().fold(
                ScanOptions::new(),
                |acc, (module_name, meta)| {
                    acc.set_module_metadata(module_name, meta)
                },
            );

            let scan_results = scanner
                .scan_file_with_options(file_path.as_path(), scan_options)
                .with_context(|| format!("scanning {:?}", &file_path));

            state
                .files_in_progress
                .lock()
                .unwrap()
                .retain(|(p, _)| !file_path.eq(p));

            let scan_results = scan_results?;
            let mut wanted_rules = match args.get_flag("negate") {
                true => Box::new(scan_results.non_matching_rules())
                    as Box<dyn ExactSizeIterator<Item=Rule>>,
                false => Box::new(scan_results.matching_rules()),
            };

            state.num_scanned_files.fetch_add(1, Ordering::Relaxed);

            // The number of matching files is incremented only if
            // `on_file_scanned` returns `true`, which indicates that the
            // match is actually included in the output and not ignored.
            if output_handler.on_file_scanned(
                &file_path,
                &mut wanted_rules,
                output,
            ) {
                state.num_matching_files.fetch_add(1, Ordering::Relaxed);
            }

            Ok(())
        },
        // Finalization
        #[allow(unused_variables)]
        |scanner, _| {
            #[cfg(feature = "rules-profiling")]
            if profiling {
                let mut mer = slowest_rules.lock().unwrap();
                for profiling_data in scanner.slowest_rules(1000) {
                    if let Some(r) = mer.iter_mut().find(|r| {
                        r.rule == profiling_data.rule
                            && r.namespace == profiling_data.namespace
                    }) {
                        r.condition_exec_time +=
                            profiling_data.condition_exec_time;
                        r.pattern_matching_time +=
                            profiling_data.pattern_matching_time;
                        r.total_time += profiling_data.condition_exec_time
                            + profiling_data.pattern_matching_time;
                    } else {
                        mer.push(profiling_data.into());
                    }
                }
            }
        },
        // Walk done.
        |output| output_handler.on_done(output),
        // Error handler
        |err, output| {
            let error = err.to_string();
            let root_cause = err.root_cause().to_string();
            let msg = if error != root_cause {
                format!(
                    "{}{error}: {root_cause}",
                    "error: ".paint(Red).bold(),
                )
            } else {
                format!("{}{error}", "error: ".paint(Red).bold())
            };

            let _ = output.send(Message::Error(msg));

            // In case of timeout walk is aborted.
            if let Ok(scan_err) = err.downcast::<ScanError>() {
                if matches!(scan_err, ScanError::Timeout) {
                    return Err(scan_err.into());
                }
            }

            Ok(())
        },
    )
        .unwrap();

    #[cfg(feature = "rules-profiling")]
    if profiling {
        let mut mer = slowest_rules.lock().unwrap();

        println!("\n«««««««««««« PROFILING INFORMATION »»»»»»»»»»»»");

        if mer.is_empty() {
            println!(
                "\n{}",
                "No profiling information gathered, all rules were very fast."
                    .paint(Green)
                    .bold()
            );
        } else {
            // Sort by total time in descending order.
            mer.sort_by(|a, b| b.total_time.cmp(&a.total_time));
            println!("\n{}", "Slowest rules:".paint(Red).bold());
            for r in mer.iter().take(10) {
                println!(
                    r#"
* rule                 : {}
  namespace            : {}
  pattern matching     : {:?}
  condition evaluation : {:?}
  TOTAL                : {:?}"#,
                    r.rule,
                    r.namespace,
                    r.pattern_matching_time,
                    r.condition_exec_time,
                    r.total_time
                );
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ScanState {
    start_time: Instant,
    num_scanned_files: AtomicUsize,
    num_matching_files: AtomicUsize,
    files_in_progress: Mutex<Vec<(PathBuf, Instant)>>,
}

impl ScanState {
    fn new(start_time: Instant) -> Self {
        Self {
            start_time,
            num_scanned_files: AtomicUsize::new(0),
            num_matching_files: AtomicUsize::new(0),
            files_in_progress: Mutex::new(Vec::new()),
        }
    }
}

// superconsole will not print any string that contains Unicode characters that
// are spaces but are not the ASCII space character, so we replace them all.
// See https://github.com/VirusTotal/yara-x/pull/163 for discussion.
fn replace_whitespace(path: &Path) -> Cow<'_, str> {
    let mut s = path.to_string_lossy();
    if s.chars().any(|c| c != ' ' && c.is_whitespace()) {
        let mut r = String::with_capacity(s.len());
        for c in s.chars() {
            if c.is_whitespace() {
                r.push(' ')
            } else {
                r.push(c)
            }
        }
        s = Cow::Owned(r);
    }
    s
}

impl Component for ScanState {
    fn draw_unchecked(
        &self,
        dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<Lines> {
        let mut lines = Lines::new();

        lines.push(Line::from_iter([Span::new_unstyled(
            "─".repeat(dimensions.width),
        )?]));

        let scanned = format!(
            " {} file(s) scanned in {:.1}s. ",
            self.num_scanned_files.load(Ordering::Relaxed),
            self.start_time.elapsed().as_secs_f32()
        );

        let num_matching_files =
            self.num_matching_files.load(Ordering::Relaxed);

        let matched = format!("{num_matching_files} file(s) matched.");

        lines.push(Line::from_iter([
            Span::new_unstyled(scanned)?,
            Span::new_styled(if num_matching_files > 0 {
                matched.red().bold()
            } else {
                matched.green().bold()
            })?,
        ]));

        if matches!(mode, superconsole::DrawMode::Normal) {
            lines.push(Line::from_iter([Span::new_unstyled(
                "╶".repeat(dimensions.width),
            )?]));

            for (file, start_time) in
                self.files_in_progress.lock().unwrap().iter()
            {
                // The length of the elapsed time is 7 characters.
                let max_path_with = dimensions.width.saturating_sub(7);

                let (path, path_width) = truncate_with_ellipsis(
                    replace_whitespace(file),
                    max_path_with,
                );

                let spaces =
                    " ".repeat(max_path_with.saturating_sub(path_width));

                let line = format!(
                    "{}{}{:6.1}s",
                    path,
                    spaces,
                    Instant::elapsed(start_time).as_secs_f32()
                );
                lines.push(Line::from_iter([Span::new_unstyled(line)?]))
            }
        }

        Ok(lines)
    }
}

use crate::config::Config;
use output_handler::*;

mod output_handler {
    use super::*;
    use std::collections::HashMap;
    use yara_x::PatternKind;

    #[derive(serde::Serialize)]
    struct PatternJson {
        identifier: String,
        offset: usize,
        r#match: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        xor_key: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plaintext: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct RuleJson {
        identifier: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        strings: Option<Vec<PatternJson>>,
    }

    #[derive(serde::Serialize)]
    struct JsonOutput<'a> {
        path: &'a str,
        rules: &'a [RuleJson],
    }

    #[derive(serde::Serialize)]
    struct JsonCountOutput<'a> {
        path: &'a str,
        count: usize,
    }

    fn rules_to_json(
        output_options: &OutputOptions,
        scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
    ) -> Vec<RuleJson> {
        scan_results
            .filter(move |rule| {
                output_options.only_tag.as_ref().is_none_or(|only_tag| {
                    rule.tags().any(|tag| tag.identifier() == only_tag)
                })
            })
            .map(move |rule| RuleJson {
                identifier: rule.identifier().to_string(),
                namespace: output_options
                    .include_namespace
                    .then(|| rule.namespace().to_string()),
                meta: output_options
                    .include_meta
                    .then(|| rule.metadata().into_json()),
                tags: output_options.include_tags.then(|| {
                    rule.tags()
                        .map(|t| t.identifier().to_string())
                        .collect::<Vec<_>>()
                }),
                strings: output_options
                    .include_strings
                    .map(|limit| patterns_to_json(rule.patterns(), limit)),
            })
            .collect()
    }

    fn patterns_to_json(
        patterns: Patterns<'_, '_>,
        string_limit: usize,
    ) -> Vec<PatternJson> {
        patterns
            .flat_map(|pattern| {
                let identifier = pattern.identifier();

                pattern.matches().map(|pattern_match| {
                    let match_range = pattern_match.range();
                    let match_data = pattern_match.data();

                    let more_bytes_message =
                        match match_data.len().saturating_sub(string_limit) {
                            0 => None,
                            n => Some(format!(" ... {n} more bytes")),
                        };

                    let string = match_data
                        .iter()
                        .take(string_limit)
                        .flat_map(|char| char.escape_ascii())
                        .map(|c| c as char)
                        .chain(
                            more_bytes_message
                                .iter()
                                .flat_map(|msg| msg.chars()),
                        )
                        .collect::<String>();

                    PatternJson {
                        identifier: identifier.to_owned(),
                        offset: match_range.start,
                        r#match: string,
                        xor_key: pattern_match.xor_key(),
                        plaintext: pattern_match.xor_key().map(|xor_key| {
                            match_data
                                .iter()
                                .take(string_limit)
                                .map(|char| char ^ xor_key)
                                .flat_map(|char| char.escape_ascii())
                                .map(|char| char as char)
                                .collect()
                        }),
                    }
                })
            })
            .collect()
    }

    /// Trait implemented by all output handlers like [`TextOutputHandler`],
    /// [`NdjsonOutputHandler`] and [`JsonOutputHandler`].
    pub(super) trait OutputHandler: Sync {
        /// Called for each scanned file.
        ///
        /// Must return `true` when the file was included in the output,
        /// or `false` if the file was ignored.
        fn on_file_scanned(
            &self,
            file_path: &Path,
            scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
            output: &Sender<Message>,
        ) -> bool;
        /// Called when the last file has been scanned.
        fn on_done(&self, _output: &Sender<Message>);
    }

    pub(super) struct TextOutputHandler {
        output_options: OutputOptions,
    }

    impl TextOutputHandler {
        pub(super) fn new(output_options: OutputOptions) -> Self {
            Self { output_options }
        }
    }

    impl OutputHandler for TextOutputHandler {
        fn on_file_scanned(
            &self,
            file_path: &Path,
            scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
            output: &Sender<Message>,
        ) -> bool {
            if self.output_options.count_only {
                output
                    .send(Message::Info(format!(
                        "{}: {}",
                        &file_path.display().to_string(),
                        scan_results.len()
                    )))
                    .unwrap();
                return true;
            }

            let mut result = false;

            for matching_rule in scan_results {
                if let Some(ref only_tag) = self.output_options.only_tag {
                    if !matching_rule
                        .tags()
                        .any(|tag| tag.identifier() == only_tag)
                    {
                        continue;
                    }
                }

                result = true;

                let mut msg = if self.output_options.include_namespace {
                    format!(
                        "{}:{}",
                        matching_rule.namespace().paint(Cyan).bold(),
                        matching_rule.identifier().paint(Cyan).bold()
                    )
                } else {
                    format!(
                        "{}",
                        matching_rule.identifier().paint(Cyan).bold()
                    )
                };

                let tags = matching_rule.tags();

                if self.output_options.include_tags && !tags.is_empty() {
                    msg.push_str(" [");
                    for (pos, tag) in tags.with_position() {
                        msg.push_str(tag.identifier());
                        if !matches!(pos, itertools::Position::Last) {
                            msg.push(',');
                        }
                    }
                    msg.push(']');
                }

                let metadata = matching_rule.metadata();

                if self.output_options.include_meta && !metadata.is_empty() {
                    msg.push_str(" [");
                    for (pos, (m, v)) in metadata.with_position() {
                        match v {
                            MetaValue::Bool(v) => {
                                msg.push_str(&format!("{m}={v}"))
                            }
                            MetaValue::Integer(v) => {
                                msg.push_str(&format!("{m}={v}"))
                            }
                            MetaValue::Float(v) => {
                                msg.push_str(&format!("{m}={v}"))
                            }
                            MetaValue::String(v) => {
                                msg.push_str(&format!("{m}=\"{v}\""))
                            }
                            MetaValue::Bytes(v) => msg.push_str(&format!(
                                "{}=\"{}\"",
                                m,
                                v.escape_ascii()
                            )),
                        };
                        if !matches!(pos, itertools::Position::Last) {
                            msg.push(',');
                        }
                    }
                    msg.push(']');
                }

                msg.push(' ');
                msg.push_str(&file_path.display().to_string());

                if let Some(limit) = self.output_options.include_strings {
                    for p in matching_rule.patterns() {
                        for m in p.matches() {
                            let match_range = m.range();
                            let match_data = m.data();

                            let mut match_str = format!(
                                "\n{:#x}:{}:{}",
                                match_range.start,
                                match_range.len(),
                                p.identifier(),
                            );

                            match m.xor_key() {
                                Some(k) => {
                                    match_str.push_str(
                                        format!(" xor({k:#x},").as_str(),
                                    );
                                    for b in &match_data
                                        [..min(match_data.len(), limit)]
                                    {
                                        for c in (b ^ k).escape_ascii() {
                                            match_str.push_str(
                                                format!("{}", c as char)
                                                    .as_str(),
                                            );
                                        }
                                    }
                                    match_str.push_str("): ");
                                }
                                _ => {
                                    match_str.push_str(": ");
                                }
                            }

                            let data =
                                &match_data[..min(match_data.len(), limit)];

                            match p.kind() {
                                PatternKind::Text | PatternKind::Regexp => {
                                    for b in data {
                                        for c in b.escape_ascii() {
                                            match_str.push_str(
                                                format!("{}", c as char)
                                                    .as_str(),
                                            );
                                        }
                                    }
                                }
                                PatternKind::Hex => {
                                    for (pos, b) in data.iter().with_position()
                                    {
                                        match_str.push_str(
                                            format!("{b:02x}").as_str(),
                                        );
                                        if !matches!(
                                            pos,
                                            itertools::Position::Last
                                        ) {
                                            match_str.push(' ');
                                        }
                                    }
                                }
                            }

                            if match_data.len() > limit {
                                match_str.push_str(
                                    format!(
                                        " ... {} more bytes",
                                        match_data.len().saturating_sub(limit)
                                    )
                                    .as_str(),
                                );
                            }

                            msg.push_str(&match_str)
                        }
                    }
                }

                output.send(Message::Info(msg)).unwrap();
            }

            result
        }

        fn on_done(&self, _output: &Sender<Message>) {
            // Nothing to do here.
        }
    }

    pub(super) struct NdjsonOutputHandler {
        output_options: OutputOptions,
    }

    impl NdjsonOutputHandler {
        pub(super) fn new(output_options: OutputOptions) -> Self {
            Self { output_options }
        }
    }

    impl OutputHandler for NdjsonOutputHandler {
        fn on_file_scanned(
            &self,
            file_path: &Path,
            scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
            output: &Sender<Message>,
        ) -> bool {
            let path = file_path.to_str().unwrap();

            if self.output_options.count_only {
                let json = serde_json::to_string(&JsonCountOutput {
                    count: scan_results.len(),
                    path,
                })
                .unwrap();

                output.send(Message::Info(json)).unwrap();
                return true;
            }

            let matching_rules =
                rules_to_json(&self.output_options, scan_results);

            let line = serde_json::to_string(&JsonOutput {
                path,
                rules: matching_rules.as_slice(),
            })
            .unwrap();

            output.send(Message::Info(line)).unwrap();

            // Return `false` if `matching_rules` is empty.
            !matching_rules.is_empty()
        }

        fn on_done(&self, _output: &Sender<Message>) {
            // Nothing to do here.
        }
    }

    #[derive(serde::Serialize, Clone)]
    struct StringJson {
        identifier: String,
        offset: usize,
        r#match: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        xor_key: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plaintext: Option<String>,
    }

    #[derive(serde::Serialize, Clone)]
    struct MatchJson {
        rule: String,
        file: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<HashMap<String, serde_json::Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        strings: Option<Vec<StringJson>>,
    }

    #[derive(serde::Serialize)]
    struct OutputJson {
        version: String,
        matches: Vec<MatchJson>,
    }

    pub(super) struct JsonOutputHandler {
        output_options: OutputOptions,
        output_buffer: std::sync::Arc<std::sync::Mutex<Vec<MatchJson>>>,
    }

    impl JsonOutputHandler {
        pub(super) fn new(output_options: OutputOptions) -> Self {
            let output_buffer = Default::default();
            Self { output_options, output_buffer }
        }
    }

    fn patterns_to_string_jsons(
        patterns: Patterns<'_, '_>,
        string_limit: usize,
    ) -> Vec<StringJson> {
        patterns
            .flat_map(|pattern| {
                let identifier = pattern.identifier();

                pattern.matches().map(|pattern_match| {
                    let match_range = pattern_match.range();
                    let match_data = pattern_match.data();

                    let more_bytes_message =
                        match match_data.len().saturating_sub(string_limit) {
                            0 => None,
                            n => Some(format!(" ... {n} more bytes")),
                        };

                    let string = match_data
                        .iter()
                        .take(string_limit)
                        .flat_map(|char| char.escape_ascii())
                        .map(|c| c as char)
                        .chain(
                            more_bytes_message
                                .iter()
                                .flat_map(|msg| msg.chars()),
                        )
                        .collect::<String>();

                    StringJson {
                        identifier: identifier.to_owned(),
                        offset: match_range.start,
                        r#match: string.clone(),
                        xor_key: pattern_match.xor_key(),
                        plaintext: pattern_match.xor_key().map(|xor_key| {
                            match_data
                                .iter()
                                .take(string_limit)
                                .map(|char| char ^ xor_key)
                                .flat_map(|char| char.escape_ascii())
                                .map(|char| char as char)
                                .collect()
                        }),
                    }
                })
            })
            .collect()
    }

    impl OutputHandler for JsonOutputHandler {
        fn on_file_scanned(
            &self,
            file_path: &Path,
            scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
            _output: &Sender<Message>,
        ) -> bool {
            let path = file_path
                .canonicalize()
                .ok()
                .as_ref()
                .and_then(|absolute| absolute.to_str())
                .map(|s| s.to_string())
                .unwrap_or_default();

            // prepare the increment *outside* the critical section
            let matching_rules = scan_results
                .filter(|rule| {
                    self.output_options.only_tag.as_ref().is_none_or(
                        |only_tag| {
                            rule.tags().any(|tag| tag.identifier() == only_tag)
                        },
                    )
                })
                .map(|rule| {
                    let meta = self.output_options.include_meta.then(|| {
                        // Group metadata by key to handle duplicate keys.
                        let mut grouped: HashMap<
                            String,
                            Vec<serde_json::Value>,
                        > = HashMap::new();

                        for (meta_key, meta_val) in rule.metadata() {
                            let key = meta_key.to_owned();
                            let val = serde_json::to_value(meta_val).expect(
                                "Derived Serialize impl should never fail",
                            );
                            grouped.entry(key).or_default().push(val);
                        }

                        // Single values stay as-is, multiple values become arrays.
                        grouped
                            .into_iter()
                            .map(|(k, mut v)| {
                                let val = if v.len() == 1 {
                                    v.pop().unwrap()
                                } else {
                                    serde_json::Value::Array(v)
                                };
                                (k, val)
                            })
                            .collect::<HashMap<_, _>>()
                    });

                    let file = path.clone();

                    let tags = self.output_options.include_tags.then(|| {
                        rule.tags()
                            .map(|t| t.identifier().to_string())
                            .collect::<Vec<_>>()
                    });

                    let strings = self.output_options.include_strings.map(
                        |strings_limit| {
                            patterns_to_string_jsons(
                                rule.patterns(),
                                strings_limit,
                            )
                        },
                    );

                    MatchJson {
                        rule: rule.identifier().to_string(),
                        meta,
                        file,
                        tags,
                        strings,
                    }
                });

            {
                let mut output = self.output_buffer.lock().unwrap();
                output.extend(matching_rules);
                !output.is_empty()
            }
        }

        fn on_done(&self, output: &Sender<Message>) {
            let matches = {
                let mut lock = self.output_buffer.lock().unwrap();
                std::mem::take(&mut *lock)
            };
            let version = env!("CARGO_PKG_VERSION").to_string();

            let rendered_json = match self.output_options.count_only {
                true => {
                    let json_output = matches
                        .iter()
                        .fold(HashMap::new(), |mut acc, it| {
                            *acc.entry(&it.file).or_insert(0) += 1;
                            acc
                        })
                        .into_iter()
                        .map(|(path, count)| JsonCountOutput { path, count })
                        .collect::<Vec<_>>();

                    serde_json::to_string_pretty(&json_output)
                }
                false => {
                    let output_json = OutputJson { matches, version };

                    serde_json::to_string_pretty(&output_json)
                }
            }
            .expect("Derived Serialize impl should never fail");

            output.send(Message::Info(rendered_json)).unwrap();
        }
    }
}
