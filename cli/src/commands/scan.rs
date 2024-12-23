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
    compile_rules, external_var_parser, get_external_vars,
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
        // Keep options sorted alphabetically by their long name.
        // For instance, --bar goes before --foo.
        .arg(
            arg!(-C --"compiled-rules")
                .help("Indicate that RULES_PATH is a file with compiled rules")
                .long_help(help::COMPILED_RULES_LONG_HELP)
        )
        .arg(
            arg!(-c --"count")
                .help("Print only the number of matches per file")
        )
        .arg(
            arg!(-d --"define")
                .help("Define external variable")
                .long_help(help::DEFINE_LONG_HELP)
                .value_name("VAR=VALUE")
                .value_parser(external_var_parser)
                .action(ArgAction::Append)
        )
        .arg(
            arg!(--"disable-console-logs")
                .help("Disable printing console log messages")
        )
        .arg(
            arg!(-w --"disable-warnings" [WARNING_ID])
                .help("Disable warnings")
                .long_help(help::DISABLE_WARNINGS_LONG_HELP)
                .default_missing_value("all")
                .num_args(0..)
                .require_equals(true)
                .value_delimiter(',')
                .action(ArgAction::Append)
        )
        .arg(
            arg!(--"ignore-module" <MODULE>)
                .help("Ignore rules that use the specified module")
                .long_help(help::IGNORE_MODULE_LONG_HELP)
                .action(ArgAction::Append)
        )
        .arg(
            arg!(-x --"module-data")
                .help("Pass FILE's content as extra data to MODULE")
                .long_help(help::MODULE_DATA_LONG_HELP)
                .required(false)
                .value_name("MODULE=FILE")
                .value_parser(meta_file_value_parser)
                .action(ArgAction::Append)
        )
        .arg(
            arg!(-n --"negate")
                .help("Print non-satisfied rules only")
        )
        .arg(
            arg!(-o --"output-format" <FORMAT>)
                .help("Output format for results")
                .long_help(help::OUTPUT_FORMAT_LONG_HELP)
                .value_parser(value_parser!(OutputFormats))
        )
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace")
        )
        .arg(
            arg!(--"profiling")
                .help("Show profiling information")
        )
        .arg(
            arg!(-m --"print-meta")
                .help("Print rule metadata")
        )
        .arg(
            arg!(-e --"print-namespace")
                .help("Print rule namespace")
        )
        .arg(
            arg!(-s --"print-strings" [N])
                .help("Print matching patterns")
                .long_help(help::SCAN_PRINT_STRING_LONG_HELP)
                .default_missing_value("120")
                .require_equals(true)
                .value_parser(value_parser!(usize))
        )
        .arg(
            arg!(-g --"print-tags")
                .help("Print rule tags")
        )
        .arg(
            arg!(-r --"recursive" [MAX_DEPTH])
                .help("Scan directories recursively")
                .long_help(help::SCAN_RECURSIVE_LONG_HELP)
                .default_missing_value("100")
                .require_equals(true)
                .value_parser(value_parser!(usize))
        )
        .arg(
            arg!(--"relaxed-re-syntax")
                .help("Use a more relaxed syntax check while parsing regular expressions")
                .conflicts_with("compiled-rules")
        )
        .arg(
            arg!(--"scan-list")
                .help("Indicate that TARGET_PATH is a file containing the paths to be scanned")
                .long_help(help::SCAN_LIST_LONG_HELP)
        )
        .arg(
            arg!(-z --"skip-larger" <FILE_SIZE>)
                .help("Skip files larger than the given size")
                .value_parser(value_parser!(u64))
        )
        .arg(
            arg!(-t --"tag" <TAG>)
                .help("Print only rules tagged as TAG")
                .value_parser(value_parser!(String))
        )
        .arg(
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .value_parser(value_parser!(u8).range(1..))
        )
        .arg(
            arg!(-a --"timeout" <SECONDS>)
                .help("Abort scanning after the given number of seconds")
                .value_parser(value_parser!(u64).range(1..))
        )

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

pub fn exec_scan(args: &ArgMatches) -> anyhow::Result<()> {
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

    let timeout =
        args.get_one::<u64>("timeout").map(|t| Duration::from_secs(*t));

    let mut external_vars = get_external_vars(args);

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
        compile_rules(rules_path, external_vars.take(), args)?
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
            Box::new(NdJsonOutputHandler::new(args.into()))
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
        |_, output| {
            let mut scanner = Scanner::new(rules_ref);

            if !disable_console_logs {
                let output = output.clone();
                scanner.console_log(move |msg| {
                    output
                        .send(Message::Error(format!("{}", msg.paint(Yellow))))
                        .unwrap();
                });
            }

            if let Some(ref vars) = external_vars {
                for (ident, value) in vars {
                    // It's ok to use `unwrap()`, this can not fail because
                    // we already verified that external variables are correct.
                    scanner.set_global(ident.as_str(), value).unwrap();
                }
            }

            scanner
        },
        // File handler. Called for every file found while walking the path.
        |state, output, file_path, scanner| {
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
                    as Box<dyn ExactSizeIterator<Item = Rule>>,
                false => Box::new(scan_results.matching_rules()),
            };

            let matched_count = wanted_rules.len();
            output_handler.on_file_scanned(
                &file_path,
                &mut wanted_rules,
                output,
            );

            state.num_scanned_files.fetch_add(1, Ordering::Relaxed);
            if matched_count > 0 {
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
                    "{} {}: {}",
                    "error: ".paint(Red).bold(),
                    error,
                    root_cause,
                )
            } else {
                format!("{}: {}", "error: ".paint(Red).bold(), error)
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
fn replace_whitespace(path: &Path) -> Cow<str> {
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

        let matched = format!("{} file(s) matched.", num_matching_files);

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
                let path = replace_whitespace(file);
                // The length of the elapsed is 7 characters.
                let spaces = " "
                    .repeat(dimensions.width.saturating_sub(path.len() + 7));
                let line = format!(
                    "{}{}{:6.1}s",
                    truncate_with_ellipsis(path, dimensions.width - 7),
                    spaces,
                    Instant::elapsed(start_time).as_secs_f32()
                );
                lines.push(Line::from_iter([Span::new_unstyled(line)?]))
            }
        }

        Ok(lines)
    }
}

use output_handler::*;
mod output_handler {
    use super::*;
    use std::collections::HashMap;

    #[derive(serde::Serialize)]
    struct JsonPattern {
        identifier: String,
        offset: usize,
        r#match: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        xor_key: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plaintext: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct JsonRule {
        identifier: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        strings: Option<Vec<JsonPattern>>,
    }

    #[derive(serde::Serialize)]
    struct JsonOutput<'a> {
        path: &'a str,
        rules: &'a [JsonRule],
    }

    #[derive(serde::Serialize)]
    struct JsonCountOutput<'a> {
        path: &'a str,
        count: usize,
    }

    fn rules_to_json(
        output_options: &OutputOptions,
        scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
    ) -> Vec<JsonRule> {
        scan_results
            .filter(move |rule| {
                output_options.only_tag.as_ref().map_or(true, |only_tag| {
                    rule.tags().any(|tag| tag.identifier() == only_tag)
                })
            })
            .map(move |rule| JsonRule {
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
    ) -> Vec<JsonPattern> {
        patterns
            .flat_map(|pattern| {
                let identifier = pattern.identifier();

                pattern.matches().map(|pattern_match| {
                    let match_range = pattern_match.range();
                    let match_data = pattern_match.data();

                    let more_bytes_message =
                        match match_data.len().saturating_sub(string_limit) {
                            0 => None,
                            n => Some(format!(" ... {} more bytes", n)),
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

                    JsonPattern {
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
        fn on_file_scanned(
            &self,
            file_path: &Path,
            scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
            output: &Sender<Message>,
        );
        /// Called when the last file has been scanned.
        fn on_done(&self, _output: &Sender<Message>) {}
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
        ) {
            if self.output_options.count_only {
                let count = scan_results.len();
                let line =
                    format!("{}: {}", &file_path.display().to_string(), count);

                output.send(Message::Info(line)).unwrap();
                return;
            }

            for matching_rule in scan_results {
                if let Some(ref only_tag) = self.output_options.only_tag {
                    if !matching_rule
                        .tags()
                        .any(|tag| tag.identifier() == only_tag)
                    {
                        continue;
                    }
                }

                let mut line = if self.output_options.include_namespace {
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
                    line.push_str(" [");
                    for (pos, tag) in tags.with_position() {
                        line.push_str(tag.identifier());
                        if !matches!(pos, itertools::Position::Last) {
                            line.push(',');
                        }
                    }
                    line.push(']');
                }

                let metadata = matching_rule.metadata();

                if self.output_options.include_meta && !metadata.is_empty() {
                    line.push_str(" [");
                    for (pos, (m, v)) in metadata.with_position() {
                        match v {
                            MetaValue::Bool(v) => {
                                line.push_str(&format!("{}={}", m, v))
                            }
                            MetaValue::Integer(v) => {
                                line.push_str(&format!("{}={}", m, v))
                            }
                            MetaValue::Float(v) => {
                                line.push_str(&format!("{}={}", m, v))
                            }
                            MetaValue::String(v) => {
                                line.push_str(&format!("{}=\"{}\"", m, v))
                            }
                            MetaValue::Bytes(v) => line.push_str(&format!(
                                "{}=\"{}\"",
                                m,
                                v.escape_ascii()
                            )),
                        };
                        if !matches!(pos, itertools::Position::Last) {
                            line.push(',');
                        }
                    }
                    line.push(']');
                }

                line.push(' ');
                line.push_str(&file_path.display().to_string());

                output.send(Message::Info(line)).unwrap();

                if let Some(limit) = self.output_options.include_strings {
                    for p in matching_rule.patterns() {
                        for m in p.matches() {
                            let match_range = m.range();
                            let match_data = m.data();

                            let mut msg = format!(
                                "{:#x}:{}:{}",
                                match_range.start,
                                match_range.len(),
                                p.identifier(),
                            );

                            match m.xor_key() {
                                Some(k) => {
                                    msg.push_str(
                                        format!(" xor({:#x},", k).as_str(),
                                    );
                                    for b in &match_data
                                        [..min(match_data.len(), limit)]
                                    {
                                        for c in (b ^ k).escape_ascii() {
                                            msg.push_str(
                                                format!("{}", c as char)
                                                    .as_str(),
                                            );
                                        }
                                    }
                                    msg.push_str("): ");
                                }
                                _ => {
                                    msg.push_str(": ");
                                }
                            }

                            for b in
                                &match_data[..min(match_data.len(), limit)]
                            {
                                for c in b.escape_ascii() {
                                    msg.push_str(
                                        format!("{}", c as char).as_str(),
                                    );
                                }
                            }

                            if match_data.len() > limit {
                                msg.push_str(
                                    format!(
                                        " ... {} more bytes",
                                        match_data.len().saturating_sub(limit)
                                    )
                                    .as_str(),
                                );
                            }

                            output.send(Message::Info(msg)).unwrap();
                        }
                    }
                }
            }
        }
    }

    pub(super) struct NdJsonOutputHandler {
        output_options: OutputOptions,
    }

    impl NdJsonOutputHandler {
        pub(super) fn new(output_options: OutputOptions) -> Self {
            Self { output_options }
        }
    }

    impl OutputHandler for NdJsonOutputHandler {
        fn on_file_scanned(
            &self,
            file_path: &Path,
            scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
            output: &Sender<Message>,
        ) {
            let path = file_path.to_str().unwrap();

            if self.output_options.count_only {
                let json = serde_json::to_string(&JsonCountOutput {
                    count: scan_results.len(),
                    path,
                })
                .unwrap();

                output.send(Message::Info(json)).unwrap();
                return;
            }

            let rules = rules_to_json(&self.output_options, scan_results);
            let line = serde_json::to_string(&JsonOutput {
                path,
                rules: rules.as_slice(),
            })
            .unwrap();

            output.send(Message::Info(line)).unwrap();
        }
    }

    pub(super) struct JsonOutputHandler {
        output_options: OutputOptions,
        matches: std::sync::Arc<Mutex<HashMap<String, Vec<JsonRule>>>>,
    }

    impl JsonOutputHandler {
        pub(super) fn new(output_options: OutputOptions) -> Self {
            let matches = std::sync::Arc::new(Mutex::new(HashMap::new()));
            Self { output_options, matches }
        }
    }

    impl OutputHandler for JsonOutputHandler {
        fn on_file_scanned(
            &self,
            file_path: &Path,
            scan_results: &mut dyn ExactSizeIterator<Item = Rule>,
            _output: &Sender<Message>,
        ) {
            let path = file_path
                .canonicalize()
                .ok()
                .as_ref()
                .and_then(|absolute| absolute.to_str())
                .map(|s| s.to_string())
                .unwrap_or_default();

            let mut matches = self.matches.lock().unwrap();

            matches
                .entry(path)
                .or_default()
                .extend(rules_to_json(&self.output_options, scan_results));
        }

        fn on_done(&self, output: &Sender<Message>) {
            let matches = self.matches.lock().unwrap();

            let json = if self.output_options.count_only {
                let json_output = matches
                    .iter()
                    .map(|(path, rules)| JsonCountOutput {
                        path,
                        count: rules.len(),
                    })
                    .collect::<Vec<_>>();

                serde_json::to_string_pretty(&json_output).unwrap_or_default()
            } else {
                let json_output = matches
                    .iter()
                    .map(|(path, rules)| JsonOutput { path, rules })
                    .collect::<Vec<_>>();

                serde_json::to_string_pretty(&json_output).unwrap_or_default()
            };

            output.send(Message::Info(json)).unwrap();
        }
    }
}
