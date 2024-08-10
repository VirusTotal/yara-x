use std::borrow::Cow;
use std::cmp::min;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Error};
use clap::{arg, value_parser, ArgAction, ArgMatches, Command, ValueEnum};
use crossbeam::channel::Sender;
use itertools::Itertools;
use superconsole::style::Stylize;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Cyan, Red, Yellow};
use yansi::Paint;
use yara_x::{MetaValue, Rule, Rules, ScanError, ScanResults, Scanner};

use crate::commands::{
    compile_rules, external_var_parser, truncate_with_ellipsis,
};
use crate::walk::Message;
use crate::{help, walk};

#[derive(Clone, ValueEnum)]
enum OutputFormats {
    /// Default output format.
    Text,
    /// Newline delimited JSON (i.e: one JSON object per line).
    Ndjson,
}

const STRINGS_LIMIT: usize = 120;

#[rustfmt::skip]
pub fn scan() -> Command {
    super::command("scan")
        .about("Scan a file or directory")
        .long_about(help::SCAN_LONG_HELP)
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to a YARA source file or directory")
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append)
        )
        .arg(
            arg!(<TARGET_PATH>)
                .help("Path to the file or directory that will be scanned")
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            arg!(-o --"output-format" <FORMAT>)
                .help("Output format for results")
                .long_help(help::OUTPUT_FORMAT_LONG_HELP)
                .required(false)
                .value_parser(value_parser!(OutputFormats))
        )
        .arg(
            arg!(-e --"print-namespace")
                .help("Print rule namespace")
        )
        .arg(
            arg!(-s --"print-strings")
                .help("Print matching patterns, limited to the first 120 bytes")
        )
        .arg(
            arg!(--"print-strings-limit" <N>)
                .help("Print matching patterns, limited to the first N bytes")
                .value_parser(value_parser!(usize))
        )
        .arg(
            arg!(-m --"print-meta")
                .help("Print rule metadata")
        )
        .arg(
            arg!(-g --"print-tags")
                .help("Print rule tags")
        )
        .arg(
            arg!(-c --"count")
                .help("Print only the number of matches per file")
        )
        .arg(
            arg!(--"disable-console-logs")
                .help("Disable printing console log messages")
        )
        .arg(
            arg!(-t --"tag" <TAG>)
                .help("Print only rules tagged as TAG")
                .required(false)
                .value_parser(value_parser!(String))
        )
        .arg(
            arg!(-n --"negate")
                .help("Print non-satisfied rules only")
        )
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace")
        )
        .arg(
            arg!(-C --"compiled-rules")
                .help("Indicate that RULES_PATH is a file with compiled rules")
                .long_help(help::COMPILED_RULES_LONG_HELP)
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
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .required(false)
                .value_parser(value_parser!(u8).range(1..))
        )
        .arg(
            arg!(-a --"timeout" <SECONDS>)
                .help("Abort scanning after the given number of seconds")
                .required(false)
                .value_parser(value_parser!(u64).range(1..))
        )
        .arg(
            arg!(--"relaxed-re-syntax")
                .help("Use a more relaxed syntax check while parsing regular expressions")
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
            arg!(-d --"define")
                .help("Define external variable")
                .long_help(help::DEFINE_LONG_HELP)
                .required(false)
                .value_name("VAR=VALUE")
                .value_parser(external_var_parser)
                .action(ArgAction::Append)
        )
}

pub fn exec_scan(args: &ArgMatches) -> anyhow::Result<()> {
    let mut rules_path = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let target_path = args.get_one::<PathBuf>("TARGET_PATH").unwrap();
    let compiled_rules = args.get_flag("compiled-rules");
    let num_threads = args.get_one::<u8>("threads");
    let path_as_namespace = args.get_flag("path-as-namespace");
    let skip_larger = args.get_one::<u64>("skip-larger");
    let disable_console_logs = args.get_flag("disable-console-logs");
    let scan_list = args.get_flag("scan-list");

    let timeout = args.get_one::<u64>("timeout");

    let mut external_vars: Option<Vec<(String, serde_json::Value)>> = args
        .get_many::<(String, serde_json::Value)>("define")
        .map(|var| var.cloned().collect());

    let rules = if compiled_rules {
        if rules_path.len() > 1 {
            bail!(
                "can't use '{}' with more than one RULES_PATH",
                Paint::bold("--compiled-rules")
            );
        }

        if args.get_flag("relaxed-re-syntax") {
            bail!(
                "can't use '{}' together with '{}'",
                Paint::bold("--relaxed-re-syntax"),
                Paint::bold("--compiled-rules")
            );
        }

        let rules_path = rules_path.next().unwrap();

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
        // Vector with the IDs of the warnings that should be disabled, if the
        // vector contains "all", all warnings are disabled.
        let disabled_warnings = args
            .get_many::<String>("disable-warnings")
            .map(|warnings| warnings.map(|id| id.as_str()).collect())
            .unwrap_or_default();

        // With `take()` we pass the external variables to `compile_rules`,
        // while leaving a `None` in `external_vars`. This way external
        // variables are not set again in the scanner.
        compile_rules(
            rules_path,
            path_as_namespace,
            external_vars.take(),
            args.get_flag("relaxed-re-syntax"),
            disabled_warnings,
        )?
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

    let timeout = if let Some(timeout) = timeout {
        Duration::from_secs(*timeout)
    } else {
        Duration::from_secs(u64::MAX)
    };

    let start_time = Instant::now();
    let state = ScanState::new(start_time);

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

            if let Some(timeout) = timeout.checked_sub(elapsed_time) {
                scanner.set_timeout(timeout);
            } else {
                return Err(Error::from(ScanError::Timeout));
            }

            let now = Instant::now();

            state
                .files_in_progress
                .lock()
                .unwrap()
                .push((file_path.clone(), now));

            let scan_results = scanner
                .scan_file(&file_path)
                .with_context(|| format!("scanning {:?}", &file_path));

            state
                .files_in_progress
                .lock()
                .unwrap()
                .retain(|(p, _)| !file_path.eq(p));

            let scan_results = scan_results?;
            let matched_count =
                process_scan_results(args, &file_path, &scan_results, output);

            state.num_scanned_files.fetch_add(1, Ordering::Relaxed);
            if matched_count > 0 {
                state.num_matching_files.fetch_add(1, Ordering::Relaxed);
            }

            Ok(())
        },
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

    Ok(())
}

fn print_rules_as_json(
    args: &ArgMatches,
    file_path: &Path,
    rules: &mut dyn Iterator<Item = Rule>,
    output: &Sender<Message>,
) {
    let print_namespace = args.get_flag("print-namespace");
    let only_tag = args.get_one::<String>("tag");
    let print_tags = args.get_flag("print-tags");
    let print_meta = args.get_flag("print-meta");
    let print_strings = args.get_flag("print-strings");
    let print_strings_limit = args.get_one::<usize>("print-strings-limit");

    // One JSON object per file, with a "rules" key that contains a list of
    // matched rules.
    let mut json = serde_json::json!({"path": file_path.to_str().unwrap()});
    let mut json_rules: Vec<serde_json::Value> = Vec::new();

    // Clippy insists on replacing the `while let` statement with
    // `for matching_rule in rules.by_ref()`, but that fails with
    // `the `by_ref` method cannot be invoked on a trait object`
    #[allow(clippy::while_let_on_iterator)]
    while let Some(matching_rule) = rules.next() {
        if only_tag.is_some()
            && !matching_rule
                .tags()
                .any(|t| t.identifier() == only_tag.unwrap())
        {
            return;
        }

        let mut json_rule = if print_namespace {
            serde_json::json!({
                "namespace": matching_rule.namespace(),
                "identifier": matching_rule.identifier()
            })
        } else {
            serde_json::json!({
                "identifier": matching_rule.identifier()
            })
        };

        if print_meta {
            json_rule["meta"] = matching_rule.metadata().into_json();
        }

        if print_tags {
            let tags: Vec<&str> =
                matching_rule.tags().map(|t| t.identifier()).collect();
            json_rule["tags"] = serde_json::json!(tags);
        }

        if print_strings || print_strings_limit.is_some() {
            let limit = print_strings_limit.unwrap_or(&STRINGS_LIMIT);
            let mut match_vec: Vec<serde_json::Value> = Vec::new();
            for p in matching_rule.patterns() {
                for m in p.matches() {
                    let match_range = m.range();
                    let match_data = m.data();

                    let mut s = String::new();

                    for b in &match_data[..min(match_data.len(), *limit)] {
                        for c in b.escape_ascii() {
                            s.push_str(format!("{}", c as char).as_str());
                        }
                    }

                    if match_data.len() > *limit {
                        s.push_str(
                            format!(
                                " ... {} more bytes",
                                match_data.len().saturating_sub(*limit)
                            )
                            .as_str(),
                        );
                    }

                    let mut match_json = serde_json::json!({
                        "identifier": p.identifier(),
                        "start": match_range.start,
                        "length": match_range.len(),
                        "data": s.as_str()
                    });

                    if let Some(k) = m.xor_key() {
                        let mut p = String::with_capacity(s.len());
                        for b in &match_data[..min(match_data.len(), *limit)] {
                            for c in (b ^ k).escape_ascii() {
                                p.push_str(format!("{}", c as char).as_str());
                            }
                        }
                        match_json["xor_key"] = serde_json::json!(k);
                        match_json["plaintext"] = serde_json::json!(p);
                    }
                    match_vec.push(match_json);
                }
                json_rule["strings"] = serde_json::json!(match_vec);
            }
        }
        json_rules.push(json_rule);
    }

    json["rules"] = serde_json::json!(json_rules);

    output.send(Message::Info(format!("{}", json))).unwrap();
}

fn print_rules_as_text(
    args: &ArgMatches,
    file_path: &Path,
    rules: &mut dyn Iterator<Item = Rule>,
    output: &Sender<Message>,
) {
    let print_namespace = args.get_flag("print-namespace");
    let only_tag = args.get_one::<String>("tag");
    let print_tags = args.get_flag("print-tags");
    let print_meta = args.get_flag("print-meta");
    let print_strings = args.get_flag("print-strings");
    let print_strings_limit = args.get_one::<usize>("print-strings-limit");

    // Clippy insists on replacing the `while let` statement with
    // `for matching_rule in rules.by_ref()`, but that fails with
    // `the `by_ref` method cannot be invoked on a trait object`
    #[allow(clippy::while_let_on_iterator)]
    while let Some(matching_rule) = rules.next() {
        if only_tag.is_some()
            && !matching_rule
                .tags()
                .any(|t| t.identifier() == only_tag.unwrap())
        {
            return;
        }

        let mut line = if print_namespace {
            format!(
                "{}:{}",
                matching_rule.namespace().paint(Cyan).bold(),
                matching_rule.identifier().paint(Cyan).bold()
            )
        } else {
            format!("{}", matching_rule.identifier().paint(Cyan).bold())
        };

        let tags = matching_rule.tags();

        if print_tags && !tags.is_empty() {
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

        if print_meta && !metadata.is_empty() {
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

        if print_strings || print_strings_limit.is_some() {
            let limit = print_strings_limit.unwrap_or(&STRINGS_LIMIT);
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
                            msg.push_str(format!(" xor({:#x},", k).as_str());
                            for b in
                                &match_data[..min(match_data.len(), *limit)]
                            {
                                for c in (b ^ k).escape_ascii() {
                                    msg.push_str(
                                        format!("{}", c as char).as_str(),
                                    );
                                }
                            }
                            msg.push_str("): ");
                        }
                        _ => {
                            msg.push_str(": ");
                        }
                    }

                    for b in &match_data[..min(match_data.len(), *limit)] {
                        for c in b.escape_ascii() {
                            msg.push_str(format!("{}", c as char).as_str());
                        }
                    }

                    if match_data.len() > *limit {
                        msg.push_str(
                            format!(
                                " ... {} more bytes",
                                match_data.len().saturating_sub(*limit)
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

fn print_matching_rules(
    args: &ArgMatches,
    file_path: &Path,
    rules: &mut dyn Iterator<Item = Rule>,
    output: &Sender<Message>,
) {
    match args.get_one::<OutputFormats>("output-format") {
        Some(OutputFormats::Ndjson) => {
            print_rules_as_json(args, file_path, rules, output);
        }
        Some(OutputFormats::Text) | None => {
            print_rules_as_text(args, file_path, rules, output);
        }
    };
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

// Process scan results and output matches, non-matches, or count of matches
// based upon command line arguments. Return the number of "matched" files so
// the state can be updated.
fn process_scan_results(
    args: &ArgMatches,
    file_path: &Path,
    scan_results: &ScanResults,
    output: &Sender<Message>,
) -> usize {
    let negate = args.get_flag("negate");
    let count = args.get_flag("count");

    if negate {
        let mut rules = scan_results.non_matching_rules();
        let match_count = rules.len();
        if count {
            print_match_count(args, file_path, &match_count, output);
        } else {
            print_matching_rules(args, file_path, &mut rules, output);
        }
        match_count
    } else {
        let mut rules = scan_results.matching_rules();
        let match_count = rules.len();
        if count {
            print_match_count(args, file_path, &match_count, output);
        } else {
            print_matching_rules(args, file_path, &mut rules, output);
        }
        match_count
    }
}

fn print_match_count(
    args: &ArgMatches,
    file_path: &Path,
    count: &usize,
    output: &Sender<Message>,
) {
    let line = match args.get_one::<OutputFormats>("output-format") {
        Some(OutputFormats::Ndjson) => {
            format!(
                "{}",
                serde_json::json!({"path": file_path.to_str().unwrap(), "count": count})
            )
        }
        Some(OutputFormats::Text) | None => {
            format!("{}: {}", &file_path.display().to_string(), count)
        }
    };
    output.send(Message::Info(line)).unwrap();
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
