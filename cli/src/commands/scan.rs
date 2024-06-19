use std::cmp::min;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Error};
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use crossbeam::channel::Sender;
use superconsole::style::Stylize;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Cyan, Red, Yellow};
use yansi::Paint;
use yara_x::{Rule, Rules, ScanError, Scanner};

use crate::commands::{
    compile_rules, external_var_parser, truncate_with_ellipsis,
};
use crate::walk::Message;
use crate::{help, walk};

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
            arg!(--"disable-console-logs")
                .help("Disable printing console log messages")
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
    let negate = args.get_flag("negate");
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

            if negate {
                let mut matching_rules = scan_results.non_matching_rules();
                if matching_rules.len() > 0 {
                    state.num_matching_files.fetch_add(1, Ordering::Relaxed);
                }
                print_matching_rules(
                    args,
                    &file_path,
                    &mut matching_rules,
                    output,
                );
            } else {
                let mut matching_rules = scan_results.matching_rules();
                if matching_rules.len() > 0 {
                    state.num_matching_files.fetch_add(1, Ordering::Relaxed);
                }
                print_matching_rules(
                    args,
                    &file_path,
                    &mut matching_rules,
                    output,
                );
            };

            state.num_scanned_files.fetch_add(1, Ordering::Relaxed);

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

fn print_matching_rules(
    args: &ArgMatches,
    file_path: &Path,
    rules: &mut dyn Iterator<Item = Rule>,
    output: &Sender<Message>,
) {
    let print_namespace = args.get_flag("print-namespace");
    let print_strings = args.get_flag("print-strings");
    let print_strings_limit = args.get_one::<usize>("print-strings-limit");

    // Clippy insists on replacing the `while let` statement with
    // `for matching_rule in rules.by_ref()`, but that fails with
    // `the `by_ref` method cannot be invoked on a trait object`
    #[allow(clippy::while_let_on_iterator)]
    while let Some(matching_rule) = rules.next() {
        let line = if print_namespace {
            format!(
                "{}:{} {}",
                matching_rule.namespace().paint(Cyan).bold(),
                matching_rule.identifier().paint(Cyan).bold(),
                file_path.display(),
            )
        } else {
            format!(
                "{} {}",
                matching_rule.identifier().paint(Cyan).bold(),
                file_path.display()
            )
        };

        output.send(Message::Info(line)).unwrap();

        if print_strings || print_strings_limit.is_some() {
            let limit = print_strings_limit.unwrap_or(&120);
            for p in matching_rule.patterns() {
                for m in p.matches() {
                    let match_range = m.range();
                    let match_data = m.data();

                    let mut msg = format!(
                        "{:#x}:{}:{}: ",
                        match_range.start,
                        match_range.len(),
                        p.identifier(),
                    );

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
                let path = file.display().to_string();
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
