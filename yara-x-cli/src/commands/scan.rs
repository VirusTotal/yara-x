use std::cmp::min;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Error};
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use crossbeam::channel::Sender;
use superconsole::style::Stylize;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Cyan, Red};
use yansi::Paint;
use yara_x::{Rule, Rules, ScanError, Scanner};

use crate::commands::compile_rules;
use crate::walk::Message;
use crate::{help, walk};

pub fn scan() -> Command {
    super::command("scan")
        .about("Scan a file or directory")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append),
        )
        .arg(
            arg!(<PATH>)
                .help("Path to the file or directory that will be scanned")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-e - -"print-namespace").help("Print rule namespace"))
        .arg(
            arg!(-s - -"print-strings").help(
                "Print matching patterns, limited to the first 120 bytes",
            ),
        )
        .arg(
            arg!(--"print-strings-limit" <N>)
                .help("Print matching patterns, limited to the first N bytes")
                .value_parser(value_parser!(usize)),
        )
        .arg(arg!(-n - -"negate").help("Print non-satisfied rules only"))
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace"),
        )
        .arg(
            arg!(-C - -"compiled-rules")
                .help("Tells that RULES_PATH is a file with compiled rules")
                .long_help(help::COMPILED_RULES_HELP),
        )
        .arg(
            arg!(-z --"skip-larger" <FILE_SIZE>)
                .help("Skip files larger than the given size")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .required(false)
                .value_parser(value_parser!(u8).range(1..)),
        )
        .arg(
            arg!(-a --"timeout" <SECONDS>)
                .help("Abort scanning after the given number seconds")
                .required(false)
                .value_parser(value_parser!(u64).range(1..)),
        )
}

pub fn exec_scan(args: &ArgMatches) -> anyhow::Result<()> {
    let mut rules_path = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let path = args.get_one::<PathBuf>("PATH").unwrap();
    let compiled_rules = args.get_flag("compiled-rules");
    let num_threads = args.get_one::<u8>("threads");
    let path_as_namespace = args.get_flag("path-as-namespace");
    let skip_larger = args.get_one::<u64>("skip-larger");
    let negate = args.get_flag("negate");
    let timeout = args.get_one::<u64>("timeout");

    let rules = if compiled_rules {
        if rules_path.len() > 1 {
            bail!(
                "can't use '{}' with more than one RULES_PATH",
                Paint::new("--compiled-rules").bold()
            );
        }

        // TODO: implement Rules::deserialize_from reader
        let mut file = File::open(rules_path.next().unwrap())?;
        let mut data = Vec::new();
        File::read_to_end(&mut file, &mut data)?;
        Rules::deserialize(data.as_slice())?
    } else {
        compile_rules(rules_path, path_as_namespace)?
    };

    let rules_ref = &rules;

    let mut w = walk::ParDirWalker::new();

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
        path,
        state,
        || Scanner::new(rules_ref),
        |file_path, state, output, scanner| {
            let elapsed_time = Instant::elapsed(&start_time);

            if let Some(timeout) = timeout.checked_sub(elapsed_time) {
                scanner.timeout(timeout);
            } else {
                return Err(Error::from(ScanError::Timeout));
            }

            state.files_in_progress.lock().unwrap().push(file_path.clone());

            let scan_results = scanner
                .scan_file(&file_path)
                .with_context(|| format!("scanning {:?}", &file_path));

            state
                .files_in_progress
                .lock()
                .unwrap()
                .retain(|p| !file_path.eq(p));

            let scan_results = scan_results?;

            let matching_rules: Vec<Rule> = if negate {
                scan_results.non_matching_rules().collect()
            } else {
                scan_results.matching_rules().collect()
            };

            state.num_scanned_files.fetch_add(1, Ordering::Relaxed);

            if !matching_rules.is_empty() {
                state.num_matching_files.fetch_add(1, Ordering::Relaxed);
            }

            print_matching_rules(
                args,
                &file_path,
                matching_rules.as_slice(),
                output,
            );

            Ok(())
        },
        |err, output| {
            let _ = output.send(Message::Error(format!(
                "{} {}: {}",
                Red.paint("error:").bold(),
                err,
                err.root_cause(),
            )));

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
    rules: &[Rule],
    output: &Sender<Message>,
) {
    let print_namespace = args.get_flag("print-namespace");
    let print_strings = args.get_flag("print-strings");
    let print_strings_limit = args.get_one::<usize>("print-strings-limit");

    for matching_rule in rules {
        let line = if print_namespace {
            format!(
                "{}:{} {}",
                Cyan.paint(matching_rule.namespace()).bold(),
                Cyan.paint(matching_rule.name()).bold(),
                file_path.display(),
            )
        } else {
            format!(
                "{} {}",
                Cyan.paint(matching_rule.name()).bold(),
                file_path.display()
            )
        };

        output.send(Message::Info(line)).unwrap();

        if print_strings || print_strings_limit.is_some() {
            let limit = print_strings_limit.unwrap_or(&120);
            for p in matching_rule.patterns() {
                for m in p.matches() {
                    let mut msg = format!(
                        "{:#x}:{}:{}: ",
                        m.range.start,
                        m.range.len(),
                        p.identifier(),
                    );

                    for b in &m.data[..min(m.data.len(), *limit)] {
                        for c in b.escape_ascii() {
                            msg.push_str(format!("{}", c as char).as_str());
                        }
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
    files_in_progress: Mutex<Vec<PathBuf>>,
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

            for file in self.files_in_progress.lock().unwrap().iter() {
                lines.push(Line::from_iter([Span::new_unstyled(
                    file.display(),
                )?]))
            }
        }

        Ok(lines)
    }
}
