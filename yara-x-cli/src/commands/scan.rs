use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use superconsole::style::Stylize;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Cyan, Red};
use yara_x::{Rule, Scanner};

use crate::commands::compile_rules;
use crate::walk::Message;
use crate::{help, walk};

pub fn scan() -> Command {
    super::command("scan")
        .about("Scans a file or directory")
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
        .arg(arg!(-s - -"print-strings").help("Print matching patterns"))
        .arg(arg!(-n - -"negate").help("Print non-satisfied rules only"))
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace"),
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
}

pub fn exec_scan(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let path = args.get_one::<PathBuf>("PATH").unwrap();
    let num_threads = args.get_one::<u8>("threads");
    let print_namespace = args.get_flag("print-namespace");
    let print_strings = args.get_flag("print-strings");
    let path_as_namespace = args.get_flag("path-as-namespace");
    let skip_larger = args.get_one::<u64>("skip-larger");
    let negate = args.get_flag("negate");

    let rules = compile_rules(rules_path, path_as_namespace)?;
    let rules_ref = &rules;

    let mut walker = walk::ParallelWalk::new(path);

    if let Some(num_threads) = num_threads {
        walker = walker.num_threads(*num_threads);
    }

    walker
        .run(
            ScanState::new(),
            || Scanner::new(rules_ref),
            |file_path, file_metadata, state, output, scanner| {
                // Skip files larger than the size specified by `--skip-larger`
                if let Some(max_file_size) = skip_larger {
                    if file_metadata.len() > *max_file_size {
                        return;
                    }
                }

                let scan_results = scanner.scan_file(&file_path);

                if let Err(err) = scan_results {
                    output
                        .send(Message::Error(format!(
                            "{} {}",
                            Red.paint("error:").bold(),
                            err
                        )))
                        .unwrap();
                    return;
                }

                let scan_results = scan_results.unwrap();

                let matching_rules: Vec<Rule> = if negate {
                    scan_results.non_matching_rules().collect()
                } else {
                    scan_results.matching_rules().collect()
                };

                state.num_scanned_files.fetch_add(1, Ordering::Relaxed);

                if !matching_rules.is_empty() {
                    state.num_matching_files.fetch_add(1, Ordering::Relaxed);
                }

                for matching_rule in matching_rules {
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

                    if print_strings {
                        for p in matching_rule.patterns() {
                            for m in p.matches() {
                                output
                                    .send(Message::Info(format!(
                                        "{:#x}:{}:{}: {:02X?}",
                                        m.range.start,
                                        m.range.len(),
                                        p.identifier(),
                                        m.data,
                                    )))
                                    .unwrap();
                            }
                        }
                    }
                }
            },
        )
        .unwrap();

    Ok(())
}

struct ScanState {
    start: Instant,
    num_scanned_files: AtomicUsize,
    num_matching_files: AtomicUsize,
}

impl ScanState {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            num_scanned_files: AtomicUsize::new(0),
            num_matching_files: AtomicUsize::new(0),
        }
    }
}

impl Component for ScanState {
    fn draw_unchecked(
        &self,
        _dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<superconsole::Lines> {
        let res = match mode {
            superconsole::DrawMode::Normal => {
                let state = format!(
                    "{} file(s) matched. {} file(s) scanned in {:.1}s",
                    self.num_matching_files.load(Ordering::Relaxed),
                    self.num_scanned_files.load(Ordering::Relaxed),
                    self.start.elapsed().as_secs_f32()
                );
                let state = Span::new_styled(state.bold())?;
                Line::from_iter([state])
            }
            superconsole::DrawMode::Final => {
                let num_scanned_files =
                    self.num_scanned_files.load(Ordering::Relaxed);
                let num_matching_files =
                    self.num_matching_files.load(Ordering::Relaxed);
                let matched =
                    format!("{} file(s) matched.", num_matching_files,);
                let scanned = format!(
                    " {} file(s) scanned in {:.1}s",
                    num_scanned_files,
                    self.start.elapsed().as_secs_f32()
                );
                let matched = if num_matching_files > 0 {
                    Span::new_styled(matched.red().bold())?
                } else {
                    Span::new_styled(matched.green().bold())?
                };
                Line::from_iter([matched, Span::new_styled(scanned.bold())?])
            }
        };
        Ok(Lines(vec![res]))
    }
}
