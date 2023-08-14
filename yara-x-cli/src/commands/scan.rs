use anyhow::bail;
use std::cmp::min;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use superconsole::style::Stylize;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Cyan, Red};
use yansi::Paint;
use yara_x::{Rule, Rules, Scanner};

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
}

pub fn exec_scan(args: &ArgMatches) -> anyhow::Result<()> {
    let mut rules_path = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let path = args.get_one::<PathBuf>("PATH").unwrap();
    let compiled_rules = args.get_flag("compiled-rules");
    let num_threads = args.get_one::<u8>("threads");
    let print_namespace = args.get_flag("print-namespace");
    let print_strings = args.get_flag("print-strings");
    let print_strings_limit = args.get_one::<usize>("print-strings-limit");
    let path_as_namespace = args.get_flag("path-as-namespace");
    let skip_larger = args.get_one::<u64>("skip-larger");
    let negate = args.get_flag("negate");

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

    w.walk(
        path,
        ScanState::new(),
        || Scanner::new(rules_ref),
        |file_path, state, output, scanner| {
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
                                    msg.push_str(
                                        format!("{}", c as char).as_str(),
                                    );
                                }
                            }

                            output.send(Message::Info(msg)).unwrap();
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
