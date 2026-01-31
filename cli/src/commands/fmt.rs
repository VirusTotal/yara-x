use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, io, process};

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Green, Red};
use yansi::Paint;
use yara_x_fmt::{Formatter, Indentation};

use crate::config::Config;
use crate::walk::Message;
use crate::{help, walk};

pub fn fmt() -> Command {
    super::command("fmt")
        .about("Format YARA source files")
        .long_about(help::FMT_LONG_HELP)
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file or directory")
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-c --check  "Run in 'check' mode")
                .long_help(help::FMT_CHECK_MODE),
        )
        .arg(
            arg!(-f --filter <PATTERN>)
                .help("Format files that match the given pattern only")
                .long_help(help::FILTER_LONG_HELP)
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-r - -"recursive"[MAX_DEPTH])
                .help("Walk directories recursively up to a given depth")
                .long_help(help::RECURSIVE_LONG_HELP)
                .default_missing_value("1000")
                .require_equals(true)
                .value_parser(value_parser!(usize)),
        )
        .arg(
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .required(false)
                .value_parser(value_parser!(u8).range(1..)),
        )
        .arg(
            arg!(-t - -"tab-size" <NUM_SPACES>)
                .help("Tab size (in spaces) used in source files")
                .long_help(help::FMT_TAB_SIZE)
                .default_value("4")
                .value_parser(value_parser!(usize)),
        )
}

pub fn exec_fmt(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let rules_paths = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let check = args.get_flag("check");
    let tab_size = args.get_one::<usize>("tab-size").unwrap();
    let filters: Option<Vec<&String>> =
        args.get_many::<String>("filter").map(|f| f.collect());
    let recursive = args.get_one::<usize>("recursive");
    let num_threads = args.get_one::<u8>("threads");

    let formatter = Formatter::new()
        .input_tab_size(*tab_size)
        .align_metadata(config.fmt.meta.align_values)
        .align_patterns(config.fmt.patterns.align_values)
        .indent_section_headers(config.fmt.rule.indent_section_headers)
        .indent_section_contents(config.fmt.rule.indent_section_contents)
        .indentation(if config.fmt.rule.indent_spaces == 0 {
            Indentation::Tabs
        } else {
            Indentation::Spaces(config.fmt.rule.indent_spaces as usize)
        })
        .newline_before_curly_brace(config.fmt.rule.newline_before_curly_brace)
        .empty_line_before_section_header(
            config.fmt.rule.empty_line_before_section_header,
        )
        .empty_line_after_section_header(
            config.fmt.rule.empty_line_after_section_header,
        );

    let mut total_modified = 0usize;
    let mut total_errors = 0usize;

    for rules_path in rules_paths {
        let mut w = walk::ParWalker::path(rules_path);

        w.max_depth(*recursive.unwrap_or(&0));

        if let Some(num_threads) = num_threads {
            w.num_threads(*num_threads);
        }

        if let Some(ref filters) = filters {
            for filter in filters {
                w.filter(filter);
            }
        } else {
            // Default filters are `**/*.yar` and `**/*.yara`.
            w.filter("**/*.yar").filter("**/*.yara");
        }

        let state = w
            .walk(
                FmtState::new(check),
                // Initialization
                |_, _| {},
                // Action
                |state, output, file_path, _| {
                    let input = match fs::read(&file_path) {
                        Ok(input) => input,
                        Err(err) => {
                            state.errors.fetch_add(1, Ordering::Relaxed);
                            output.send(Message::Error(format!(
                                "{} can not read `{}`: {}",
                                "error:".paint(Red).bold(),
                                file_path.display(),
                                err
                            )))?;
                            return Ok(());
                        }
                    };

                    let format_result = if state.check {
                        formatter.format(input.as_slice(), io::sink())
                    } else {
                        let mut formatted =
                            Cursor::new(Vec::with_capacity(input.len()));
                        match formatter.format(input.as_slice(), &mut formatted)
                        {
                            Ok(true) => {
                                formatted.seek(SeekFrom::Start(0))?;
                                let mut output_file =
                                    File::create(&file_path)?;
                                io::copy(&mut formatted, &mut output_file)?;
                                Ok(true)
                            }
                            Ok(false) => Ok(false),
                            Err(err) => Err(err),
                        }
                    };

                    match format_result {
                        Ok(true) => {
                            state.modified.fetch_add(1, Ordering::Relaxed);
                            let action = if state.check {
                                "needs formatting"
                            } else {
                                "formatted"
                            };
                            output.send(Message::Info(format!(
                                "{:>14} {}",
                                action.paint(Green).bold(),
                                file_path.display()
                            )))?;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            state.errors.fetch_add(1, Ordering::Relaxed);
                            output.send(Message::Error(format!(
                                "{} {}",
                                "error:".paint(Red).bold(),
                                err
                            )))?;
                        }
                    }

                    Ok(())
                },
                // Finalization
                |_, _| {},
                // Walk done
                |_| {},
                // Error handling
                |err, output| {
                    let _ = output.send(Message::Error(format!(
                        "{} {}",
                        "error:".paint(Red).bold(),
                        err
                    )));

                    Ok(())
                },
            )
            .unwrap();

        total_modified += state.modified.load(Ordering::Relaxed);
        total_errors += state.errors.load(Ordering::Relaxed);
    }

    if total_modified > 0 || total_errors > 0 {
        process::exit(1)
    }

    Ok(())
}

#[derive(Debug)]
struct FmtState {
    check: bool,
    modified: AtomicUsize,
    errors: AtomicUsize,
}

impl FmtState {
    fn new(check: bool) -> Self {
        Self {
            check,
            modified: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        }
    }
}

impl Component for FmtState {
    fn draw_unchecked(
        &self,
        _dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<superconsole::Lines> {
        let res = match mode {
            superconsole::DrawMode::Normal | superconsole::DrawMode::Final => {
                let action =
                    if self.check { "needed formatting" } else { "formatted" };
                let msg = format!(
                    "{} file(s) {}.",
                    self.modified.load(Ordering::Relaxed),
                    action
                );

                Line::from_iter([Span::new_unstyled(msg.paint(Green).bold())?])
            }
        };
        Ok(Lines(vec![res]))
    }
}
