use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, io};

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use crossterm::tty::IsTty;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Green, Red, Yellow};
use yara_x_parser::{Parser, SourceCode};

use crate::walk::Message;
use crate::{help, walk};

pub fn check() -> Command {
    super::command("check")
        .about("Check if YARA source files are syntactically correct")
        .long_about(help::CHECK_LONG_HELP)
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file or directory")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-d --"max-depth" <MAX_DEPTH>)
                .help("Walk directories recursively up to a given depth")
                .long_help(help::DEPTH_LONG_HELP)
                .value_parser(value_parser!(u16)),
        )
        .arg(
            arg!(-f --filter <PATTERN>)
                .help("Check files that match the given pattern only")
                .long_help(help::FILTER_LONG_HELP)
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .required(false)
                .value_parser(value_parser!(u8).range(1..)),
        )
}

pub fn exec_check(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let max_depth = args.get_one::<u16>("max-depth");
    let filters = args.get_many::<String>("filter");
    let num_threads = args.get_one::<u8>("threads");

    let mut w = walk::ParDirWalker::new();

    if let Some(max_depth) = max_depth {
        w.max_depth(*max_depth as usize);
    }

    if let Some(num_threads) = num_threads {
        w.num_threads(*num_threads);
    }

    if let Some(filters) = filters {
        for filter in filters {
            w.filter(filter);
        }
    } else {
        // Default filters are `**/*.yar` and `**/*.yara`.
        w.filter("**/*.yar").filter("**/*.yara");
    }

    w.walk(
        rules_path,
        CheckState::new(),
        || {},
        |file_path, state, output, _| {
            let src = fs::read(file_path.clone())
                .with_context(|| {
                    format!("can not read `{}`", file_path.display())
                })
                .unwrap();

            let src = SourceCode::from(src.as_slice())
                .with_origin(file_path.as_os_str().to_str().unwrap());

            let mut lines = Vec::new();

            match Parser::new()
                .colorize_errors(io::stdout().is_tty())
                .build_ast(src)
            {
                Ok(ast) => {
                    if ast.warnings.is_empty() {
                        state.files_passed.fetch_add(1, Ordering::Relaxed);
                        lines.push(format!(
                            "[ {} ] {}",
                            Green.paint("PASS").bold(),
                            file_path.display()
                        ));
                    } else {
                        state
                            .warnings
                            .fetch_add(ast.warnings.len(), Ordering::Relaxed);
                        lines.push(format!(
                            "[{}] {}",
                            Yellow.paint("WARN").bold(),
                            file_path.display()
                        ));
                        for warning in ast.warnings {
                            lines.push(warning.to_string());
                        }
                    }
                }
                Err(err) => {
                    state.errors.fetch_add(1, Ordering::Relaxed);
                    lines.push(format!(
                        "[{}] {}\n{}",
                        Red.paint("FAIL").bold(),
                        file_path.display(),
                        err,
                    ));
                }
            };

            output.send(Message::Info(lines.join("\n"))).unwrap();
        },
    )
    .unwrap();

    Ok(())
}

struct CheckState {
    files_passed: AtomicUsize,
    warnings: AtomicUsize,
    errors: AtomicUsize,
}

impl CheckState {
    fn new() -> Self {
        Self {
            files_passed: AtomicUsize::new(0),
            warnings: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        }
    }
}

impl Component for CheckState {
    fn draw_unchecked(
        &self,
        _dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<superconsole::Lines> {
        let res = match mode {
            superconsole::DrawMode::Normal | superconsole::DrawMode::Final => {
                let ok = Green
                    .paint(format!(
                        "{} file(s) ok. ",
                        self.files_passed.load(Ordering::Relaxed)
                    ))
                    .bold();
                let warnings = Yellow
                    .paint(format!(
                        "warnings: {}. ",
                        self.warnings.load(Ordering::Relaxed)
                    ))
                    .bold();
                let errors = Red
                    .paint(format!(
                        "errors: {}.",
                        self.errors.load(Ordering::Relaxed)
                    ))
                    .bold();
                Line::from_iter([
                    Span::new_unstyled(ok)?,
                    Span::new_unstyled(warnings)?,
                    Span::new_unstyled(errors)?,
                ])
            }
        };
        Ok(Lines(vec![res]))
    }
}
