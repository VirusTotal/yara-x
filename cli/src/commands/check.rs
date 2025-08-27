use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, io};

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use crossterm::tty::IsTty;
use regex;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Green, Red, Yellow};
use yansi::Paint;
use yara_x::{linters, SourceCode};
use yara_x_parser::ast::MetaValue;

use crate::config::{Config, MetaValueType};
use crate::walk::Message;
use crate::{help, walk};

pub fn check() -> Command {
    super::command("check")
        .about("Check if source files are syntactically correct")
        // The `check` command is not ready yet.
        .hide(true)
        .long_about(help::CHECK_LONG_HELP)
        // Keep options sorted alphabetically by their long name.
        // For instance, --bar goes before --foo.
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file or directory")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-f --filter <PATTERN>)
                .help("Check files that match the given pattern only")
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
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_sha1(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_md5(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn exec_check(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let recursive = args.get_one::<usize>("recursive");
    let filters = args.get_many::<String>("filter");
    let num_threads = args.get_one::<u8>("threads");

    let mut w = walk::ParWalker::path(rules_path);

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

    w.max_depth(*recursive.unwrap_or(&0));

    w.walk(
        CheckState::new(),
        // Initialization
        |_, _| {},
        // Action
        |state, output, file_path, _| {
            let src = fs::read(file_path.clone())
                .with_context(|| {
                    format!("can not read `{}`", file_path.display())
                })
                .unwrap();

            let src = SourceCode::from(src.as_slice())
                .with_origin(file_path.as_os_str().to_str().unwrap());

            let mut lines = Vec::new();
            let mut compiler = yara_x::Compiler::new();

            for (identifier, config) in config.check.metadata.iter() {
                let mut linter =
                    linters::metadata(identifier)
                        .required(config.required)
                        .error(config.error);

                match config.ty {
                    MetaValueType::String => {
                        let message = if let Some(regexp) = &config.regexp {
                            // Make sure that the regexp is valid.
                            let _ = regex::bytes::Regex::new(&regexp)?;
                            format!("`{identifier}` must be a string that matches `/{regexp}/`")
                        } else {
                            format!("`{identifier}` must be a string")
                        };
                        linter = linter.validator(
                            |meta| {
                                match (&meta.value, &config.regexp) {
                                    (MetaValue::String((s, _)), Some(regexp)) => {
                                        regex::Regex::new(&regexp).unwrap().is_match(s)
                                    }
                                    (MetaValue::Bytes((s, _)), Some(regexp)) => {
                                        regex::bytes::Regex::new(&regexp).unwrap().is_match(s)
                                    }
                                    (MetaValue::String(_), None) => true,
                                    (MetaValue::Bytes(_), None) => true,
                                    _ => false,
                                }
                            },
                            message,
                        );
                    }
                    MetaValueType::Integer => {
                        linter = linter.validator(
                            |meta| matches!(meta.value, MetaValue::Integer(_)),
                            format!("`{identifier}` must be an integer"),
                        );
                    }
                    MetaValueType::Float => {
                        linter = linter.validator(
                            |meta| matches!(meta.value, MetaValue::Float(_)),
                            format!("`{identifier}` must be a float"),
                        );
                    }
                    MetaValueType::Bool => {
                        linter = linter.validator(
                            |meta| matches!(meta.value, MetaValue::Bool(_)),
                            format!("`{identifier}` must be a bool"),
                        );
                    }
                    MetaValueType::Sha256 => {
                        linter = linter.validator(
                            |meta| matches!(meta.value, MetaValue::String((s,_)) if is_sha256(s)),
                            format!("`{identifier}` must be a SHA-256"),
                        );
                    }
                    MetaValueType::Sha1 => {
                        linter = linter.validator(
                            |meta| matches!(meta.value, MetaValue::String((s,_)) if is_sha1(s)),
                            format!("`{identifier}` must be a SHA-1"),
                        );
                    }
                    MetaValueType::MD5 => {
                        linter = linter.validator(
                            |meta| matches!(meta.value, MetaValue::String((s,_)) if is_md5(s)),
                            format!("`{identifier}` must be a MD5"),
                        );
                    }
                    MetaValueType::Hash => {
                        linter = linter.validator(
                            |meta| matches!(meta.value, MetaValue::String((s,_))
                                if is_md5(s) || is_sha1(s) || is_sha256(s)),
                            format!("`{identifier}` must be a MD5, SHA-1 or SHA-256"),
                        );
                    }
                }

                compiler.add_linter(linter);
            }

            if let Some(re) = config
                .check
                .rule_name
                .regexp
                .as_ref()
                .filter(|re| !re.is_empty()) {
                compiler.add_linter(
                    linters::rule_name(re)?.error(config.check.rule_name.error));
            }

            // Prefer allowed list over the regex, as it is more explicit.
            if !config.check.tags.allowed.is_empty() {
                compiler.add_linter(
                    linters::tags_allowed(config.check.tags.allowed.clone())
                        .error(config.check.tags.error));
            } else if let Some(re) = config
                .check
                .tags
                .regexp
                .as_ref()
                .filter(|re| !re.is_empty()) {
                compiler.add_linter(
                    linters::tag_regex(re)?.error(config.check.tags.error)
                );
            }

            compiler.colorize_errors(io::stdout().is_tty());

            match compiler.add_source(src) {
                Ok(compiler) => {
                    if compiler.warnings().is_empty() {
                        state.files_passed.fetch_add(1, Ordering::Relaxed);
                        lines.push(format!(
                            "[ {} ] {}",
                            "PASS".paint(Green).bold(),
                            file_path.display()
                        ));
                    } else {
                        state.warnings.fetch_add(
                            compiler.warnings().len(),
                            Ordering::Relaxed,
                        );
                        lines.push(format!(
                            "[ {} ] {}",
                            "WARN".paint(Yellow).bold(),
                            file_path.display()
                        ));
                        for warning in compiler.warnings() {
                            eprintln!("{warning}");
                        }
                    }
                }
                Err(err) => {
                    state.errors.fetch_add(1, Ordering::Relaxed);
                    lines.push(format!(
                        "[ {} ] {}\n{}",
                        "FAIL".paint(Red).bold(),
                        file_path.display(),
                        err,
                    ));
                }
            };

            output.send(Message::Info(lines.join("\n")))?;

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
                let ok = format!(
                    "{} file(s) ok. ",
                    self.files_passed.load(Ordering::Relaxed)
                );

                let warnings = format!(
                    "warnings: {}. ",
                    self.warnings.load(Ordering::Relaxed)
                );

                let errors = format!(
                    "errors: {}.",
                    self.errors.load(Ordering::Relaxed)
                );

                Line::from_iter([
                    Span::new_unstyled(ok.paint(Green).bold())?,
                    Span::new_unstyled(warnings.paint(Yellow).bold())?,
                    Span::new_unstyled(errors.paint(Red).bold())?,
                ])
            }
        };
        Ok(Lines(vec![res]))
    }
}
