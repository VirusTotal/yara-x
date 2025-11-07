use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Context;
use clap::{arg, value_parser, Arg, ArgAction, ArgMatches, Command};
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Green, Red, Yellow};
use yansi::Paint;
use yara_x::Patch;

use crate::commands::{compile_rules, path_with_namespace_parser};
use crate::config::Config;
use crate::walk::Message;
use crate::{help, walk};

pub fn fix() -> Command {
    super::command("fix")
        .about("Utilities for fixing source code")
        // The `fix` command is still in beta.
        .hide(true)
        .arg_required_else_help(true)
        .subcommand(fix_encoding())
        .subcommand(fix_warnings())
}

pub fn fix_encoding() -> Command {
    super::command("encoding")
        .about("Convert source files to UTF-8")
        .long_about(help::FIX_ENCODING_LONG_HELP)
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file or directory")
                .value_parser(value_parser!(PathBuf)),
        )
        // Keep options sorted alphabetically by their long name.
        // For instance, --bar goes before --foo.
        .arg(arg!(-d - -"dry-run").help("Don't modify source files"))
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

pub fn fix_warnings() -> Command {
    super::command("warnings")
        .about("Automatically fix warnings")
        .arg(
            Arg::new("[NAMESPACE:]RULES_PATH")
                .required(true)
                .help("Path to a YARA source file or directory (optionally prefixed with a namespace)")
                .value_parser(path_with_namespace_parser)
                .action(ArgAction::Append)
        )
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace"),
        )
        .arg(
            arg!(--"relaxed-re-syntax")
                .help("Use a more relaxed syntax check while parsing regular expressions"),
        )
        .arg(
            arg!(-I --"ignore-module" <MODULE>)
                .help("Ignore rules that use the specified module")
                .long_help(help::IGNORE_MODULE_LONG_HELP)
                .action(ArgAction::Append)
        )
        .arg(
            arg!(--"include-dir" <PATH>)
                .help("Directory in which to search for included files")
                .long_help(help::INCLUDE_DIR_LONG_HELP)
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append)
        )
}

pub fn exec_fix(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    match args.subcommand() {
        Some(("encoding", args)) => exec_fix_encoding(args, config),
        Some(("warnings", args)) => exec_fix_warnings(args, config),
        _ => unreachable!(),
    }
}

pub fn exec_fix_encoding(
    args: &ArgMatches,
    _config: &Config,
) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let filters = args.get_many::<String>("filter");
    let dry_run = args.get_flag("dry-run");
    let recursive = args.get_one::<usize>("recursive");
    let num_threads = args.get_one::<u8>("threads");

    let mut w = walk::ParWalker::path(rules_path);

    w.max_depth(*recursive.unwrap_or(&0));

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
        FixEncodingState::new(),
        // Initialization
        |_, _| {},
        // Action
        |state, output, file_path, _| {
            let src = fs::read(&file_path).with_context(|| {
                format!("can not read `{}`", file_path.display())
            })?;

            // Detect the original encoding.
            let mut detector = chardetng::EncodingDetector::new();
            detector.feed(src.as_slice(), true);

            // Decode the source file as UTF-8. `invalid_chars` will be true
            // if some character could not be encoded as UTF-8 and was replaced
            // by the replacement character.
            let (src_utf8, encoding, invalid_chars) =
                detector.guess(None, true).decode(src.as_slice());

            // Re-write the source as UTF-8, except if --dry-run was used or
            // the original source was not modified at all.
            if !dry_run && matches!(src_utf8, Cow::Owned(_)) {
                fs::write(&file_path, src_utf8.as_bytes())?;
                state.files_modified.fetch_add(1, Ordering::Relaxed);
            }

            output.send(Message::Info(format!(
                "{:>14} {}",
                encoding
                    .name()
                    .paint(if invalid_chars { Yellow } else { Green })
                    .bold(),
                file_path.display()
            )))?;

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

pub fn exec_fix_warnings(
    args: &ArgMatches,
    config: &Config,
) -> anyhow::Result<()> {
    let rules_path = args
        .get_many::<(Option<String>, PathBuf)>("[NAMESPACE:]RULES_PATH")
        .unwrap();

    let rules = compile_rules(rules_path, args, config)?;

    let mut patches_per_origin = HashMap::new();

    // Iterator over all patches from all warnings.
    let patches = rules.warnings().iter().flat_map(|w| w.patches());

    // Create a map where keys are file paths (stored in patch origin), and
    // values are a list of patches that must be applied to that file. Patches
    // are ordered by their starting positions in the file.
    for patch in patches {
        match patches_per_origin.entry(patch.origin().unwrap()) {
            Entry::Occupied(mut entry) => {
                let patches: &mut Vec<Patch> = entry.get_mut();
                patches.push(patch);
                patches.sort_by_key(|patch| patch.span().start());
            }
            Entry::Vacant(entry) => {
                entry.insert(vec![patch]);
            }
        }
    }

    for (origin, patches) in patches_per_origin {
        println!("---- file: {origin}");
        for patch in patches {
            println!("{} {}", patch.span(), patch.replacement())
        }
    }

    Ok(())
}

#[derive(Debug)]
struct FixEncodingState {
    files_modified: AtomicUsize,
}

impl FixEncodingState {
    fn new() -> Self {
        Self { files_modified: AtomicUsize::new(0) }
    }
}

impl Component for FixEncodingState {
    fn draw_unchecked(
        &self,
        _dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<superconsole::Lines> {
        let res = match mode {
            superconsole::DrawMode::Normal | superconsole::DrawMode::Final => {
                let modified = format!(
                    "{} file(s) modified.",
                    self.files_modified.load(Ordering::Relaxed)
                );

                Line::from_iter([Span::new_unstyled(
                    modified.paint(Green).bold(),
                )?])
            }
        };
        Ok(Lines(vec![res]))
    }
}
