use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use yansi::Color::{Green, Red, Yellow};
use yara_x_parser::{Parser, SourceCode};

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

    let mut walker = walk::ParallelWalk::new(rules_path);

    if let Some(max_depth) = max_depth {
        walker = walker.max_depth(*max_depth as usize);
    }

    if let Some(num_threads) = num_threads {
        walker = walker.num_threads(*num_threads);
    }

    if let Some(filters) = filters {
        for filter in filters {
            walker = walker.filter(filter);
        }
    } else {
        // Default filters are `**/*.yar` and `**/*.yara`.
        walker = walker.filter("**/*.yar").filter("**/*.yara");
    }

    walker.run(
        || {},
        |_, file_path| {
            let src = fs::read(file_path.clone()).with_context(|| {
                format!("can not read `{}`", file_path.display())
            })?;

            let src = SourceCode::from(src.as_slice())
                .origin(file_path.as_os_str().to_str().unwrap());

            match Parser::new().colorize_errors(true).build_ast(src) {
                Ok(ast) => {
                    if ast.warnings.is_empty() {
                        println!(
                            "[{}] {}",
                            Green.paint("PASS"),
                            file_path.display()
                        );
                    } else {
                        println!(
                            "[{}] {}\n",
                            Yellow.paint("WARN"),
                            file_path.display()
                        );
                        for warning in ast.warnings {
                            println!("{}\n", warning);
                        }
                    }
                }
                Err(err) => {
                    println!(
                        "[{}] {}\n",
                        Red.paint("ERROR"),
                        file_path.display()
                    );
                    println!("{}", err);
                }
            };

            Ok::<(), anyhow::Error>(())
        },
    )
}
