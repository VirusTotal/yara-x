use std::path::PathBuf;

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use yara_x::{Rule, Scanner};

use crate::commands::compile_rules;
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
        .arg(arg!(-n - -"negate").help("Print non-satisfied rules only"))
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace"),
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
    let path_as_namespace = args.get_flag("path-as-namespace");
    let negate = args.get_flag("negate");

    let rules = compile_rules(rules_path, path_as_namespace)?;
    let rules_ref = &rules;

    let mut walker = walk::ParallelWalk::new(path);

    if let Some(num_threads) = num_threads {
        walker = walker.num_threads(*num_threads);
    }

    walker.run(
        // The initialization function creates a scanner for each thread.
        || Scanner::new(rules_ref),
        |scanner, file_path| {
            let scan_results = scanner.scan_file(&file_path)?;

            let matching_rules: Vec<Rule> = if negate {
                scan_results.non_matching_rules().collect()
            } else {
                scan_results.matching_rules().collect()
            };

            for matching_rule in matching_rules {
                if print_namespace {
                    println!(
                        "{}:{} {}",
                        matching_rule.namespace(),
                        matching_rule.name(),
                        file_path.display()
                    );
                } else {
                    println!(
                        "{} {}",
                        matching_rule.name(),
                        file_path.display()
                    );
                }
            }
            Ok::<(), anyhow::Error>(())
        },
    )
}
