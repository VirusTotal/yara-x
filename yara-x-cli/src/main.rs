mod walk;

use std::fs;
use std::fs::File;
use std::io::{stdin, stdout};
use std::path::PathBuf;

use ansi_term::Color::{Green, Red, Yellow};
use anyhow::Context;
use clap::{
    arg, command, crate_authors, value_parser, ArgAction, ArgMatches, Command,
};

use yara_x::{Compiler, Rule};
use yara_x::{Error, Rules, Scanner};
use yara_x_fmt::Formatter;
use yara_x_parser::{Parser, SourceCode};

const APP_HELP_TEMPLATE: &str = r#"{about-with-newline}
{author-with-newline}
{before-help}{usage-heading}
    {usage}

{all-args}{after-help}
"#;

const CHECK_LONG_HELP: &str = r#"Check if YARA source files are syntactically correct

If <PATH> is a directory, all files with extensions `yar` and `yara` will be
checked. The `--filter` option allows changing this behavior."#;

const THREADS_LONG_HELP: &str = r#"Use the specified number of threads

The default value is automatically determined based on the number of CPU cores."#;

const DEPTH_LONG_HELP: &str = r#"Walk directories recursively up to a given depth

This is ignored if <RULES_PATH> is not a directory. When <MAX_DEPTH> is 0 it means
that files located in the specified directory will be processed, but subdirectories
won't be traversed. By default <MAX_DEPTH> is infinite."#;

const FILTER_LONG_HELP: &str = r#"Only check files that match the given pattern

Patterns can contains the following wildcards:

?      matches any single character.

*      matches any sequence of characters, except the path separator.

**     matches any sequence of characters, including the path separator.

[...]  matches any character inside the brackets. Can also specify ranges of
       characters (e.g. [0-9], [a-z])

[!...] is the negation of [...]

This option can be used more than once with different patterns. In such cases
files matching any of the patterns will be checked.

The absense of this options is equivalent to using this:

--filter='**/*.yara' --filter='**/*.yar'"#;

fn command(name: &'static str) -> Command {
    Command::new(name).help_template(
        r#"{about-with-newline}
{usage-heading}
    {usage}

{all-args}
"#,
    )
}

fn main() -> anyhow::Result<()> {
    // Enable support for ANSI escape codes in Windows. In other platforms
    // this is a no-op.
    if let Err(err) = enable_ansi_support::enable_ansi_support() {
        println!("could not enable ANSI support: {}", err)
    }

    let rules_path_arg = arg!(<RULES_PATH>)
        .help("Path to YARA source file")
        .value_parser(value_parser!(PathBuf))
        .action(ArgAction::Append);

    let num_threads_arg = arg!(-p --"threads" <NUM_THREADS>)
        .help("Use the given number of threads")
        .long_help(THREADS_LONG_HELP)
        .required(false)
        .value_parser(value_parser!(u8).range(1..));

    let path_as_namespaces_arg =
        arg!(--"path-as-namespace").help("Use file path as rule namespace");

    let args = command!()
        .author(crate_authors!("\n")) // requires `cargo` feature
        .arg_required_else_help(true)
        .help_template(APP_HELP_TEMPLATE)
        .subcommands(vec![
            command("scan")
                .about(
                    "Scans a file or directory",
                )
                .arg(&rules_path_arg)
                .arg(
                    arg!(<PATH>)
                        .help("Path to the file or directory that will be scanned")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(-e --"print-namespace")
                        .help("Print rule namespace")
                )
                .arg(
                    arg!(-n --"negate")
                        .help("Print non-satisfied rules only")
                )
                .arg(&path_as_namespaces_arg)
                .arg(&num_threads_arg),

            command("compile")
                .about(
                    "Compiles YARA rules into binary form",
                )
                .arg(&rules_path_arg
                )
                .arg(
                    arg!(<OUTPUT_PATH>)
                        .help("Path to file with compiled results")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(&path_as_namespaces_arg),

            command("ast")
                .about(
                    "Print Abstract Syntax Tree (AST) for a YARA source file",
                )
                .arg(&rules_path_arg),

            command("wasm")
                .about("Emits a .wasm file with the code generated for a YARA source file")
                .arg(
                    arg!(<RULES_PATH>)
                        .help("Path to YARA source file")
                        .value_parser(value_parser!(PathBuf)),
                ),

            command("check")
                .about("Check if YARA source files are syntactically correct")
                .long_about(CHECK_LONG_HELP)
                .arg(
                    arg!(<RULES_PATH>)
                        .help("Path to YARA source file or directory")
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    arg!(-d --"max-depth" <MAX_DEPTH>)
                        .help(
                            "Walk directories recursively up to a given depth",
                        )
                        .long_help(DEPTH_LONG_HELP)
                        .value_parser(value_parser!(u16)),
                )
                .arg(
                    arg!(-f --filter <PATTERN>)
                        .help("Check files that match the given pattern only")
                        .long_help(FILTER_LONG_HELP)
                        .action(ArgAction::Append)
                )
                .arg(&num_threads_arg),

            command("fmt")
                .about("Format YARA source files")
                .arg(&rules_path_arg),
        ])
        .get_matches_from(wild::args());

    #[cfg(feature = "profiling")]
    let guard =
        pprof::ProfilerGuardBuilder::default().frequency(1000).build()?;

    match args.subcommand() {
        Some(("ast", args)) => cmd_ast(args)?,
        Some(("wasm", args)) => cmd_wasm(args)?,
        Some(("check", args)) => cmd_check(args)?,
        Some(("fmt", args)) => cmd_format(args)?,
        Some(("scan", args)) => cmd_scan(args)?,
        Some(("compile", args)) => cmd_compile(args)?,
        _ => unreachable!(),
    };

    #[cfg(feature = "profiling")]
    if let Ok(report) = guard.report().build() {
        let file = std::fs::File::create("flamegraph.svg")?;
        report.flamegraph(file)?;
        println!("profiling information written to flamegraph.svg");
    };

    Ok(())
}

fn cmd_scan(args: &ArgMatches) -> anyhow::Result<()> {
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

fn cmd_compile(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let output_path = args.get_one::<PathBuf>("OUTPUT_PATH").unwrap();
    let path_as_namespace = args.get_flag("path-as-namespace");

    let rules = compile_rules(rules_path, path_as_namespace)?;

    let output_file = File::create(output_path).with_context(|| {
        format!("can not write `{}`", output_path.display())
    })?;

    Ok(rules.serialize_into(&output_file)?)
}

fn cmd_ast(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let src = SourceCode::from(src.as_slice())
        .origin(rules_path.as_os_str().to_str().unwrap());

    let ast = Parser::new().colorize_errors(true).build_ast(src)?;

    let mut output = String::new();
    ascii_tree::write_tree(&mut output, &ast.ascii_tree())?;

    println!("{output}");
    Ok(())
}

fn cmd_wasm(args: &ArgMatches) -> anyhow::Result<()> {
    let mut rules_path =
        args.get_one::<PathBuf>("RULES_PATH").unwrap().to_path_buf();

    let src = fs::read(rules_path.as_path())
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let src = SourceCode::from(src.as_slice())
        .origin(rules_path.as_os_str().to_str().unwrap());

    rules_path.set_extension("wasm");

    Compiler::new()
        .colorize_errors(true)
        .add_source(src)?
        .emit_wasm_file(rules_path.as_path())?;

    Ok(())
}

fn cmd_check(args: &ArgMatches) -> anyhow::Result<()> {
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

fn cmd_format(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_many::<PathBuf>("RULES_PATH");
    let formatter = Formatter::new();

    if let Some(files) = rules_path {
        for file in files {
            let input = fs::read(file.as_path())?;
            let output = File::create(file.as_path())?;
            formatter.format(input.as_slice(), output)?;
        }
    } else {
        formatter.format(stdin(), stdout())?;
    }

    Ok(())
}

fn compile_rules<'a, P>(
    paths: P,
    path_as_namespace: bool,
) -> Result<Rules, Error>
where
    P: Iterator<Item = &'a PathBuf>,
{
    let mut compiler = Compiler::new().colorize_errors(true);

    for path in paths {
        let src = fs::read(path)
            .with_context(|| format!("can not read `{}`", path.display()))?;

        let src = SourceCode::from(src.as_slice())
            .origin(path.as_os_str().to_str().unwrap());

        if path_as_namespace {
            compiler = compiler.new_namespace(path.to_string_lossy().as_ref());
        }

        compiler = compiler.add_source(src)?;
    }

    compiler.build()
}
