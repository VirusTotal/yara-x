use std::fs;
use std::fs::metadata;
use std::io::{stdin, stdout};
use std::path::PathBuf;

use ansi_term::Color::{Blue, Red};
use anyhow::Context;
use clap::{arg, command, crate_authors, value_parser, ArgMatches, Command};
use globset::GlobBuilder;
use yara_x::compiler::Compiler;

use yara_x::formatter;
use yara_x::parser::{Parser, SourceCode};
use yara_x::scanner::Scanner;

mod check;

const APP_HELP_TEMPLATE: &str = r#"{about-with-newline}
{author-with-newline}
{before-help}{usage-heading}
    {usage}

{all-args}{after-help}
"#;

const CHECK_LONG_HELP: &str = r#"Check if YARA source files are syntactically correct

If <PATH> is a directory, all files with extensions `yar` and `yara` will be
checked. The `--filter` option allows changing this behavior.

"#;

const DEPTH_LONG_HELP: &str = r#"Walk directories recursively up to a given depth

Controls how many levels to go down in the directory tree while looking for
files. This only applies when <PATH> is a directory. The default value is 1,
which means that only the files in the specified directory will be checked,
without entering in subdirectories.

"#;

const FILTER_LONG_HELP: &str = r#"Check files that match the given pattern only

Patterns can contains the following wilcards:

?      matches any single character.

*      matches any sequence of characters, except the path separator.

**     matches any sequence of characters, including the path separator.

[...]  matches any character inside the brackets. Can also specify ranges of
       characters (e.g. [0-9], [a-z])

[!...] is the negation of [...]

This option can be used more than once with different patterns. In such cases
files matching any one of patterns will be checked.

The absense of this options is equivalent to using this:

--filter='**/*.yara' --filter='**/*.yar'

"#;

fn command(name: &str) -> Command {
    Command::new(name).help_template(
        r#"{about-with-newline}
{usage-heading}
    {usage}

{all-args}
"#,
    )
}

fn main() -> anyhow::Result<()> {
    let args = command!()
        .author(crate_authors!("\n")) // requires `cargo` feature
        .arg_required_else_help(true)
        .help_template(APP_HELP_TEMPLATE)
        .subcommands(vec![
            command("scan")
                .about(
                    "Scans a file with some YARA",
                )
                .arg(
                    arg!(<RULES_FILE>)
                        .help("Path to YARA source file")
                        .value_parser(value_parser!(PathBuf)),

                ).arg(
                    arg!(<FILE>)
                        .help("Path to the file that will be scanned")
                        .value_parser(value_parser!(PathBuf))
                ),
            command("ast")
                .about(
                    "Print Abstract Syntax Tree (AST) for a YARA source file",
                )
                .arg(
                    arg!(<FILE>)
                        .help("Path to YARA source file")
                        .value_parser(value_parser!(PathBuf)),
                ),
            command("wasm")
                .about("Emits a .wasm file with the code generated for a YARA source file")
                .arg(
                    arg!(<FILE>)
                        .help("Path to YARA source file")
                        .value_parser(value_parser!(PathBuf)),
                )
            ,
            command("check")
                .about("Check if YARA source files are syntactically correct")
                .long_about(CHECK_LONG_HELP)
                .arg(
                    arg!(<PATH>)
                        .help("Path to YARA source file or directory")
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    arg!(-d --"max-depth" <DEPTH>)
                        .help(
                            "Walk directories recursively up to a given depth",
                        )
                        .long_help(DEPTH_LONG_HELP)
                        .required(false)
                        .value_parser(value_parser!(u16).range(1..)),
                )
                .arg(
                    arg!(-f --filter <PATTERN>)
                        .help("Check files that match the given pattern only")
                        .long_help(FILTER_LONG_HELP)
                        .required(false)
                        .multiple_occurrences(true),
                ),
            command("fmt").about("Format YARA source files").arg(
                arg!([FILE])
                    .help("Path to YARA source files")
                    .multiple_values(true)
                    .value_parser(value_parser!(PathBuf)),
            ),
        ])
        .get_matches();

    #[cfg(feature = "profiling")]
    let guard =
        pprof::ProfilerGuardBuilder::default().frequency(1000).build()?;

    let result = match args.subcommand() {
        Some(("ast", args)) => cmd_ast(args),
        Some(("wasm", args)) => cmd_wasm(args),
        Some(("check", args)) => cmd_check(args),
        Some(("fmt", args)) => cmd_format(args),
        Some(("scan", args)) => cmd_scan(args),
        _ => unreachable!(),
    };

    if let Err(err) = result {
        println!("{}", err);
    }

    #[cfg(feature = "profiling")]
    if let Ok(report) = guard.report().build() {
        let file = std::fs::File::create("flamegraph.svg")?;
        report.flamegraph(file)?;
        println!("profiling information written to flamegraph.svg");
    };

    Ok(())
}

fn cmd_scan(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_FILE").unwrap();
    let file_path = args.get_one::<PathBuf>("FILE").unwrap();

    let src = fs::read_to_string(rules_path).with_context(|| {
        format!("could not read file `{}`", rules_path.display())
    })?;

    let src = SourceCode::from(src.as_str())
        .origin(file_path.as_os_str().to_str().unwrap());

    let rules =
        Compiler::new().colorize_errors(true).add_source(src)?.build()?;

    let mut scanner = Scanner::new(&rules);

    scanner.scan_file(file_path)?;

    Ok(())
}

fn cmd_ast(args: &ArgMatches) -> anyhow::Result<()> {
    let file_path = args.get_one::<PathBuf>("FILE").unwrap();

    let src = fs::read_to_string(file_path).with_context(|| {
        format!("could not read file `{}`", file_path.display())
    })?;

    let src = SourceCode::from(src.as_str())
        .origin(file_path.as_os_str().to_str().unwrap());

    let ast = Parser::new().colorize_errors(true).build_ast(src)?;

    let mut output = String::new();
    ascii_tree::write_tree(&mut output, &ast.ascii_tree())?;

    println!("{output}");
    Ok(())
}

fn cmd_wasm(args: &ArgMatches) -> anyhow::Result<()> {
    let mut file_path = args.get_one::<PathBuf>("FILE").unwrap().to_path_buf();

    let src = fs::read_to_string(file_path.as_path()).with_context(|| {
        format!("could not read file `{}`", file_path.display())
    })?;

    let src = SourceCode::from(src.as_str())
        .origin(file_path.as_os_str().to_str().unwrap());

    file_path.set_extension("wasm");

    Compiler::new()
        .colorize_errors(true)
        .add_source(src)?
        .emit_wasm_file(file_path.as_path())?;

    Ok(())
}

fn cmd_check(args: &ArgMatches) -> anyhow::Result<()> {
    let path = args.get_one::<PathBuf>("PATH").unwrap();
    let max_depth = args.get_one::<u16>("max-depth").unwrap_or(&1);

    let metadata = metadata(path)
        .with_context(|| format!("can not access `{}`", path.display()))?;

    let result = if metadata.is_dir() {
        let mut patterns = Vec::new();
        if let Some(filters) = args.get_many::<String>("filter") {
            for f in filters {
                patterns.push(
                    GlobBuilder::new(f)
                        .literal_separator(true)
                        .build()?
                        .compile_matcher(),
                )
            }
        } else {
            patterns.push(
                GlobBuilder::new("**/*.yar")
                    .literal_separator(true)
                    .build()
                    .unwrap()
                    .compile_matcher(),
            );
            patterns.push(
                GlobBuilder::new("**/*.yara")
                    .literal_separator(true)
                    .build()
                    .unwrap()
                    .compile_matcher(),
            );
        }

        check::check_dir(path, *max_depth, Some(&patterns))
    } else {
        check::check_file(path, None)
    };

    if let Err(err) = result {
        println!(
            "\n{}: {:?}\n {} {}",
            Red.paint("error"),
            err,
            Blue.paint("-->"),
            path.display(),
        );
    }

    Ok(())
}

fn cmd_format(args: &ArgMatches) -> anyhow::Result<()> {
    let files = args.get_many::<PathBuf>("FILE");

    let formatter = formatter::Formatter::new();

    if let Some(files) = files {
        println!("{:?}", files);
    } else {
        formatter.format(stdin(), stdout())?;
    }

    Ok(())
}
