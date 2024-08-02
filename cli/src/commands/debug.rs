use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgMatches, Command};

use yara_x::{Compiler, SourceCode};
use yara_x_parser::Parser;

pub fn ast() -> Command {
    super::command("ast")
        .about("Print Abstract Syntax Tree (AST) for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
}

pub fn cst() -> Command {
    super::command("cst")
        .about("Print Concrete Syntax Tree (CST) for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
}

pub fn wasm() -> Command {
    super::command("wasm")
        .about(
            "Emit a .wasm file with the code generated for a YARA source file",
        )
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
}

pub fn debug() -> Command {
    super::command("debug")
        .about("Debug utilities")
        .arg_required_else_help(true)
        .hide(true)
        .subcommand(ast())
        .subcommand(cst())
        .subcommand(wasm())
}

pub fn exec_debug(args: &ArgMatches) -> anyhow::Result<()> {
    match args.subcommand() {
        Some(("ast", args)) => exec_ast(args),
        Some(("cst", args)) => exec_cst(args),
        Some(("wasm", args)) => exec_wasm(args),
        _ => unreachable!(),
    }
}

pub fn exec_ast(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let parser = Parser::new(src.as_slice());
    let ast = parser.into_ast();

    println!("{ast:?}");
    Ok(())
}

pub fn exec_cst(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let parser = Parser::new(src.as_slice());
    let cst = parser.into_cst();

    println!("{cst:?}");
    Ok(())
}

fn exec_wasm(args: &ArgMatches) -> anyhow::Result<()> {
    let mut rules_path =
        args.get_one::<PathBuf>("RULES_PATH").unwrap().to_path_buf();

    let src = fs::read(rules_path.as_path())
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let src = SourceCode::from(src.as_slice())
        .with_origin(rules_path.as_os_str().to_str().unwrap());

    rules_path.set_extension("wasm");

    let mut compiler = Compiler::new();

    compiler.colorize_errors(true);
    compiler.add_source(src)?;
    compiler.emit_wasm_file(rules_path.as_path())?;

    Ok(())
}
