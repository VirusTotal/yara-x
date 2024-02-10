use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgMatches, Command};

use yara_x::Compiler;
use yara_x_parser::{Parser, SourceCode};

pub fn ast() -> Command {
    super::command("ast")
        .about("Print Abstract Syntax Tree (AST) for a YARA source file")
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
        .subcommand(wasm())
}

pub fn exec_debug(args: &ArgMatches) -> anyhow::Result<()> {
    match args.subcommand() {
        Some(("ast", args)) => exec_ast(args),
        Some(("wasm", args)) => exec_wasm(args),
        _ => unreachable!(),
    }
}

pub fn exec_ast(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let src = SourceCode::from(src.as_slice())
        .with_origin(rules_path.as_os_str().to_str().unwrap());

    let ast = Parser::new().colorize_errors(true).build_ast(src)?;

    let mut output = String::new();
    ascii_tree::write_tree(&mut output, &ast.ascii_tree())?;

    println!("{output}");
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

    let mut compiler = Compiler::new().colorize_errors(true);

    compiler.add_source(src)?;
    compiler.emit_wasm_file(rules_path.as_path())?;

    Ok(())
}
