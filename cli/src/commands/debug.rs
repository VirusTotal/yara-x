#![cfg(feature = "debug-cmd")]
use std::fs;
use std::io::stdout;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};

use yara_x::SourceCode;
use yara_x_parser::Parser;

use crate::commands::{
    create_compiler, external_var_parser, get_external_vars,
};
use crate::help;

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

pub fn ir() -> Command {
    super::command("ir")
        .about("Print Intermediate Representation (IR) for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-d - -"define")
                .help("Define external variable")
                .long_help(help::DEFINE_LONG_HELP)
                .value_name("VAR=VALUE")
                .value_parser(external_var_parser)
                .action(ArgAction::Append),
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
        .arg(
            arg!(-d - -"define")
                .help("Define external variable")
                .long_help(help::DEFINE_LONG_HELP)
                .value_name("VAR=VALUE")
                .value_parser(external_var_parser)
                .action(ArgAction::Append),
        )
}

pub fn modules() -> Command {
    super::command("modules").about("List available modules")
}

pub fn debug() -> Command {
    super::command("debug")
        .about("Debug utilities")
        .arg_required_else_help(true)
        .subcommand(ast())
        .subcommand(cst())
        .subcommand(ir())
        .subcommand(wasm())
        .subcommand(modules())
}

pub fn exec_debug(args: &ArgMatches) -> anyhow::Result<()> {
    match args.subcommand() {
        Some(("ast", args)) => exec_ast(args),
        Some(("cst", args)) => exec_cst(args),
        Some(("ir", args)) => exec_ir(args),
        Some(("wasm", args)) => exec_wasm(args),
        Some(("modules", args)) => exec_modules(args),
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
    let cst = parser.try_into_cst()?;

    println!("{cst:?}");
    Ok(())
}

pub fn exec_ir(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let external_vars = get_external_vars(args);
    let mut compiler = create_compiler(external_vars, args)?;

    compiler.set_ir_writer(stdout());
    compiler.add_source(src.as_slice())?;

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

    let external_vars = get_external_vars(args);
    let mut compiler = create_compiler(external_vars, args)?;

    compiler.add_source(src)?;
    compiler.emit_wasm_file(rules_path.as_path())?;

    Ok(())
}

fn exec_modules(_args: &ArgMatches) -> anyhow::Result<()> {
    for name in yara_x::mods::module_names() {
        println!("{}", name);
    }
    Ok(())
}
