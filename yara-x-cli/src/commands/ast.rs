use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgMatches, Command};
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

pub fn exec_ast(args: &ArgMatches) -> anyhow::Result<()> {
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
