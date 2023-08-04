use anyhow::Context;
use std::fs;
use std::path::PathBuf;

use clap::{arg, value_parser, ArgMatches, Command};
use yara_x::Compiler;
use yara_x_parser::SourceCode;

pub fn wasm() -> Command {
    super::command("wasm")
        .about("Emits a .wasm file with the code generated for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
}

pub fn exec_wasm(args: &ArgMatches) -> anyhow::Result<()> {
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
