use std::fs::File;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};

use crate::commands::compile_rules;

pub fn compile() -> Command {
    super::command("compile")
        .about("Compiles YARA rules into binary form")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append),
        )
        .arg(
            arg!(<OUTPUT_PATH>)
                .help("Path to file with compiled results")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace"),
        )
}

pub fn exec_compile(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let output_path = args.get_one::<PathBuf>("OUTPUT_PATH").unwrap();
    let path_as_namespace = args.get_flag("path-as-namespace");

    let rules = compile_rules(rules_path, path_as_namespace)?;

    let output_file = File::create(output_path).with_context(|| {
        format!("can not write `{}`", output_path.display())
    })?;

    Ok(rules.serialize_into(&output_file)?)
}
