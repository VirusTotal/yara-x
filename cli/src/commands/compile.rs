use std::fs::File;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, Arg, ArgAction, ArgMatches, Command};

use crate::commands::{
    compilation_args, compile_rules, path_with_namespace_parser,
};
use crate::config::Config;

pub fn compile() -> Command {
    super::command("compile")
        .about("Compile rules to binary form")
        .arg(
            Arg::new("[NAMESPACE:]RULES_PATH")
                .required(true)
                .help("Path to a YARA source file or directory (optionally prefixed with a namespace)")
                .value_parser(path_with_namespace_parser)
                .action(ArgAction::Append)
        )
        .args(itertools::merge(compilation_args(), [
            arg!(-o --"output" <OUTPUT_PATH>)
                .help("Output file with compiled results")
                .default_value("output.yarc")
                .value_parser(value_parser!(PathBuf))]))
}

pub fn exec_compile(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let rules_path = args
        .get_many::<(Option<String>, PathBuf)>("[NAMESPACE:]RULES_PATH")
        .unwrap();

    let output_path = args.get_one::<PathBuf>("output").unwrap();
    let rules = compile_rules(rules_path, args, config)?;

    let output_file = File::create(output_path).with_context(|| {
        format!("can not write `{}`", output_path.display())
    })?;

    Ok(rules.serialize_into(&output_file)?)
}
