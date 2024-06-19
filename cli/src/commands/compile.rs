use std::fs::File;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, Arg, ArgAction, ArgMatches, Command};

use crate::commands::{compile_rules, external_var_parser};
use crate::help;

pub fn compile() -> Command {
    super::command("compile")
        .about("Compile rules to binary form")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-o --"output" <OUTPUT_PATH>)
                .help("Output file with compiled results")
                .default_value("output.yarc")
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            Arg::new("define")
                .short('d')
                .long("define")
                .help("Define external variable")
                .long_help(help::DEFINE_LONG_HELP)
                .required(false)
                .value_name("VAR=VALUE")
                .value_parser(external_var_parser)
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-w --"disable-warnings" [WARNING_ID])
                .help("Disable warnings")
                .long_help(help::DISABLE_WARNINGS_LONG_HELP)
                .default_missing_value("all")
                .num_args(0..)
                .require_equals(true)
                .value_delimiter(',')
                .action(ArgAction::Append)
        )
        .arg(
            arg!(--"path-as-namespace")
                .help("Use file path as rule namespace"),
        )
        .arg(
            arg!(--"relaxed-re-syntax")
                .help("Use a more relaxed syntax check while parsing regular expressions"),
        )
}

pub fn exec_compile(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_many::<PathBuf>("RULES_PATH").unwrap();
    let path_as_namespace = args.get_flag("path-as-namespace");
    let output_path = args.get_one::<PathBuf>("output").unwrap();

    let external_vars: Option<Vec<(String, serde_json::Value)>> = args
        .get_many::<(String, serde_json::Value)>("define")
        .map(|var| var.cloned().collect());

    let disabled_warnings = args
        .get_many::<String>("disable-warnings")
        .map(|warnings| warnings.map(|id| id.as_str()).collect())
        .unwrap_or_default();

    let rules = compile_rules(
        rules_path,
        path_as_namespace,
        external_vars,
        args.get_flag("relaxed-re-syntax"),
        disabled_warnings,
    )?;

    let output_file = File::create(output_path).with_context(|| {
        format!("can not write `{}`", output_path.display())
    })?;

    Ok(rules.serialize_into(&output_file)?)
}
