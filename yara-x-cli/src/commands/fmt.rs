use std::fs;
use std::fs::File;
use std::io::{stdin, stdout};
use std::path::PathBuf;

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use yara_x_fmt::Formatter;

pub fn fmt() -> Command {
    super::command("fmt").about("Format YARA source files").arg(
        arg!(<RULES_PATH>)
            .help("Path to YARA source file or directory")
            .value_parser(value_parser!(PathBuf))
            .action(ArgAction::Append),
    )
}

pub fn exec_fmt(args: &ArgMatches) -> anyhow::Result<()> {
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
