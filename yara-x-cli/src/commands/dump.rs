use clap::{arg, value_parser, Arg, ArgAction, ArgMatches, Command};
use std::fs::File;
use std::io::stdin;
use std::path::PathBuf;

use yara_x_dump::Dumper;

use crate::commands::modules_parser;

pub fn dump() -> Command {
    super::command("dump")
        .about("Dump information about binary files")
        .arg(
            arg!(<FILE>)
                .help("Path to binary file")
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append)
                .required(false),
        )
        .arg(
            Arg::new("modules")
            .long("modules")
            .help("Name of the module or comma-separated list of modules to be used for parsing")
            .required(false)
            .value_parser(modules_parser),
        )
}

pub fn exec_dump(args: &ArgMatches) -> anyhow::Result<()> {
    let file = args.get_one::<PathBuf>("FILE");
    let modules = args.get_one::<Vec<String>>("modules");

    let dumper = Dumper::new();

    if let Some(file) = file {
        println!("Dumping file: {:?}", file.as_path());
        let input = File::open(file.as_path())?;
        dumper.dump(input, modules)?;
    } else {
        println!("Dumping stdin");
        dumper.dump(stdin(), modules)?;
    }

    Ok(())
}
