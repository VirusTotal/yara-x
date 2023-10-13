use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use std::fs::File;
use std::io::stdin;
use std::path::PathBuf;

use yara_x_dump::Dumper;

pub fn dump() -> Command {
    super::command("dump").about("Dump information about binary files").arg(
        arg!(<FILE>)
            .help("Path to binary file")
            .value_parser(value_parser!(PathBuf))
            .action(ArgAction::Append)
            .required(false),
    )
}

pub fn exec_dump(args: &ArgMatches) -> anyhow::Result<()> {
    let file = args.get_one::<PathBuf>("FILE");

    let dumper = Dumper::new();

    if let Some(file) = file {
        println!("Dumping file: {:?}", file.as_path());
        let input = File::open(file.as_path())?;
        dumper.dump(input)?;
    } else {
        println!("Dumping stdin");
        dumper.dump(stdin())?;
    }

    Ok(())
}
