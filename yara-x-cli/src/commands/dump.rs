use clap::{arg, value_parser, Arg, ArgAction, ArgMatches, Command};
use std::fs::File;
use std::io::stdin;
use std::path::PathBuf;

use yara_x_dump::Dumper;

use yara_x::get_builtin_modules_names;

pub fn dump() -> Command {
    super::command("dump")
        .about("Dump information about binary files")
        .arg(
            arg!(<FILE>)
                .help("Path to binary file")
                .value_parser(value_parser!(PathBuf))
                .required(false),
        )
        .arg(
            arg!(-o --"output-format" <FORMAT>)
                .help("Desired output format")
                .value_parser(value_parser!(String))
                .required(false),
        )
        .arg(
            Arg::new("modules")
            .long("modules")
            .short('m')
            .help("Name of the module or comma-separated list of modules to be used for parsing")
            .required(false)
            .action(ArgAction::Append)
            .value_parser(get_builtin_modules_names()),
        )
}

pub fn exec_dump(args: &ArgMatches) -> anyhow::Result<()> {
    let file = args.get_one::<PathBuf>("FILE");
    let output_format = args.get_one::<String>("output-format");

    // get vector of modules
    let modules: Vec<&str> = args
        .get_many::<String>("modules")
        .unwrap_or_default()
        .map(|s| s.as_str())
        .collect();

    let dumper = Dumper::default();

    let input: Box<dyn std::io::Read> = if let Some(file) = file {
        Box::new(File::open(file.as_path())?)
    } else {
        Box::new(stdin())
    };

    println!("{}", dumper.dump(input, modules, output_format)?);
    Ok(())
}
