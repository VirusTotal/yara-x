use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use std::fs::File;
use std::io::stdin;
use std::path::PathBuf;

use yara_x::get_builtin_modules_names;
use yara_x_dump::Dumper;

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
            arg!(--"modules" <NAME>)
                .help("Name of the module or comma-separated list of modules to be used for parsing")
                .value_parser(value_parser!(String))
                .value_delimiter(',')
                .required(false),
        )
}

pub fn exec_dump(args: &ArgMatches) -> anyhow::Result<()> {
    let file = args.get_one::<PathBuf>("FILE");
    let modules = args
        .get_many::<String>("modules")
        .unwrap_or_default()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    // Validate modules
    let supported_modules = get_builtin_modules_names();
    for module in &modules {
        if !supported_modules.contains(&module.as_str()) {
            anyhow::bail!("Unsupported module: {}. Supported modules for --modules argument are: {}", module, supported_modules.join(", "));
        }
    }

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
