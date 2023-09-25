use std::fs;
use std::fs::File;
use std::io::{stdin, stdout, Cursor, Seek, Write};
use std::path::PathBuf;

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use yara_x_fmt::Formatter;

pub fn fmt() -> Command {
    super::command("fmt").about("Format YARA source files")
        .arg(
            arg!(<FILE>)
            .help("Path to YARA source file")
            .value_parser(value_parser!(PathBuf))
            .action(ArgAction::Append),
        )
        .arg(
            arg!(-w  --write ... "Write output to source file instead of stdout")
                .action(ArgAction::SetTrue),
        )
}

pub fn exec_fmt(args: &ArgMatches) -> anyhow::Result<()> {
    let files = args.get_many::<PathBuf>("FILE");
    let write = args.get_one::<bool>("write");

    let formatter = Formatter::new();

    if let Some(files) = files {
        for file in files {
            let input = fs::read(file.as_path())?;
            if *write.unwrap() {
                let mut formatted = Cursor::new(Vec::new());

                formatter.format(input.as_slice(), &mut formatted)?;
                formatted.rewind()?;

                File::create(file.as_path())?
                    .write_all(formatted.into_inner().as_slice())?;
            } else {
                formatter.format(input.as_slice(), stdout())?;
            };
        }
    } else {
        formatter.format(stdin(), stdout())?;
    }

    Ok(())
}
