use std::fs;
use std::fs::File;
use std::io::{stdin, stdout, Cursor, Seek, Write};
use std::path::PathBuf;
use std::process;

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
        .arg(
            arg!(-t  --test ... "Exit with failure if reformatting changed the file")
                .action(ArgAction::SetTrue),
        )
}

pub fn exec_fmt(args: &ArgMatches) -> anyhow::Result<()> {
    let files = args.get_many::<PathBuf>("FILE");
    let write = args.get_one::<bool>("write");
    let test = args.get_one::<bool>("test");

    let formatter = Formatter::new();

    if let Some(files) = files {
        let mut changed_files = Vec::new();

        for file in files {
            let input = fs::read(file.as_path())?;

            let mut formatted = Cursor::new(Vec::new());

            formatter.format(input.as_slice(), &mut formatted)?;
            formatted.rewind()?;

            let output = formatted.into_inner();

            if *test.unwrap() && input != output {
                changed_files.push(file.display().to_string());
            }

            if *write.unwrap() {
                File::create(file.as_path())?.write_all(output.as_slice())?;
            } else {
                print!("{}", String::from_utf8(output)?);
            };
        }

        if changed_files.len() >= 1 {
            eprintln!("File(s) to format: {}", changed_files.join(", "));
            process::exit(2)
        }
    } else {
        formatter.format(stdin(), stdout())?;
    }

    Ok(())
}
