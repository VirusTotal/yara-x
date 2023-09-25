use std::fs;
use std::fs::File;
use std::io::{stdin, stdout};
use std::path::PathBuf;

use clap::{arg, value_parser, ArgAction, Command};
use yara_x_fmt::Formatter;

const APP_HELP_TEMPLATE: &str = r#"{about-with-newline}
{author-with-newline}
{before-help}{usage-heading}
    {usage}

{all-args}{after-help}
"#;

fn main() -> anyhow::Result<()> {
    // Enable support for ANSI escape codes in Windows. In other platforms
    // this is a no-op.
    if let Err(err) = enable_ansi_support::enable_ansi_support() {
        println!("could not enable ANSI support: {}", err)
    }

    let args = Command::new("yrfmt")
        .about("Format YARA source code")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .help_template(APP_HELP_TEMPLATE)
        .arg(
            arg!([FILE])
                .help("Path to YARA source file")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-w  --write ... "Write output to source file instead of stdout")
                .action(ArgAction::SetTrue),

        )
        .get_matches();

    let files = args.get_many::<PathBuf>("FILE");
    let write = args.get_one::<bool>("write");

    let formatter = Formatter::new();

    if let Some(files) = files {
        for file in files {
            let input = fs::read(file.as_path())?;
            if *write.unwrap() {
                let output = File::create(file.as_path())?;
                formatter.format(input.as_slice(), output)?;
            } else {
                formatter.format(input.as_slice(), stdout())?;
            };
        }
    } else {
        formatter.format(stdin(), stdout())?;
    }

    Ok(())
}
