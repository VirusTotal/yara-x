use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;
use std::{fs, io, process};

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use yara_x_fmt::Formatter;

use crate::config::Config;
use crate::help::FMT_CHECK_MODE;

pub fn fmt() -> Command {
    super::command("fmt")
        .about("Format YARA source files")
        .arg(
            arg!(<FILE>)
                .help("Path to YARA source file")
                .required(true)
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append),
        )
        .arg(arg!(-c --check  "Run in 'check' mode").long_help(FMT_CHECK_MODE))
}

pub fn exec_fmt(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let files = args.get_many::<PathBuf>("FILE").unwrap();
    let check = args.get_flag("check");

    let formatter = Formatter::new()
        .align_metadata(config.fmt.meta.align_values)
        .align_patterns(config.fmt.patterns.align_values)
        .indent_section_headers(config.fmt.rule.indent_section_headers)
        .indent_section_contents(config.fmt.rule.indent_section_contents)
        .indent_spaces(config.fmt.rule.indent_spaces)
        .newline_before_curly_brace(config.fmt.rule.newline_before_curly_brace)
        .empty_line_before_section_header(
            config.fmt.rule.empty_line_before_section_header,
        )
        .empty_line_after_section_header(
            config.fmt.rule.empty_line_after_section_header,
        );

    let mut modified = false;

    for file in files {
        let input = fs::read(file.as_path())?;
        modified = if check {
            formatter.format(input.as_slice(), io::sink())?
        } else {
            let mut formatted = Cursor::new(Vec::with_capacity(input.len()));
            if formatter.format(input.as_slice(), &mut formatted)? {
                formatted.seek(SeekFrom::Start(0))?;
                let mut output_file = File::create(file.as_path())?;
                io::copy(&mut formatted, &mut output_file)?;
                true
            } else {
                false
            }
        } || modified;
    }

    if modified {
        process::exit(1)
    }

    Ok(())
}
