use std::fs::File;
use std::path::PathBuf;
use std::{fs, io, process};

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use yara_x_fmt::Formatter;

use crate::config::FormatConfig;
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

pub fn exec_fmt(
    args: &ArgMatches,
    config: FormatConfig,
) -> anyhow::Result<()> {
    let files = args.get_many::<PathBuf>("FILE").unwrap();
    let check = args.get_flag("check");

    let formatter = Formatter::new()
        .align_metadata(config.meta.align_values)
        .align_patterns(config.patterns.align_values)
        .indent_section_headers(config.rule.indent_section_headers)
        .indent_section_contents(config.rule.indent_section_contents)
        .indent_spaces(config.rule.indent_spaces)
        .newline_before_curly_brace(config.rule.newline_before_curly_brace)
        .empty_line_before_section_header(
            config.rule.empty_line_before_section_header,
        )
        .empty_line_after_section_header(
            config.rule.empty_line_after_section_header,
        );

    let mut changed = false;

    for file in files {
        let input = fs::read(file.as_path())?;
        changed = if check {
            formatter.format(input.as_slice(), io::sink())?
        } else {
            let output_file = File::create(file.as_path())?;
            formatter.format(input.as_slice(), output_file)?
        } || changed;
    }

    if changed {
        process::exit(1)
    }

    Ok(())
}
