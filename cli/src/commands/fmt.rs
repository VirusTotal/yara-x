use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;
use std::{fs, io, process};

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use yara_x_fmt::{Formatter, Indentation};

use crate::config::Config;
use crate::help;

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
        .arg(
            arg!(-c --check  "Run in 'check' mode")
                .long_help(help::FMT_CHECK_MODE),
        )
        .arg(
            arg!(-t - -"tab-size" <NUM_SPACES>)
                .help("Tab size (in spaces) used in source files")
                .long_help(help::FMT_TAB_SIZE)
                .default_value("4")
                .value_parser(value_parser!(usize)),
        )
}

pub fn exec_fmt(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let files = args.get_many::<PathBuf>("FILE").unwrap();
    let check = args.get_flag("check");
    let tab_size = args.get_one::<usize>("tab-size").unwrap();

    let formatter = Formatter::new()
        .input_tab_size(*tab_size)
        .align_metadata(config.fmt.meta.align_values)
        .align_patterns(config.fmt.patterns.align_values)
        .indent_section_headers(config.fmt.rule.indent_section_headers)
        .indent_section_contents(config.fmt.rule.indent_section_contents)
        .indentation(if config.fmt.rule.indent_spaces == 0 {
            Indentation::Tabs
        } else {
            Indentation::Spaces(config.fmt.rule.indent_spaces as usize)
        })
        .newline_before_curly_brace(config.fmt.rule.newline_before_curly_brace)
        .empty_line_before_section_header(
            config.fmt.rule.empty_line_before_section_header,
        )
        .empty_line_after_section_header(
            config.fmt.rule.empty_line_after_section_header,
        );

    let mut modified_files: Vec<&PathBuf> = Vec::new();

    for file in files {
        let input = fs::read(file.as_path())?;
        let file_modified = if check {
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
        };

        if file_modified {
            modified_files.push(file);
        }
    }

    if !modified_files.is_empty() {
        if check {
            for file in &modified_files {
                eprintln!("{}", file.display());
            }
        }
        process::exit(1)
    }

    Ok(())
}
