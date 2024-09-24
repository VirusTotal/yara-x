use std::fs::File;
use std::path::PathBuf;
use std::{fs, io, process};

use crate::help::{FMT_CHECK_MODE, FMT_CONFIG_FILE};
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use yara_x_fmt::Formatter;

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    rule: Rule,
    meta: Meta,
    patterns: Patterns,
}

#[derive(Deserialize, Serialize, Debug)]
struct Rule {
    indent_section_headers: bool,
    indent_section_contents: bool,
}

#[derive(Deserialize, Serialize, Debug)]
struct Meta {
    align_values: bool,
}

#[derive(Deserialize, Serialize, Debug)]
struct Patterns {
    align_values: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            rule: Rule {
                indent_section_headers: true,
                indent_section_contents: true,
            },
            meta: Meta { align_values: true },
            patterns: Patterns { align_values: true },
        }
    }
}

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
        .arg(
            arg!(-C --config <CONFIG_FILE> "Config file")
                .value_parser(value_parser!(PathBuf))
                .long_help(FMT_CONFIG_FILE),
        )
}

pub fn exec_fmt(args: &ArgMatches) -> anyhow::Result<()> {
    let files = args.get_many::<PathBuf>("FILE").unwrap();
    let check = args.get_flag("check");
    let config_file = args.get_one::<PathBuf>("config");

    let formatter = if config_file.is_some() {
        let config: Config =
            Figment::from(Serialized::defaults(Config::default()))
                .merge(Toml::file_exact(&config_file.unwrap()))
                .extract()?;
        Formatter::new()
            .align_metadata(config.meta.align_values)
            .align_patterns(config.patterns.align_values)
            .indent_section_headers(config.rule.indent_section_headers)
            .indent_section_contents(config.rule.indent_section_contents)
    } else {
        Formatter::new()
    };

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
