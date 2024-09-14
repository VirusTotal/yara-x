use clap::{arg, value_parser, ArgAction, ArgMatches, Command, ValueEnum};

use colored_json::{ColorMode, ToColoredJson};
use crossterm::tty::IsTty;
use protobuf::MessageField;
use protobuf_json_mapping::print_to_string;
use std::fs::File;
use std::io::{stdin, stdout, Read};
use std::path::PathBuf;
use strum_macros::Display;

use crate::help;
use yara_x::mods::*;
use yara_x_proto_yaml::Serializer;

#[derive(Debug, Clone, ValueEnum, Display, PartialEq)]
enum SupportedModules {
    Lnk,
    Macho,
    Elf,
    Pe,
    Dotnet,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormats {
    Json,
    Yaml,
}

/// Creates the `dump` command.
/// The `dump` command dumps information about binary files.
///
/// # Returns
///
/// Returns a `Command` struct that represents the `dump` command.
pub fn dump() -> Command {
    super::command("dump")
        .about("Show the data produced by YARA modules for a file")
        .long_about(help::DUMP_LONG_HELP)
        .arg(
            arg!(<FILE>)
                .help("Path to binary file")
                .value_parser(value_parser!(PathBuf)),
        )
        // Keep options sorted alphabetically by their long name.
        // For instance, --bar goes before --foo.
        .arg(
            arg!(-m - -"module")
                .help("Module name")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .value_parser(value_parser!(SupportedModules)),
        )
        .arg(arg!(--"no-colors").help("Turn off colors in YAML output"))
        .arg(
            arg!(-o --"output-format" <FORMAT>)
                .help("Desired output format")
                .value_parser(value_parser!(OutputFormats)),
        )
}

/// Executes the `dump` command.
///
/// # Arguments
///
/// * `args`: The arguments passed to the `dump` command.
///
/// # Returns
///
/// Returns a `Result<(), anyhow::Error>` indicating whether the operation was
/// successful or not.
pub fn exec_dump(args: &ArgMatches) -> anyhow::Result<()> {
    let mut buffer = Vec::new();

    let file = args.get_one::<PathBuf>("FILE");
    let output_format = args.get_one::<OutputFormats>("output-format");
    let requested_modules = args.get_many::<SupportedModules>("module");
    let no_colors = args.get_flag("no-colors");

    // By default, use colors if output is stdout. When output is a standard
    // file colors are disabled, and also when `--no-colors` is used.
    let use_color = stdout().is_tty() && !no_colors;

    // Get the input.
    if let Some(file) = file {
        File::open(file.as_path())?.read_to_end(&mut buffer)?
    } else {
        stdin().read_to_end(&mut buffer)?
    };

    let mut module_output = invoke_all(&buffer);

    if let Some(modules) = requested_modules {
        // The user asked explicitly for one or more modules, clear out
        // those that weren't explicitly asked for.
        let requested_modules: Vec<_> = modules.collect();

        if !requested_modules.contains(&&SupportedModules::Dotnet) {
            module_output.dotnet = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Elf) {
            module_output.elf = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Lnk) {
            module_output.lnk = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Macho) {
            module_output.macho = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Pe) {
            module_output.pe = MessageField::none()
        }
    } else {
        // Module was not specified, only show those that produced meaningful
        // results, the rest are cleared out.
        if !module_output.dotnet.is_dotnet() {
            module_output.dotnet = MessageField::none()
        }
        if !module_output.elf.has_type() {
            module_output.elf = MessageField::none()
        }
        if !module_output.lnk.is_lnk() {
            module_output.lnk = MessageField::none()
        }
        if !module_output.macho.has_magic()
            && !module_output.macho.has_fat_magic()
        {
            module_output.macho = MessageField::none()
        }
        if !module_output.pe.is_pe() {
            module_output.pe = MessageField::none()
        }
    }

    match output_format {
        Some(OutputFormats::Json) => {
            let mode = if use_color { ColorMode::On } else { ColorMode::Off };
            println!(
                "{}",
                print_to_string(module_output.as_ref())?
                    .to_colored_json(mode)?
            );
        }
        Some(OutputFormats::Yaml) | None => {
            let mut serializer = Serializer::new(stdout());
            serializer
                .with_colors(use_color)
                .serialize(module_output.as_ref())
                .expect("Failed to serialize");
            println!();
        }
    }

    Ok(())
}
