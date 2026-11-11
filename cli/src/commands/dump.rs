use clap::{ArgAction, ArgMatches, Command, ValueEnum, arg, value_parser};

use crossterm::tty::IsTty;
use std::fs::File;
use std::io::{Read, stdin, stdout};
use std::path::PathBuf;

use yara_x::mods::*;
use yara_x_proto::json::{Format as JsonFormat, Serializer as JsonSerializer};
use yara_x_proto::yaml::Serializer as YamlSerializer;

use crate::help;

#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum SupportedModules {
    Lnk,
    Macho,
    Elf,
    Pe,
    Dotnet,
    Olecf,
    Vba,
    Crx,
    Dex,
    Zip,
}

impl SupportedModules {
    /// Returns the name of the module.
    fn name(&self) -> &'static str {
        match self {
            SupportedModules::Lnk => "lnk",
            SupportedModules::Macho => "macho",
            SupportedModules::Elf => "elf",
            SupportedModules::Pe => "pe",
            SupportedModules::Dotnet => "dotnet",
            SupportedModules::Olecf => "olecf",
            SupportedModules::Vba => "vba",
            SupportedModules::Crx => "crx",
            SupportedModules::Dex => "dex",
            SupportedModules::Zip => "zip",
        }
    }
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
        let requested_modules =
            modules.map(|m| m.name()).collect::<Vec<&str>>();

        retain_requested(module_output.as_mut(), &requested_modules)?;
    } else {
        // Module was not specified, only show those that produced meaningful
        // results, the rest are cleared out.
        retain_meaningful(module_output.as_mut());
    }

    match output_format {
        Some(OutputFormats::Json) => {
            let mut serializer = JsonSerializer::new(stdout());
            serializer
                .with_colors(use_color)
                .with_format(JsonFormat::Legacy)
                .serialize(module_output.as_ref())?;
            println!();
        }
        Some(OutputFormats::Yaml) | None => {
            let mut serializer = YamlSerializer::new(stdout());
            serializer
                .with_colors(use_color)
                .serialize(module_output.as_ref())?;
            println!();
        }
    }

    Ok(())
}
