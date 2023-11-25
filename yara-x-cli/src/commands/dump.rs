use anyhow::Error;
use clap::{
    arg, value_parser, Arg, ArgAction, ArgMatches, Command, ValueEnum,
};

use colored_json::ToColoredJson;
use protobuf::MessageDyn;
use protobuf_json_mapping::print_to_string;
use std::fs::File;
use std::io::{stdin, stdout, Read};
use std::path::PathBuf;
use strum_macros::Display;
use yansi::{Color::Cyan, Paint};

use yara_x_proto_yaml::Serializer;

#[derive(Debug, Clone, ValueEnum, Display)]
enum SupportedModules {
    Lnk,
    Macho,
    Elf,
    Pe,
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
        .about("Dump information about binary files")
        .arg(
            arg!(<FILE>)
                .help("Path to binary file")
                .value_parser(value_parser!(PathBuf))
                .required(false),
        )
        .arg(
            arg!(-o --"output-format" <FORMAT>)
                .help("Desired output format")
                .value_parser(value_parser!(OutputFormats))
                .required(false),
        )
        .arg(
            arg!(-c - -"color")
                .help("Use colorful output")
        )
        .arg(
            Arg::new("modules")
            .long("modules")
            .short('m')
            .help("Name of the module or comma-separated list of modules to be used for parsing")
            .required(false)
            .action(ArgAction::Append)
            .value_parser(value_parser!(SupportedModules)),
        )
}

// Obtains information about a module by calling dumper crate.
//
// # Arguments
//
// * `output_format`: The output format.
// * `module`: The module name.
// * `output`: The output protobuf structure to be dumped.
//
// # Returns
//
// Returns a `Result<(), Error>` indicating whether the operation was
// successful or not.
fn obtain_module_info(
    output_format: Option<&OutputFormats>,
    module: &SupportedModules,
    output: &dyn MessageDyn,
) -> Result<(), Error> {
    match output_format {
        Some(OutputFormats::Json) => {
            println!("{}", Cyan.paint(module).bold());
            println!(">>>");
            println!("{}", print_to_string(output)?.to_colored_json_auto()?);
            println!("<<<");
        }
        Some(OutputFormats::Yaml) | None => {
            println!("{}", Cyan.paint(module).bold());
            println!(">>>");
            let mut serializer = Serializer::new(stdout());
            serializer
                .with_colors(true)
                .serialize(output)
                .expect("Failed to serialize");
            println!("\n<<<");
        }
    }
    Ok(())
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
    let modules = args.get_many::<SupportedModules>("modules");
    let colors_flag = args.get_flag("color");

    // Disable colors if the flag is not set.
    if !colors_flag {
        Paint::disable();
    }

    // Get the input.
    if let Some(file) = file {
        File::open(file.as_path())?.read_to_end(&mut buffer)?
    } else {
        stdin().read_to_end(&mut buffer)?
    };

    if let Some(modules) = modules {
        for module in modules {
            if let Some(output) = match module {
                SupportedModules::Lnk => {
                    yara_x::mods::invoke_mod_dyn::<yara_x::mods::Lnk>(&buffer)
                }
                SupportedModules::Macho => yara_x::mods::invoke_mod_dyn::<
                    yara_x::mods::Macho,
                >(&buffer),
                SupportedModules::Elf => {
                    yara_x::mods::invoke_mod_dyn::<yara_x::mods::ELF>(&buffer)
                }
                SupportedModules::Pe => {
                    yara_x::mods::invoke_mod_dyn::<yara_x::mods::PE>(&buffer)
                }
            } {
                obtain_module_info(output_format, module, &*output)?;
            }
        }
    } else {
        // Module was not specified therefore we have to obtain ouput for every supported module and decide which is valid.
        if let Some(lnk_output) =
            yara_x::mods::invoke_mod::<yara_x::mods::Lnk>(&buffer)
        {
            if lnk_output.is_lnk() {
                obtain_module_info(
                    output_format,
                    &SupportedModules::Lnk,
                    &*lnk_output,
                )?;
            }
        }
        if let Some(macho_output) =
            yara_x::mods::invoke_mod::<yara_x::mods::Macho>(&buffer)
        {
            if macho_output.has_magic() {
                obtain_module_info(
                    output_format,
                    &SupportedModules::Macho,
                    &*macho_output,
                )?;
            }
        }
        if let Some(elf_output) =
            yara_x::mods::invoke_mod::<yara_x::mods::ELF>(&buffer)
        {
            if elf_output.has_type() {
                obtain_module_info(
                    output_format,
                    &SupportedModules::Elf,
                    &*elf_output,
                )?;
            }
        }
        if let Some(pe_output) =
            yara_x::mods::invoke_mod::<yara_x::mods::PE>(&buffer)
        {
            if pe_output.is_pe() {
                obtain_module_info(
                    output_format,
                    &SupportedModules::Pe,
                    &*pe_output,
                )?;
            }
        }
    }

    Ok(())
}
