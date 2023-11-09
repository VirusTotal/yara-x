use clap::{
    arg, value_parser, Arg, ArgAction, ArgMatches, Command, ValueEnum,
};

use colored_json::ToColoredJson;
use protobuf::{reflect::ReflectValueRef::Bool, MessageDyn};
use protobuf_json_mapping::print_to_string;
use std::fmt::Write;
use std::fs::File;
use std::io::stdin;
use std::io::Read;
use std::path::PathBuf;
use yansi::{Color::Cyan, Paint};
use yara_x_proto::exts::module_options;

use yara_x_dump::Dumper;

use yara_x::get_builtin_modules_names;

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
            .value_parser(get_builtin_modules_names()),
        )
}

// Checks if the module output is valid by checking the validity flag.
//
// # Arguments
//
// * `mod_output`: The module output to check.
//
// # Returns
//
// * `true` if the module output is valid, `false` otherwise.
fn module_is_valid(mod_output: &dyn MessageDyn) -> bool {
    // Get the module options.
    if let Some(module_desc) = module_options
        .get(&mod_output.descriptor_dyn().file_descriptor_proto().options)
    {
        // Get the field name which is considered as the validity flag.
        if let Some(validity_flag_str) = module_desc.validity_flag.as_deref() {
            // Get the validity flag value.
            if let Some(field) =
                mod_output.descriptor_dyn().field_by_name(validity_flag_str)
            {
                // Check if the validity flag is set.
                // Validity flag is set if the value present and is not
                // false.
                if let Some(value) = field.get_singular(mod_output) {
                    return value != Bool(false);
                }
            }
        }
    }

    false
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
    let mut result = String::new();

    let file = args.get_one::<PathBuf>("FILE");
    let output_format = args.get_one::<OutputFormats>("output-format");
    let colors_flag = args.get_flag("color");

    // Disable colors if the flag is not set.
    if !colors_flag {
        Paint::disable();
    }

    // get vector of modules
    let modules: Vec<&str> = args
        .get_many::<String>("modules")
        .unwrap_or_default()
        .map(|s| s.as_str())
        .collect();

    // Get the input.
    if let Some(file) = file {
        File::open(file.as_path())?.read_to_end(&mut buffer)?
    } else {
        stdin().read_to_end(&mut buffer)?
    };

    // Get the list of modules to import.
    let import_modules = if !modules.is_empty() {
        modules.clone()
    } else {
        yara_x::get_builtin_modules_names()
    };

    // Create a rule that imports all the built-in modules.
    let import_statements = import_modules
        .iter()
        .map(|module_name| format!("import \"{}\"", module_name))
        .collect::<Vec<_>>()
        .join("\n");

    // Create a dummy rule
    let rule =
        format!(r#"{} rule test {{ condition: false }}"#, import_statements);

    // Compile the rule.
    let rules = yara_x::compile(rule.as_str()).unwrap();

    let mut scanner = yara_x::Scanner::new(&rules);

    // Scan the buffer and get the results.
    let scan_results = scanner.scan(&buffer).expect("scan should not fail");

    for (mod_name, mod_output) in scan_results.module_outputs() {
        if mod_output.compute_size_dyn() != 0
            && (module_is_valid(mod_output) || modules.contains(&mod_name))
        {
            match output_format {
                Some(OutputFormats::Json) => {
                    writeln!(
                        result,
                        ">>>\n{}:\n{}\n<<<",
                        Cyan.paint(mod_name).bold(),
                        print_to_string(mod_output)?.to_colored_json_auto()?
                    )?;
                }
                Some(OutputFormats::Yaml) | None => {
                    let dumper = Dumper::default();
                    write!(
                        result,
                        ">>>\n{}:\n{}<<<",
                        Cyan.paint(mod_name).bold(),
                        dumper.dump(mod_output)?
                    )?;
                }
            }
        }
    }

    println!("{}", result);
    Ok(())
}
