use clap::{ArgAction, ArgMatches, Command, ValueEnum, arg, value_parser};

use crossterm::tty::IsTty;
use protobuf::{MessageDyn, MessageField};
use std::fs::File;
use std::io::{BufWriter, Read, Write, stdin, stdout};
use std::ops::ControlFlow;
use std::path::PathBuf;
use strum_macros::Display;

use yara_x::Extractor;
use yara_x::mods::*;
use yara_x_proto::json::{
    Format as JsonFormat, MapSerializer as JsonMapSerializer,
    Serializer as JsonSerializer,
};
use yara_x_proto::yaml::{
    MapSerializer as YamlMapSerializer, Serializer as YamlSerializer,
};

use crate::help;

#[derive(Debug, Clone, ValueEnum, Display, PartialEq)]
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

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormats {
    Json,
    Yaml,
}

enum DumpMapSerializer<'a, W: Write> {
    Json(JsonMapSerializer<'a, W>),
    Yaml(YamlMapSerializer<'a, W>),
}

impl<W: Write> DumpMapSerializer<'_, W> {
    fn serialize_entry(
        &mut self,
        key: &str,
        msg: &dyn MessageDyn,
    ) -> std::io::Result<()> {
        match self {
            Self::Json(s) => s.serialize_entry(key, msg),
            Self::Yaml(s) => s.serialize_entry(key, msg),
        }
    }

    fn finish(self) -> std::io::Result<()> {
        match self {
            Self::Json(s) => s.finish(),
            Self::Yaml(s) => s.finish(),
        }
    }
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
            arg!(-d --"max-depth" <DEPTH>)
                .help("Maximum container extraction depth")
                .long_help(help::DUMP_MAX_DEPTH_LONG_HELP)
                .value_parser(value_parser!(usize))
                .default_value("0"),
        )
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

fn invoke_modules(
    data: &[u8],
    requested_modules: Option<&[&SupportedModules]>,
    only_matching: bool,
) -> Box<Modules> {
    let mut module_output = invoke_all(data);

    // Clear modules that did not produce meaningful results when no specific
    // module was requested, or when `only_matching` is enforced.
    if only_matching || requested_modules.is_none() {
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
        if !module_output.crx.is_crx() {
            module_output.crx = MessageField::none()
        }
        if !module_output.dex.is_dex() {
            module_output.dex = MessageField::none()
        }
        if !module_output.olecf.is_olecf() {
            module_output.olecf = MessageField::none()
        }
        if !module_output.vba.has_macros() {
            module_output.vba = MessageField::none()
        }
        if !module_output.zip.is_zip() {
            module_output.zip = MessageField::none()
        }
        if !module_output.msi.is_signed()
            && module_output.msi.signatures.is_empty()
        {
            module_output.msi = MessageField::none()
        }
    }

    if let Some(requested_modules) = requested_modules {
        // The user asked explicitly for one or more modules, clear out
        // those that weren't explicitly asked for.
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
        if !requested_modules.contains(&&SupportedModules::Crx) {
            module_output.crx = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Dex) {
            module_output.dex = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Olecf) {
            module_output.olecf = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Vba) {
            module_output.vba = MessageField::none()
        }
        if !requested_modules.contains(&&SupportedModules::Zip) {
            module_output.zip = MessageField::none()
        }
        module_output.msi = MessageField::none()
    }

    module_output
}

fn has_any_module(m: &Modules) -> bool {
    m.pe.is_some()
        || m.elf.is_some()
        || m.dotnet.is_some()
        || m.macho.is_some()
        || m.lnk.is_some()
        || m.olecf.is_some()
        || m.vba.is_some()
        || m.crx.is_some()
        || m.dex.is_some()
        || m.msi.is_some()
        || m.zip.is_some()
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
    let max_depth = *args.get_one::<usize>("max-depth").unwrap_or(&0);
    let output_format = args.get_one::<OutputFormats>("output-format");
    let requested_modules: Option<Vec<_>> =
        args.get_many::<SupportedModules>("module").map(|m| m.collect());
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

    let mut out = BufWriter::new(stdout().lock());

    if max_depth == 0 {
        let module_output =
            invoke_modules(&buffer, requested_modules.as_deref(), false);

        match output_format {
            Some(OutputFormats::Json) => {
                let mut serializer = JsonSerializer::new(&mut out);
                serializer
                    .with_colors(use_color)
                    .with_format(JsonFormat::Legacy)
                    .serialize(module_output.as_ref())?;
            }
            Some(OutputFormats::Yaml) | None => {
                let mut serializer = YamlSerializer::new(&mut out);
                serializer
                    .with_colors(use_color)
                    .serialize(module_output.as_ref())?;
            }
        }

        writeln!(out)?;
        out.flush()?;
        return Ok(());
    }

    let mut json_serializer;
    let mut yaml_serializer;

    let mut map_serializer = match output_format {
        Some(OutputFormats::Json) => {
            json_serializer = JsonSerializer::new(&mut out);
            json_serializer
                .with_colors(use_color)
                .with_format(JsonFormat::Legacy);
            DumpMapSerializer::Json(json_serializer.serialize_map()?)
        }
        Some(OutputFormats::Yaml) | None => {
            yaml_serializer = YamlSerializer::new(&mut out);
            yaml_serializer.with_colors(use_color);
            DumpMapSerializer::Yaml(yaml_serializer.serialize_map()?)
        }
    };

    let root_path = file.cloned().unwrap_or_default();

    let root_output =
        invoke_modules(&buffer, requested_modules.as_deref(), true);

    if has_any_module(&root_output) {
        map_serializer.serialize_entry(
            &root_path.to_string_lossy(),
            root_output.as_ref(),
        )?;
    }
    drop(root_output);

    let mut extractor = Extractor::new();
    extractor.max_depth(max_depth);

    let mut extract_err = None;

    let _ = extractor.extract(&buffer, |_module, inner_path, bytes| {
        let module_output =
            invoke_modules(bytes, requested_modules.as_deref(), true);

        if has_any_module(&module_output) {
            let full_path = if root_path.as_os_str().is_empty() {
                inner_path.to_path_buf()
            } else {
                root_path.join(inner_path)
            };

            if let Err(err) = map_serializer.serialize_entry(
                &full_path.to_string_lossy(),
                module_output.as_ref(),
            ) {
                extract_err = Some(err);
                return ControlFlow::Break(());
            }
        }

        ControlFlow::Continue(())
    });

    if let Some(err) = extract_err {
        return Err(err.into());
    }

    map_serializer.finish()?;
    writeln!(out)?;
    out.flush()?;

    Ok(())
}
