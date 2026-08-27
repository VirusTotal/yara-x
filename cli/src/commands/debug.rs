#![cfg(feature = "debug-cmd")]
use std::fs;
use std::io::stdout;
use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgAction, ArgMatches, Command, arg, value_parser};

use yara_x::SourceCode;
use yara_x_parser::Parser;
use yara_x_parser::ast::AST;
use yara_x_parser::cst::CST;

use crate::commands::{
    create_compiler, external_var_parser, get_external_vars,
};
use crate::config::Config;
use crate::help;

pub fn atoms() -> Command {
    super::command("atoms")
        .about("Print final atoms selected for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(--json).help("Print output in JSON format"))
}

pub fn ast() -> Command {
    super::command("ast")
        .about("Print Abstract Syntax Tree (AST) for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
}

pub fn cst() -> Command {
    super::command("cst")
        .about("Print Concrete Syntax Tree (CST) for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
}

pub fn ir() -> Command {
    super::command("ir")
        .about("Print Intermediate Representation (IR) for a YARA source file")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-d - -"define")
                .help("Define external variable")
                .long_help(help::DEFINE_LONG_HELP)
                .value_name("VAR=VALUE")
                .value_parser(external_var_parser)
                .action(ArgAction::Append),
        )
}

pub fn wasm() -> Command {
    super::command("wasm")
        .about(
            "Emit a .wasm file with the code generated for a YARA source file",
        )
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-d - -"define")
                .help("Define external variable")
                .long_help(help::DEFINE_LONG_HELP)
                .value_name("VAR=VALUE")
                .value_parser(external_var_parser)
                .action(ArgAction::Append),
        )
}

pub fn modules() -> Command {
    super::command("modules").about("List available modules")
}

pub fn debug() -> Command {
    super::command("debug")
        .about("Debug utilities")
        .arg_required_else_help(true)
        .subcommand(ast())
        .subcommand(cst())
        .subcommand(ir())
        .subcommand(wasm())
        .subcommand(modules())
        .subcommand(atoms())
}

pub fn exec_debug(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    match args.subcommand() {
        Some(("ast", args)) => exec_ast(args, config),
        Some(("cst", args)) => exec_cst(args, config),
        Some(("ir", args)) => exec_ir(args, config),
        Some(("wasm", args)) => exec_wasm(args, config),
        Some(("modules", args)) => exec_modules(args, config),
        Some(("atoms", args)) => exec_atoms(args, config),
        _ => unreachable!(),
    }
}

pub fn exec_ast(args: &ArgMatches, _config: &Config) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let parser = Parser::new(src.as_slice());
    let ast: AST = parser.into();

    println!("{ast:?}");
    Ok(())
}

pub fn exec_cst(args: &ArgMatches, _config: &Config) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let parser = Parser::new(src.as_slice());
    let cst: CST = parser.try_into()?;

    println!("{cst:?}");
    Ok(())
}

pub fn exec_ir(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let external_vars = get_external_vars(args);
    let mut compiler = create_compiler(external_vars, args, config)?;

    compiler.set_ir_writer(stdout());
    compiler.add_source(src.as_slice())?;

    Ok(())
}

fn exec_wasm(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let mut rules_path =
        args.get_one::<PathBuf>("RULES_PATH").unwrap().to_path_buf();

    let src = fs::read(rules_path.as_path())
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let src = SourceCode::from(src.as_slice())
        .with_origin(rules_path.as_os_str().to_str().unwrap());

    rules_path.set_extension("wasm");

    let external_vars = get_external_vars(args);
    let mut compiler = create_compiler(external_vars, args, config)?;

    compiler.add_source(src)?;
    compiler.emit_wasm_file(rules_path.as_path())?;

    Ok(())
}

fn exec_modules(_args: &ArgMatches, _config: &Config) -> anyhow::Result<()> {
    for name in yara_x::mods::module_names() {
        println!("{}", name);
    }
    Ok(())
}

fn is_consecutive(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut carry = 1u16;
    for (byte_a, byte_b) in a.iter().rev().zip(b.iter().rev()) {
        let sum = *byte_a as u16 + carry;
        if (sum as u8) != *byte_b {
            return false;
        }
        carry = sum >> 8;
    }
    carry == 0
}

fn is_printable(atom: &[u8]) -> bool {
    !atom.is_empty() && atom.iter().all(|b| (0x20..=0x7E).contains(b))
}

fn print_atom_hex(atom: &[u8]) {
    for byte in atom {
        print!("{byte:02X}");
    }
}

fn print_range(start: &[u8], end: &[u8]) {
    print!("    ");
    print_atom_hex(start);
    if start != end {
        print!("..");
        print_atom_hex(end);
    }
    if is_printable(start) && is_printable(end) {
        let s = std::str::from_utf8(start).unwrap();
        if start == end {
            print!(" ({s})");
        } else {
            let e = std::str::from_utf8(end).unwrap();
            print!(" ({s}..{e})");
        }
    }
    println!();
}

#[derive(serde::Serialize)]
struct PatternAtomsJson<'a> {
    rule: &'a str,
    pattern: &'a str,
    atoms: Vec<String>,
}

fn exec_atoms(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let json = args.get_flag("json");

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let src = SourceCode::from(src.as_slice())
        .with_origin(rules_path.as_os_str().to_str().unwrap());

    let mut compiler = create_compiler(None, args, config)?;

    compiler.add_source(src)?;

    let rules = compiler.build();

    if json {
        let mut output = Vec::new();

        for rule in rules.iter() {
            for pattern in rule.patterns().include_private(true) {
                let atoms: Vec<String> = pattern
                    .atoms()
                    .map(|atom| {
                        atom.as_slice()
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect()
                    })
                    .collect();

                output.push(PatternAtomsJson {
                    rule: rule.identifier(),
                    pattern: pattern.identifier(),
                    atoms,
                });
            }
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        for rule in rules.iter() {
            println!("rule {}", rule.identifier());

            for pattern in rule.patterns().include_private(true) {
                println!("  {}", pattern.identifier());

                let mut current_range: Option<(&[u8], &[u8])> = None;

                for atom in pattern.atoms() {
                    let atom_slice = atom.as_slice();
                    match current_range {
                        None => {
                            current_range = Some((atom_slice, atom_slice));
                        }
                        Some((start, end)) => {
                            if is_consecutive(end, atom_slice) {
                                current_range = Some((start, atom_slice));
                            } else {
                                print_range(start, end);
                                current_range = Some((atom_slice, atom_slice));
                            }
                        }
                    }
                }

                if let Some((start, end)) = current_range {
                    print_range(start, end);
                }
            }
        }
    }

    Ok(())
}
