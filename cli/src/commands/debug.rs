#![cfg(feature = "debug-cmd")]
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::stdout;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};

use dot_writer::{Attributes, Color, DotWriter, Scope, Style};
use yara_x::SourceCode;
use yara_x_parser::ast::dfs::{DFSEvent, DFSIter};
use yara_x_parser::ast::{Expr, Quantifier, AST};
use yara_x_parser::cst::CST;
use yara_x_parser::Parser;

use crate::commands::{
    create_compiler, external_var_parser, get_external_vars,
};
use crate::config::Config;
use crate::help;

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

pub fn deps() -> Command {
    super::command("deps")
        .about("Show rule dependencies, modules and unknown identifiers")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-r - -"rule")
                .help("Rules to display information for")
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-R - -"reverse")
                .help("Also show reverse dependencies of selected rules"),
        )
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
        .subcommand(deps())
}

pub fn exec_debug(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    match args.subcommand() {
        Some(("ast", args)) => exec_ast(args, config),
        Some(("cst", args)) => exec_cst(args, config),
        Some(("ir", args)) => exec_ir(args, config),
        Some(("wasm", args)) => exec_wasm(args, config),
        Some(("modules", args)) => exec_modules(args, config),
        Some(("deps", args)) => exec_deps(args, config),
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

#[derive(Debug)]
struct Deps<'a> {
    rules: HashSet<&'a str>,
    modules: HashSet<&'a str>,
    unknowns: HashSet<&'a str>,
}

fn exec_deps(args: &ArgMatches, _config: &Config) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let requested_rules = args.get_many::<String>("rule");
    let reverse_deps = args.get_flag("reverse");

    let requested_rules: Vec<_> = requested_rules
        .map_or(Vec::new(), |v| v.collect())
        .into_iter()
        .map(|v| v.as_str())
        .collect();

    if requested_rules.is_empty() && reverse_deps {
        println!("Must specify a rule when displaying reverse dependencies.");
        return Ok(());
    }

    let src = fs::read(rules_path)
        .with_context(|| format!("can not read `{}`", rules_path.display()))?;

    let parser = Parser::new(src.as_slice());
    let ast: AST = parser.into();

    if !ast.errors().is_empty() {
        for err in ast.errors().iter() {
            println!("{err:?}");
        }
        return Ok(());
    }

    // Map of rules to dependencies, modules and unknown identifiers they use.
    //
    // Given these rules:
    //
    // rule a { condition: pe.is_dll() }
    // rule b { condition: a or x }
    //
    // Deps would look like:
    //
    // {
    //  "a": Deps { rules: {}, modules: {"pe"}, unknowns: {} },
    //  "b": Deps { rules: {"a"}, modules: {}, unknowns: {"x"} }
    // }
    let mut dep_map: BTreeMap<&str, Deps> = BTreeMap::new();

    for rule in ast.rules() {
        dep_map.insert(
            rule.identifier.name,
            Deps {
                rules: HashSet::new(),
                modules: HashSet::new(),
                unknowns: HashSet::new(),
            },
        );
        check_expr(&rule.condition, rule.identifier.name, &mut dep_map);
    }

    let graph = generate_graph(&dep_map, &requested_rules, reverse_deps);
    println!("{graph}");

    Ok(())
}

fn generate_graph(
    dep_map: &BTreeMap<&str, Deps>,
    requested_rules: &Vec<&str>,
    reverse_deps: bool,
) -> String {
    let mut bytes = Vec::new();

    // Set of created nodes to avoid creating duplicates.
    let mut nodes: HashSet<&str> = HashSet::new();
    {
        let mut writer = DotWriter::from(&mut bytes);
        let mut graph = writer.digraph();
        for (rule, deps) in dep_map.iter() {
            if (!requested_rules.is_empty() && requested_rules.contains(rule))
                || (reverse_deps
                    && deps.rules.iter().any(|d| nodes.contains(d)))
            {
                generate_node_for_ident(
                    &mut graph,
                    &rule,
                    &deps,
                    &mut nodes,
                    &dep_map,
                    reverse_deps,
                );
            }
        }
    }

    // Now that writer is out of scope we can read from bytes again.
    String::from_utf8(bytes).unwrap()
}

fn generate_node_for_ident<'a>(
    graph: &mut Scope,
    ident: &'a str,
    deps: &Deps<'a>,
    nodes: &mut HashSet<&'a str>,
    dep_map: &BTreeMap<&str, Deps<'a>>,
    reverse_deps: bool,
) {
    {
        let mut node = graph.node_named(ident);
        node.set_fill_color(Color::PaleTurquoise).set_style(Style::Filled);
        nodes.insert(ident);
    }

    if reverse_deps {
        for rule_dep in deps.rules.iter() {
            if nodes.contains(rule_dep) {
                graph.edge(ident, rule_dep);
            }
        }
        return;
    }

    for rule_dep in deps.rules.iter() {
        if !nodes.contains(*rule_dep) {
            generate_node_for_ident(
                graph,
                rule_dep,
                &dep_map[rule_dep],
                nodes,
                dep_map,
                reverse_deps,
            );
        }
        graph.edge(ident, rule_dep);
    }

    for module in deps.modules.iter() {
        if !nodes.contains(*module) {
            let mut node = graph.node_named(*module);
            node.set_fill_color(Color::PaleGreen).set_style(Style::Filled);
            nodes.insert(module);
        }
        graph.edge(ident, module);
    }

    for unknown in deps.unknowns.iter() {
        if !nodes.contains(*unknown) {
            let mut node = graph.node_named(*unknown);
            node.set_fill_color(Color::Red).set_style(Style::Filled);
            nodes.insert(unknown);
        }
        graph.edge(ident, unknown);
    }
}

fn check_expr<'a>(
    expr: &'a Expr<'a>,
    rule_name: &'a str,
    dep_map: &mut BTreeMap<&'a str, Deps<'a>>,
) {
    let mut variables: Vec<&str> = vec![];
    for event in DFSIter::new(expr) {
        match event {
            DFSEvent::Enter(expr) => match expr {
                Expr::Ident(ident) => {
                    if let Some(_) = dep_map.get(ident.name) {
                        // This is an identifier that matches a previously seen
                        // rule.
                        dep_map.entry(rule_name).and_modify(|v| {
                            v.rules.insert(ident.name);
                        });
                    } else if yara_x::mods::module_names()
                        .any(|module| module == ident.name)
                        && !variables.contains(&ident.name)
                    {
                        // This is a known module or is not in the list of
                        // variable identifier to be ignored.
                        dep_map.entry(rule_name).and_modify(|v| {
                            v.modules.insert(ident.name);
                        });
                    } else {
                        dep_map.entry(rule_name).and_modify(|v| {
                            v.unknowns.insert(ident.name);
                        });
                    }
                }
                Expr::Of(of) => match &of.quantifier {
                    Quantifier::Percentage(quantifier)
                    | Quantifier::Expr(quantifier) => {
                        check_expr(&quantifier, rule_name, dep_map);
                    }
                    _ => {}
                },
                Expr::ForOf(for_of) => match &for_of.quantifier {
                    Quantifier::Percentage(quantifier)
                    | Quantifier::Expr(quantifier) => {
                        check_expr(&quantifier, rule_name, dep_map);
                    }
                    _ => {}
                },
                Expr::ForIn(for_in) => {
                    variables =
                        for_in.variables.iter().map(|v| v.name).collect();
                    match &for_in.quantifier {
                        Quantifier::Percentage(quantifier)
                        | Quantifier::Expr(quantifier) => {
                            check_expr(&quantifier, rule_name, dep_map);
                        }
                        _ => {}
                    }
                }
                Expr::With(with) => {
                    variables = with
                        .declarations
                        .iter()
                        .map(|d| d.identifier.name)
                        .collect();
                }
                _ => {}
            },
            DFSEvent::Leave(expr) => match expr {
                Expr::ForIn(_) | Expr::With(_) => {
                    variables.clear();
                }
                _ => {}
            },
        }
    }
}
