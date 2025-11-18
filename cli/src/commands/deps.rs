use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};

use dot_writer::{Attributes, Color, DotWriter, Scope, Style};
use yara_x_parser::ast::dfs::{DFSContext, DFSEvent, DFSIter};
use yara_x_parser::ast::{Expr, AST};
use yara_x_parser::Parser;

#[derive(Debug)]
struct Deps<'a> {
    rules: HashSet<&'a str>,
    modules: HashSet<&'a str>,
    unknowns: HashSet<&'a str>,
}

pub fn deps() -> Command {
    super::command("deps")
        .about("Show rule dependencies, modules and unknown identifiers")
        // The `deps` command is not ready yet.
        .hide(true)
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-r - -"rule")
                .required(true)
                .help("Rules to display dependency information for")
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-R - -"reverse")
                .help("Also show reverse dependencies of selected rules"),
        )
}

pub fn exec_deps(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let requested_rules = args.get_many::<String>("rule");
    let reverse_deps = args.get_flag("reverse");

    let requested_rules: Vec<_> = requested_rules
        .map_or(Vec::new(), |v| v.collect())
        .into_iter()
        .map(|v| v.as_str())
        .collect();

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
            if requested_rules.contains(rule)
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
    let mut variable_stack: Vec<Vec<&str>> = vec![];
    let mut new_variables: Vec<&str> = vec![];
    let mut variables: Vec<&str> = vec![];

    // In the case of a field access expression (ie: pe.number_of_signatures) we
    // only want to collect the first identifier after entering that field
    // expression. If we don't do this we will pick up "number_of_signatures" as
    // an unknown identifier. However, conditions like (pe).signatures.len()
    // alter the AST so that the second operand of the field access expression
    // is now a function call, so we need to be careful to avoid picking up the
    // second operand in this case too.
    let mut field_access_root = false;

    let mut dfs = DFSIter::new(expr);
    while let Some(event) = dfs.next() {
        match event {
            DFSEvent::Enter(expr) => {
                let ctx = dfs.contexts().next().unwrap();
                //println!("===============================");
                //println!("{event:?}");
                //println!("{ctx:?}");
                if let DFSContext::Body(_) = ctx {
                    variable_stack.push(variables.clone());
                    // Extend the list of known variables because variables
                    // defined in an outer scope are visible in the inner
                    // scope. For example:
                    //
                    // for 1 x in (2): (
                    //   for 1 y in (3): (
                    //     x + y == 5
                    //   )
                    // )
                    //
                    variables.extend(new_variables.iter());
                    new_variables.clear();
                }

                match expr {
                    Expr::FieldAccess(_) => {
                        field_access_root = true;
                    }
                    Expr::Ident(ident) => {
                        if let DFSContext::Operand(parent) = ctx {
                            if let Expr::FieldAccess(_) = parent {
                                if !field_access_root {
                                    continue;
                                }
                                field_access_root = false;
                            }
                        }

                        // If this is a known variable, ignore it.
                        if variables.contains(&ident.name) {
                            continue;
                        }

                        if dep_map.contains_key(ident.name) {
                            // This is an identifier that matches a previously
                            // seen rule.
                            dep_map.entry(rule_name).and_modify(|v| {
                                v.rules.insert(ident.name);
                            });
                        } else if yara_x::mods::module_names()
                            .any(|module| module == ident.name)
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
                    Expr::ForIn(for_in) => {
                        new_variables =
                            for_in.variables.iter().map(|v| v.name).collect();
                    }
                    Expr::With(with) => {
                        new_variables = with
                            .declarations
                            .iter()
                            .map(|d| d.identifier.name)
                            .collect();
                    }
                    _ => {}
                };
            }
            DFSEvent::Leave(expr) => {
                match expr {
                    Expr::ForIn(_) | Expr::With(_) => {
                        // Given the condition:
                        //
                        // for 1 x in (2): (...)
                        //
                        // The context is None if we are leaving the ForIn so
                        // unwrap it in with a Root context that we don't
                        // actually care about. We only care about leaving a
                        // body context.
                        if let DFSContext::Body(_) =
                            dfs.contexts().next().unwrap_or(&DFSContext::Root)
                        {
                            variables = variable_stack
                                .pop()
                                .expect("Variable stack pop failed");
                            new_variables = vec![];
                        }
                    }
                    _ => {}
                };
            }
        }
    }
}
