use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;

use ::ascii_tree::Tree;
use ::ascii_tree::Tree::Node;
use ::ascii_tree::write_tree;
use anyhow::{Context, bail};
use clap::{ArgAction, ArgMatches, Command, arg, value_parser};

use yara_x_parser::Parser;
use yara_x_parser::ast::dfs::{DFSContext, DFSEvent, DFSIter};
use yara_x_parser::ast::{AST, Expr};

#[derive(Debug, Default)]
struct Deps<'a> {
    rules: HashSet<&'a str>,
    modules: HashSet<&'a str>,
}

pub fn deps() -> Command {
    super::command("deps")
        .about("Show rule dependencies")
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-r - -"rule")
                .required(false)
                .help("Rules to display dependency information for")
                .action(ArgAction::Append),
        )
}

pub fn exec_deps(args: &ArgMatches) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let requested_rules = args.get_many::<String>("rule");

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
        bail!("{} syntax error(s) found", ast.errors().len());
    }

    // Map of rules to dependencies and modules they use.
    //
    // Given these rules:
    //
    // rule a { condition: pe.is_dll() }
    // rule b { condition: a or x }
    //
    // Deps would look like:
    //
    // {
    //  "a": Deps { rules: {}, modules: {"pe"} },
    //  "b": Deps { rules: {"a"}, modules: {} }
    // }
    //
    // The unknown identifier "x" is silently ignored.
    let mut dep_map: BTreeMap<&str, Deps> = BTreeMap::new();

    for rule in ast.rules() {
        if dep_map.contains_key(rule.identifier.name) {
            bail!("Duplicate rule \"{}\" found", rule.identifier.name);
        }
        // Compute dependencies before inserting the rule into `dep_map` so
        // self-references (or rules named after a module) are not recorded as
        // cyclic dependencies on the rule itself.
        let deps = find_dependencies(&rule.condition, &dep_map);
        dep_map.insert(rule.identifier.name, deps);
    }

    let dep_tree = generate_dep_tree(&dep_map, &requested_rules);

    for dep in dep_tree.iter() {
        let mut output = String::new();
        write_tree(&mut output, dep)?;
        println!("{output}");
    }

    Ok(())
}

fn generate_dep_tree<'a>(
    dep_map: &BTreeMap<&'a str, Deps<'a>>,
    requested_rules: &[&str],
) -> Vec<Tree> {
    let mut nodes: Vec<Tree> = Vec::new();

    for (rule, deps) in dep_map.iter() {
        if requested_rules.is_empty() || requested_rules.contains(rule) {
            let mut ancestors = HashSet::from([*rule]);
            nodes.push(tree_for_rule(rule, deps, dep_map, &mut ancestors));
        }
    }

    nodes
}

fn tree_for_rule<'a>(
    rule: &'a str,
    deps: &Deps<'a>,
    dep_map: &BTreeMap<&'a str, Deps<'a>>,
    ancestors: &mut HashSet<&'a str>,
) -> Tree {
    let mut nodes: Vec<Tree> = Vec::new();

    for module in deps.modules.iter() {
        nodes.push(Node(format!("mod: {module}"), vec![]));
    }

    for dep in deps.rules.iter() {
        match dep_map.get(dep) {
            Some(new_deps) if ancestors.insert(dep) => {
                nodes.push(tree_for_rule(dep, new_deps, dep_map, ancestors));
                ancestors.remove(dep);
            }
            _ => {
                nodes.push(Node(dep.to_string(), vec![]));
            }
        }
    }

    Node(rule.to_string(), nodes)
}

fn find_dependencies<'a>(
    expr: &'a Expr<'a>,
    dep_map: &BTreeMap<&'a str, Deps<'a>>,
) -> Deps<'a> {
    let mut deps = Deps::default();
    // Contains the variables that are currently defined. This acts
    // as a stack where the variables defined by the innermost `for`
    // or `with` statements are at top of the array.
    let mut variables = Vec::new();
    // The `scopes` array contains the indexes within the `variables`
    // array where a scope start. For instance, if we have two nested
    // `with` statements where the outermost one defines variables `a`
    // and `b`, while the innermost defines variables `c` and `d`, the
    // `variables` vector will contain [`a`, `b`, `c`, `d`] and the
    // `scopes` vector will contain: [2], which indicates that index
    // within `variables` where the innermost scope starts.
    let mut scopes = Vec::new();

    let mut dfs = DFSIter::new(expr);
    while let Some(event) = dfs.next() {
        match event {
            DFSEvent::Enter(expr) => {
                match dfs.contexts().next() {
                    Some(DFSContext::Body(Expr::ForIn(for_in))) => {
                        scopes.push(variables.len());
                        variables
                            .extend(for_in.variables.iter().map(|v| v.name));
                    }
                    Some(DFSContext::Body(Expr::With(with))) => {
                        scopes.push(variables.len());
                        variables.extend(
                            with.declarations
                                .iter()
                                .map(|d| d.identifier.name),
                        );
                    }
                    _ => {}
                }
                if let Expr::Ident(ident) = expr {
                    // If this is a known variable, ignore it.
                    if variables.contains(&ident.name) {
                        continue;
                    }
                    if dep_map.contains_key(ident.name) {
                        // This is an identifier that matches a previously
                        // seen rule.
                        deps.rules.insert(ident.name);
                    } else if yara_x::mods::module_names()
                        .any(|module| module == ident.name)
                    {
                        // This is a known module or is not in the list of
                        // variable identifier to be ignored.
                        deps.modules.insert(ident.name);
                    }
                }
            }
            DFSEvent::Leave(expr) => {
                // When leaving a `for` or `with` statement, remove all the
                // variables they defined.
                if matches!(expr, Expr::ForIn(_) | Expr::With(_)) {
                    variables.drain(scopes.pop().unwrap()..);
                }
                // When leaving the operand of a FieldAccess expression we prune
                // the DFS tree, which prevents the siblings of this node from
                // being traversed. This implies that only the first operand of the
                // FieldAccess node is visited. The rest of the operands of a
                // field access expression can contain identifiers, but those
                // identifiers will correspond to some field in a structure, not
                // to a variable or module name.
                if matches!(
                    dfs.contexts().next(),
                    Some(DFSContext::Operand(Expr::FieldAccess(_)))
                ) {
                    dfs.prune();
                }
            }
        }
    }

    deps
}
