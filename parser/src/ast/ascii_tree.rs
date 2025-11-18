/*! Functions that returns an ASCII representation of YARA Abstract Syntax Trees (ASTs).*/

use ::ascii_tree::Tree;
use ::ascii_tree::Tree::{Leaf, Node};
use itertools::Itertools;

use crate::ast::dfs::{DFSEvent, DFSIter};
use crate::ast::*;

/// Returns a representation of the rule as an ASCII tree.
pub(crate) fn rule_ascii_tree(rule: &Rule) -> Tree {
    let mut rule_children = Vec::new();

    if let Some(meta) = &rule.meta {
        rule_children.push(Node(
            "meta".to_owned(),
            meta.iter()
                .map(|m| {
                    Leaf(vec![format!("{} = {}", m.identifier.name, m.value)])
                })
                .collect(),
        ))
    }

    if let Some(patterns) = &rule.patterns {
        rule_children.push(Node(
            "strings".to_owned(),
            patterns.iter().map(pattern_ascii_tree).collect(),
        ))
    }

    rule_children.push(Node(
        "condition".to_owned(),
        vec![expr_ascii_tree(&rule.condition)],
    ));

    let mut modifiers = Vec::new();

    if rule.flags.contains(RuleFlags::Private) {
        modifiers.push("private");
    }

    if rule.flags.contains(RuleFlags::Global) {
        modifiers.push("global");
    }

    Node(
        if modifiers.is_empty() {
            format!("rule {}", rule.identifier.name)
        } else {
            format!("{} rule {}", modifiers.join(" "), rule.identifier.name)
        },
        rule_children,
    )
}

/// Returns a representation of the expression as an ASCII tree.
pub(crate) fn expr_ascii_tree(expr: &Expr) -> Tree {
    let mut tree_stack: Vec<Tree> = Vec::new();
    let mut len_stack: Vec<usize> = Vec::new();

    for event in DFSIter::new(expr) {
        match event {
            DFSEvent::Enter(_) => {
                // Save the size of `tree_stack` at the moment of entering
                // the expression. This will be useful during the Leave
                // event for obtaining the children of this expression.
                len_stack.push(tree_stack.len());
            }
            DFSEvent::Leave(expr) => {
                // The top of `len_stack` tell us the size of `tree_stack` at
                // the moment of the Enter event for the current expression,
                // anything in `tree_stack` that was added after that is a
                // children of `expr`.
                let children_start = len_stack.pop().unwrap();
                let children = tree_stack.drain(children_start..).collect();
                tree_stack.push(build_tree_for_expr(expr, children));
            }
        }
    }

    assert_eq!(tree_stack.len(), 1);
    tree_stack.pop().unwrap()
}

fn build_tree_for_expr(expr: &Expr, children: Vec<Tree>) -> Tree {
    match expr {
        Expr::True { .. } => Leaf(vec!["true".to_string()]),
        Expr::False { .. } => Leaf(vec!["false".to_string()]),
        Expr::Entrypoint { .. } => Leaf(vec!["entrypoint".to_string()]),
        Expr::Filesize { .. } => Leaf(vec!["filesize".to_string()]),
        Expr::LiteralString(lit) => Leaf(vec![lit.literal.to_string()]),
        Expr::LiteralFloat(lit) => Leaf(vec![lit.literal.to_string()]),
        Expr::LiteralInteger(lit) => Leaf(vec![lit.literal.to_string()]),
        Expr::Ident(ident) => Leaf(vec![ident.name.to_string()]),
        Expr::Regexp(regexp) => {
            match (regexp.case_insensitive, regexp.dot_matches_new_line) {
                (true, true) => Leaf(vec![format!("/{}/is", regexp.src)]),
                (true, false) => Leaf(vec![format!("/{}/i", regexp.src)]),
                (false, true) => Leaf(vec![format!("/{}/s", regexp.src)]),
                (false, false) => Leaf(vec![format!("/{}/", regexp.src)]),
            }
        }
        Expr::Defined(_) => Node("defined".to_string(), children),
        Expr::Not(_) => Node("not".to_string(), children),
        Expr::And(_) => Node("and".to_string(), children),
        Expr::Or(_) => Node("or".to_string(), children),
        Expr::Minus(_) => Node("minus".to_string(), children),
        Expr::Add(_) => Node("add".to_string(), children),
        Expr::Sub(_) => Node("sub".to_string(), children),
        Expr::Mul(_) => Node("mul".to_string(), children),
        Expr::Div(_) => Node("div".to_string(), children),
        Expr::Mod(_) => Node("mod".to_string(), children),
        Expr::Shl(_) => Node("shl".to_string(), children),
        Expr::Shr(_) => Node("shr".to_string(), children),
        Expr::BitwiseNot(_) => Node("bitwise_not".to_string(), children),
        Expr::BitwiseAnd(_) => Node("bitwise_and".to_string(), children),
        Expr::BitwiseOr(_) => Node("bitwise_or".to_string(), children),
        Expr::BitwiseXor(_) => Node("bitwise_xor".to_string(), children),
        Expr::Eq(_) => Node("eq".to_string(), children),
        Expr::Ne(_) => Node("ne".to_string(), children),
        Expr::Lt(_) => Node("lt".to_string(), children),
        Expr::Le(_) => Node("le".to_string(), children),
        Expr::Gt(_) => Node("gt".to_string(), children),
        Expr::Ge(_) => Node("ge".to_string(), children),
        Expr::Contains(_) => Node("contains".to_string(), children),
        Expr::IContains(_) => Node("icontains".to_string(), children),
        Expr::StartsWith(_) => Node("startswith".to_string(), children),
        Expr::IStartsWith(_) => Node("istartswith".to_string(), children),
        Expr::EndsWith(_) => Node("endswith".to_string(), children),
        Expr::IEndsWith(_) => Node("iendswith".to_string(), children),
        Expr::IEquals(_) => Node("iequals".to_string(), children),
        Expr::Matches(_) => Node("matches".to_string(), children),
        Expr::PatternMatch(s) => {
            if let Some(anchor) = &s.anchor {
                match anchor {
                    MatchAnchor::At(_) => Node(
                        format!("{} at <expr>", s.identifier.name),
                        vec![Node("<expr>".to_string(), children)],
                    ),
                    MatchAnchor::In(_) => {
                        let mut children_iter = children.into_iter();
                        Node(
                            format!(
                                "{} in (<start>, <end>)",
                                s.identifier.name
                            ),
                            vec![
                                Node(
                                    "<start>".to_string(),
                                    vec![children_iter.next().unwrap()],
                                ),
                                Node(
                                    "<end>".to_string(),
                                    vec![children_iter.next().unwrap()],
                                ),
                            ],
                        )
                    }
                }
            } else {
                Leaf(vec![s.identifier.name.to_string()])
            }
        }
        Expr::PatternCount(s) => {
            if s.range.is_some() {
                Node(
                    format!("{} in <range>", s.identifier.name),
                    vec![Node("<range>".to_string(), children)],
                )
            } else {
                Leaf(vec![s.identifier.name.to_string()])
            }
        }
        Expr::PatternOffset(s) | Expr::PatternLength(s) => {
            if s.index.is_some() {
                Node(
                    format!("{}[<index>]", s.identifier.name),
                    vec![Node("<index>".to_string(), children)],
                )
            } else {
                Leaf(vec![s.identifier.name.to_string()])
            }
        }
        Expr::Lookup(_) => {
            let mut children_iter = children.into_iter();
            Node(
                "<expr>[<index>]".to_string(),
                vec![
                    Node(
                        "<expr>".to_string(),
                        vec![children_iter.next().unwrap()],
                    ),
                    Node(
                        "<index>".to_string(),
                        vec![children_iter.next().unwrap()],
                    ),
                ],
            )
        }
        Expr::FieldAccess(_) => Node("field access".to_string(), children),
        Expr::FuncCall(expr) => {
            let mut children_iter = children.into_iter();
            let mut new_children = Vec::new();

            if expr.object.is_some() {
                new_children.push(Node(
                    "<object>".to_string(),
                    vec![children_iter.next().unwrap()],
                ));
            }

            let labelled_args: Vec<String> =
                (0..expr.args.len()).map(|i| format!("<arg{i}>")).collect();

            let comma_sep_labels = labelled_args.join(", ");

            for label in labelled_args {
                new_children
                    .push(Node(label, vec![children_iter.next().unwrap()]));
            }

            Node(
                format!("{}({})", expr.identifier.name, comma_sep_labels),
                new_children,
            )
        }
        Expr::Of(of) => {
            let mut children_iter = children.into_iter();

            let quantifier =
                quantifier_ascii_tree(&of.quantifier, children_iter.by_ref());

            let mut new_children =
                vec![Node("<quantifier>".to_string(), vec![quantifier])];

            let items = match &of.items {
                OfItems::PatternSet(set) => Node(
                    "<items: pattern_set>".to_string(),
                    vec![pattern_set_ascii_tree(set)],
                ),
                OfItems::BoolExprTuple(set) => Node(
                    "<items: boolean_expr_set>".to_string(),
                    children_iter.by_ref().take(set.len()).collect(),
                ),
            };

            new_children.push(items);

            let node_title = if let Some(anchor) = &of.anchor {
                match anchor {
                    MatchAnchor::At(_) => {
                        new_children.push(Node(
                            "<expr>".to_string(),
                            vec![children_iter.next().unwrap()],
                        ));
                        "<quantifier> of <items> at <expr>".to_string()
                    }
                    MatchAnchor::In(_) => {
                        new_children.push(Node(
                            "<start>".to_string(),
                            vec![children_iter.next().unwrap()],
                        ));
                        new_children.push(Node(
                            "<end>".to_string(),
                            vec![children_iter.next().unwrap()],
                        ));
                        "<quantifier> of <items> in (<start>..<end>)"
                            .to_string()
                    }
                }
            } else {
                "<quantifier> of <items>".to_string()
            };

            Node(node_title, new_children)
        }
        Expr::ForOf(for_of) => {
            let mut children_iter = children.into_iter();

            Node(
                "for <quantifier> of <items> : ( <condition> )".to_string(),
                vec![
                    Node(
                        "<quantifier>".to_string(),
                        vec![quantifier_ascii_tree(
                            &for_of.quantifier,
                            children_iter.by_ref(),
                        )],
                    ),
                    Node(
                        "<items>".to_string(),
                        vec![pattern_set_ascii_tree(&for_of.pattern_set)],
                    ),
                    Node(
                        "<condition>".to_string(),
                        vec![children_iter.next().unwrap()],
                    ),
                ],
            )
        }
        Expr::ForIn(f) => {
            let mut children_iter = children.into_iter();

            let mut new_children = vec![
                Node(
                    "<quantifier>".to_string(),
                    vec![quantifier_ascii_tree(
                        &f.quantifier,
                        children_iter.by_ref(),
                    )],
                ),
                Node(
                    "<vars>".to_string(),
                    vec![Leaf(
                        f.variables
                            .iter()
                            .map(|v| v.name.to_string())
                            .collect(),
                    )],
                ),
            ];

            let node_title = match &f.iterable {
                Iterable::Range(_) => {
                    new_children.push(Node(
                        "<start>".to_string(),
                        vec![children_iter.next().unwrap()],
                    ));
                    new_children.push(Node(
                        "<end>".to_string(),
                        vec![children_iter.next().unwrap()],
                    ));
                    "for <quantifier> <vars> in (<start>..<end>) : ( <condition> )".to_string()
                }
                Iterable::ExprTuple(args) => {
                    let labelled_args: Vec<String> = (0..args.len())
                        .map(|i| format!("<expr{i}>"))
                        .collect();

                    let comma_sep_labels = labelled_args.join(", ");

                    for label in labelled_args {
                        new_children.push(Node(
                            label,
                            vec![children_iter.next().unwrap()],
                        ));
                    }

                    format!("for <quantifier> <vars> in ({comma_sep_labels}) : ( <condition> )")
                }
                Iterable::Expr(_) => {
                    new_children.push(Node(
                        "<expr>".to_string(),
                        vec![children_iter.next().unwrap()],
                    ));
                    "for <quantifier> <vars> in <expr> : ( <condition> )"
                        .to_string()
                }
            };

            new_children.push(Node(
                "<condition>".to_string(),
                vec![children_iter.next().unwrap()],
            ));

            Node(node_title, new_children)
        }
        Expr::With(w) => {
            let mut children_iter = children.into_iter();
            Node(
                "with <identifiers> : ( <boolean expression> )".to_string(),
                vec![
                    Node(
                        "<identifiers>".to_string(),
                        w.declarations
                            .iter()
                            .flat_map(|d| {
                                vec![
                                    Leaf(vec![format!(
                                        "{}",
                                        d.identifier.name
                                    )]),
                                    children_iter.next().unwrap(),
                                ]
                            })
                            .collect(),
                    ),
                    Node(
                        "<boolean expression>".to_string(),
                        vec![children_iter.next().unwrap()],
                    ),
                ],
            )
        }
    }
}

pub(crate) fn quantifier_ascii_tree(
    quantifier: &Quantifier,
    mut children: impl Iterator<Item = Tree>,
) -> Tree {
    match quantifier {
        Quantifier::All { .. } => Leaf(vec!["all".to_string()]),
        Quantifier::Any { .. } => Leaf(vec!["any".to_string()]),
        Quantifier::None { .. } => Leaf(vec!["none".to_string()]),
        Quantifier::Expr(_) => children.next().unwrap(),
        Quantifier::Percentage(_) => {
            Node("percentage".to_string(), vec![children.next().unwrap()])
        }
    }
}

pub(crate) fn pattern_set_ascii_tree(pattern_set: &PatternSet) -> Tree {
    match pattern_set {
        PatternSet::Them { .. } => Leaf(vec!["them".to_string()]),
        PatternSet::Set(set) => {
            Leaf(set.iter().map(|s| s.identifier.to_string()).collect())
        }
    }
}

pub(crate) fn pattern_ascii_tree(pattern: &Pattern) -> Tree {
    match pattern {
        Pattern::Text(s) => Leaf(vec![format!(
            "{} = {} {}",
            s.identifier.name,
            s.text.literal,
            s.modifiers.iter().map(|m| m.to_string()).join(" ")
        )]),
        Pattern::Hex(h) => Node(
            h.identifier.name.to_string(),
            vec![hex_tokens_ascii_tree(&h.sub_patterns)],
        ),
        Pattern::Regexp(r) => Leaf(vec![format!(
            "{} = /{}/{}{} {}",
            r.identifier.name,
            r.regexp.src,
            if r.regexp.case_insensitive { "i" } else { "" },
            if r.regexp.dot_matches_new_line { "s" } else { "" },
            r.modifiers.iter().map(|m| m.to_string()).join(" ")
        )]),
    }
}

pub(crate) fn hex_tokens_ascii_tree(tokens: &HexSubPattern) -> Tree {
    let nodes = tokens
        .iter()
        .map(|t| match t {
            HexToken::Byte(b) => {
                Leaf(vec![format!("{:#04X} mask: {:#04X}", b.value, b.mask)])
            }
            HexToken::NotByte(b) => {
                Leaf(vec![format!("~ {:#04X} mask: {:#04X}", b.value, b.mask)])
            }
            HexToken::Alternative(a) => Node(
                "alt".to_string(),
                a.alternatives.iter().map(hex_tokens_ascii_tree).collect(),
            ),
            HexToken::Jump(j) => Leaf(vec![format!(
                "[{}-{}]",
                j.start.map_or("".to_string(), |v| v.to_string()),
                j.end.map_or("".to_string(), |v| v.to_string())
            )]),
        })
        .collect();

    Node("hex".to_string(), nodes)
}
