use crate::parser::*;
use crate::Struct;
use crate::Value;
use ascii_tree::Tree::{Leaf, Node};

/// Returns a representation of the namespace as an ASCII tree.
pub fn namespace_ascii_tree(
    namespace: &Namespace,
    sym_tbl: &Struct,
) -> ascii_tree::Tree {
    Node(
        "namespace".to_string(),
        namespace
            .rules
            .iter()
            .map(|(_, rule)| rule_ascii_tree(rule, sym_tbl))
            .collect(),
    )
}

/// Returns a representation of the rule as an ASCII tree.
pub fn rule_ascii_tree(rule: &Rule, sym_tbl: &Struct) -> ascii_tree::Tree {
    let mut rule_children = vec![];

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
            patterns.iter().map(|p| pattern_ascii_tree(&p, sym_tbl)).collect(),
        ))
    }

    rule_children.push(Node(
        "condition".to_owned(),
        vec![expr_ascii_tree(&rule.condition, sym_tbl)],
    ));

    let mut modifiers = vec![];

    if rule.flags.contains(RuleFlag::Private) {
        modifiers.push("private");
    }

    if rule.flags.contains(RuleFlag::Global) {
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
pub fn expr_ascii_tree(expr: &Expr, sym_tbl: &Struct) -> ascii_tree::Tree {
    let value = {
        let (_, value) = expr.type_value();
        if matches!(value, Value::Unknown) {
            "".to_string()
        } else {
            format!(" (value: {})", value)
        }
    };
    match expr {
        Expr::True { .. } => Leaf(vec!["true".to_string()]),
        Expr::False { .. } => Leaf(vec!["false".to_string()]),
        Expr::Entrypoint { .. } => Leaf(vec!["entrypoint".to_string()]),
        Expr::Filesize { .. } => Leaf(vec!["filesize".to_string()]),
        Expr::LiteralInt(lit) => Leaf(vec![lit.literal.to_string()]),
        Expr::LiteralFlt(lit) => Leaf(vec![lit.literal.to_string()]),
        Expr::LiteralStr(lit) => Leaf(vec![lit.literal.to_string()]),
        Expr::Ident(ident) => Leaf(vec![ident.name.to_string()]),
        Expr::Not(expr) => Node(
            format!("not{}", value),
            vec![expr_ascii_tree(&expr.operand, sym_tbl)],
        ),
        Expr::And(expr) => Node(
            format!("and{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Or(expr) => Node(
            format!("or{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Minus(expr) => Node(
            format!("minus{}", value),
            vec![expr_ascii_tree(&expr.operand, sym_tbl)],
        ),
        Expr::Add(expr) => Node(
            format!("add{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Sub(expr) => Node(
            format!("sub{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Mul(expr) => Node(
            format!("mul{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Div(expr) => Node(
            format!("div{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Shl(expr) => Node(
            format!("shl{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Shr(expr) => Node(
            format!("shr{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::BitwiseNot(expr) => Node(
            format!("bitwise_not{}", value),
            vec![expr_ascii_tree(&expr.operand, sym_tbl)],
        ),
        Expr::BitwiseAnd(expr) => Node(
            format!("bitwise_and{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::BitwiseOr(expr) => Node(
            format!("bitwise_or{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::BitwiseXor(expr) => Node(
            format!("bitwise_xor{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Modulus(expr) => Node(
            format!("mod{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Eq(expr) => Node(
            format!("eq{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Neq(expr) => Node(
            format!("neq{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Lt(expr) => Node(
            format!("lt{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Le(expr) => Node(
            format!("le{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Gt(expr) => Node(
            format!("gt{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Ge(expr) => Node(
            format!("ge{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::Contains(expr) => Node(
            format!("contains{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::IContains(expr) => Node(
            format!("icontains{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::StartsWith(expr) => Node(
            format!("startswith{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::IStartsWith(expr) => Node(
            format!("istartswith{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::EndsWith(expr) => Node(
            format!("endswith{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::IEndsWith(expr) => Node(
            format!("iendswith{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::IEquals(expr) => Node(
            format!("iequals{}", value),
            vec![
                expr_ascii_tree(&expr.lhs, sym_tbl),
                expr_ascii_tree(&expr.rhs, sym_tbl),
            ],
        ),
        Expr::PatternMatch(s) => {
            if let Some(anchor) = &s.anchor {
                match anchor {
                    MatchAnchor::At(anchor_at) => Node(
                        format!("{} at <expr>", s.identifier.name),
                        vec![Node(
                            "<expr>".to_string(),
                            vec![expr_ascii_tree(&anchor_at.expr, sym_tbl)],
                        )],
                    ),
                    MatchAnchor::In(anchor_in) => Node(
                        format!("{} in (<start>, <end>)", s.identifier.name),
                        vec![
                            Node(
                                "<start>".to_string(),
                                vec![expr_ascii_tree(
                                    &anchor_in.range.lower_bound,
                                    sym_tbl,
                                )],
                            ),
                            Node(
                                "<end>".to_string(),
                                vec![expr_ascii_tree(
                                    &anchor_in.range.upper_bound,
                                    sym_tbl,
                                )],
                            ),
                        ],
                    ),
                }
            } else {
                Leaf(vec![s.identifier.name.to_string()])
            }
        }
        Expr::PatternCount(s) => {
            if let Some(range) = &s.range {
                Node(
                    format!("{} in <range>", s.name),
                    vec![Node(
                        "<range>".to_string(),
                        vec![
                            expr_ascii_tree(&range.lower_bound, sym_tbl),
                            expr_ascii_tree(&range.upper_bound, sym_tbl),
                        ],
                    )],
                )
            } else {
                Leaf(vec![s.name.to_string()])
            }
        }
        Expr::PatternOffset(s) | Expr::PatternLength(s) => {
            if let Some(index) = &s.index {
                Node(
                    format!("{}[<index>]", s.name),
                    vec![Node(
                        "<index>".to_string(),
                        vec![expr_ascii_tree(&index, sym_tbl)],
                    )],
                )
            } else {
                Leaf(vec![s.name.to_string()])
            }
        }
        Expr::LookupIndex(l) => Node(
            "<expr>[<index>]".to_string(),
            vec![
                Node(
                    "<expr>".to_string(),
                    vec![expr_ascii_tree(&l.primary, sym_tbl)],
                ),
                Node(
                    "<index>".to_string(),
                    vec![expr_ascii_tree(&l.index, sym_tbl)],
                ),
            ],
        ),
        Expr::FieldAccess(expr) => Node(
            "<struct>.<field>".to_string(),
            vec![
                Node(
                    "<struct>".to_string(),
                    vec![expr_ascii_tree(&expr.lhs, sym_tbl)],
                ),
                Node(
                    "<field>".to_string(),
                    vec![expr_ascii_tree(&expr.rhs, sym_tbl)],
                ),
            ],
        ),
        Expr::FnCall(expr) => {
            // Create a vector where each argument is accompanied by a label
            // "<arg0>", "<arg1>", "<arg2>", and so on.
            let labelled_args: Vec<(String, &Expr)> = expr
                .args
                .iter()
                .enumerate()
                .map(|(i, arg)| (format!("<arg{i}>"), arg))
                .collect();

            // Build string with all the labels separated by commas.
            let comma_sep_labels = labelled_args
                .iter()
                .map(|(label, _)| label.as_str())
                .collect::<Vec<&str>>()
                .join(", ");

            let mut children = vec![Node(
                "<callable>".to_string(),
                vec![expr_ascii_tree(&expr.callable, sym_tbl)],
            )];

            for (label, arg) in labelled_args.into_iter() {
                children
                    .push(Node(label, vec![expr_ascii_tree(&arg, sym_tbl)]))
            }

            Node(format!("<callable>({})", comma_sep_labels), children)
        }
        Expr::Of(of) => {
            let set_ascii_tree = match &of.items {
                OfItems::PatternSet(set) => Node(
                    "<items: pattern_set>".to_string(),
                    vec![pattern_set_ascii_tree(&set)],
                ),
                OfItems::BoolExprTuple(set) => Node(
                    "<items: boolean_expr_set>".to_string(),
                    set.iter().map(|x| expr_ascii_tree(&x, sym_tbl)).collect(),
                ),
            };

            let mut children = vec![
                Node(
                    "<quantifier>".to_string(),
                    vec![quantifier_ascii_tree(&of.quantifier, sym_tbl)],
                ),
                set_ascii_tree,
            ];

            let node_title = if let Some(anchor) = &of.anchor {
                match anchor {
                    MatchAnchor::At(anchor_at) => {
                        children.push(Node(
                            "<expr>".to_string(),
                            vec![expr_ascii_tree(&anchor_at.expr, sym_tbl)],
                        ));
                        "<quantifier> of <items> at <expr>".to_string()
                    }
                    MatchAnchor::In(anchor_in) => {
                        children.push(Node(
                            "<start>".to_string(),
                            vec![expr_ascii_tree(
                                &anchor_in.range.lower_bound,
                                sym_tbl,
                            )],
                        ));
                        children.push(Node(
                            "<end>".to_string(),
                            vec![expr_ascii_tree(
                                &anchor_in.range.upper_bound,
                                sym_tbl,
                            )],
                        ));
                        "<quantifier> of <items> in (<start>..<end>)"
                            .to_string()
                    }
                }
            } else {
                "<quantifier> of <items>".to_string()
            };

            Node(node_title, children)
        }
        Expr::ForOf(for_of) => Node(
            "for <quantifier> of <items> : ( <condition> )".to_string(),
            vec![
                Node(
                    "<quantifier>".to_string(),
                    vec![quantifier_ascii_tree(&for_of.quantifier, sym_tbl)],
                ),
                Node(
                    "<items>".to_string(),
                    vec![pattern_set_ascii_tree(&for_of.pattern_set)],
                ),
                Node(
                    "<condition>".to_string(),
                    vec![expr_ascii_tree(&for_of.condition, sym_tbl)],
                ),
            ],
        ),
        Expr::ForIn(f) => {
            let mut children = vec![
                Node(
                    "<quantifier>".to_string(),
                    vec![quantifier_ascii_tree(&f.quantifier, sym_tbl)],
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
                Iterable::Range(range) => {
                    children.push(Node(
                        "<start>".to_string(),
                        vec![expr_ascii_tree(&range.lower_bound, sym_tbl)],
                    ));
                    children.push(Node(
                        "<end>".to_string(),
                        vec![expr_ascii_tree(&range.upper_bound, sym_tbl)],
                    ));
                    "for <quantifier> <vars> in (<start>..<end>) : ( <condition> )".to_string()
                }
                Iterable::ExprTuple(args) => {
                    let labelled_args: Vec<(String, &Expr)> = args
                        .iter()
                        .enumerate()
                        .map(|(i, arg)| (format!("<expr{i}>"), arg))
                        .collect();

                    let comma_sep_labels = labelled_args
                        .iter()
                        .map(|(label, _)| label.as_str())
                        .collect::<Vec<&str>>()
                        .join(", ");

                    for (label, arg) in labelled_args.into_iter() {
                        children.push(Node(
                            label,
                            vec![expr_ascii_tree(&arg, sym_tbl)],
                        ))
                    }

                    format!("for <quantifier> <vars> in ({comma_sep_labels}) : ( <condition> )")
                }
                Iterable::Ident(ident) => {
                    children.push(Node(
                        "<identifier>".to_string(),
                        vec![Leaf(vec![ident.name.to_string()])],
                    ));
                    "for <quantifier> <vars> in <identifier> : ( <condition> )"
                        .to_string()
                }
            };

            children.push(Node(
                "<condition>".to_string(),
                vec![expr_ascii_tree(&f.condition, sym_tbl)],
            ));

            Node(node_title, children)
        }
    }
}

fn quantifier_ascii_tree(
    quantifier: &Quantifier,
    sym_tbl: &Struct,
) -> ascii_tree::Tree {
    match quantifier {
        Quantifier::None { .. } => Leaf(vec!["none".to_string()]),
        Quantifier::All { .. } => Leaf(vec!["all".to_string()]),
        Quantifier::Any { .. } => Leaf(vec!["any".to_string()]),
        Quantifier::Percentage(expr) => Node(
            "percentage".to_string(),
            vec![expr_ascii_tree(&expr, sym_tbl)],
        ),
        Quantifier::Expr(expr) => expr_ascii_tree(&expr, sym_tbl),
    }
}

fn pattern_set_ascii_tree(pattern_set: &PatternSet) -> ascii_tree::Tree {
    match pattern_set {
        PatternSet::Them => Leaf(vec!["them".to_string()]),
        PatternSet::Set(set) => {
            Leaf(set.iter().map(|s| s.identifier.to_string()).collect())
        }
    }
}

fn pattern_ascii_tree(
    pattern: &Pattern,
    sym_tbl: &Struct,
) -> ascii_tree::Tree {
    match pattern {
        Pattern::Text(s) => {
            let modifiers = if let Some(modifiers) = &s.modifiers {
                // The pattern has modifiers, let's generate a textual
                // representation of them.
                let mut m = modifiers
                    .values()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>();
                // .values() doesn't guarantee a stable order, so we need
                // to explicitly sort the vector in order to have a
                // predictable result.
                m.sort();
                m.join(" ")
            } else {
                "".to_string()
            };

            Leaf(vec![format!(
                "{} = \"{}\" {}",
                s.identifier.name, s.value, modifiers
            )])
        }
        Pattern::Hex(h) => Node(
            h.identifier.name.to_string(),
            vec![hex_tokens_ascii_tree(&h.tokens, sym_tbl)],
        ),
        Pattern::Regexp(r) => Leaf(vec![r.identifier.name.to_string()]),
    }
}

fn hex_tokens_ascii_tree(
    tokens: &HexTokens,
    sym_tbl: &Struct,
) -> ascii_tree::Tree {
    let nodes = tokens
        .tokens
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
                a.alternatives
                    .iter()
                    .map(|alt| hex_tokens_ascii_tree(&alt, sym_tbl))
                    .collect(),
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
