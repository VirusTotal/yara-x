/*! Functions that returns an ASCII representation of YARA Abstract Syntax Trees (ASTs).*/

use ::ascii_tree::Tree;
use ::ascii_tree::Tree::{Leaf, Node};
use itertools::Itertools;

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
pub(crate) fn expr_ascii_tree(expr: &Expr) -> Tree {
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
        Expr::Defined(expr) => {
            Node("defined".to_string(), vec![expr_ascii_tree(&expr.operand)])
        }
        Expr::Not(expr) => {
            Node("not".to_string(), vec![expr_ascii_tree(&expr.operand)])
        }
        Expr::And(expr) => Node(
            "and".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::Or(expr) => Node(
            "or".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::Minus(expr) => {
            Node("minus".to_string(), vec![expr_ascii_tree(&expr.operand)])
        }
        Expr::Add(expr) => Node(
            "add".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::Sub(expr) => Node(
            "sub".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::Mul(expr) => Node(
            "mul".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::Div(expr) => Node(
            "div".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::Mod(expr) => Node(
            "mod".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::Shl(expr) => Node(
            "shl".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Shr(expr) => Node(
            "shr".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::BitwiseNot(expr) => Node(
            "bitwise_not".to_string(),
            vec![expr_ascii_tree(&expr.operand)],
        ),
        Expr::BitwiseAnd(expr) => Node(
            "bitwise_and".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::BitwiseOr(expr) => Node(
            "bitwise_or".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::BitwiseXor(expr) => Node(
            "bitwise_xor".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),

        Expr::Eq(expr) => Node(
            "eq".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Ne(expr) => Node(
            "ne".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Lt(expr) => Node(
            "lt".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Le(expr) => Node(
            "le".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Gt(expr) => Node(
            "gt".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Ge(expr) => Node(
            "ge".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Contains(expr) => Node(
            "contains".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::IContains(expr) => Node(
            "icontains".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::StartsWith(expr) => Node(
            "startswith".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::IStartsWith(expr) => Node(
            "istartswith".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::EndsWith(expr) => Node(
            "endswith".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::IEndsWith(expr) => Node(
            "iendswith".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::IEquals(expr) => Node(
            "iequals".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::Matches(expr) => Node(
            "matches".to_string(),
            vec![expr_ascii_tree(&expr.lhs), expr_ascii_tree(&expr.rhs)],
        ),
        Expr::PatternMatch(s) => {
            if let Some(anchor) = &s.anchor {
                match anchor {
                    MatchAnchor::At(anchor_at) => Node(
                        format!("{} at <expr>", s.identifier.name),
                        vec![Node(
                            "<expr>".to_string(),
                            vec![expr_ascii_tree(&anchor_at.expr)],
                        )],
                    ),
                    MatchAnchor::In(anchor_in) => Node(
                        format!("{} in (<start>, <end>)", s.identifier.name),
                        vec![
                            Node(
                                "<start>".to_string(),
                                vec![expr_ascii_tree(
                                    &anchor_in.range.lower_bound,
                                )],
                            ),
                            Node(
                                "<end>".to_string(),
                                vec![expr_ascii_tree(
                                    &anchor_in.range.upper_bound,
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
                    format!("{} in <range>", s.ident.name),
                    vec![Node(
                        "<range>".to_string(),
                        vec![
                            expr_ascii_tree(&range.lower_bound),
                            expr_ascii_tree(&range.upper_bound),
                        ],
                    )],
                )
            } else {
                Leaf(vec![s.ident.name.to_string()])
            }
        }
        Expr::PatternOffset(s) | Expr::PatternLength(s) => {
            if let Some(index) = &s.index {
                Node(
                    format!("{}[<index>]", s.ident.name),
                    vec![Node(
                        "<index>".to_string(),
                        vec![expr_ascii_tree(index)],
                    )],
                )
            } else {
                Leaf(vec![s.ident.name.to_string()])
            }
        }
        Expr::Lookup(l) => Node(
            "<expr>[<index>]".to_string(),
            vec![
                Node("<expr>".to_string(), vec![expr_ascii_tree(&l.primary)]),
                Node("<index>".to_string(), vec![expr_ascii_tree(&l.index)]),
            ],
        ),
        Expr::FieldAccess(expr) => Node(
            "field access".to_string(),
            expr.operands().map(expr_ascii_tree).collect(),
        ),
        Expr::FuncCall(expr) => {
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
                vec![expr_ascii_tree(&expr.callable)],
            )];

            for (label, arg) in labelled_args.into_iter() {
                children.push(Node(label, vec![expr_ascii_tree(arg)]))
            }

            Node(format!("<callable>({})", comma_sep_labels), children)
        }
        Expr::Of(of) => {
            let set_ascii_tree = match &of.items {
                OfItems::PatternSet(set) => Node(
                    "<items: pattern_set>".to_string(),
                    vec![pattern_set_ascii_tree(set)],
                ),
                OfItems::BoolExprTuple(set) => Node(
                    "<items: boolean_expr_set>".to_string(),
                    set.iter().map(expr_ascii_tree).collect(),
                ),
            };

            let mut children = vec![
                Node(
                    "<quantifier>".to_string(),
                    vec![quantifier_ascii_tree(&of.quantifier)],
                ),
                set_ascii_tree,
            ];

            let node_title = if let Some(anchor) = &of.anchor {
                match anchor {
                    MatchAnchor::At(anchor_at) => {
                        children.push(Node(
                            "<expr>".to_string(),
                            vec![expr_ascii_tree(&anchor_at.expr)],
                        ));
                        "<quantifier> of <items> at <expr>".to_string()
                    }
                    MatchAnchor::In(anchor_in) => {
                        children.push(Node(
                            "<start>".to_string(),
                            vec![expr_ascii_tree(
                                &anchor_in.range.lower_bound,
                            )],
                        ));
                        children.push(Node(
                            "<end>".to_string(),
                            vec![expr_ascii_tree(
                                &anchor_in.range.upper_bound,
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
                    vec![quantifier_ascii_tree(&for_of.quantifier)],
                ),
                Node(
                    "<items>".to_string(),
                    vec![pattern_set_ascii_tree(&for_of.pattern_set)],
                ),
                Node(
                    "<condition>".to_string(),
                    vec![expr_ascii_tree(&for_of.condition)],
                ),
            ],
        ),
        Expr::ForIn(f) => {
            let mut children = vec![
                Node(
                    "<quantifier>".to_string(),
                    vec![quantifier_ascii_tree(&f.quantifier)],
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
                        vec![expr_ascii_tree(&range.lower_bound)],
                    ));
                    children.push(Node(
                        "<end>".to_string(),
                        vec![expr_ascii_tree(&range.upper_bound)],
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
                        children.push(Node(label, vec![expr_ascii_tree(arg)]))
                    }

                    format!("for <quantifier> <vars> in ({comma_sep_labels}) : ( <condition> )")
                }
                Iterable::Expr(expr) => {
                    children.push(Node(
                        "<expr>".to_string(),
                        vec![expr_ascii_tree(expr)],
                    ));
                    "for <quantifier> <vars> in <expr> : ( <condition> )"
                        .to_string()
                }
            };

            children.push(Node(
                "<condition>".to_string(),
                vec![expr_ascii_tree(&f.condition)],
            ));

            Node(node_title, children)
        }
    }
}

pub(crate) fn quantifier_ascii_tree(quantifier: &Quantifier) -> Tree {
    match quantifier {
        Quantifier::None { .. } => Leaf(vec!["none".to_string()]),
        Quantifier::All { .. } => Leaf(vec!["all".to_string()]),
        Quantifier::Any { .. } => Leaf(vec!["any".to_string()]),
        Quantifier::Percentage(expr) => {
            Node("percentage".to_string(), vec![expr_ascii_tree(expr)])
        }
        Quantifier::Expr(expr) => expr_ascii_tree(expr),
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
            vec![hex_tokens_ascii_tree(&h.tokens)],
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

pub(crate) fn hex_tokens_ascii_tree(tokens: &HexTokens) -> Tree {
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
