/*! Functions that returns an ASCII representation for the IR. */
/*

use super::*;
use ::ascii_tree::Tree;
use ::ascii_tree::Tree::{Leaf, Node};

pub(crate) fn rule_ascii_ir(ir: &IR) -> Tree {
    let mut rules = Vec::new();

    for rule in ir.rules.iter() {
        rules.push(rule_ascii_tree(rule, &ir.ident_pool));
    }

    Node("root".to_string(), rules)
}

/// Returns a representation of the rule's IR as an ASCII tree.
fn rule_ascii_tree(rule: &Rule, ident_pool: &StringPool<IdentId>) -> Tree {
    let mut rule_children = Vec::new();

    rule_children.push(Node(
        "condition".to_owned(),
        vec![expr_ascii_tree(&rule.condition, ident_pool)],
    ));

    Node(
        format!("rule {}", ident_pool.get(rule.ident_id).unwrap()),
        rule_children,
    )
}

fn expr_ascii_tree(expr: &Expr, _ident_pool: &StringPool<IdentId>) -> Tree {
    match expr {
        Expr::ConstBool { value, .. } => Leaf(vec![format!("{}", value)]),
        Expr::ConstInt { value, .. } => Leaf(vec![format!("{}", value)]),
        Expr::And { .. } => {
            todo!()
        }
        Expr::Or { .. } => {
            todo!()
        }
        Expr::FieldAccess { .. } => {
            todo!()
        }
        Expr::Ident { .. } => {
            todo!()
        }
    }
}
*/
