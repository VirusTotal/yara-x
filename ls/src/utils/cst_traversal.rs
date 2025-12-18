/*! This module contains functions for traversing [`yara_x_parser::cst`].

These functions are mainly used in [`crate::features`] module to find
rules and patterns within the CST based on provided identifiers or positions.
 */

use yara_x_parser::cst::{
    Immutable, Node, NodeOrToken, SyntaxKind, Token, CST,
};

/// Returns [`yara_x_parser::cst::Node`] containing rule declaration matching
/// the provided identifier if exists in the CST.
pub(crate) fn rule_from_ident(
    cst: &CST,
    ident: &str,
) -> Option<Node<Immutable>> {
    // Iterator over all rule declarations in the CST
    let rules = cst
        .root()
        .children()
        .filter(|node| node.kind() == SyntaxKind::RULE_DECL);

    for rule in rules {
        // First token within `SyntaxKind::RULE_DECL` is always rule identifier
        let first_ident: Option<Token<Immutable>> =
            rule.children_with_tokens().find_map(|node_or_token| {
                if let NodeOrToken::Token(token) = node_or_token {
                    if token.kind() == SyntaxKind::IDENT {
                        Some(token)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });

        if let Some(first_ident) = first_ident {
            if first_ident.text() == ident {
                return Some(rule);
            }
        }
    }

    None
}

/// Given a token in the CST, returns the `RULE_DECL` node that corresponds to
/// the rule containing that token, or `None` if the token is outside a rule.
pub(crate) fn rule_containing_token(
    token: &Token<Immutable>,
) -> Option<Node<Immutable>> {
    token.ancestors().find(|node| node.kind() == SyntaxKind::RULE_DECL)
}

/// Returns the `PATTERN_DEF` node that contains the declaration of the pattern
/// identified as `ident`, within the given `rule`.
///
/// This function expects that `rule` is a `RULE_DECL` node.
pub(crate) fn pattern_from_ident(
    rule: &Node<Immutable>,
    ident: &str,
) -> Option<Node<Immutable>> {
    assert_eq!(rule.kind(), SyntaxKind::RULE_DECL);

    // Find "strings" block.
    let patterns_blk = rule
        .children()
        .find(|node| node.kind() == SyntaxKind::PATTERNS_BLK)?;

    // Iterator over all pattern declarations in "strings" block.
    let pattern_decls = patterns_blk
        .children()
        .filter(|node| node.kind() == SyntaxKind::PATTERN_DEF);

    for pattern in pattern_decls {
        // Check if the pattern declaration has identical identifier
        let identical_ident =
            pattern.children_with_tokens().any(|node_or_token| {
                if let NodeOrToken::Token(token) = node_or_token {
                    token.kind() == SyntaxKind::PATTERN_IDENT
                    // Ignore first symbols($ @ # !) to compare only
                    // pattern identifiers
                        && token.text()[1..] == ident[1..]
                } else {
                    false
                }
            });

        if identical_ident {
            return Some(pattern);
        }
    }

    None
}

/// Returns vector of [`yara_x_parser::cst::Token`] containing all pattern
/// usages within the given rule Node matching the provided identifier.
///
/// This function expect that `rule_node` argument is of kind
/// `SyntaxKind::RULE_DECL`.
pub(crate) fn pattern_usages(
    rule: &Node<Immutable>,
    ident: &str,
) -> Option<Vec<Token<Immutable>>> {
    assert_eq!(rule.kind(), SyntaxKind::RULE_DECL);

    let mut result_tokens: Vec<Token<Immutable>> = Vec::new();

    // Find condition block
    let condition_blk = rule
        .children()
        .find(|node| node.kind() == SyntaxKind::CONDITION_BLK)?;

    let mut nodes_or_tokens: Vec<NodeOrToken<Immutable>> =
        vec![NodeOrToken::Node(condition_blk)];

    // Traverse all nodes and tokens within condition block to
    // find pattern usages
    while let Some(node_or_token) = nodes_or_tokens.pop() {
        match node_or_token {
            NodeOrToken::Node(node) => {
                node.children_with_tokens().for_each(|node_or_token_inner| {
                    nodes_or_tokens.push(node_or_token_inner)
                })
            }
            NodeOrToken::Token(token) => {
                if matches!(
                    token.kind(),
                    SyntaxKind::PATTERN_IDENT
                        | SyntaxKind::PATTERN_COUNT
                        | SyntaxKind::PATTERN_OFFSET
                        | SyntaxKind::PATTERN_LENGTH
                )
                // Ignore first symbols($ @ # !) to compare only pattern
                // identifiers
                && token.text()[1..] == ident[1..]
                {
                    result_tokens.push(token);
                }
            }
        }
    }

    Some(result_tokens)
}

/// Returns vector of [`yara_x_parser::cst::Token`] containing all rule
/// usages in the CST matching the provided identifier.
pub(crate) fn rule_usages(
    cst: &CST,
    ident: &str,
) -> Option<Vec<Token<Immutable>>> {
    // Iterator over all rule declarations in the CST
    let rules = cst
        .root()
        .children()
        .filter(|node| node.kind() == SyntaxKind::RULE_DECL);

    let mut result_tokens: Vec<Token<Immutable>> = Vec::new();

    let mut nodes_or_tokens: Vec<NodeOrToken<Immutable>>;

    for rule_node in rules {
        //Find condition block
        let condition_blk = rule_node
            .children()
            .find(|node| node.kind() == SyntaxKind::CONDITION_BLK)?;

        nodes_or_tokens = vec![NodeOrToken::Node(condition_blk)];

        // Traverse all nodes and tokens within condition block to
        // find rule usages
        while let Some(node_or_token) = nodes_or_tokens.pop() {
            match node_or_token {
                NodeOrToken::Node(node) => node
                    .children_with_tokens()
                    .for_each(|node_or_token_inner| {
                        nodes_or_tokens.push(node_or_token_inner)
                    }),
                NodeOrToken::Token(token) => {
                    if token.kind() == SyntaxKind::IDENT
                        && token.text() == ident
                    {
                        result_tokens.push(token);
                    }
                }
            }
        }
    }

    Some(result_tokens)
}
