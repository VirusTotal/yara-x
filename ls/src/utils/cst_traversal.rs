/*! This module contains functions for traversing [`yara_x_parser::cst`].

These functions are mainly used in [`crate::features`] module to find
rules and patterns within the CST based on provided identifiers or positions.
 */

use async_lsp::lsp_types::Position;
use yara_x_parser::cst::{
    Immutable, Node, NodeOrToken, SyntaxKind, Token, Utf16, CST,
};

/// Return the token that appears before the given one, without taking
/// into account newlines and whitespaces.
pub(crate) fn prev_non_trivia_token(
    token: &Token<Immutable>,
) -> Option<Token<Immutable>> {
    let mut prev_token = token.prev_token();
    while let Some(token) = prev_token {
        if !matches!(
            token.kind(),
            SyntaxKind::NEWLINE | SyntaxKind::WHITESPACE
        ) {
            return Some(token);
        }
        prev_token = token.prev_token()
    }
    None
}

/// Returns the parent of a node, except if the parent is an
/// `ERROR` node, in which case returns the parent's parent.
pub(crate) fn non_error_parent(
    token: &Token<Immutable>,
) -> Option<Node<Immutable>> {
    let mut parent = token.parent()?;
    while parent.kind() == SyntaxKind::ERROR {
        parent = parent.parent()?;
    }
    Some(parent)
}

/// Returns the token at a given position in the CST.
pub(crate) fn token_at_position(
    cst: &CST,
    pos: Position,
) -> Option<Token<Immutable>> {
    cst.root().token_at_position::<Utf16, _>((
        pos.line as usize,
        pos.character as usize,
    ))
}

/// Returns the identifier at a given position in the CST.
///
/// This function returns the identifier even if the position is past the
/// identifier, at the first position of the next token.
pub(crate) fn ident_at_position(
    cst: &CST,
    mut pos: Position,
) -> Option<Token<Immutable>> {
    let ident_at_pos = |cst, pos| {
        if let Some(token) = token_at_position(cst, pos) {
            if matches!(
                token.kind(),
                SyntaxKind::IDENT
                    | SyntaxKind::PATTERN_IDENT
                    | SyntaxKind::PATTERN_COUNT
                    | SyntaxKind::PATTERN_OFFSET
                    | SyntaxKind::PATTERN_LENGTH
            ) {
                return Some(token);
            }
        }
        None
    };

    if let Some(token) = ident_at_pos(cst, pos) {
        return Some(token);
    }

    pos.character = pos.character.saturating_sub(1);

    if let Some(token) = ident_at_pos(cst, pos) {
        return Some(token);
    }

    None
}

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
        if let Some(rule_ident) = rule
            .children_with_tokens()
            .find(|n| n.kind() == SyntaxKind::IDENT)
            .and_then(|node| node.into_token())
        {
            if rule_ident.text() == ident {
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
        if let Some(pattern_ident) = pattern
            .children_with_tokens()
            .find(|n| n.kind() == SyntaxKind::PATTERN_IDENT)
            .and_then(|n| n.into_token())
        {
            // Ignore first character ($, @, # or !) to compare only the actual
            // identifier.
            if pattern_ident.text()[1..] == ident[1..] {
                return Some(pattern);
            }
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

    for rule_node in rules {
        // Find condition block
        let condition_blk = rule_node
            .children()
            .find(|node| node.kind() == SyntaxKind::CONDITION_BLK)?;

        result_tokens.extend(occurrences_in_node(condition_blk, ident));
    }

    Some(result_tokens)
}

/// Finds the declaration of `identifier` in a `with` or `for` expression. The
/// `identifier` token must be of `SyntaxKind::IDENT` kind and be contained
/// within the `with` or `for` expression. It returns the `SyntaxKind::IDENT`
/// token in the identifier declaration and the `SyntaxKind::FOR_EXPR` or
/// `SyntaxKind::WITH_EXPR` node where it was declared.
pub fn find_identifier_declaration(
    identifier: &Token<Immutable>,
) -> Option<(Token<Immutable>, Node<Immutable>)> {
    assert_eq!(identifier.kind(), SyntaxKind::IDENT);

    for ancestor in identifier.ancestors() {
        match ancestor.kind() {
            SyntaxKind::FOR_EXPR => {
                for declared_ident in identifiers_declared_by_for(&ancestor) {
                    if identifier.text() == declared_ident.text() {
                        return Some((declared_ident, ancestor));
                    }
                }
            }
            SyntaxKind::WITH_EXPR => {
                for declared_ident in identifiers_declared_by_with(&ancestor) {
                    if identifier.text() == declared_ident.text() {
                        return Some((declared_ident, ancestor));
                    }
                }
            }
            _ => {}
        }
    }

    None
}

/// Finds all identifiers declared in a `with` or `for` expression that are in
/// the same scope as `child` Token is.
pub fn identifiers_declared_by_with_or_for(
    child: &Token<Immutable>,
) -> Vec<Token<Immutable>> {
    let mut result_idents: Vec<Token<Immutable>> = Vec::new();
    for ancestor in child.ancestors() {
        match ancestor.kind() {
            SyntaxKind::FOR_EXPR => {
                for ident in identifiers_declared_by_for(&ancestor) {
                    result_idents.push(ident);
                }
            }
            SyntaxKind::WITH_EXPR => {
                for ident in identifiers_declared_by_with(&ancestor) {
                    result_idents.push(ident);
                }
            }
            _ => {}
        }
    }
    result_idents
}

/// Finds all identifiers declared by a `with` expression.
pub fn identifiers_declared_by_with(
    with_expr: &Node<Immutable>,
) -> impl Iterator<Item = Token<Immutable>> {
    assert_eq!(with_expr.kind(), SyntaxKind::WITH_EXPR);

    with_expr
        .children()
        .find(|node| node.kind() == SyntaxKind::WITH_DECLS)
        .map(|with_decls| {
            with_decls
                .children()
                .filter(|node| node.kind() == SyntaxKind::WITH_DECL)
        })
        .map(|with_decls| {
            with_decls.filter_map(|with_decl| {
                with_decl
                    .first_token()
                    .filter(|token| token.kind() == SyntaxKind::IDENT)
            })
        })
        .into_iter()
        .flatten()
}

/// Finds all identifiers declared by a `for` expression.
pub fn identifiers_declared_by_for(
    for_expr: &Node<Immutable>,
) -> impl Iterator<Item = Token<Immutable>> {
    assert_eq!(for_expr.kind(), SyntaxKind::FOR_EXPR);
    for_expr
        .children_with_tokens()
        .take_while(|node_or_token| {
            !matches!(
                node_or_token.kind(),
                SyntaxKind::COLON | SyntaxKind::IN_KW
            )
        })
        .filter_map(|node_or_token| node_or_token.into_token())
        .filter(|token| token.kind() == SyntaxKind::IDENT)
}

/// This function finds all occurrences of `ident` identifier declared in
/// `with` or `for` statements
///
/// The `with_for` argument should be a Node of either `SyntaxKind::FOR_EXPR` or `SyntaxKind::WITH_EXPR`.
pub fn occurrences_in_with_for(
    with_for: Node<Immutable>,
    ident: &str,
) -> Option<Vec<Token<Immutable>>> {
    // Find the bool expression which is body of the `with` or `for` statement
    let bool_expr = with_for
        .children_with_tokens()
        .skip_while(|node_or_token| node_or_token.kind() != SyntaxKind::COLON)
        .find(|node_or_token| {
            node_or_token.kind() == SyntaxKind::BOOLEAN_EXPR
        })?
        .into_node()?;

    Some(occurrences_in_node(bool_expr, ident))
}

/// This function tries to find all occurrences of the provided identifier
/// by traversing all children of the specified node.
///
/// This function is also context-aware, meaning it can distinguish when
/// the identifier is redefined within the node in `with` and `for`
/// statements. It also ignores identifiers which are part of the field
/// access expression (e.g. `characteristics` is ignored in
/// `pe.characteristics`).
fn occurrences_in_node(
    node: Node<Immutable>,
    ident: &str,
) -> Vec<Token<Immutable>> {
    let mut result_tokens: Vec<Token<Immutable>> = Vec::new();

    let mut nodes_or_tokens = vec![NodeOrToken::Node(node)];

    while let Some(node_or_token) = nodes_or_tokens.pop() {
        match node_or_token {
            NodeOrToken::Node(node) => {
                // Check if this node does not contatin definition
                // of the same identifier
                if !with_for_defines_ident(&node, ident) {
                    node.children_with_tokens().for_each(
                        |node_or_token_inner| {
                            nodes_or_tokens.push(node_or_token_inner)
                        },
                    );
                }
            }
            NodeOrToken::Token(token) => {
                if token.kind() == SyntaxKind::IDENT
                    //Ignore identifiers within module function calls, field access, etc.
                    && token
                        .prev_token()
                        .is_none_or(|t| t.kind() != SyntaxKind::DOT)
                    && token.text() == ident
                {
                    result_tokens.push(token);
                }
            }
        }
    }

    result_tokens
}

/// This function checks if the node represents `with` or `for` statement
/// and also contains defintion of an `ident`. If the kind of the
/// specified node is not `SyntaxKind::WITH_EXPR` or `SyntaxKind::FOR_EXPR`,
/// the function just return false.
fn with_for_defines_ident(with_for: &Node<Immutable>, ident: &str) -> bool {
    match with_for.kind() {
        SyntaxKind::WITH_EXPR => with_for
            .children()
            .find(|node| node.kind() == SyntaxKind::WITH_DECLS)
            .is_some_and(|decls| {
                decls
                    .children()
                    .filter(|decl_node| {
                        decl_node.kind() == SyntaxKind::WITH_DECL
                    })
                    .any(|decl| {
                        decl.first_token()
                            .is_some_and(|token| token.text() == ident)
                    })
            }),
        SyntaxKind::FOR_EXPR => with_for
            .children_with_tokens()
            .take_while(|node_or_token| {
                !matches!(
                    node_or_token.kind(),
                    SyntaxKind::COLON | SyntaxKind::IN_KW
                )
            })
            .any(|node_or_token| {
                node_or_token.into_token().is_some_and(|t| {
                    t.kind() == SyntaxKind::IDENT && t.text() == ident
                })
            }),
        _ => false,
    }
}
