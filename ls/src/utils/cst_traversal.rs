/*! This module contains functions for traversing [`yara_x_parser::cst`].

These functions are mainly used in [`crate::features`] module to find
rules and patterns within the CST based on provided identifiers or positions.
 */

use async_lsp::lsp_types::{Position, Url};
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
    root: &Node<Immutable>,
    ident: &str,
) -> Option<Node<Immutable>> {
    // Iterator over all rule declarations in the CST
    let rules =
        root.children().filter(|node| node.kind() == SyntaxKind::RULE_DECL);

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
    root: &Node<Immutable>,
    ident: &str,
) -> Option<Vec<Token<Immutable>>> {
    // Iterator over all rule declarations in the CST
    let rules =
        root.children().filter(|node| node.kind() == SyntaxKind::RULE_DECL);

    let mut result_tokens: Vec<Token<Immutable>> = Vec::new();

    let mut nodes_or_tokens: Vec<NodeOrToken<Immutable>>;

    for rule_node in rules {
        // Find condition block
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

/// Returns a vector of [`async_lsp::lsp_types::Url`] that represent all includes
/// of the document that were found in the root [`yara_x_parser::cst::Node`].
pub fn get_includes(root: &Node<Immutable>, base: &Url) -> Vec<Url> {
    let mut includes: Vec<Url> = vec![];
    root.children()
        .filter(|child| child.kind() == SyntaxKind::INCLUDE_STMT)
        .for_each(|include| {
            if let Some(include_token) = include.last_token() {
                let include_text = include_token.text();
                let include_len = include_text.len();

                if include_token.kind() == SyntaxKind::STRING_LIT
                    && include_len > 2
                {
                    if let Ok(new_url) =
                        base.join(&include_text[1..include_len - 1])
                    {
                        includes.push(new_url);
                    }
                }
            }
        });
    includes
}
