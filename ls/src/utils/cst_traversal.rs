/*! This module contains functions for traversing [`yara_x_parser::cst`].

These functions are mainly used in [`crate::features`] module to find
rules and patterns within the CST based on provided identifiers or positions.
 */

use async_lsp::lsp_types::{Position, Url};
use yara_x_parser::cst::{
    CST, Immutable, Node, NodeOrToken, SyntaxKind, Token, Utf16,
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
        if let Some(token) = token_at_position(cst, pos)
            && matches!(
                token.kind(),
                SyntaxKind::IDENT
                    | SyntaxKind::PATTERN_IDENT
                    | SyntaxKind::PATTERN_COUNT
                    | SyntaxKind::PATTERN_OFFSET
                    | SyntaxKind::PATTERN_LENGTH
            )
        {
            return Some(token);
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

/// Returns the `RULE_DECL` node for the rule with the given `ident`.
pub(crate) fn rule_from_ident(
    source_file: &Node<Immutable>,
    ident: &Token<Immutable>,
) -> Option<Node<Immutable>> {
    assert_eq!(source_file.kind(), SyntaxKind::SOURCE_FILE);
    assert_eq!(ident.kind(), SyntaxKind::IDENT);

    // Iterator over all rule declarations in the CST
    let rules = source_file
        .children()
        .filter(|node| node.kind() == SyntaxKind::RULE_DECL);

    for rule in rules {
        if let Some(rule_ident) = rule
            .children_with_tokens()
            .find(|n| n.kind() == SyntaxKind::IDENT)
            .and_then(|node| node.into_token())
            && rule_ident.text() == ident.text()
        {
            return Some(rule);
        }
    }

    None
}

/// Returns the `RULE_DECL` node for the rule containing the given `token`
/// or `None` if the token is outside a rule.
pub(crate) fn rule_containing_token(
    token: &Token<Immutable>,
) -> Option<Node<Immutable>> {
    token.ancestors().find(|node| node.kind() == SyntaxKind::RULE_DECL)
}

/// Returns the `PATTERN_DEF` node containing the declaration of the pattern
/// identified as `ident`, within the given `rule`.
pub(crate) fn pattern_from_ident(
    rule: &Node<Immutable>,
    ident: &Token<Immutable>,
) -> Option<Node<Immutable>> {
    assert_eq!(rule.kind(), SyntaxKind::RULE_DECL);
    assert!(matches!(
        ident.kind(),
        SyntaxKind::PATTERN_IDENT
            | SyntaxKind::PATTERN_COUNT
            | SyntaxKind::PATTERN_OFFSET
            | SyntaxKind::PATTERN_LENGTH
    ));

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
            if pattern_ident.text()[1..] == ident.text()[1..] {
                return Some(pattern);
            }
        }
    }

    None
}

/// Returns vector of [`Token`] containing all the usages of the
/// pattern with a given `ident` in `rule`.
pub(crate) fn pattern_usages(
    rule: &Node<Immutable>,
    ident: &Token<Immutable>,
) -> Option<Vec<Token<Immutable>>> {
    assert_eq!(rule.kind(), SyntaxKind::RULE_DECL);
    assert!(matches!(
        ident.kind(),
        SyntaxKind::PATTERN_IDENT
            | SyntaxKind::PATTERN_COUNT
            | SyntaxKind::PATTERN_OFFSET
            | SyntaxKind::PATTERN_LENGTH
    ));

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
                && token.text()[1..] == ident.text()[1..]
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
    ident: &Token<Immutable>,
) -> Option<Vec<Token<Immutable>>> {
    assert_eq!(ident.kind(), SyntaxKind::IDENT);

    // Iterator over all rule declarations in the CST
    let rules =
        root.children().filter(|node| node.kind() == SyntaxKind::RULE_DECL);

    let mut result_tokens: Vec<Token<Immutable>> = Vec::new();

    for rule_node in rules {
        // Find condition block
        let condition_blk = rule_node
            .children()
            .find(|node| node.kind() == SyntaxKind::CONDITION_BLK)?;

        result_tokens.extend(occurrences_in_node(&condition_blk, ident));
    }

    Some(result_tokens)
}

/// Finds the declaration of `ident` in a `with` or `for` expression. The
/// `identifier` token must be of `SyntaxKind::IDENT` kind and be contained
/// within the `with` or `for` expression. It returns the `SyntaxKind::IDENT`
/// token in the identifier declaration and the `SyntaxKind::FOR_EXPR` or
/// `SyntaxKind::WITH_EXPR` node where it was declared.
pub fn find_declaration(
    ident: &Token<Immutable>,
) -> Option<(Token<Immutable>, Node<Immutable>)> {
    assert_eq!(ident.kind(), SyntaxKind::IDENT);

    for ancestor in ident.ancestors() {
        match ancestor.kind() {
            SyntaxKind::FOR_EXPR => {
                for declared_ident in idents_declared_by_for(&ancestor) {
                    if ident.text() == declared_ident.text() {
                        return Some((declared_ident, ancestor));
                    }
                }
            }
            SyntaxKind::WITH_EXPR => {
                for declared_ident in idents_declared_by_with(&ancestor) {
                    if ident.text() == declared_ident.text() {
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
pub fn idents_declared_by_expr(
    child: &Token<Immutable>,
) -> Vec<Token<Immutable>> {
    let mut result_idents: Vec<Token<Immutable>> = Vec::new();
    for ancestor in child.ancestors() {
        match ancestor.kind() {
            SyntaxKind::FOR_EXPR => {
                for ident in idents_declared_by_for(&ancestor) {
                    result_idents.push(ident);
                }
            }
            SyntaxKind::WITH_EXPR => {
                for ident in idents_declared_by_with(&ancestor) {
                    result_idents.push(ident);
                }
            }
            _ => {}
        }
    }
    result_idents
}

/// Finds all identifiers declared by a `with` expression.
pub fn idents_declared_by_with(
    with_expr: &Node<Immutable>,
) -> impl Iterator<Item = Token<Immutable>> + use<> {
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
pub fn idents_declared_by_for(
    for_expr: &Node<Immutable>,
) -> impl Iterator<Item = Token<Immutable>> + use<> {
    assert_eq!(for_expr.kind(), SyntaxKind::FOR_EXPR);
    for_expr
        .children_with_tokens()
        .take_while(|child| {
            !matches!(child.kind(), SyntaxKind::COLON | SyntaxKind::IN_KW)
        })
        .filter_map(|child| child.into_token())
        .filter(|token| token.kind() == SyntaxKind::IDENT)
}

/// This function finds all occurrences of `ident` identifier declared in
/// `with` or `for` statements
///
/// The `with_for` argument should be a Node of either `SyntaxKind::FOR_EXPR` or `SyntaxKind::WITH_EXPR`.
pub fn occurrences_in_with_for(
    with_for: &Node<Immutable>,
    ident: &Token<Immutable>,
) -> Option<Vec<Token<Immutable>>> {
    // Find the bool expression which is body of the `with` or `for` statement
    let bool_expr = with_for
        .children_with_tokens()
        .skip_while(|child| child.kind() != SyntaxKind::COLON)
        .find(|child| child.kind() == SyntaxKind::BOOLEAN_EXPR)?
        .into_node()?;

    Some(occurrences_in_node(&bool_expr, ident))
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
    node: &Node<Immutable>,
    ident: &Token<Immutable>,
) -> Vec<Token<Immutable>> {
    let mut result: Vec<Token<Immutable>> = Vec::new();
    let mut stack = vec![NodeOrToken::Node(node.clone())];

    while let Some(node_or_token) = stack.pop() {
        match node_or_token {
            NodeOrToken::Node(node) => {
                if !expr_declares_ident(&node, ident) {
                    node.children_with_tokens()
                        .for_each(|child| stack.push(child));
                }
            }
            NodeOrToken::Token(token) => {
                if token.kind() == SyntaxKind::IDENT
                    // Ignore identifiers within module function calls, field access, etc.
                    && token
                        .prev_token()
                        .is_none_or(|t| t.kind() != SyntaxKind::DOT)
                    && token.text() == ident.text()
                {
                    result.push(token);
                }
            }
        }
    }

    result
}

/// Checks if `expr` represents a `with` or `for` statement that declares the
/// given `ident`.
fn expr_declares_ident(
    expr: &Node<Immutable>,
    ident: &Token<Immutable>,
) -> bool {
    match expr.kind() {
        SyntaxKind::WITH_EXPR => idents_declared_by_with(expr)
            .any(|declared_ident| declared_ident.text() == ident.text()),
        SyntaxKind::FOR_EXPR => idents_declared_by_for(expr)
            .any(|declared_ident| declared_ident.text() == ident.text()),
        _ => false,
    }
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
                    && let Ok(new_url) =
                        base.join(&include_text[1..include_len - 1])
                {
                    includes.push(new_url);
                }
            }
        });
    includes
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_lsp::lsp_types::Position;

    fn find_tokens(
        node: &Node<Immutable>,
        target: &str,
    ) -> Vec<Token<Immutable>> {
        let mut tokens = Vec::new();
        let mut stack = vec![NodeOrToken::Node(node.clone())];
        while let Some(nt) = stack.pop() {
            match nt {
                NodeOrToken::Node(n) => stack.extend(n.children_with_tokens()),
                NodeOrToken::Token(t) => {
                    if t.text() == target {
                        tokens.push(t);
                    }
                }
            }
        }
        tokens
    }

    #[test]
    fn test_token_and_ident_at_position() {
        let text = "rule test_rule {\n  strings:\n    $my_str = \"hello\"\n  condition:\n    $my_str and test_rule\n}";
        let cst = CST::from(text);

        let pos = Position::new(0, 6);
        let token = ident_at_position(&cst, pos).expect("ident found");
        assert_eq!(token.text(), "test_rule");
        assert_eq!(token.kind(), SyntaxKind::IDENT);

        let pos_past = Position::new(0, 14);
        let token =
            ident_at_position(&cst, pos_past).expect("ident found past end");
        assert_eq!(token.text(), "test_rule");

        let pos_str = Position::new(2, 6);
        let token =
            ident_at_position(&cst, pos_str).expect("pattern ident found");
        assert_eq!(token.text(), "$my_str");
        assert_eq!(token.kind(), SyntaxKind::PATTERN_IDENT);
    }

    #[test]
    fn test_rule_and_pattern_queries() {
        let text = "rule r1 {\n  strings:\n    $s1 = \"abc\"\n    $s2 = \"xyz\"\n  condition:\n    #s1 > 0 and @s2[1] == 0\n}";
        let cst = CST::from(text);
        let root = cst.root();

        let r1_token = find_tokens(&root, "r1").pop().unwrap();

        let rule_node = rule_from_ident(&root, &r1_token).expect("rule node");
        assert_eq!(rule_node.kind(), SyntaxKind::RULE_DECL);
        assert_eq!(
            rule_containing_token(&r1_token).unwrap().kind(),
            SyntaxKind::RULE_DECL
        );

        let hash_s1_token = find_tokens(&root, "#s1").pop().unwrap();

        let pattern_def = pattern_from_ident(&rule_node, &hash_s1_token)
            .expect("pattern def");
        assert_eq!(pattern_def.kind(), SyntaxKind::PATTERN_DEF);

        let usages = pattern_usages(&rule_node, &hash_s1_token)
            .expect("pattern usages");
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].text(), "#s1");
    }

    #[test]
    fn test_rule_usages() {
        let text =
            "rule helper { condition: true }\nrule main { condition: helper }";
        let cst = CST::from(text);
        let root = cst.root();

        let helper_ident = find_tokens(&root, "helper").pop().unwrap();

        let usages = rule_usages(&root, &helper_ident).expect("usages");
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].text(), "helper");
    }

    #[test]
    fn test_with_and_for_declarations() {
        let text = "rule loop_test {\n  condition:\n    for any x in (1..10) : ( x == 5 ) and with y = 2 : ( y == 2 )\n}";
        let cst = CST::from(text);
        let root = cst.root();

        let x_tokens = find_tokens(&root, "x");
        let x_in_cond = x_tokens.first().unwrap(); // due to stack pop, tokens might be reversed or forward; let's pick one that works or test each

        let (decl_ident, decl_node) =
            find_declaration(x_in_cond).expect("finds x declaration");
        assert_eq!(decl_ident.text(), "x");
        assert_eq!(decl_node.kind(), SyntaxKind::FOR_EXPR);

        let idents_for: Vec<_> = idents_declared_by_for(&decl_node).collect();
        assert_eq!(idents_for.len(), 1);
        assert_eq!(idents_for[0].text(), "x");

        let y_tokens = find_tokens(&root, "y");
        let y_in_cond = y_tokens.first().unwrap();

        let (y_decl, y_node) =
            find_declaration(y_in_cond).expect("finds y declaration");
        assert_eq!(y_decl.text(), "y");
        assert_eq!(y_node.kind(), SyntaxKind::WITH_EXPR);

        let occ = occurrences_in_with_for(&y_node, &y_decl)
            .expect("occurrences of y");
        assert_eq!(occ.len(), 1);
        assert_eq!(occ[0].text(), "y");
    }

    #[test]
    fn test_get_includes() {
        let text = "include \"common.yar\"\ninclude \"sub/rules.yar\"\nrule foo { condition: true }";
        let cst = CST::from(text);
        let base = Url::parse("file:///project/main.yar").unwrap();

        let incs = get_includes(&cst.root(), &base);
        assert_eq!(incs.len(), 2);
        assert_eq!(incs[0].as_str(), "file:///project/common.yar");
        assert_eq!(incs[1].as_str(), "file:///project/sub/rules.yar");
    }
}
