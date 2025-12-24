use async_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails,
    InsertTextFormat, InsertTextMode, Position,
};

use yara_x_parser::cst::{
    Immutable, Node, NodeOrToken, SyntaxKind, Token, CST,
};

use crate::features::completion_const::{
    CONDITION_SUGGESTIONS, PATTERN_MODS, RULE_KW_BLKS, SRC_SUGGESTIONS,
};

use crate::utils::cst_traversal::{
    non_error_parent, prev_non_trivia_token, rule_containing_token,
    token_at_position,
};

pub fn completion(cst: &CST, pos: Position) -> Option<Vec<CompletionItem>> {
    // Get the token before cursor. There might be no token at cursor when the
    // cursor is at of the file. In this case, take the last token of the file.
    let token = token_at_position(cst, pos)
        .and_then(|token| token.prev_token())
        .or_else(|| cst.root().last_token())?;

    // If the token is a direct child of `SOURCE_FILE` top-level suggestions.
    if non_error_parent(&token)?.kind() == SyntaxKind::SOURCE_FILE {
        return Some(source_file_suggestions());
    }

    let prev_token = prev_non_trivia_token(&token)?;

    if let Some(pattern_def) =
        prev_token.ancestors().find(|n| n.kind() == SyntaxKind::PATTERN_DEF)
    {
        return Some(pattern_modifier_suggestions(pattern_def));
    }

    if prev_token.ancestors().any(|n| n.kind() == SyntaxKind::CONDITION_BLK) {
        return condition_suggestions(cst, token);
    }

    if prev_token.ancestors().any(|n| n.kind() == SyntaxKind::RULE_DECL) {
        return Some(rule_suggestions());
    }

    Some(vec![])
}

/// Collects completion suggestions for condition block.
fn condition_suggestions(
    cst: &CST,
    token: Token<Immutable>,
) -> Option<Vec<CompletionItem>> {
    let mut result = Vec::new();

    match token.kind() {
        // Suggest completion of
        SyntaxKind::IDENT => {
            // Rule identifiers
            for rule_decl in cst.root().children() {
                let Some(NodeOrToken::Token(ident)) =
                    rule_decl.children_with_tokens().find(|node_or_token| {
                        node_or_token.kind() == SyntaxKind::IDENT
                    })
                else {
                    continue;
                };

                result.push(CompletionItem {
                    label: ident.text().to_string(),
                    label_details: Some(CompletionItemLabelDetails {
                        description: Some("Rule".to_string()),
                        ..Default::default()
                    }),
                    kind: Some(CompletionItemKind::VARIABLE),
                    ..Default::default()
                });
            }

            // Keywords
            CONDITION_SUGGESTIONS.iter().for_each(|(kw, insert)| {
                result.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    insert_text_format: insert
                        .map(|_| InsertTextFormat::SNIPPET),
                    insert_text: insert
                        .map(|insert_text| insert_text.to_string()),
                    ..Default::default()
                });
            });
        }
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_containing_token(&token)?;

            let patterns = rule
                .children()
                .find(|node| node.kind() == SyntaxKind::PATTERNS_BLK)?;

            for pattern_def in patterns.children() {
                let Some(NodeOrToken::Token(ident)) =
                    pattern_def.children_with_tokens().find(|node_or_token| {
                        node_or_token.kind() == SyntaxKind::PATTERN_IDENT
                    })
                else {
                    continue;
                };
                let label = String::from(&ident.text()[1..]);

                result.push(CompletionItem {
                    label,
                    label_details: Some(CompletionItemLabelDetails {
                        description: Some("Pattern".to_string()),
                        ..Default::default()
                    }),
                    kind: Some(CompletionItemKind::VARIABLE),
                    ..Default::default()
                });
            }
        }
        _ => {
            CONDITION_SUGGESTIONS.iter().for_each(|(kw, insert)| {
                result.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    insert_text_format: insert
                        .map(|_| InsertTextFormat::SNIPPET),
                    insert_text: insert
                        .map(|insert_text| insert_text.to_string()),
                    ..Default::default()
                });
            });
        }
    }

    Some(result)
}

/// Collects completion suggestions outside any block
fn source_file_suggestions() -> Vec<CompletionItem> {
    // Propose import or rule definition with snippet
    SRC_SUGGESTIONS
        .map(|(label, insert_text)| CompletionItem {
            label: label.to_string(),
            kind: if insert_text.is_none() {
                Some(CompletionItemKind::KEYWORD)
            } else {
                Some(CompletionItemKind::METHOD)
            },
            insert_text_mode: insert_text
                .map(|_| InsertTextMode::ADJUST_INDENTATION),
            insert_text_format: insert_text.map(|_| InsertTextFormat::SNIPPET),
            insert_text: insert_text
                .map(|insert_text| insert_text.to_string()),
            ..Default::default()
        })
        .into_iter()
        .collect()
}

fn pattern_modifier_suggestions(node: Node<Immutable>) -> Vec<CompletionItem> {
    for (kind, valid_modifiers) in PATTERN_MODS {
        if node.children_with_tokens().any(|child| child.kind() == *kind) {
            return valid_modifiers
                .iter()
                .map(|modifier| CompletionItem {
                    label: modifier.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    ..Default::default()
                })
                .collect();
        }
    }
    vec![]
}

/// Collects completion suggestion for different blocks of the rule
fn rule_suggestions() -> Vec<CompletionItem> {
    RULE_KW_BLKS
        .iter()
        .map(|kw| CompletionItem {
            label: kw.to_string(),
            label_details: Some(CompletionItemLabelDetails {
                description: Some(format!("Block of {kw}")),
                ..Default::default()
            }),
            kind: Some(CompletionItemKind::KEYWORD),
            insert_text_mode: Some(InsertTextMode::ADJUST_INDENTATION),
            insert_text: Some(format!("{kw}:\n\t")),
            ..Default::default()
        })
        .collect()
}
