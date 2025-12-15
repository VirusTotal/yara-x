use async_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails,
    CompletionResponse, InsertTextFormat, InsertTextMode, Position,
};
use yara_x_parser::cst::{
    Immutable, NodeOrToken, SyntaxKind, Token, Utf16, CST,
};

use crate::features::completion_const::{
    CONDITION_SUGGESTIONS, PATTERN_MOD, RULE_KW_BLKS, SRC_SUGGESTIONS,
};

use crate::utils::cst_traversal::rule_from_span;

/// Provides completion suggestions based on the cursor position and the
/// block it is in.
pub fn completion(cst: CST, pos: Position) -> Option<CompletionResponse> {
    let completion_cursor = cst.root().token_at_position::<Utf16, _>((
        pos.line as usize,
        pos.character as usize,
    ));
    let completion_token: Token<Immutable>;

    // Extract token before cursor
    // There might be no token at cursor, when the cursor is at of the file
    // In this case, take the last token of the file
    if let Some(token) = completion_cursor {
        completion_token = token.prev_token()?;
    } else {
        completion_token = cst.root().last_token()?;
    }

    let mut nearets_section_kind: SyntaxKind = SyntaxKind::ERROR;

    // Try to find node in siblings, from which we can decide what should be suggested
    if let Some(mut nearest_sibling) = completion_token.prev_sibling_or_token()
    {
        loop {
            if !matches!(
                nearest_sibling.kind(),
                SyntaxKind::COMMENT
                    | SyntaxKind::NEWLINE
                    | SyntaxKind::WHITESPACE
                    | SyntaxKind::ERROR
            ) {
                nearets_section_kind = nearest_sibling.kind();
                break;
            }
            if let Some(prev) = nearest_sibling.prev_sibling_or_token() {
                nearest_sibling = prev;
            } else {
                break;
            }
        }
    }

    // If failed, try the same in the ancestors
    if !matches!(
        nearets_section_kind,
        SyntaxKind::PATTERN_DEF
            | SyntaxKind::CONDITION_BLK
            | SyntaxKind::BOOLEAN_EXPR
    ) {
        nearets_section_kind = completion_token
            .ancestors()
            .find(|node| {
                matches!(
                    node.kind(),
                    SyntaxKind::CONDITION_BLK
                        | SyntaxKind::RULE_DECL
                        | SyntaxKind::SOURCE_FILE
                        | SyntaxKind::BOOLEAN_EXPR
                )
            })?
            .kind();
    }

    let completion_vec = match nearets_section_kind {
        SyntaxKind::SOURCE_FILE => Some(source_file_suggestions()),
        SyntaxKind::CONDITION_BLK | SyntaxKind::BOOLEAN_EXPR => {
            condition_suggestions(cst, completion_token)
        }
        SyntaxKind::PATTERN_DEF => pattern_suggestions(completion_token),
        SyntaxKind::RULE_DECL => Some(rule_suggestions()),
        _ => None,
    }?;

    Some(CompletionResponse::Array(completion_vec))
}

/// Collects completion suggestions for condition block
fn condition_suggestions(
    cst: CST,
    completion_prev_token: Token<Immutable>,
) -> Option<Vec<CompletionItem>> {
    let mut completion_vec: Vec<CompletionItem> = Vec::new();

    match completion_prev_token.kind() {
        //Suggest completion of
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

                completion_vec.push(CompletionItem {
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
                completion_vec.push(CompletionItem {
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
            let rule = rule_from_span(&cst, &completion_prev_token.span())?;

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

                completion_vec.push(CompletionItem {
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
                completion_vec.push(CompletionItem {
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

    Some(completion_vec)
}

/// Collects completion suggestions outside any block
fn source_file_suggestions() -> Vec<CompletionItem> {
    //Propose import or rule definition with snippet
    let completion_vec: Vec<CompletionItem> = SRC_SUGGESTIONS
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
        .collect();

    completion_vec
}

/// Collects completion suggestions for strings block
#[allow(irrefutable_let_patterns)]
fn pattern_suggestions(
    completion_prev_token: Token<Immutable>,
) -> Option<Vec<CompletionItem>> {
    let mut nearest_sibling = completion_prev_token.prev_sibling_or_token()?;

    while let prev = nearest_sibling.prev_sibling_or_token() {
        if !matches!(
            nearest_sibling.kind(),
            SyntaxKind::COMMENT | SyntaxKind::NEWLINE | SyntaxKind::WHITESPACE
        ) {
            break;
        }
        nearest_sibling = prev?;
    }

    if matches!(
        nearest_sibling.kind(),
        SyntaxKind::PATTERN_MODS
            | SyntaxKind::STRING_LIT
            | SyntaxKind::REGEXP
            | SyntaxKind::HEX_PATTERN
            | SyntaxKind::PATTERN_DEF
    ) {
        Some(
            PATTERN_MOD
                .iter()
                .map(|kw| CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    ..Default::default()
                })
                .collect(),
        )
    } else {
        None
    }
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
