use std::collections::HashMap;
use std::sync::Arc;

use async_lsp::lsp_types::{Position, TextEdit, Url};
use yara_x_parser::cst::SyntaxKind;

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::{
    find_declaration, ident_at_position, occurrences_in_with_for,
    pattern_from_ident, pattern_usages, rule_containing_token,
};
use crate::utils::position::token_to_range;

/// Renames all occurrences of a symbol at the given position in the text.
pub fn rename(
    documents: Arc<DocumentStorage>,
    uri: Url,
    new_name: String,
    pos: Position,
) -> Option<HashMap<Url, Vec<TextEdit>>> {
    let document = documents.get(&uri)?;
    let cst = &document.cst;
    let ident = ident_at_position(cst, pos)?;
    let mut result: HashMap<Url, Vec<TextEdit>> = HashMap::new();

    match ident.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_containing_token(&ident)?;
            let mut text_edits = vec![];

            // If user entered `$`, `!`, `#` or `@`, then ignore it because
            // only text after these characters will change
            let new_text = if new_name.starts_with(['$', '!', '#', '@']) {
                String::from(&new_name[1..])
            } else {
                new_name
            };

            if let Some(definition) = pattern_from_ident(&rule, &ident) {
                if let Some(first_token) = definition.first_token() {
                    // Don't change first character (`$`, `!`, `#` or `@`)
                    let mut range = token_to_range(&first_token)?;
                    range.start.character += 1;

                    text_edits
                        .push(TextEdit { range, new_text: new_text.clone() });
                }
            }

            if let Some(occurrences) = pattern_usages(&rule, &ident) {
                for occurrence in occurrences {
                    // Don't change first character (`$`, `!`, `#` or `@`)
                    let mut range = token_to_range(&occurrence)?;
                    range.start.character += 1;

                    text_edits
                        .push(TextEdit { range, new_text: new_text.clone() });
                }
            }

            result.insert(uri, text_edits);
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            if let Some((t, n)) = find_declaration(&ident) {
                let mut text_edits = vec![];
                text_edits.push(TextEdit {
                    range: token_to_range(&t).unwrap(),
                    new_text: new_name.clone(),
                });

                if let Some(occurrences) = occurrences_in_with_for(&n, &ident)
                {
                    for occurrence in occurrences {
                        text_edits.push(TextEdit {
                            range: token_to_range(&occurrence).unwrap(),
                            new_text: new_name.clone(),
                        });
                    }
                }

                return Some(HashMap::from([(uri.clone(), text_edits)]));
            }

            let occurrences = documents.find_rule_occurrences(&uri, &ident)?;

            for (k, v) in occurrences.usages {
                result.insert(
                    k,
                    v.iter()
                        .map(|occurrence| TextEdit {
                            new_text: new_name.clone(),
                            range: token_to_range(occurrence).unwrap(),
                        })
                        .collect(),
                );
            }

            let definition_token = occurrences
                .definition
                .1
                .children_with_tokens()
                .find(|node_or_token| {
                    node_or_token.kind() == SyntaxKind::IDENT
                })
                .and_then(|node_or_token| node_or_token.into_token())?;

            result.entry(occurrences.definition.0).or_default().push(
                TextEdit {
                    new_text: new_name.clone(),
                    range: token_to_range(&definition_token).unwrap(),
                },
            );
        }
        _ => {}
    }

    Some(result)
}
