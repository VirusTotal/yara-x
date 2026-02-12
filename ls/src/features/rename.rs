use async_lsp::lsp_types::{Position, TextEdit};
use yara_x_parser::cst::{NodeOrToken, SyntaxKind, CST};

use crate::utils::cst_traversal::{
    ident_at_position, occurrences_in_with_for, pattern_from_ident,
    pattern_usages, rule_from_ident, rule_usages,
};
use crate::utils::cst_traversal::{
    rule_containing_token, with_for_from_ident,
};
use crate::utils::position::token_to_range;

/// Renames all occurrences of a symbol at the given position in the text.
pub fn rename(
    cst: &CST,
    new_name: String,
    pos: Position,
) -> Option<Vec<TextEdit>> {
    let mut result: Vec<TextEdit> = Vec::new();
    let token = ident_at_position(cst, pos)?;

    match token.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_containing_token(&token)?;

            // If user entered `$`, `!`, `#` or `@`, then ignore it because
            // only text after these characters will change
            let new_text = if new_name.starts_with(['$', '!', '#', '@']) {
                String::from(&new_name[1..])
            } else {
                new_name
            };

            let definition = pattern_from_ident(&rule, token.text());

            if let Some(definition) = definition {
                if let Some(first_token) = definition.first_token() {
                    // Don't change first character (`$`, `!`, `#` or `@`)
                    let mut range = token_to_range(&first_token)?;
                    range.start.character += 1;

                    result
                        .push(TextEdit { range, new_text: new_text.clone() });
                }
            }

            let occurrences = pattern_usages(&rule, token.text());

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    // Don't change first character (`$`, `!`, `#` or `@`)
                    let mut range = token_to_range(&occurrence)?;
                    range.start.character += 1;

                    result
                        .push(TextEdit { range, new_text: new_text.clone() });
                }
            }
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let rule = rule_from_ident(cst, token.text());

            if let Some((t, n)) = with_for_from_ident(&token) {
                result.push(TextEdit {
                    range: token_to_range(&t).unwrap(),
                    new_text: new_name.clone(),
                });

                for occurrence in occurrences_in_with_for(n, token.text()) {
                    result.push(TextEdit {
                        range: token_to_range(&occurrence).unwrap(),
                        new_text: new_name.clone(),
                    });
                }

                return Some(result);
            }

            if let Some(rule) = rule {
                if let Some(NodeOrToken::Token(ident)) =
                    rule.children_with_tokens().find(|node_or_token| {
                        node_or_token.kind() == SyntaxKind::IDENT
                    })
                {
                    let range = token_to_range(&ident)?;
                    result
                        .push(TextEdit { range, new_text: new_name.clone() });
                }
            }

            let occurrences = rule_usages(cst, token.text());

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    let range = token_to_range(&occurrence)?;
                    result
                        .push(TextEdit { range, new_text: new_name.clone() });
                }
            }
        }
        _ => {}
    }

    Some(result)
}
