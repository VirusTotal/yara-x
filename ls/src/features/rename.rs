use async_lsp::lsp_types::{Position, TextEdit};
use yara_x_parser::cst::{NodeOrToken, SyntaxKind, CST};

use crate::utils::{
    cst_traversal::{
        pattern_from_condition, pattern_from_strings, rule_from_condition,
        rule_from_ident, rule_from_pos,
    },
    position::{to_abs, to_range},
};

/// Renames all occurrences of a symbol at the given position in the text.
pub fn rename(
    cst: CST,
    text: &str,
    new_name: String,
    pos: Position,
) -> Option<Vec<TextEdit>> {
    let mut result: Vec<TextEdit> = Vec::new();

    let pos_span = to_abs(pos, text);

    let rename_click = cst.root().token_at_offset(pos_span as usize)?;

    match rename_click.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_from_pos(&cst, &pos_span)?;

            //If user entered `$`, `!`, `#` or `@`, then ignore it
            //Because only text after these characters will change
            let new_text = if new_name.starts_with(['$', '!', '#', '@']) {
                String::from(&new_name[1..])
            } else {
                new_name
            };

            let definition = pattern_from_strings(&rule, rename_click.text());

            if let Some(definition) = definition {
                if let Some(first_token) = definition.first_token() {
                    //Don't change first character (`$`, `!`, `#` or `@`)
                    let mut range = to_range(first_token.span(), text);
                    range.start.character += 1;

                    result
                        .push(TextEdit { range, new_text: new_text.clone() });
                }
            }

            let occurrences =
                pattern_from_condition(&rule, rename_click.text());

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    //Don't change first character (`$`, `!`, `#` or `@`)
                    let mut range = to_range(occurrence.span(), text);
                    range.start.character += 1;

                    result
                        .push(TextEdit { range, new_text: new_text.clone() });
                }
            }
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let rule = rule_from_ident(&cst, rename_click.text());

            if let Some(rule) = rule {
                if let Some(NodeOrToken::Token(ident)) =
                    rule.children_with_tokens().find(|node_or_token| {
                        node_or_token.kind() == SyntaxKind::IDENT
                    })
                {
                    let range = to_range(ident.span(), text);
                    result
                        .push(TextEdit { range, new_text: new_name.clone() });
                }
            }

            let occurrences = rule_from_condition(&cst, rename_click.text());

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    let range = to_range(occurrence.span(), text);
                    result
                        .push(TextEdit { range, new_text: new_name.clone() });
                }
            }
        }
        _ => {}
    }

    Some(result)
}
