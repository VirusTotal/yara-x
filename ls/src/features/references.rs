use async_lsp::lsp_types::{Location, Position, Url};
use yara_x_parser::cst::{SyntaxKind, CST};

use crate::utils::{
    cst_traversal::{
        pattern_from_condition, pattern_from_strings, rule_from_condition,
        rule_from_ident, rule_from_pos,
    },
    position::{to_abs, to_range},
};

/// Finds all references of a symbol at the given position in the text.
pub fn find_references(
    cst: CST,
    text: &str,
    pos: Position,
    uri: Url,
) -> Option<Vec<Location>> {
    let pos_span = to_abs(pos, text);

    let references_click = cst.root().token_at_offset(pos_span as usize)?;

    match references_click.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let mut location_vec: Vec<Location> = Vec::new();

            let rule = rule_from_pos(&cst, &pos_span)?;

            let references =
                pattern_from_condition(&rule, references_click.text());

            if let Some(unwrapped_references) = references {
                for reference in unwrapped_references {
                    location_vec.push(Location {
                        uri: uri.clone(),
                        range: to_range(reference.span(), text),
                    });
                }
            }

            let definition =
                pattern_from_strings(&rule, references_click.text());

            if let Some(unwrapped_definition) = definition {
                location_vec.push(Location {
                    uri: uri.clone(),
                    range: to_range(unwrapped_definition.span(), text),
                });
            }

            return Some(location_vec);
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let mut location_vec: Vec<Location> = Vec::new();

            let rule = rule_from_ident(&cst, references_click.text());

            if let Some(unwrapped_rule) = rule {
                location_vec.push(Location {
                    uri: uri.clone(),
                    range: to_range(unwrapped_rule.span(), text),
                });
            }

            let references =
                rule_from_condition(&cst, references_click.text());

            if let Some(unwrapped_references) = references {
                for reference in unwrapped_references {
                    location_vec.push(Location {
                        uri: uri.clone(),
                        range: to_range(reference.span(), text),
                    });
                }
            }

            return Some(location_vec);
        }
        _ => {}
    }

    None
}
