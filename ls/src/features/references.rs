use async_lsp::lsp_types::{Location, Position, Url};
use yara_x_parser::cst::{SyntaxKind, Utf16, CST};

use crate::utils::{
    cst_traversal::{
        pattern_from_condition, pattern_from_strings, rule_from_condition,
        rule_from_ident, rule_from_span,
    },
    position::{node_to_range, token_to_range},
};

/// Finds all references of a symbol at the given position in the text.
pub fn find_references(
    cst: &CST,
    pos: Position,
    uri: Url,
) -> Option<Vec<Location>> {
    let references_click = cst.root().token_at_position::<Utf16, _>((
        pos.line as usize,
        pos.character as usize,
    ))?;

    match references_click.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let mut location_vec: Vec<Location> = Vec::new();

            let rule = rule_from_span(cst, &references_click.span())?;

            let references =
                pattern_from_condition(&rule, references_click.text());

            if let Some(references) = references {
                for reference in references {
                    if let Some(range) = token_to_range(&reference) {
                        location_vec
                            .push(Location { uri: uri.clone(), range });
                    }
                }
            }

            let definition =
                pattern_from_strings(&rule, references_click.text());

            if let Some(definition) = definition {
                if let Some(range) = node_to_range(&definition) {
                    location_vec.push(Location { uri: uri.clone(), range });
                }
            }

            return Some(location_vec);
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let mut location_vec: Vec<Location> = Vec::new();

            let rule = rule_from_ident(cst, references_click.text());

            if let Some(rule) = rule {
                if let Some(range) = node_to_range(&rule) {
                    location_vec.push(Location { uri: uri.clone(), range });
                }
            }

            let references =
                rule_from_condition(cst, references_click.text());

            if let Some(references) = references {
                for reference in references {
                    if let Some(range) = token_to_range(&reference) {
                        location_vec
                            .push(Location { uri: uri.clone(), range });
                    }
                }
            }

            return Some(location_vec);
        }
        _ => {}
    }

    None
}
