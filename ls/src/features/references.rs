use std::sync::Arc;

use async_lsp::lsp_types::{Location, Position, Url};

use yara_x_parser::cst::SyntaxKind;

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::{
    find_declaration, ident_at_position, occurrences_in_with_for,
    pattern_from_ident, pattern_usages, rule_containing_token,
};
use crate::utils::position::{node_to_range, token_to_range};

/// Finds all references of a symbol at the given position in the text.
pub fn find_references(
    documents: Arc<DocumentStorage>,
    uri: Url,
    pos: Position,
) -> Option<Vec<Location>> {
    let document = documents.get(&uri)?;
    let cst = &document.cst;
    let ident = ident_at_position(cst, pos)?;

    match ident.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let mut result = Vec::new();
            let rule = rule_containing_token(&ident)?;

            if let Some(range) = pattern_from_ident(&rule, &ident)
                .as_ref()
                .and_then(node_to_range)
            {
                result.push(Location { uri: uri.clone(), range });
            }

            if let Some(references) = pattern_usages(&rule, &ident) {
                result.extend(references.iter().map(|t| Location {
                    uri: uri.clone(),
                    range: token_to_range(t).unwrap(),
                }));
            }

            Some(result)
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let mut result = Vec::new();

            if let Some((t, n)) = find_declaration(&ident) {
                result.push(Location {
                    uri: uri.clone(),
                    range: token_to_range(&t).unwrap(),
                });

                if let Some(occurrences) = occurrences_in_with_for(&n, &ident)
                {
                    for occurrence in occurrences {
                        result.push(Location {
                            uri: uri.clone(),
                            range: token_to_range(&occurrence).unwrap(),
                        });
                    }
                }

                return Some(result);
            }

            let occurrences = documents.find_rule_occurrences(&uri, &ident)?;

            result.push(Location {
                uri: occurrences.definition.0,
                range: node_to_range(&occurrences.definition.1).unwrap(),
            });

            for (k, v) in occurrences.usages {
                result.extend(v.iter().map(|occurrence| Location {
                    uri: k.clone(),
                    range: token_to_range(occurrence).unwrap(),
                }));
            }

            Some(result)
        }
        _ => None,
    }
}
