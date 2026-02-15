use std::sync::Arc;

use async_lsp::lsp_types::{Location, Position, Url};
use yara_x_parser::cst::SyntaxKind;

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::{
    ident_at_position, pattern_from_ident, rule_containing_token,
};
use crate::utils::position::node_to_range;

/// Given a position that points some identifier, returns the range
/// of source code that contains the definition of that identifier.
pub fn go_to_definition(
    documents: Arc<DocumentStorage>,
    uri: Url,
    pos: Position,
) -> Option<Location> {
    let document = documents.get(&uri)?;
    let token = ident_at_position(&document.cst, pos)?;

    #[allow(irrefutable_let_patterns)]
    match token.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_containing_token(&token)?;
            let pattern = pattern_from_ident(&rule, token.text())?;
            let range = node_to_range(&pattern)?;
            Some(Location { uri: document.uri.clone(), range })
        }
        // Rule identifiers
        SyntaxKind::IDENT => documents
            .find_rule_definition(&uri, token.text())
            .map(|(rule, uri)| {
                let range = node_to_range(&rule).unwrap();
                Location { uri, range }
            }),
        _ => None,
    }
}
