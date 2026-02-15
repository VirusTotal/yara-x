use std::sync::Arc;

use async_lsp::lsp_types::{
    DocumentHighlight, DocumentHighlightKind, Position, Url,
};

use yara_x_parser::cst::SyntaxKind;

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::rule_containing_token;
use crate::utils::cst_traversal::{
    ident_at_position, pattern_from_ident, pattern_usages, rule_from_ident,
    rule_usages,
};
use crate::utils::position::{node_to_range, token_to_range};

/// The document highlight request is sent from the client to the server to
/// resolve document highlights for a given text document position. When the
/// specified position is contained in a symbol, the response contains the
/// ranges of all occurrences of that symbol in the source code.
pub fn document_highlight(
    documents: Arc<DocumentStorage>,
    uri: Url,
    pos: Position,
) -> Option<Vec<DocumentHighlight>> {
    let cst = &documents.get(&uri)?.cst;
    let token = ident_at_position(cst, pos)?;

    match token.kind() {
        //Find highlight of pattern within the same rule
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let mut result: Vec<DocumentHighlight> = Vec::new();
            let rule = rule_containing_token(&token)?;

            if let Some(range) = pattern_from_ident(&rule, token.text())
                .as_ref()
                .and_then(node_to_range)
            {
                result.push(DocumentHighlight {
                    range,
                    kind: Some(DocumentHighlightKind::WRITE),
                });
            }

            if let Some(usages) = pattern_usages(&rule, token.text()) {
                for range in usages.iter().filter_map(token_to_range) {
                    result.push(DocumentHighlight {
                        range,
                        kind: Some(DocumentHighlightKind::READ),
                    });
                }
            }

            Some(result)
        }
        // Find rule declaration and its occurrences in other condition blocks
        SyntaxKind::IDENT => {
            let mut result: Vec<DocumentHighlight> = Vec::new();

            if let Some(range) = rule_from_ident(&cst.root(), token.text())
                .as_ref()
                .and_then(node_to_range)
            {
                result.push(DocumentHighlight {
                    range,
                    kind: Some(DocumentHighlightKind::WRITE),
                });
            }

            if let Some(usages) = rule_usages(cst, token.text()) {
                for range in usages.iter().filter_map(token_to_range) {
                    result.push(DocumentHighlight {
                        range,
                        kind: Some(DocumentHighlightKind::READ),
                    });
                }
            }

            Some(result)
        }
        _ => None,
    }
}
