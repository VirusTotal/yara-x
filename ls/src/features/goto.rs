use std::path::PathBuf;
use std::sync::Arc;

use async_lsp::lsp_types::{Location, Position, Url};
use yara_x_parser::cst::SyntaxKind;

use crate::document::Document;
use crate::utils::cst_traversal::{
    ident_at_position, pattern_from_ident, rule_containing_token,
    rule_from_ident,
};
use crate::utils::position::node_to_range;

/// Given a position that points some identifier, returns the range
/// of source code that contains the definition of that identifier.
pub fn go_to_definition(
    document: Arc<Document>,
    pos: Position,
) -> Option<Location> {
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
        SyntaxKind::IDENT => go_to_rule_definition(document, token.text()),
        _ => None,
    }
}

fn go_to_rule_definition(
    document: Arc<Document>,
    ident: &str,
) -> Option<Location> {
    // Check if the rule is defined in the current document
    if let Some(rule) = rule_from_ident(&document.cst, ident) {
        return Some(Location {
            uri: document.uri.clone(),
            range: node_to_range(&rule)?,
        });
    }

    // If the rule is not declared in the current document, we need to look
    // into any included document.
    let included_paths = document
        .cst
        .root()
        .children()
        .filter(|node| node.kind() == SyntaxKind::INCLUDE_STMT)
        .filter_map(|include_stmt| {
            include_stmt
                .children_with_tokens()
                .find(|t| t.kind() == SyntaxKind::STRING_LIT)
                .and_then(|n| n.into_token())
        });

    let document_path = document.uri.to_file_path().unwrap();
    let document_dir = document_path.parent().unwrap();

    for included_path in included_paths {
        let included_path = included_path.text();

        // Remove the quotes surrounding the included path.
        let included_path =
            PathBuf::from(&included_path[1..included_path.len() - 1]);

        // If the included path is already absolute, use it as is,
        // join it to the current document directory if otherwise.
        let abs_included_path = if included_path.is_absolute() {
            included_path
        } else {
            document_dir.join(included_path)
        };

        let uri = Url::from_file_path(abs_included_path).ok()?;
        let document = Arc::new(Document::read(uri).ok()?);

        if let Some(location) = go_to_rule_definition(document, ident) {
            return Some(location);
        }
    }

    None
}
