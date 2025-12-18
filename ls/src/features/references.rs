use async_lsp::lsp_types::{Position, Range};
use yara_x_parser::cst::{SyntaxKind, Utf16, CST};

use crate::utils::cst_traversal::{
    pattern_from_ident, pattern_usages, rule_from_ident,
};
use crate::utils::cst_traversal::{rule_containing_token, rule_usages};
use crate::utils::position::{node_to_range, token_to_range};

/// Finds all references of a symbol at the given position in the text.
pub fn find_references(cst: &CST, pos: Position) -> Option<Vec<Range>> {
    let token = cst.root().token_at_position::<Utf16, _>((
        pos.line as usize,
        pos.character as usize,
    ))?;

    match token.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let mut result = Vec::new();
            let rule = rule_containing_token(&token)?;

            if let Some(range) = pattern_from_ident(&rule, token.text())
                .as_ref()
                .and_then(node_to_range)
            {
                result.push(range);
            }

            if let Some(references) = pattern_usages(&rule, token.text()) {
                for reference in references {
                    if let Some(range) = token_to_range(&reference) {
                        result.push(range);
                    }
                }
            }

            Some(result)
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let mut result = Vec::new();

            if let Some(range) = rule_from_ident(cst, token.text())
                .as_ref()
                .and_then(node_to_range)
            {
                result.push(range);
            }

            if let Some(references) = rule_usages(cst, token.text()) {
                for reference in references {
                    if let Some(range) = token_to_range(&reference) {
                        result.push(range);
                    }
                }
            }

            Some(result)
        }
        _ => None,
    }
}
