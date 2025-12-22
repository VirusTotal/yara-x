use async_lsp::lsp_types::{Position, Range};
use yara_x_parser::cst::{SyntaxKind, CST};

use crate::utils::cst_traversal::{
    ident_at_position, pattern_from_ident, rule_containing_token,
    rule_from_ident,
};
use crate::utils::position::node_to_range;

/// Given a position that points some identifier, returns the range
/// of source code that contains the definition of that identifier.
pub fn go_to_definition(cst: &CST, pos: Position) -> Option<Range> {
    let token = ident_at_position(cst, pos)?;

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
            node_to_range(&pattern)
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let rule = rule_from_ident(cst, token.text())?;
            node_to_range(&rule)
        }
        _ => None,
    }
}
