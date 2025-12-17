use async_lsp::lsp_types::{Position, Range};
use yara_x_parser::cst::{SyntaxKind, Utf16, CST};

use crate::utils::cst_traversal::{
    pattern_from_strings, rule_containing_token, rule_from_ident,
};
use crate::utils::position::node_to_range;

/// Return the range of the definition of a symbol at the specified
/// position in the text if exists.
pub fn go_to_definition(cst: &CST, pos: Position) -> Option<Range> {
    let goto_cursor = cst.root().token_at_position::<Utf16, _>((
        pos.line as usize,
        pos.character as usize,
    ))?;

    #[allow(irrefutable_let_patterns)]
    match goto_cursor.kind() {
        //Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_containing_token(&goto_cursor)?;
            let pattern = pattern_from_strings(&rule, goto_cursor.text())?;

            node_to_range(&pattern)
        }
        //Rule identifiers
        SyntaxKind::IDENT => {
            let rule = rule_from_ident(cst, goto_cursor.text())?;
            node_to_range(&rule)
        }
        _ => None,
    }
}
