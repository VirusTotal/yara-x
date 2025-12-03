use crate::utils::cst_traversal::{
    pattern_from_strings, rule_from_ident, rule_from_pos,
};
use crate::utils::position::{to_abs, to_range};
use async_lsp::lsp_types::{Position, Range};
use yara_x_parser::cst::{SyntaxKind, CST};

/// Return the range of the definition of a symbol at the specified
/// position in the text if exists.
pub fn go_to_definition(cst: CST, text: &str, pos: Position) -> Option<Range> {
    let pos_span = to_abs(pos, text);

    let goto_cursor = cst.root().token_at_offset(pos_span as usize)?;

    #[allow(irrefutable_let_patterns)]
    match goto_cursor.kind() {
        //Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_from_pos(&cst, &pos_span)?;

            let pattern = pattern_from_strings(&rule, goto_cursor.text())?;

            Some(to_range(pattern.span(), text))
        }
        //Rule identifiers
        SyntaxKind::IDENT => {
            let rule = rule_from_ident(&cst, goto_cursor.text())?;
            Some(to_range(rule.span(), text))
        }
        _ => None,
    }
}
