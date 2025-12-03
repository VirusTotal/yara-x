use async_lsp::lsp_types::{
    DocumentHighlight, DocumentHighlightKind, Position,
};
use yara_x_parser::cst::{SyntaxKind, CST};

use crate::utils::{
    cst_traversal::{
        pattern_from_condition, pattern_from_strings, rule_from_condition,
        rule_from_ident, rule_from_pos,
    },
    position::{to_abs, to_range},
};

/// Returns document highlight vector of a symbol at the specified
/// position in the text.
pub fn document_highlight(
    cst: CST,
    text: &str,
    pos: Position,
) -> Option<Vec<DocumentHighlight>> {
    let pos_span = to_abs(pos, text);

    let highlight_cursor = cst.root().token_at_offset(pos_span as usize)?;

    match highlight_cursor.kind() {
        //Find highlight of pattern within the same rule
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let mut highlight_vec: Vec<DocumentHighlight> = Vec::new();

            let rule = rule_from_pos(&cst, &pos_span)?;

            let declaration =
                pattern_from_strings(&rule, highlight_cursor.text());

            let occurrences =
                pattern_from_condition(&rule, highlight_cursor.text());

            if let Some(declaration) = declaration {
                highlight_vec.push(DocumentHighlight {
                    range: to_range(declaration.span(), text),
                    kind: Some(DocumentHighlightKind::WRITE),
                });
            }

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    highlight_vec.push(DocumentHighlight {
                        range: to_range(occurrence.span(), text),
                        kind: Some(DocumentHighlightKind::READ),
                    });
                }
            }

            Some(highlight_vec)
        }
        //Find rule declaration and its occurrences in other condition blocks
        SyntaxKind::IDENT => {
            let mut highlight_vec: Vec<DocumentHighlight> = Vec::new();

            let rule = rule_from_ident(&cst, highlight_cursor.text());

            if let Some(rule) = rule {
                highlight_vec.push(DocumentHighlight {
                    range: to_range(rule.span(), text),
                    kind: Some(DocumentHighlightKind::WRITE),
                });
            }

            let occurrences =
                rule_from_condition(&cst, highlight_cursor.text());

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    highlight_vec.push(DocumentHighlight {
                        range: to_range(occurrence.span(), text),
                        kind: Some(DocumentHighlightKind::READ),
                    });
                }
            }

            Some(highlight_vec)
        }
        _ => None,
    }
}
