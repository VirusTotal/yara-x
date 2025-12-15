use async_lsp::lsp_types::{
    DocumentHighlight, DocumentHighlightKind, Position,
};
use yara_x_parser::cst::{SyntaxKind, CST};

use crate::utils::{
    cst_traversal::{
        pattern_from_condition, pattern_from_strings, rule_from_condition,
        rule_from_ident, rule_from_span,
    },
    position::{node_to_range, token_to_range},
};

// The document highlight request is sent from the client to the server to
// resolve document highlights for a given text document position. When the
// specified position is contained in a symbol, the response contains the
// ranges of all occurrences of that symbol in the source code.
pub fn document_highlight(
    cst: CST,
    pos: Position,
) -> Option<Vec<DocumentHighlight>> {
    let highlight_cursor = cst
        .root()
        .token_at_position((pos.line as usize, pos.character as usize))?;

    match highlight_cursor.kind() {
        //Find highlight of pattern within the same rule
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let mut highlight_vec: Vec<DocumentHighlight> = Vec::new();

            let rule = rule_from_span(&cst, &highlight_cursor.span())?;

            let declaration =
                pattern_from_strings(&rule, highlight_cursor.text());

            let occurrences =
                pattern_from_condition(&rule, highlight_cursor.text());

            if let Some(declaration) = declaration {
                if let Some(range) = node_to_range(&declaration) {
                    highlight_vec.push(DocumentHighlight {
                        range,
                        kind: Some(DocumentHighlightKind::WRITE),
                    });
                }
            }

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    if let Some(range) = token_to_range(&occurrence) {
                        highlight_vec.push(DocumentHighlight {
                            range,
                            kind: Some(DocumentHighlightKind::READ),
                        });
                    }
                }
            }

            Some(highlight_vec)
        }
        //Find rule declaration and its occurrences in other condition blocks
        SyntaxKind::IDENT => {
            let mut highlight_vec: Vec<DocumentHighlight> = Vec::new();

            let rule = rule_from_ident(&cst, highlight_cursor.text());

            if let Some(rule) = rule {
                if let Some(range) = node_to_range(&rule) {
                    highlight_vec.push(DocumentHighlight {
                        range,
                        kind: Some(DocumentHighlightKind::WRITE),
                    });
                }
            }

            let occurrences =
                rule_from_condition(&cst, highlight_cursor.text());

            if let Some(occurrences) = occurrences {
                for occurrence in occurrences {
                    if let Some(range) = token_to_range(&occurrence) {
                        highlight_vec.push(DocumentHighlight {
                            range,
                            kind: Some(DocumentHighlightKind::READ),
                        });
                    }
                }
            }

            Some(highlight_vec)
        }
        _ => None,
    }
}
