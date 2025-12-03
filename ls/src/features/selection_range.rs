use async_lsp::lsp_types::{Position, SelectionRange};
use yara_x_parser::cst::{Immutable, Node, CST};

use crate::utils::position::{to_abs, to_range};

/// Provides selection ranges from the given positions in the text
/// based on the given CST of this document.
pub fn selection_range(
    cst: CST,
    positions: Vec<Position>,
    text: &str,
) -> Option<Vec<SelectionRange>> {
    let root = cst.root();

    let mut result: Vec<SelectionRange> = Vec::new();

    for position in positions {
        let pos_span = to_abs(position, text);

        let nth_position_token = root.token_at_offset(pos_span as usize)?;

        let parent = nth_position_token.parent();

        let base = if let Some(parent) = parent {
            if parent.span() == nth_position_token.span() {
                *get_parent_selection_range(parent, text)
            } else {
                SelectionRange {
                    range: to_range(nth_position_token.span(), text),
                    parent: Some(get_parent_selection_range(parent, text)),
                }
            }
        } else {
            SelectionRange {
                range: to_range(nth_position_token.span(), text),
                parent: None,
            }
        };

        result.push(base);
    }

    Some(result)
}

/// Recursively gets parent [`yara_x_parser::cst::Node`] spans to construct
/// selection ranges.
fn get_parent_selection_range(
    parent: Node<Immutable>,
    text: &str,
) -> Box<SelectionRange> {
    match parent.parent() {
        Some(next_parent) => {
            // Ignore parents with the same span to avoid
            // duplicate selection ranges
            if parent.span() == next_parent.span() {
                get_parent_selection_range(next_parent, text)
            } else {
                Box::new(SelectionRange {
                    range: to_range(parent.span(), text),
                    parent: Some(get_parent_selection_range(
                        next_parent,
                        text,
                    )),
                })
            }
        }
        None => Box::new(SelectionRange {
            range: to_range(parent.span(), text),
            parent: None,
        }),
    }
}
