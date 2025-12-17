use async_lsp::lsp_types::{Position, SelectionRange};

use yara_x_parser::cst::{Immutable, Node, Utf16, CST};

use crate::utils::position::{node_to_range, token_to_range};

/// Provides selection ranges from the given positions in the text
/// based on the given CST of this document.
pub fn selection_range(
    cst: &CST,
    positions: Vec<Position>,
) -> Option<Vec<SelectionRange>> {
    let root = cst.root();

    let mut result: Vec<SelectionRange> = Vec::new();

    for position in positions {
        let nth_position_token = root.token_at_position::<Utf16, _>((
            position.line as usize,
            position.character as usize,
        ))?;

        let parent = nth_position_token.parent();

        let base = if let Some(parent) = parent {
            if parent.span() == nth_position_token.span() {
                *(get_parent_selection_range(parent)?)
            } else {
                SelectionRange {
                    range: token_to_range(&nth_position_token)?,
                    parent: get_parent_selection_range(parent),
                }
            }
        } else {
            SelectionRange {
                range: token_to_range(&nth_position_token)?,
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
) -> Option<Box<SelectionRange>> {
    match parent.parent() {
        Some(next_parent) => {
            // Ignore parents with the same span to avoid
            // duplicate selection ranges
            if parent.span() == next_parent.span() {
                get_parent_selection_range(next_parent)
            } else {
                Some(Box::new(SelectionRange {
                    range: node_to_range(&parent)?,
                    parent: get_parent_selection_range(next_parent),
                }))
            }
        }
        None => Some(Box::new(SelectionRange {
            range: node_to_range(&parent)?,
            parent: None,
        })),
    }
}
