use std::sync::Arc;

use async_lsp::lsp_types::{Position, SelectionRange, Url};

use yara_x_parser::cst::{Immutable, Node};

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::token_at_position;
use crate::utils::position::{node_to_range, token_to_range};

/// Provides selection ranges from the given positions in the text
/// based on the given CST of this document.
pub fn selection_range(
    documents: Arc<DocumentStorage>,
    uri: Url,
    positions: Vec<Position>,
) -> Option<Vec<SelectionRange>> {
    let document = documents.get(&uri)?;
    let mut result: Vec<SelectionRange> = Vec::new();

    for position in positions {
        let nth_position_token = token_at_position(&document.cst, position)?;
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

/// Builds the linked chain of enclosing [`SelectionRange`]s starting at `node`
/// and expanding outward up to the CST root.
///
/// In LSP (`textDocument/selectionRange`), editors use this chain to power
/// "Expand Selection" / "Shrink Selection": the returned [`SelectionRange`]
/// covers `node`, its `parent` field covers the next wider ancestor, and so on
/// until the root node (`parent: None`).
///
/// Consecutive CST ancestors that cover the exact same byte span (such as
/// single-token expression wrappers like `PRIMARY_EXPR` -> `TERM`) are
/// collapsed into a single entry so expanding the selection always widens the
/// range. The chain is constructed in two passes (bottom-up collection, then
/// top-down linking) to avoid recursion on deeply nested CSTs.
fn get_parent_selection_range(
    node: Node<Immutable>,
) -> Option<Box<SelectionRange>> {
    // 1. Walk from `node` up to the root, keeping only nodes whose span is
    //    strictly narrower than their parent's span (plus the root itself).
    let mut nodes = Vec::new();
    let mut current = node;

    while let Some(next_parent) = current.parent() {
        if current.span() != next_parent.span() {
            nodes.push(current);
        }
        current = next_parent;
    }
    nodes.push(current);

    // 2. Link the ranges from outermost (root, `parent: None`) back down to
    //    innermost (`node`, returned at the head of the list).
    let mut outer = None;
    for ancestor in nodes.into_iter().rev() {
        outer = Some(Box::new(SelectionRange {
            range: node_to_range(&ancestor)?,
            parent: outer,
        }));
    }
    outer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection_range_dedup_and_nesting() {
        let storage = Arc::new(DocumentStorage::new());
        let uri = Url::parse("file:///test.yar").unwrap();
        let nested = format!(
            "rule r {{ condition: {}true{} }}",
            "(".repeat(100),
            ")".repeat(100)
        );
        storage.insert(uri.clone(), nested);

        let ranges =
            selection_range(storage, uri, vec![Position::new(0, 120)])
                .expect("selection ranges");
        assert_eq!(ranges.len(), 1);

        let mut cur = &ranges[0];
        let mut depth = 1;
        while let Some(parent) = &cur.parent {
            assert_ne!(cur.range, parent.range);
            cur = parent;
            depth += 1;
        }
        assert!(depth > 100);
    }
}
