/*! This modules provides Position related type conversions.

Provides utility function for converting absolute positions and spans
to LSP `Position` and `Range` types and vice versa.
 */

use async_lsp::lsp_types::{Position, Range};
use yara_x_parser::cst::Utf16;
use yara_x_parser::{
    cst::{Immutable, Node, Token},
    Span,
};

/// Converts the absolute position in text to `Position` LSP object.
pub(crate) fn to_pos(pos: u32, text: &str) -> Position {
    let mut remainder = pos as usize;
    for (i, s) in text.split("\n").enumerate() {
        if remainder <= s.len() {
            return Position::new(i as u32, remainder as u32);
        } else {
            remainder -= s.len() + 1;
        }
    }
    Position::new(0, 0)
}

/// Converts [`yara_x_parser::Span`] to `Range` LSP object.
pub(crate) fn to_range(span: Span, text: &str) -> Range {
    Range {
        start: to_pos(span.start() as u32, text),
        end: to_pos(span.end() as u32, text),
    }
}

pub(crate) fn token_to_range(token: &Token<Immutable>) -> Option<Range> {
    let start = token.start_pos::<Utf16>();
    let start = Position::new(start.line as u32, start.column as u32);
    let end = token.end_pos::<Utf16>();
    let end = Position::new(end.line as u32, end.column as u32);

    Some(Range { start, end })
}

pub(crate) fn node_to_range(node: &Node<Immutable>) -> Option<Range> {
    let start = node.start_pos::<Utf16>();
    let start = Position::new(start.line as u32, start.column as u32);
    let end = node.end_pos::<Utf16>();
    let end = Position::new(end.line as u32, end.column as u32);

    Some(Range { start, end })
}
