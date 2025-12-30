/*! This modules provides Position related type conversions.

Provides utility function for converting absolute positions and spans
to LSP `Position` and `Range` types and vice versa.
 */

use async_lsp::lsp_types::{Position, Range};

use yara_x_parser::cst::Utf16;
use yara_x_parser::cst::{Immutable, Node, Token};
use yara_x_parser::Span;

/// Given a span within `src`, returns the corresponding [`Range`].
pub(crate) fn span_to_range(span: Span, src: &str) -> Range {
    Range {
        start: offset_to_position(span.start(), src),
        end: offset_to_position(span.end(), src),
    }
}

/// Given an offset within `src`, returns the corresponding [`Position`].
pub(crate) fn offset_to_position(offset: usize, src: &str) -> Position {
    let (line, col) = if let Some(newline) = src[0..offset].rfind('\n') {
        let line = src[0..newline].chars().filter(|c| *c == '\n').count() + 1;
        let col = src[newline + 1..offset].encode_utf16().count();
        (line, col)
    } else {
        (0, src[0..offset].encode_utf16().count())
    };
    Position::new(line as u32, col as u32)
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
