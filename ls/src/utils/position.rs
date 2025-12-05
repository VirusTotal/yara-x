/*! This modules provides Position related type conversions.

Provides utility function for converting absolute positions and spans
to LSP `Position` and `Range` types and vice versa.
 */

use async_lsp::lsp_types::{Position, Range};
use yara_x_parser::Span;

/// Converts `Position` LSP object to the absolute position in text.
pub(crate) fn to_abs(pos: Position, text: &str) -> u32 {
    let mut result = 0;
    for (i, s) in text.split("\n").enumerate() {
        if i as u32 == pos.line {
            return result as u32 + pos.character;
        }
        result += s.len() + 1;
    }
    0
}

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
