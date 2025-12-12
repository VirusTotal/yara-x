/*! This modules provides Position related type conversions.

Provides utility function for converting absolute positions and spans
to LSP `Position` and `Range` types and vice versa.
 */

use async_lsp::lsp_types::{Position, Range};
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
    let position = token.position();
    let len = token.span().len();
    Some(Range {
        start: Position {
            line: position.line as u32,
            character: position.column as u32,
        },
        end: Position {
            line: position.line as u32,
            character: (position.column + len) as u32,
        },
    })
}

pub(crate) fn node_to_range(node: &Node<Immutable>) -> Option<Range> {
    let first = node.first_token()?;
    let last = node.last_token()?;
    let start = first.position();
    let end = last.position();
    let end_len = last.span().len();
    Some(Range {
        start: Position {
            line: start.line as u32,
            character: start.column as u32,
        },
        end: Position {
            line: end.line as u32,
            character: (end.column + end_len) as u32,
        },
    })
}
