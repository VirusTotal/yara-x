use async_lsp::lsp_types::Position;
use yara_x_parser::Span;

/// A utility for converting between byte offsets and line/column numbers.
///
/// This is particularly useful for Language Server Protocol (LSP)
/// implementations where positions are represented as line and column numbers.
pub(crate) struct LineIndex {
    line_starts: Vec<usize>,
}

impl LineIndex {
    /// Creates a new `LineIndex` for the given text.
    ///
    /// This function pre-calculates the starting byte offset for each line,
    /// which allows for efficient conversion between byte offsets and
    /// line/column numbers.
    pub(crate) fn new(text: &str) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        Self { line_starts }
    }

    /// Converts a byte `offset` in the text to an LSP `Position` (line and
    /// character).
    pub(crate) fn offset_to_position(&self, offset: usize) -> Position {
        let line = self.line_starts.partition_point(|&i| i <= offset) - 1;
        let start_of_line = self.line_starts[line];
        let character = offset - start_of_line;
        Position::new(line as u32, character as u32)
    }

    /// Converts a `Span` (byte range) in the text to an LSP `Range`.
    pub(crate) fn span_to_range(
        &self,
        span: Span,
    ) -> async_lsp::lsp_types::Range {
        async_lsp::lsp_types::Range {
            start: self.offset_to_position(span.start()),
            end: self.offset_to_position(span.end()),
        }
    }
}
