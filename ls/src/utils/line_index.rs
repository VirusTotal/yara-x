use std::collections::HashMap;

use async_lsp::lsp_types::Position;
use yara_x_parser::Span;

/// A utility for converting between byte offsets and LSP line/UTF-16 column
/// positions.
pub(crate) struct LineIndex {
    line_starts: Vec<usize>,
    text_len: usize,
    /// Maps line index -> sorted `(byte_col, utf16_col)` pairs (including end
    /// of line before `\n`) for lines containing non-ASCII UTF-8 characters.
    non_ascii: HashMap<usize, Vec<(usize, usize)>>,
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
        let text_len = text.len();
        let mut non_ascii = HashMap::new();

        for (line_idx, &start) in line_starts.iter().enumerate() {
            let end = line_starts
                .get(line_idx + 1)
                .map_or(text_len, |&next| next - 1);
            let line_text = &text[start..end];
            if !line_text.is_ascii() {
                let mut cols = Vec::new();
                let mut utf16_col = 0;
                for (byte_col, ch) in line_text.char_indices() {
                    cols.push((byte_col, utf16_col));
                    utf16_col += ch.len_utf16();
                }
                cols.push((line_text.len(), utf16_col));
                non_ascii.insert(line_idx, cols);
            }
        }

        Self { line_starts, text_len, non_ascii }
    }

    /// Converts a byte `offset` in the text to an LSP `Position` (line and
    /// UTF-16 character offset).
    pub(crate) fn offset_to_position(&self, offset: usize) -> Position {
        let offset = offset.min(self.text_len);
        let line = self.line_starts.partition_point(|&i| i <= offset) - 1;
        let byte_col = offset - self.line_starts[line];
        let utf16_col = if let Some(cols) = self.non_ascii.get(&line) {
            let idx = cols.partition_point(|&(b, _)| b <= byte_col) - 1;
            cols[idx].1
        } else {
            byte_col
        };
        Position::new(
            u32::try_from(line).unwrap_or(u32::MAX),
            u32::try_from(utf16_col).unwrap_or(u32::MAX),
        )
    }

    /// Converts an LSP `Position` (line and UTF-16 character offset) to a
    /// clamped UTF-8 byte offset in the text.
    fn position_to_offset(&self, pos: Position) -> usize {
        let line = pos.line as usize;
        // Editors may send `{ line: N, character: 0 }` as the exclusive end of
        // an N-line document that lacks a trailing `\n` (`line_starts.len() == N`).
        let Some(&start_of_line) = self.line_starts.get(line) else {
            return self.text_len;
        };
        let end_of_line = self
            .line_starts
            .get(line + 1)
            .map_or(self.text_len, |&next| next - 1);
        let target_u16 = pos.character as usize;

        let byte_col = if let Some(cols) = self.non_ascii.get(&line) {
            match cols.binary_search_by_key(&target_u16, |&(_, u16_c)| u16_c) {
                Ok(idx) => cols[idx].0,
                Err(idx) => cols
                    .get(idx)
                    .map_or(end_of_line - start_of_line, |&(b, _)| b),
            }
        } else {
            target_u16.min(end_of_line - start_of_line)
        };

        start_of_line + byte_col
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

    /// Converts an LSP `Range` to a `Span` (byte range) in the text.
    pub(crate) fn range_to_span(
        &self,
        range: async_lsp::lsp_types::Range,
    ) -> Span {
        let start = u32::try_from(self.position_to_offset(range.start))
            .unwrap_or(u32::MAX);
        let end = u32::try_from(self.position_to_offset(range.end))
            .unwrap_or(u32::MAX)
            .max(start);
        Span(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_index_conversions() {
        let text = "first line\nsecond line\nthird";
        let index = LineIndex::new(text);

        // Offset 0 -> line 0, char 0
        let pos = index.offset_to_position(0);
        assert_eq!(pos.line, 0);
        assert_eq!(pos.character, 0);

        // Offset 10 ('\n' at end of first line)
        let pos = index.offset_to_position(10);
        assert_eq!(pos.line, 0);
        assert_eq!(pos.character, 10);

        // Offset 11 (start of second line)
        let pos = index.offset_to_position(11);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);

        // Span roundtrip
        let span = Span(11..22); // "second line"
        let range = index.span_to_range(span.clone());
        assert_eq!(range.start.line, 1);
        assert_eq!(range.start.character, 0);
        assert_eq!(range.end.line, 1);
        assert_eq!(range.end.character, 11);

        let roundtrip_span = index.range_to_span(range);
        assert_eq!(roundtrip_span, span);

        // Exclusive EOF position `{ line: 3, character: 0 }` on a 3-line file
        // without trailing `\n` must clamp to `text.len()` instead of panicking.
        let full_span = index.range_to_span(async_lsp::lsp_types::Range {
            start: Position::new(0, 0),
            end: Position::new(3, 0),
        });
        assert_eq!(full_span, Span(0..text.len() as u32));

        // Extreme out-of-bounds positions and inverted ranges must not panic
        // or overflow `u32`.
        let extreme = index.range_to_span(async_lsp::lsp_types::Range {
            start: Position::new(u32::MAX, u32::MAX),
            end: Position::new(0, 0),
        });
        assert_eq!(extreme, Span(text.len() as u32..text.len() as u32));
    }

    #[test]
    fn test_line_index_utf16_columns() {
        // "🚀" is 4 UTF-8 bytes and 2 UTF-16 code units; "é" is 2 UTF-8 bytes
        // and 1 UTF-16 code unit.
        let text = "// 🚀éx\nrule r { condition: true }";
        let index = LineIndex::new(text);

        // Byte offset of 'x': "// " (3) + "🚀" (4) + "é" (2) = 9.
        // UTF-16 column of 'x': "// " (3) + "🚀" (2) + "é" (1) = 6.
        let pos = index.offset_to_position(9);
        assert_eq!(pos, Position::new(0, 6));

        let span = index.range_to_span(async_lsp::lsp_types::Range {
            start: Position::new(0, 3),
            end: Position::new(0, 6),
        });
        assert_eq!(span, Span(3..9));
    }
}
