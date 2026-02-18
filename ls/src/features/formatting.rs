use serde::Deserialize;
use std::{io::Cursor, sync::Arc};

use async_lsp::lsp_types::{
    DocumentFormattingParams, Position, Range, TextEdit,
};
use yara_x_fmt::Indentation;

use crate::documents::storage::DocumentStorage;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FormattingOptions {
    pub align_metadata: bool,
    pub align_patterns: bool,
    pub indent_section_headers: bool,
    pub indent_section_contents: bool,
    pub newline_before_curly_brace: bool,
    pub empty_line_before_section_header: bool,
    pub empty_line_after_section_header: bool,
}

impl Default for FormattingOptions {
    fn default() -> Self {
        Self {
            align_metadata: true,
            align_patterns: true,
            indent_section_headers: true,
            indent_section_contents: true,
            newline_before_curly_brace: false,
            empty_line_before_section_header: false,
            empty_line_after_section_header: false,
        }
    }
}

pub fn formatting(
    documents: Arc<DocumentStorage>,
    params: DocumentFormattingParams,
    options: FormattingOptions,
) -> Option<Vec<TextEdit>> {
    let document = documents.get(&params.text_document.uri)?;
    let src = document.text.as_str();
    let line_count = src.lines().count() as u32;
    let input = Cursor::new(src);
    let mut output = Vec::new();

    let indentation = if params.options.insert_spaces {
        Indentation::Spaces(params.options.tab_size as usize)
    } else {
        Indentation::Tabs
    };

    let formatter = yara_x_fmt::Formatter::new()
        .indentation(indentation)
        .align_metadata(options.align_metadata)
        .align_patterns(options.align_patterns)
        .indent_section_headers(options.indent_section_headers)
        .indent_section_contents(options.indent_section_contents)
        .newline_before_curly_brace(options.newline_before_curly_brace)
        .empty_line_before_section_header(
            options.empty_line_before_section_header,
        )
        .empty_line_after_section_header(
            options.empty_line_after_section_header,
        );

    match formatter.format(input, &mut output) {
        Ok(changed) if changed => Some(vec![TextEdit::new(
            Range::new(Position::new(0, 0), Position::new(line_count, 0)),
            output.try_into().unwrap(),
        )]),
        _ => None,
    }
}
