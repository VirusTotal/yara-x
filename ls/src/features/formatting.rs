use crate::documents::storage::DocumentStorage;
use async_lsp::lsp_types::{
    DocumentFormattingParams, Position, Range, TextEdit,
};
use std::{io::Cursor, sync::Arc};
use yara_x_fmt::Indentation;

pub fn formatting(
    documents: Arc<DocumentStorage>,
    params: DocumentFormattingParams,
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

    let formatter = yara_x_fmt::Formatter::new().indentation(indentation);

    match formatter.format(input, &mut output) {
        Ok(changed) if changed => Some(vec![TextEdit::new(
            Range::new(Position::new(0, 0), Position::new(line_count, 0)),
            output.try_into().unwrap(),
        )]),
        _ => None,
    }
}
