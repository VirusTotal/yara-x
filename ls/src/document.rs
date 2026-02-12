use std::fs;
use std::io::Error;

use async_lsp::lsp_types::Url;

use yara_x_parser::cst::CST;

use crate::utils::line_index::LineIndex;

/// Represents a document open in the editor.
pub struct Document {
    /// Document URI.
    pub uri: Url,
    /// The full text of the document.
    pub text: String,
    /// The Concrete Syntax Tree (CST) for the document.
    pub cst: CST,
    /// A helper for converting between byte offsets and line/column numbers.
    pub line_index: LineIndex,
}

impl Document {
    /// Creates a new document.
    pub fn new(uri: Url, text: String) -> Self {
        let cst = CST::from(text.as_str());
        let line_index = LineIndex::new(text.as_str());
        Self { uri, text, cst, line_index }
    }

    /// Reads a document from a uri.
    pub fn read(uri: Url) -> Result<Self, Error> {
        let path =
            uri.to_file_path().map_err(|_| Error::other("invalid path"))?;
        Ok(Self::new(uri, fs::read_to_string(path)?))
    }
}
