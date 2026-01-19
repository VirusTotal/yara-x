use crate::utils::line_index::LineIndex;
use yara_x_parser::cst::CST;

/// Represents a document open in the editor.
pub struct Document {
    /// The full text of the document.
    pub text: String,
    /// The Concrete Syntax Tree (CST) for the document.
    pub cst: CST,
    /// A helper for converting between byte offsets and line/column numbers.
    pub line_index: LineIndex,
}

impl Document {
    /// Creates a new document.
    pub fn new(text: String) -> Self {
        let cst = CST::from(text.as_str());
        let line_index = LineIndex::new(text.as_str());
        Self { text, cst, line_index }
    }
}
