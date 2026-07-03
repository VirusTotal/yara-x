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

    /// Creates a new document with precached CST.
    pub fn new_with_cst(uri: Url, text: String, cst: CST) -> Self {
        let line_index = LineIndex::new(text.as_str());
        Self { uri, text, cst, line_index }
    }

    /// Updates all stored structures.
    pub fn update(&mut self, text: String) {
        self.cst = CST::from(text.as_str());
        self.line_index = LineIndex::new(text.as_str());
        self.text = text;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_document_new_and_update() {
        let uri = Url::parse("file:///test.yar").unwrap();
        let mut doc = Document::new(
            uri.clone(),
            "rule r1 { condition: true }".to_string(),
        );

        assert_eq!(doc.uri, uri);
        assert_eq!(doc.text, "rule r1 { condition: true }");
        assert_eq!(
            doc.cst.root().kind(),
            yara_x_parser::cst::SyntaxKind::SOURCE_FILE
        );

        doc.update("rule r2 { condition: false }".to_string());
        assert_eq!(doc.text, "rule r2 { condition: false }");
        assert_eq!(
            doc.cst.root().kind(),
            yara_x_parser::cst::SyntaxKind::SOURCE_FILE
        );
    }
}
