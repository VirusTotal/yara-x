/*! Helpers for inspecting and adding `import` statements in a source file. */

use std::cell::OnceCell;
use std::collections::HashSet;

use async_lsp::lsp_types::{Position, Range, TextEdit};
use yara_x_parser::cst::{Immutable, Node, SyntaxKind, Utf16};

/// Tracks the modules imported by a source file and builds the edits needed
/// for importing new ones.
pub struct ModuleImports {
    root: Node<Immutable>,
    imported: HashSet<String>,
    /// Position where new `import` statements are inserted. It is computed
    /// the first time an import edit is requested.
    insertion_point: OnceCell<Position>,
}

impl ModuleImports {
    /// Creates a [`ModuleImports`] for the source file whose CST root is
    /// `root`.
    pub fn new(root: &Node<Immutable>) -> Self {
        Self {
            root: root.clone(),
            imported: imported_modules(root),
            insertion_point: OnceCell::new(),
        }
    }

    /// Returns `true` if the source file imports `module`.
    pub fn contains(&self, module: &str) -> bool {
        self.imported.contains(module)
    }

    /// Returns the edits that import `module`, or `None` if the module is
    /// already imported.
    ///
    /// The result is intended to be used directly as the
    /// `additional_text_edits` of a completion item.
    pub fn edits_to_import(&self, module: &str) -> Option<Vec<TextEdit>> {
        if self.contains(module) {
            return None;
        }
        let pos = *self
            .insertion_point
            .get_or_init(|| import_insertion_point(&self.root));
        Some(vec![TextEdit {
            range: Range::new(pos, pos),
            new_text: format!("import \"{module}\"\n"),
        }])
    }
}

/// Returns the names of the modules imported by the source file.
fn imported_modules(root: &Node<Immutable>) -> HashSet<String> {
    root.children()
        .filter(|node| node.kind() == SyntaxKind::IMPORT_STMT)
        // The last token in IMPORT_STMT is a STRING_LIT with the module
        // name. Strip the quotes from it.
        .filter_map(|node| node.last_token())
        .map(|module_name| module_name.text().trim_matches('"').to_string())
        .collect()
}

/// Returns the position where a new `import` statement should be inserted.
///
/// The rules, in order of priority, are:
///
/// 1. Before the first existing `import` statement, if any.
/// 2. Before the first `include` statement, if it's preceded only by
///    comments.
/// 3. After the comments at the top of the file, if they are followed by an
///    empty line. Those comments are considered a file header.
/// 4. After the block comment (`/* ... */`) at the very top of the file, if
///    any. Block comments at the top of the file are usually file headers
///    (e.g. license or copyright notices) and imports should go below them.
/// 5. At the start of the file. This includes the case in which line
///    comments (`// ...`) at the top of the file are immediately followed by
///    a rule, as those comments most likely describe the rule and should
///    stay attached to it.
fn import_insertion_point(root: &Node<Immutable>) -> Position {
    let line_start =
        |line: usize| Position::new(line.try_into().unwrap_or(u32::MAX), 0);

    if let Some(import) =
        root.children().find(|node| node.kind() == SyntaxKind::IMPORT_STMT)
    {
        return line_start(import.start_pos::<Utf16>().line);
    }

    let mut seen_comment = false;
    let mut newlines_in_a_row = 0;
    // True right after a block comment that is the first thing in the file.
    let mut after_block_header = false;
    // Line that follows the block comment at the top of the file, if any.
    let mut block_header_end = None;

    for child in root.children_with_tokens() {
        match child.kind() {
            SyntaxKind::COMMENT => {
                if !seen_comment
                    && child
                        .clone()
                        .into_token()
                        .is_some_and(|t| t.text().starts_with("/*"))
                {
                    after_block_header = true;
                }
                seen_comment = true;
                newlines_in_a_row = 0;
            }
            SyntaxKind::WHITESPACE => {}
            SyntaxKind::NEWLINE => {
                let line = child.start_pos::<Utf16>().line;
                if after_block_header {
                    block_header_end = Some(line + 1);
                    after_block_header = false;
                }
                newlines_in_a_row += 1;
                // An empty line after the header comment, insert there.
                if seen_comment && newlines_in_a_row > 1 {
                    return line_start(line);
                }
            }
            SyntaxKind::INCLUDE_STMT => {
                return line_start(child.start_pos::<Utf16>().line);
            }
            _ => break,
        }
    }

    block_header_end.map(line_start).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use yara_x_parser::cst::CST;

    use super::*;

    fn insertion_line(text: &str) -> u32 {
        let pos = import_insertion_point(&CST::from(text).root());
        assert_eq!(pos.character, 0);
        pos.line
    }

    #[test]
    fn imported_modules_are_collected() {
        let cst = CST::from(
            "import \"pe\"\nimport \"math\"\nrule foo { condition: true }",
        );
        let imports = ModuleImports::new(&cst.root());
        assert!(imports.contains("pe"));
        assert!(imports.contains("math"));
        assert!(!imports.contains("elf"));
    }

    #[test]
    fn edits_to_import() {
        let cst = CST::from(
            "// header\n\nimport \"pe\"\nrule foo { condition: true }",
        );
        let imports = ModuleImports::new(&cst.root());

        assert!(imports.edits_to_import("pe").is_none());

        let edits = imports.edits_to_import("elf").unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, "import \"elf\"\n");
        assert_eq!(edits[0].range.start, Position::new(2, 0));
        assert_eq!(edits[0].range.end, Position::new(2, 0));
    }

    #[test]
    fn insertion_point() {
        // Empty file.
        assert_eq!(insertion_line(""), 0);

        // No comments at the top of the file.
        assert_eq!(insertion_line("rule foo { condition: true }"), 0);

        // Leading empty lines without comments.
        assert_eq!(insertion_line("\n\nrule foo { condition: true }"), 0);

        // Existing imports: insert before the first one.
        assert_eq!(
            insertion_line("import \"pe\"\nrule foo { condition: true }"),
            0
        );

        // Existing imports after a header: insert before the first import,
        // not in the empty line that follows the header.
        assert_eq!(
            insertion_line(
                "// header\n\nimport \"pe\"\nrule foo { condition: true }"
            ),
            2
        );

        // Header comment immediately followed by an import.
        assert_eq!(insertion_line("// header\nimport \"pe\""), 1);

        // Include preceded only by comments: insert before it.
        assert_eq!(insertion_line("// header\ninclude \"foo.yar\""), 1);

        // Line comment immediately followed by a rule: the comment most
        // likely describes the rule, insert above the comment.
        assert_eq!(
            insertion_line("// comment\nrule foo { condition: true }"),
            0
        );

        // Block comment at the top of the file immediately followed by a
        // rule: the comment is a file header, insert below it.
        assert_eq!(
            insertion_line("/* license */\nrule foo { condition: true }"),
            1
        );
        assert_eq!(
            insertion_line(
                "/*\n * Copyright\n */\n// Rule comment\nrule foo { condition: true }"
            ),
            3
        );

        // A block comment that is not the first comment in the file is not
        // a header.
        assert_eq!(
            insertion_line(
                "// comment\n/* comment */\nrule foo { condition: true }"
            ),
            0
        );

        // A file consisting only of a block comment without trailing newline.
        assert_eq!(insertion_line("/* comment */"), 0);

        // Several line comments followed by an empty line.
        assert_eq!(
            insertion_line(
                "// First line\n// Second line\n\nrule foo { condition: true }"
            ),
            2
        );

        // Multiline block comment followed by an empty line.
        assert_eq!(
            insertion_line(
                "/* comment\ncomment */\n\nrule foo { condition: true }"
            ),
            2
        );

        // Header, then a comment describing the rule.
        assert_eq!(
            insertion_line(
                "/*\nComment\n*/\n\n// Rule comment\nrule name { condition: true }"
            ),
            3
        );
        assert_eq!(
            insertion_line(
                "/* File header */\n\n// Note\n// Note\n\n// Rule comment\nrule name { condition: true }"
            ),
            1
        );

        // CRLF line endings.
        assert_eq!(
            insertion_line("// header\r\n\r\nrule foo { condition: true }"),
            1
        );
    }
}
