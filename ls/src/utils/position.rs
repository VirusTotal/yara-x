/*! This modules provides Position related type conversions.

Provides utility function for converting absolute positions and spans
to LSP `Position` and `Range` types and vice versa.
 */

use async_lsp::lsp_types::{Position, Range};

use yara_x_parser::cst::Utf16;
use yara_x_parser::cst::{Immutable, Node, Token};

pub(crate) fn token_to_range(token: &Token<Immutable>) -> Option<Range> {
    let start = token.start_pos::<Utf16>();
    let start = Position::new(start.line as u32, start.column as u32);
    let end = token.end_pos::<Utf16>();
    let end = Position::new(end.line as u32, end.column as u32);

    Some(Range { start, end })
}

pub(crate) fn node_to_range(node: &Node<Immutable>) -> Option<Range> {
    let start = node.start_pos::<Utf16>();
    let start = Position::new(start.line as u32, start.column as u32);
    let end = node.end_pos::<Utf16>();
    let end = Position::new(end.line as u32, end.column as u32);

    Some(Range { start, end })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yara_x_parser::cst::CST;

    #[test]
    fn test_position_conversions() {
        let text = "rule foo { condition: true }";
        let cst = CST::from(text);
        let root = cst.root();

        let range = node_to_range(&root).expect("should produce range");
        assert_eq!(range.start.line, 0);
        assert_eq!(range.start.character, 0);
        assert_eq!(range.end.line, 0);
        assert_eq!(range.end.character, 28);

        // Find the "foo" token
        let mut stack = vec![yara_x_parser::cst::NodeOrToken::Node(root)];
        let mut foo_token = None;
        while let Some(nt) = stack.pop() {
            match nt {
                yara_x_parser::cst::NodeOrToken::Node(n) => {
                    stack.extend(n.children_with_tokens())
                }
                yara_x_parser::cst::NodeOrToken::Token(t) => {
                    if t.text() == "foo" {
                        foo_token = Some(t);
                        break;
                    }
                }
            }
        }
        let foo_token = foo_token.expect("foo token found");

        let token_range = token_to_range(&foo_token).expect("token range");
        assert_eq!(token_range.start.line, 0);
        assert_eq!(token_range.start.character, 5);
        assert_eq!(token_range.end.line, 0);
        assert_eq!(token_range.end.character, 8);
    }
}
