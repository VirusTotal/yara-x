use async_lsp::lsp_types::{Position, Range, SemanticToken, SemanticTokens};
use yara_x_parser::{
    cst::{CSTStream, Event, SyntaxKind},
    Parser,
};

use crate::utils::position::{to_pos, to_range};

// Used semantic token types defined in the server capabilities
const KEYWORD: u32 = 0;
const STRING: u32 = 1;
const CLASS: u32 = 2;
const VARIABLE: u32 = 3;
const NUMBER: u32 = 4;
const OPERATOR: u32 = 5;
const FUNCTION: u32 = 6;
const REGEXP: u32 = 7;
const COMMENT: u32 = 8;
const PARAMETER: u32 = 9;
const MACRO: u32 = 10;

macro_rules! push_token {
    ($vec:expr, $last_pos:expr, $span:expr, $text:expr, $ttype:expr, $modifiers:expr) => {
        let pos = to_pos($span.0.start, $text);
        $vec.push(SemanticToken {
            delta_line: pos.line - $last_pos.line,
            delta_start: if pos.line == $last_pos.line {
                pos.character - $last_pos.character
            } else {
                pos.character
            },
            length: $span.0.end - $span.0.start,
            token_type: $ttype,
            token_modifiers_bitset: $modifiers,
        });
        $last_pos = pos;
    };
}

/// Returns semantic tokens for the given CST stream and text.
///
/// Semantic tokens are used to add additional color information to a file that
//  depends on language specific symbol information.
pub fn semantic_tokens(
    cst_stream: CSTStream<Parser<'_>>,
    text: &str,
) -> SemanticTokens {
    let mut result: Vec<SemanticToken> = vec![];

    let mut last_pos: Position = Position::default();
    let mut last_begin_kind = SyntaxKind::SOURCE_FILE;

    for ev in cst_stream {
        if last_begin_kind == SyntaxKind::HEX_PATTERN {
            if let Event::End { kind: SyntaxKind::HEX_PATTERN, span: _ } = ev {
                last_begin_kind = SyntaxKind::PATTERN_DEF;
            } else {
                continue;
            }
        }

        match ev {
            Event::Begin { kind: SyntaxKind::HEX_PATTERN, span } => {
                push_token!(result, last_pos, span, text, STRING, 0);
            }
            Event::Begin { kind, span: _ } => {
                last_begin_kind = kind;
            }
            // Keywords
            Event::Token { kind: SyntaxKind::RULE_KW, span }
            | Event::Token { kind: SyntaxKind::STRINGS_KW, span }
            | Event::Token { kind: SyntaxKind::CONDITION_KW, span }
            | Event::Token { kind: SyntaxKind::META_KW, span }
            | Event::Token { kind: SyntaxKind::FALSE_KW, span }
            | Event::Token { kind: SyntaxKind::TRUE_KW, span }
            | Event::Token { kind: SyntaxKind::IMPORT_KW, span }
            | Event::Token { kind: SyntaxKind::INCLUDE_KW, span }
            | Event::Token { kind: SyntaxKind::FILESIZE_KW, span }
            | Event::Token { kind: SyntaxKind::ENTRYPOINT_KW, span }
            | Event::Token { kind: SyntaxKind::DEFINED_KW, span }
            | Event::Token { kind: SyntaxKind::FOR_KW, span }
            | Event::Token { kind: SyntaxKind::WITH_KW, span }
            | Event::Token { kind: SyntaxKind::THEM_KW, span } => {
                push_token!(result, last_pos, span, text, KEYWORD, 0);
            }
            // Pattern and rule modifier keywords
            Event::Token { kind: SyntaxKind::ASCII_KW, span }
            | Event::Token { kind: SyntaxKind::WIDE_KW, span }
            | Event::Token { kind: SyntaxKind::NOCASE_KW, span }
            | Event::Token { kind: SyntaxKind::FULLWORD_KW, span }
            | Event::Token { kind: SyntaxKind::BASE64_KW, span }
            | Event::Token { kind: SyntaxKind::BASE64WIDE_KW, span }
            | Event::Token { kind: SyntaxKind::XOR_KW, span }
            | Event::Token { kind: SyntaxKind::PRIVATE_KW, span }
            | Event::Token { kind: SyntaxKind::GLOBAL_KW, span } => {
                push_token!(result, last_pos, span, text, PARAMETER, 0);
            }
            // Operator keywords
            Event::Token { kind: SyntaxKind::AT_KW, span }
            | Event::Token { kind: SyntaxKind::IN_KW, span }
            | Event::Token { kind: SyntaxKind::OF_KW, span }
            | Event::Token { kind: SyntaxKind::AND_KW, span }
            | Event::Token { kind: SyntaxKind::OR_KW, span }
            | Event::Token { kind: SyntaxKind::NOT_KW, span }
            | Event::Token { kind: SyntaxKind::CONTAINS_KW, span }
            | Event::Token { kind: SyntaxKind::ICONTAINS_KW, span }
            | Event::Token { kind: SyntaxKind::ENDSWITH_KW, span }
            | Event::Token { kind: SyntaxKind::IENDSWITH_KW, span }
            | Event::Token { kind: SyntaxKind::STARTSWITH_KW, span }
            | Event::Token { kind: SyntaxKind::ISTARTSWITH_KW, span }
            | Event::Token { kind: SyntaxKind::IEQUALS_KW, span }
            | Event::Token { kind: SyntaxKind::MATCHES_KW, span } => {
                push_token!(result, last_pos, span, text, OPERATOR, 0);
            }
            // Quantifier keywords
            Event::Token { kind: SyntaxKind::ALL_KW, span }
            | Event::Token { kind: SyntaxKind::ANY_KW, span }
            | Event::Token { kind: SyntaxKind::NONE_KW, span } => {
                push_token!(result, last_pos, span, text, MACRO, 0);
            }
            // Regexp
            // Apparently not supported in VS Code
            Event::Token { kind: SyntaxKind::REGEXP, span } => {
                push_token!(result, last_pos, span, text, REGEXP, 0);
            }
            // Numbers
            Event::Token { kind: SyntaxKind::INTEGER_LIT, span }
            | Event::Token { kind: SyntaxKind::FLOAT_LIT, span } => {
                push_token!(result, last_pos, span, text, NUMBER, 0);
            }
            // String
            Event::Token { kind: SyntaxKind::STRING_LIT, span } => {
                push_token!(result, last_pos, span, text, STRING, 0);
            }
            // Identificator
            Event::Token { kind: SyntaxKind::IDENT, span } => {
                if last_begin_kind == SyntaxKind::FUNC_CALL {
                    push_token!(result, last_pos, span, text, FUNCTION, 0);
                } else {
                    push_token!(result, last_pos, span, text, CLASS, 1);
                }
            }
            // Variable
            Event::Token { kind: SyntaxKind::PATTERN_IDENT, span }
            | Event::Token { kind: SyntaxKind::PATTERN_COUNT, span }
            | Event::Token { kind: SyntaxKind::PATTERN_OFFSET, span }
            | Event::Token { kind: SyntaxKind::PATTERN_LENGTH, span } => {
                push_token!(
                    result,
                    last_pos,
                    span,
                    text,
                    VARIABLE,
                    if last_begin_kind == SyntaxKind::PATTERN_DEF {
                        1
                    } else {
                        0
                    }
                );
            }
            // Comments
            // Explicitly process multiline comments
            // See: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#semanticTokensClientCapabilities
            Event::Token { kind: SyntaxKind::COMMENT, span } => {
                let whole_comment_range = to_range(span, text);

                let comment_end = text
                    .lines()
                    // Take only lines with comments except last line
                    .skip(whole_comment_range.start.line as usize)
                    .take(
                        (whole_comment_range.end.line
                            - whole_comment_range.start.line)
                            as usize,
                    )
                    // Push them into result vector
                    .fold(
                        Range {
                            start: last_pos,
                            end: whole_comment_range.start,
                        },
                        |mut range, line| {
                            let length = line.len() as u32;
                            let last_pos = range.start;
                            let curr_pos = range.end;

                            result.push(SemanticToken {
                                delta_line: curr_pos.line - last_pos.line,
                                delta_start: if curr_pos.line == last_pos.line
                                {
                                    curr_pos.character - last_pos.character
                                } else {
                                    curr_pos.character
                                },
                                length,
                                token_type: COMMENT,
                                token_modifiers_bitset: 0,
                            });

                            //Save last position
                            range.start.line = curr_pos.line;
                            range.start.character =
                                curr_pos.character + length;
                            //Save next line position
                            range.end.character = 0;
                            range.end.line = curr_pos.line + 1;
                            range
                        },
                    );

                // Adds last line or single line comment
                result.push(SemanticToken {
                    delta_line: comment_end.end.line - comment_end.start.line,
                    delta_start: if comment_end.end.line
                        == comment_end.start.line
                    {
                        comment_end.end.character - comment_end.start.character
                    } else {
                        comment_end.end.character
                    },
                    length: whole_comment_range.end.character
                        - comment_end.end.character,
                    token_type: COMMENT,
                    token_modifiers_bitset: 0,
                });

                last_pos = comment_end.end;
            }
            _ => {}
        }
    }
    SemanticTokens { data: result, ..Default::default() }
}
