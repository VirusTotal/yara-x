use std::collections::VecDeque;
use std::sync::Arc;

use async_lsp::lsp_types;
use async_lsp::lsp_types::{
    Position, Range, SemanticToken, SemanticTokenType, SemanticTokens,
};
use bitflags::bitflags;

use yara_x_parser::cst::{Immutable, SyntaxKind, Token, Utf16};

use crate::document::Document;

pub const SEMANTIC_TOKEN_TYPES: &[SemanticTokenType] = &[
    SemanticTokenType::KEYWORD,
    SemanticTokenType::STRING,
    SemanticTokenType::CLASS,
    SemanticTokenType::VARIABLE,
    SemanticTokenType::NUMBER,
    SemanticTokenType::OPERATOR,
    SemanticTokenType::FUNCTION,
    SemanticTokenType::REGEXP,
    SemanticTokenType::COMMENT,
    SemanticTokenType::PARAMETER,
    SemanticTokenType::MACRO,
];

pub const SEMANTIC_TOKEN_MODIFIERS: &[lsp_types::SemanticTokenModifier] = &[
    lsp_types::SemanticTokenModifier::DEFINITION,
    lsp_types::SemanticTokenModifier::DECLARATION,
];

bitflags! {
    /// Flags representing semantic token modifiers.
    ///
    /// Each bit represents an item in the [`SEMANTIC_TOKEN_MODIFIERS`] array.
    /// For instance, bit 0 is `Definition`, and item 0 in the array is
    /// `SemanticTokenModifier::DEFINITION`.
    #[derive(Debug, Clone, Copy)]
    pub struct Modifiers: u32 {
        const Definition = 0b00000000000000000000000000000001;
        const Declaration = 0b00000000000000000000000000000010;
    }
}

/// Given a semantic token type, returns its index in the
/// [`SEMANTIC_TOKEN_TYPES`] array.
fn token_type_index(value: SemanticTokenType) -> u32 {
    SEMANTIC_TOKEN_TYPES
        .iter()
        .position(|v| v.eq(&value))
        .map(|i| i as u32)
        .unwrap()
}

/// Given a token, returns its semantic type.
fn token_type(
    token: &Token<Immutable>,
) -> Option<(SemanticTokenType, Modifiers)> {
    match token.kind() {
        SyntaxKind::ALL_KW
        | SyntaxKind::AND_KW
        | SyntaxKind::ANY_KW
        | SyntaxKind::ASCII_KW
        | SyntaxKind::BASE64_KW
        | SyntaxKind::BASE64WIDE_KW
        | SyntaxKind::CONDITION_KW
        | SyntaxKind::CONTAINS_KW
        | SyntaxKind::DEFINED_KW
        | SyntaxKind::ENDSWITH_KW
        | SyntaxKind::ENTRYPOINT_KW
        | SyntaxKind::FALSE_KW
        | SyntaxKind::FILESIZE_KW
        | SyntaxKind::FOR_KW
        | SyntaxKind::FULLWORD_KW
        | SyntaxKind::GLOBAL_KW
        | SyntaxKind::ICONTAINS_KW
        | SyntaxKind::IENDSWITH_KW
        | SyntaxKind::IEQUALS_KW
        | SyntaxKind::IMPORT_KW
        | SyntaxKind::IN_KW
        | SyntaxKind::INCLUDE_KW
        | SyntaxKind::ISTARTSWITH_KW
        | SyntaxKind::MATCHES_KW
        | SyntaxKind::META_KW
        | SyntaxKind::NOCASE_KW
        | SyntaxKind::NONE_KW
        | SyntaxKind::NOT_KW
        | SyntaxKind::OF_KW
        | SyntaxKind::OR_KW
        | SyntaxKind::PRIVATE_KW
        | SyntaxKind::RULE_KW
        | SyntaxKind::STARTSWITH_KW
        | SyntaxKind::STRINGS_KW
        | SyntaxKind::THEM_KW
        | SyntaxKind::TRUE_KW
        | SyntaxKind::WIDE_KW
        | SyntaxKind::XOR_KW
        | SyntaxKind::WITH_KW => {
            Some((SemanticTokenType::KEYWORD, Modifiers::empty()))
        }

        SyntaxKind::ADD
        | SyntaxKind::SUB
        | SyntaxKind::MUL
        | SyntaxKind::DIV
        | SyntaxKind::MOD
        | SyntaxKind::MINUS
        | SyntaxKind::SHL
        | SyntaxKind::SHR
        | SyntaxKind::BITWISE_AND
        | SyntaxKind::BITWISE_OR
        | SyntaxKind::BITWISE_XOR
        | SyntaxKind::BITWISE_NOT
        | SyntaxKind::EQ
        | SyntaxKind::NE
        | SyntaxKind::LT
        | SyntaxKind::LE
        | SyntaxKind::GT
        | SyntaxKind::GE => {
            Some((SemanticTokenType::OPERATOR, Modifiers::empty()))
        }

        SyntaxKind::REGEXP => {
            Some((SemanticTokenType::REGEXP, Modifiers::empty()))
        }

        SyntaxKind::STRING_LIT => {
            Some((SemanticTokenType::STRING, Modifiers::empty()))
        }

        SyntaxKind::INTEGER_LIT | SyntaxKind::FLOAT_LIT => {
            Some((SemanticTokenType::NUMBER, Modifiers::empty()))
        }

        SyntaxKind::COMMENT => {
            Some((SemanticTokenType::COMMENT, Modifiers::empty()))
        }

        SyntaxKind::IDENT => match token.parent().unwrap().kind() {
            SyntaxKind::RULE_DECL => {
                Some((SemanticTokenType::CLASS, Modifiers::empty()))
            }
            SyntaxKind::WITH_DECL => {
                Some((SemanticTokenType::VARIABLE, Modifiers::Definition))
            }
            SyntaxKind::FUNC_CALL => {
                Some((SemanticTokenType::FUNCTION, Modifiers::empty()))
            }
            _ => Some((SemanticTokenType::VARIABLE, Modifiers::empty())),
        },

        SyntaxKind::PATTERN_IDENT => match token.parent().unwrap().kind() {
            SyntaxKind::PATTERN_DEF => {
                Some((SemanticTokenType::VARIABLE, Modifiers::Definition))
            }
            _ => Some((SemanticTokenType::VARIABLE, Modifiers::empty())),
        },

        SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            Some((SemanticTokenType::VARIABLE, Modifiers::empty()))
        }

        _ => None,
    }
}

/// An iterator that returns semantic tokens given a CST.
///
/// The iterator returns the type of the semantic token, its position and
/// length. If a range is provided, tokens outside the range are filtered out.
struct SemanticTokensIter {
    output_queue: VecDeque<(SemanticTokenType, Modifiers, Position, u32)>,
    range: Option<Range>,
    next_token: Option<Token<Immutable>>,
    position: Position,
}

impl SemanticTokensIter {
    fn new(document: Arc<Document>, range: Option<Range>) -> Self {
        let first_token = if let Some(range) = range {
            document.cst.root().token_at_position::<Utf16, _>((
                range.start.line as usize,
                range.start.character as usize,
            ))
        } else {
            document.cst.root().first_token()
        };

        let position = first_token
            .as_ref()
            .map(|token| token.start_pos::<Utf16>())
            .map(|pos| Position::new(pos.line as u32, pos.column as u32))
            .unwrap_or_default();

        Self {
            output_queue: VecDeque::new(),
            position,
            range,
            next_token: first_token,
        }
    }

    /// Check if a token at the given position with the given length overlaps
    /// with the filter range (if any).
    fn is_in_range(&self, line: u32, column: u32, length: u32) -> bool {
        match &self.range {
            None => true,
            Some(range) => {
                // Token is before range
                if line < range.start.line {
                    return false;
                }
                if line == range.start.line
                    && column + length <= range.start.character
                {
                    return false;
                }

                // Token is after range
                if line > range.end.line {
                    return false;
                }
                if line == range.end.line && column >= range.end.character {
                    return false;
                }

                true
            }
        }
    }
}

impl Iterator for SemanticTokensIter {
    type Item = (SemanticTokenType, Modifiers, Position, u32);

    fn next(&mut self) -> Option<Self::Item> {
        // First, check if there are any items in the output queue.
        if let Some(item) = self.output_queue.pop_front() {
            return Some(item);
        }

        while let Some(token) = self.next_token.take() {
            self.next_token = token.next_token();

            if let Some((token_type, token_modifiers)) = token_type(&token) {
                let mut text = token.text();
                let mut line = self.position.line;
                let mut column = self.position.character;

                // If we've passed the range, stop iterating early.
                if let Some(range) = self.range {
                    if range.end.line < line {
                        return None;
                    }
                }

                // Multi-line tokens are not supported by the LSP client,
                // therefore tokens that contain newlines are split into
                // multiple ones, one per line. Only comments and string
                // literals can contain newlines.
                if matches!(
                    token.kind(),
                    SyntaxKind::COMMENT | SyntaxKind::STRING_LIT
                ) {
                    while let Some(newline) = text.find('\n') {
                        let token = &text[..newline];
                        let token_len = token.encode_utf16().count() as u32;

                        if self.is_in_range(line, column, token_len) {
                            self.output_queue.push_back((
                                token_type.clone(),
                                token_modifiers,
                                Position::new(line, column),
                                token_len,
                            ));
                        }

                        text = &text[newline + 1..];
                        line += 1;
                        column = 0;
                    }
                }

                let token_len = text.encode_utf16().count() as u32;

                if self.is_in_range(line, column, token_len) {
                    self.output_queue.push_back((
                        token_type,
                        token_modifiers,
                        Position::new(line, column),
                        token_len,
                    ));
                }
            }

            match token.kind() {
                SyntaxKind::COMMENT | SyntaxKind::STRING_LIT => {
                    for c in token.text().chars() {
                        if c == '\n' {
                            self.position.line += 1;
                            self.position.character = 0;
                        } else {
                            self.position.character += c.len_utf16() as u32;
                        }
                    }
                }
                SyntaxKind::NEWLINE => {
                    self.position.line += 1;
                    self.position.character = 0;
                }
                _ => {
                    self.position.character += token.len::<Utf16>() as u32;
                }
            }

            // If we have items in the queue, return the first one
            if let Some(item) = self.output_queue.pop_front() {
                return Some(item);
            }
        }

        None
    }
}

/// Returns semantic tokens for the given CST.
///
/// An optional range can be specified, in which case only the tokens in that
/// range will be returned.
pub fn semantic_tokens(
    document: Arc<Document>,
    range: Option<Range>,
) -> SemanticTokens {
    let tokens = SemanticTokensIter::new(document, range);
    let mut prev_position = Position::default();
    let mut result: Vec<SemanticToken> = Vec::new();

    for (token_type, token_modifiers, position, length) in tokens {
        result.push(SemanticToken {
            delta_line: position.line - prev_position.line,
            delta_start: if position.line == prev_position.line {
                position.character - prev_position.character
            } else {
                position.character
            },
            length,
            token_type: token_type_index(token_type),
            token_modifiers_bitset: token_modifiers.bits(),
        });
        prev_position = position
    }

    SemanticTokens { data: result, ..Default::default() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn semantic_token_modifiers() {
        // Make sure that the number of flags in `Modifiers` matches
        // the number of items in `SEMANTIC_TOKEN_MODIFIERS`.
        assert_eq!(
            super::SEMANTIC_TOKEN_MODIFIERS.len() as u32,
            super::Modifiers::all().bits().count_ones()
        );
    }
}
