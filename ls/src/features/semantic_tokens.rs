use std::collections::VecDeque;

use async_lsp::lsp_types;
use async_lsp::lsp_types::{
    Position, SemanticToken, SemanticTokenType, SemanticTokens,
};
use bitflags::bitflags;

use yara_x_parser::cst::{Immutable, SyntaxKind, Token, Utf16, CST};

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
/// length.
struct SemanticTokensIter {
    next: Option<Token<Immutable>>,
    output_queue: VecDeque<(SemanticTokenType, Modifiers, Position, u32)>,
}

impl SemanticTokensIter {
    fn new(cst: &CST) -> Self {
        Self { next: cst.root().first_token(), output_queue: VecDeque::new() }
    }
}

impl Iterator for SemanticTokensIter {
    type Item = (SemanticTokenType, Modifiers, Position, u32);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(token) = self.next.take() {
            self.next = token.next_token();

            if let Some((token_type, token_modifiers)) = token_type(&token) {
                let mut text = token.text();
                let pos = token.start_pos::<Utf16>();
                let mut line = pos.line as u32;
                let mut column = pos.column as u32;

                // Multi-line tokens are not supported by the LSP client,
                // therefore tokens that contain newlines are split into
                // multiple ones, one per line.
                while let Some(newline) = text.find('\n') {
                    let token = &text[..newline];
                    let token_len = token.encode_utf16().count();

                    self.output_queue.push_back((
                        token_type.clone(),
                        token_modifiers,
                        Position::new(line, column),
                        token_len as u32,
                    ));

                    text = &text[newline + 1..];
                    line += 1;
                    column = 0;
                }

                self.output_queue.push_back((
                    token_type,
                    token_modifiers,
                    Position::new(line, column),
                    text.encode_utf16().count() as u32,
                ));

                break;
            }
        }

        self.output_queue.pop_front()
    }
}

/// Returns semantic tokens for the given CST stream and text.
///
/// Semantic tokens are used to add additional color information to a file that
/// depends on language specific symbol information.
pub fn semantic_tokens(cst: &CST) -> SemanticTokens {
    let tokens = SemanticTokensIter::new(cst);
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
