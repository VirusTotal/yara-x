use crate::Span;

/// Each of the tokens produced by the lexer.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    // Keywords
    AND_KW(Span),
    CONDITION_KW(Span),
    FALSE_KW(Span),
    GLOBAL_KW(Span),
    IMPORT_KW(Span),
    META_KW(Span),
    NOT_KW(Span),
    OR_KW(Span),
    PRIVATE_KW(Span),
    RULE_KW(Span),
    TRUE_KW(Span),

    // Literals
    FLOAT_LIT(Span),
    INTEGER_LIT(Span),
    STRING_LIT(Span),

    // Identifiers
    IDENT(Span),

    // Punctuation
    COLON(Span),
    EQUAL(Span),
    L_BRACE(Span),
    R_BRACE(Span),
    L_PAREN(Span),
    R_PAREN(Span),

    // Hex patterns
    HEX_BYTE(Span),

    // Trivia
    WHITESPACE(Span),
    NEWLINE(Span),

    /// Not a real token. Used when a portion of the source code doesn't match
    /// any of the tokens.
    UNKNOWN(Span),

    /// Not a real token. Used when a portion of the source code is not valid
    /// UTF-8.
    INVALID_UTF8(Span),
}

impl Token {
    pub fn span(&self) -> Span {
        match self {
            // Keywords
            Token::AND_KW(span)
            | Token::CONDITION_KW(span)
            | Token::FALSE_KW(span)
            | Token::GLOBAL_KW(span)
            | Token::IMPORT_KW(span)
            | Token::META_KW(span)
            | Token::NOT_KW(span)
            | Token::OR_KW(span)
            | Token::PRIVATE_KW(span)
            | Token::RULE_KW(span)
            | Token::TRUE_KW(span)
            // Literals
            | Token::FLOAT_LIT(span)
            | Token::INTEGER_LIT(span)
            | Token::STRING_LIT(span)
            // Identifiers
            | Token::IDENT(span)
            // Punctuation
            | Token::COLON(span)
            | Token::EQUAL(span)
            | Token::L_BRACE(span)
            | Token::R_BRACE(span)
            | Token::L_PAREN(span)
            | Token::R_PAREN(span)
            // Hex patterns
            | Token::HEX_BYTE(span)
            // Trivia
            | Token::WHITESPACE(span)
            | Token::NEWLINE(span)
            | Token::UNKNOWN(span)
            | Token::INVALID_UTF8(span) => span.clone(),
        }
    }
}
