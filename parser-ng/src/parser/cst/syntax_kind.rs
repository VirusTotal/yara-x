use crate::tokenizer::Token;

/// Each of the node types in a Concrete Syntax Tree (CST).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum SyntaxKind {
    AND_KW,
    CONDITION_KW,
    DEFINED_KW,
    FALSE_KW,
    GLOBAL_KW,
    IMPORT_KW,
    META_KW,
    NOT_KW,
    OR_KW,
    PRIVATE_KW,
    RULE_KW,
    STRINGS_KW,
    TRUE_KW,

    DIV,
    COLON,
    EQUAL,
    L_BRACE,
    R_BRACE,
    L_PAREN,
    R_PAREN,

    FLOAT_LIT,
    STRING_LIT,
    INTEGER_LIT,

    COMMENT,
    WHITESPACE,
    NEWLINE,

    IDENT,
    IMPORT_STMT,
    RULE_DECL,
    RULE_MODS,
    RULE_TAGS,
    CONDITION_BLK,
    PATTERN_DEF,
    PATTERN_IDENT,
    PATTERNS_BLK,
    REGEXP,
    META_DEF,
    META_BLK,
    SOURCE_FILE,
    BOOLEAN_EXPR,
    BOOLEAN_TERM,

    HEX_PATTERN,
    HEX_BYTE,

    ERROR,
    UNKNOWN,
}

impl From<SyntaxKind> for rowan::SyntaxKind {
    fn from(value: SyntaxKind) -> Self {
        rowan::SyntaxKind(value as u16)
    }
}

impl From<&Token> for SyntaxKind {
    fn from(token: &Token) -> Self {
        match token {
            // Keywords
            Token::AND_KW(_) => SyntaxKind::AND_KW,
            Token::CONDITION_KW(_) => SyntaxKind::CONDITION_KW,
            Token::FALSE_KW(_) => SyntaxKind::FALSE_KW,
            Token::GLOBAL_KW(_) => SyntaxKind::GLOBAL_KW,
            Token::DIV(_) => SyntaxKind::DIV,
            Token::IMPORT_KW(_) => SyntaxKind::IMPORT_KW,
            Token::META_KW(_) => SyntaxKind::META_KW,
            Token::NOT_KW(_) => SyntaxKind::NOT_KW,
            Token::OR_KW(_) => SyntaxKind::OR_KW,
            Token::PRIVATE_KW(_) => SyntaxKind::PRIVATE_KW,
            Token::REGEXP(_) => SyntaxKind::REGEXP,
            Token::RULE_KW(_) => SyntaxKind::RULE_KW,
            Token::STRINGS_KW(_) => SyntaxKind::STRINGS_KW,
            Token::TRUE_KW(_) => SyntaxKind::TRUE_KW,
            // Literals
            Token::FLOAT_LIT(_) => SyntaxKind::FLOAT_LIT,
            Token::INTEGER_LIT(_) => SyntaxKind::INTEGER_LIT,
            Token::STRING_LIT(_) => SyntaxKind::STRING_LIT,
            // Punctuation
            Token::COLON(_) => SyntaxKind::COLON,
            Token::EQUAL(_) => SyntaxKind::EQUAL,
            Token::L_BRACE(_) => SyntaxKind::L_BRACE,
            Token::R_BRACE(_) => SyntaxKind::R_BRACE,
            Token::L_PAREN(_) => SyntaxKind::L_PAREN,
            Token::R_PAREN(_) => SyntaxKind::R_PAREN,
            // Hex patterns
            Token::HEX_BYTE(_) => SyntaxKind::HEX_BYTE,
            // Identifiers
            Token::IDENT(_) => SyntaxKind::IDENT,
            Token::PATTERN_IDENT(_) => SyntaxKind::PATTERN_IDENT,
            // Trivia
            Token::COMMENT(_) => SyntaxKind::COMMENT,
            Token::WHITESPACE(_) => SyntaxKind::WHITESPACE,
            Token::NEWLINE(_) => SyntaxKind::NEWLINE,
            Token::UNKNOWN(_) => SyntaxKind::UNKNOWN,
            Token::INVALID_UTF8(_) => {
                todo!()
            }
        }
    }
}
