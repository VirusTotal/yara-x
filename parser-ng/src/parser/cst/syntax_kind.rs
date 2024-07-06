use crate::tokenizer::Token;

/// Each of the node types in a Concrete Syntax Tree (CST).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum SyntaxKind {
    ALL_KW,
    AND_KW,
    ANY_KW,
    ASCII_KW,
    AT_KW,
    BASE64_KW,
    BASE64WIDE_KW,
    CONDITION_KW,
    CONTAINS_KW,
    DEFINED_KW,
    ENDSWITH_KW,
    ENTRYPOINT_KW,
    FALSE_KW,
    FILESIZE_KW,
    FOR_KW,
    FULLWORD_KW,
    GLOBAL_KW,
    ICONTAINS_KW,
    IENDSWITH_KW,
    IEQUALS_KW,
    IMPORT_KW,
    IN_KW,
    ISTARTSWITH_KW,
    MATCHES_KW,
    META_KW,
    NOCASE_KW,
    NONE_KW,
    NOT_KW,
    OF_KW,
    OR_KW,
    PRIVATE_KW,
    RULE_KW,
    STARTSWITH_KW,
    STRINGS_KW,
    THEM_KW,
    TRUE_KW,
    WIDE_KW,
    XOR_KW,

    // Arithmetic operators

    // Bitwise operators
    SHL,
    SHR,

    // Comparison operators.
    EQ,
    NE,
    LT,
    LE,
    GT,
    GE,

    // Punctuation
    AMPERSAND,
    ASTERISK,
    CARET,
    COLON,
    COMMA,
    BACKSLASH,
    DOT,
    EQUAL,
    MINUS,
    PERCENT,
    PIPE,
    PLUS,
    TILDE,

    L_BRACE,
    R_BRACE,
    L_BRACKET,
    R_BRACKET,
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
    PATTERN_MODS,
    PATTERN_MOD,
    RANGE,
    REGEXP,
    TERM,
    EXPR,
    INDEXING_EXPR,
    PRIMARY_EXPR,
    FUNC_CALL_EXPR,
    META_DEF,
    META_BLK,
    SOURCE_FILE,
    BOOLEAN_EXPR,
    BOOLEAN_TERM,

    HEX_ALTERNATIVE,
    HEX_JUMP,
    HEX_BYTE,
    HEX_PATTERN,
    HEX_SUB_PATTERN,

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
            Token::ALL_KW(_) => SyntaxKind::ALL_KW,
            Token::AND_KW(_) => SyntaxKind::AND_KW,
            Token::ANY_KW(_) => SyntaxKind::ANY_KW,
            Token::ASCII_KW(_) => SyntaxKind::ASCII_KW,
            Token::AT_KW(_) => SyntaxKind::AT_KW,
            Token::BASE64_KW(_) => SyntaxKind::BASE64_KW,
            Token::BASE64WIDE_KW(_) => SyntaxKind::BASE64WIDE_KW,
            Token::CONDITION_KW(_) => SyntaxKind::CONDITION_KW,
            Token::CONTAINS_KW(_) => SyntaxKind::CONTAINS_KW,
            Token::DEFINED_KW(_) => SyntaxKind::DEFINED_KW,
            Token::ENDSWITH_KW(_) => SyntaxKind::ENDSWITH_KW,
            Token::ENTRYPOINT_KW(_) => SyntaxKind::ENTRYPOINT_KW,
            Token::FALSE_KW(_) => SyntaxKind::FALSE_KW,
            Token::FILESIZE_KW(_) => SyntaxKind::FILESIZE_KW,
            Token::FOR_KW(_) => SyntaxKind::FOR_KW,
            Token::FULLWORD_KW(_) => SyntaxKind::FULLWORD_KW,
            Token::GLOBAL_KW(_) => SyntaxKind::GLOBAL_KW,
            Token::ICONTAINS_KW(_) => SyntaxKind::ICONTAINS_KW,
            Token::IENDSWITH_KW(_) => SyntaxKind::IENDSWITH_KW,
            Token::IEQUALS_KW(_) => SyntaxKind::IEQUALS_KW,
            Token::IMPORT_KW(_) => SyntaxKind::IMPORT_KW,
            Token::IN_KW(_) => SyntaxKind::IN_KW,
            Token::ISTARTSWITH_KW(_) => SyntaxKind::ISTARTSWITH_KW,
            Token::MATCHES_KW(_) => SyntaxKind::MATCHES_KW,
            Token::META_KW(_) => SyntaxKind::META_KW,
            Token::NOCASE_KW(_) => SyntaxKind::NOCASE_KW,
            Token::NONE_KW(_) => SyntaxKind::NONE_KW,
            Token::NOT_KW(_) => SyntaxKind::NOT_KW,
            Token::OF_KW(_) => SyntaxKind::OF_KW,
            Token::OR_KW(_) => SyntaxKind::OR_KW,
            Token::PRIVATE_KW(_) => SyntaxKind::PRIVATE_KW,
            Token::RULE_KW(_) => SyntaxKind::RULE_KW,
            Token::STARTSWITH_KW(_) => SyntaxKind::STARTSWITH_KW,
            Token::STRINGS_KW(_) => SyntaxKind::STRINGS_KW,
            Token::THEM_KW(_) => SyntaxKind::THEM_KW,
            Token::TRUE_KW(_) => SyntaxKind::TRUE_KW,
            Token::WIDE_KW(_) => SyntaxKind::WIDE_KW,
            Token::XOR_KW(_) => SyntaxKind::XOR_KW,

            // Bitwise operators
            Token::SHL(_) => SyntaxKind::SHL,
            Token::SHR(_) => SyntaxKind::SHR,

            // Comparison operators.
            Token::EQ(_) => SyntaxKind::EQ,
            Token::NE(_) => SyntaxKind::NE,
            Token::LT(_) => SyntaxKind::LT,
            Token::LE(_) => SyntaxKind::LE,
            Token::GT(_) => SyntaxKind::GT,
            Token::GE(_) => SyntaxKind::GE,

            // Literals
            Token::REGEXP(_) => SyntaxKind::REGEXP,
            Token::FLOAT_LIT(_) => SyntaxKind::FLOAT_LIT,
            Token::INTEGER_LIT(_) => SyntaxKind::INTEGER_LIT,
            Token::STRING_LIT(_) => SyntaxKind::STRING_LIT,

            // Punctuation
            Token::AMPERSAND(_) => SyntaxKind::AMPERSAND,
            Token::ASTERISK(_) => SyntaxKind::ASTERISK,
            Token::BACKSLASH(_) => SyntaxKind::BACKSLASH,
            Token::CARET(_) => SyntaxKind::CARET,
            Token::COLON(_) => SyntaxKind::COLON,
            Token::COMMA(_) => SyntaxKind::COMMA,
            Token::DOT(_) => SyntaxKind::DOT,
            Token::EQUAL(_) => SyntaxKind::EQUAL,
            Token::HYPEN(_) => SyntaxKind::MINUS,
            Token::PERCENT(_) => SyntaxKind::PERCENT,
            Token::PIPE(_) => SyntaxKind::PIPE,
            Token::PLUS(_) => SyntaxKind::PLUS,
            Token::TILDE(_) => SyntaxKind::TILDE,

            Token::L_BRACE(_) => SyntaxKind::L_BRACE,
            Token::R_BRACE(_) => SyntaxKind::R_BRACE,
            Token::L_PAREN(_) => SyntaxKind::L_PAREN,
            Token::R_PAREN(_) => SyntaxKind::R_PAREN,
            Token::L_BRACKET(_) => SyntaxKind::L_BRACKET,
            Token::R_BRACKET(_) => SyntaxKind::R_BRACKET,

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
