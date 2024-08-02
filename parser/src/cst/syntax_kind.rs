use crate::tokenizer::{Token, TokenId};

/// Each of the node or token types in a CST.
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
    ADD,
    SUB,
    MUL,
    DIV,
    MOD,
    MINUS,

    // Bitwise operators
    SHL,
    SHR,
    BITWISE_AND,
    BITWISE_OR,
    BITWISE_XOR,
    BITWISE_NOT,

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
    HYPHEN,
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
    PATTERN_IDENT,
    PATTERN_LENGTH,
    PATTERN_OFFSET,
    PATTERN_COUNT,

    IMPORT_STMT,
    RULE_DECL,
    RULE_MODS,
    RULE_TAGS,
    CONDITION_BLK,
    PATTERN_DEF,
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
    FOR_EXPR,
    OF_EXPR,
    ITERABLE,
    QUANTIFIER,
    EXPR_TUPLE,
    BOOLEAN_EXPR_TUPLE,
    PATTERN_IDENT_TUPLE,

    HEX_ALTERNATIVE,
    HEX_JUMP,
    HEX_BYTE,
    HEX_PATTERN,
    HEX_SUB_PATTERN,

    ERROR,
    UNKNOWN,
    INVALID_UTF8,
}

impl From<SyntaxKind> for rowan::SyntaxKind {
    fn from(value: SyntaxKind) -> Self {
        rowan::SyntaxKind(value as u16)
    }
}

impl SyntaxKind {
    /// Returns the token ID associated to a [`SyntaxKind`].
    ///
    /// When [`SyntaxKind`] represents a non-terminal symbol, like
    /// [`SyntaxKind::RULE_DECL`] and [`SyntaxKind::IMPORT_STMT`], they
    /// don't have an associated token ID. However, when it represents a
    /// terminal symbol like [`SyntaxKind::ALL_KW`], [`SyntaxKind::EQ`]
    /// or [`SyntaxKind::IDENT`] they have a corresponding token ID, which
    /// usually have the same name ([`TokenId::ALL_KW`], [`TokenId::EQ`]
    /// and [`TokenId::IDENT`])
    ///
    /// In some cases, multiple variants of [`SyntaxKind`] are associated to
    /// the same token ID. For instance, both [`SyntaxKind::MOD`] (the module
    /// operation) and [`SyntaxKind::PERCENT`] are associated to
    /// [`TokenId::PERCENT`], because both are represented by the same token
    /// `%`.
    ///
    /// # Panics
    ///
    /// If the current [`SyntaxKind`] doesn't have an associated token ID.
    pub(crate) fn token_id(&self) -> TokenId {
        match self {
            SyntaxKind::ALL_KW => TokenId::ALL_KW,
            SyntaxKind::AND_KW => TokenId::AND_KW,
            SyntaxKind::ANY_KW => TokenId::ANY_KW,
            SyntaxKind::ASCII_KW => TokenId::ASCII_KW,
            SyntaxKind::AT_KW => TokenId::AT_KW,
            SyntaxKind::BASE64_KW => TokenId::BASE64_KW,
            SyntaxKind::BASE64WIDE_KW => TokenId::BASE64WIDE_KW,
            SyntaxKind::CONDITION_KW => TokenId::CONDITION_KW,
            SyntaxKind::CONTAINS_KW => TokenId::CONTAINS_KW,
            SyntaxKind::DEFINED_KW => TokenId::DEFINED_KW,
            SyntaxKind::ENDSWITH_KW => TokenId::ENDSWITH_KW,
            SyntaxKind::ENTRYPOINT_KW => TokenId::ENTRYPOINT_KW,
            SyntaxKind::FALSE_KW => TokenId::FALSE_KW,
            SyntaxKind::FILESIZE_KW => TokenId::FILESIZE_KW,
            SyntaxKind::FOR_KW => TokenId::FOR_KW,
            SyntaxKind::FULLWORD_KW => TokenId::FULLWORD_KW,
            SyntaxKind::GLOBAL_KW => TokenId::GLOBAL_KW,
            SyntaxKind::ICONTAINS_KW => TokenId::ICONTAINS_KW,
            SyntaxKind::IENDSWITH_KW => TokenId::IENDSWITH_KW,
            SyntaxKind::IEQUALS_KW => TokenId::IEQUALS_KW,
            SyntaxKind::IMPORT_KW => TokenId::IMPORT_KW,
            SyntaxKind::IN_KW => TokenId::IN_KW,
            SyntaxKind::ISTARTSWITH_KW => TokenId::ISTARTSWITH_KW,
            SyntaxKind::MATCHES_KW => TokenId::MATCHES_KW,
            SyntaxKind::META_KW => TokenId::META_KW,
            SyntaxKind::NOCASE_KW => TokenId::NOCASE_KW,
            SyntaxKind::NONE_KW => TokenId::NONE_KW,
            SyntaxKind::NOT_KW => TokenId::NOT_KW,
            SyntaxKind::OF_KW => TokenId::OF_KW,
            SyntaxKind::OR_KW => TokenId::OR_KW,
            SyntaxKind::PRIVATE_KW => TokenId::PRIVATE_KW,
            SyntaxKind::RULE_KW => TokenId::RULE_KW,
            SyntaxKind::STARTSWITH_KW => TokenId::STARTSWITH_KW,
            SyntaxKind::STRINGS_KW => TokenId::STRINGS_KW,
            SyntaxKind::THEM_KW => TokenId::THEM_KW,
            SyntaxKind::TRUE_KW => TokenId::TRUE_KW,
            SyntaxKind::WIDE_KW => TokenId::WIDE_KW,
            SyntaxKind::XOR_KW => TokenId::XOR_KW,

            SyntaxKind::ADD => TokenId::PLUS,
            SyntaxKind::SUB => TokenId::HYPHEN,
            SyntaxKind::MUL => TokenId::ASTERISK,
            SyntaxKind::DIV => TokenId::BACKSLASH,
            SyntaxKind::MOD => TokenId::PERCENT,
            SyntaxKind::MINUS => TokenId::HYPHEN,

            SyntaxKind::SHL => TokenId::SHL,
            SyntaxKind::SHR => TokenId::SHR,
            SyntaxKind::BITWISE_AND => TokenId::AMPERSAND,
            SyntaxKind::BITWISE_OR => TokenId::PIPE,
            SyntaxKind::BITWISE_XOR => TokenId::CARET,
            SyntaxKind::BITWISE_NOT => TokenId::TILDE,

            SyntaxKind::EQ => TokenId::EQ,
            SyntaxKind::NE => TokenId::NE,
            SyntaxKind::LT => TokenId::LT,
            SyntaxKind::LE => TokenId::LE,
            SyntaxKind::GT => TokenId::GT,
            SyntaxKind::GE => TokenId::GE,

            SyntaxKind::L_BRACE => TokenId::L_BRACE,
            SyntaxKind::R_BRACE => TokenId::R_BRACE,
            SyntaxKind::L_BRACKET => TokenId::L_BRACKET,
            SyntaxKind::R_BRACKET => TokenId::R_BRACKET,
            SyntaxKind::L_PAREN => TokenId::L_PAREN,
            SyntaxKind::R_PAREN => TokenId::R_PAREN,

            SyntaxKind::FLOAT_LIT => TokenId::FLOAT_LIT,
            SyntaxKind::STRING_LIT => TokenId::STRING_LIT,
            SyntaxKind::INTEGER_LIT => TokenId::INTEGER_LIT,
            SyntaxKind::REGEXP => TokenId::REGEXP,
            SyntaxKind::IDENT => TokenId::IDENT,
            SyntaxKind::PATTERN_IDENT => TokenId::PATTERN_IDENT,
            SyntaxKind::PATTERN_LENGTH => TokenId::PATTERN_LENGTH,
            SyntaxKind::PATTERN_OFFSET => TokenId::PATTERN_OFFSET,
            SyntaxKind::PATTERN_COUNT => TokenId::PATTERN_COUNT,

            SyntaxKind::ASTERISK => TokenId::ASTERISK,
            SyntaxKind::COLON => TokenId::COLON,
            SyntaxKind::COMMA => TokenId::COMMA,
            SyntaxKind::DOT => TokenId::DOT,
            SyntaxKind::EQUAL => TokenId::EQUAL,
            SyntaxKind::HYPHEN => TokenId::HYPHEN,
            SyntaxKind::PERCENT => TokenId::PERCENT,
            SyntaxKind::PIPE => TokenId::PIPE,

            SyntaxKind::HEX_BYTE => TokenId::HEX_BYTE,

            SyntaxKind::COMMENT => TokenId::COMMENT,
            SyntaxKind::NEWLINE => TokenId::NEWLINE,
            SyntaxKind::WHITESPACE => TokenId::WHITESPACE,

            _ => unreachable!("{:#?} doesn't have an associated token", self,),
        }
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
            Token::HYPHEN(_) => SyntaxKind::HYPHEN,
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
            Token::PATTERN_OFFSET(_) => SyntaxKind::PATTERN_OFFSET,
            Token::PATTERN_COUNT(_) => SyntaxKind::PATTERN_COUNT,
            Token::PATTERN_LENGTH(_) => SyntaxKind::PATTERN_LENGTH,

            // Trivia
            Token::COMMENT(_) => SyntaxKind::COMMENT,
            Token::WHITESPACE(_) => SyntaxKind::WHITESPACE,
            Token::NEWLINE(_) => SyntaxKind::NEWLINE,

            // Errors
            Token::UNKNOWN(_) => SyntaxKind::UNKNOWN,
            Token::INVALID_UTF8(_) => SyntaxKind::INVALID_UTF8,
        }
    }
}
