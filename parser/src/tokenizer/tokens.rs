use crate::Span;

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum TokenId {
    // Keywords.
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

    // Bitwise operators.
    SHL,
    SHR,

    // Comparison operators.
    EQ,
    NE,
    LT,
    LE,
    GT,
    GE,

    // Literals.
    FLOAT_LIT,
    INTEGER_LIT,
    STRING_LIT,
    REGEXP,

    // Identifiers.
    IDENT,
    PATTERN_IDENT,
    PATTERN_COUNT,
    PATTERN_OFFSET,
    PATTERN_LENGTH,

    // Punctuation.
    AMPERSAND,
    ASTERISK,
    BACKSLASH,
    CARET,
    COLON,
    COMMA,
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

    // Hex patterns
    HEX_BYTE,

    // Trivia
    COMMENT,
    NEWLINE,
    WHITESPACE,

    /// Not a real token. Used when a portion of the source code is not valid
    /// UTF-8.
    INVALID_UTF8,

    /// Not a real token. Used when a portion of the source code doesn't match
    /// any of the tokens.
    #[default]
    UNKNOWN,
}

impl TokenId {
    pub fn description(&self) -> &'static str {
        match self {
            // Keywords.
            TokenId::ALL_KW => "`all`",
            TokenId::AND_KW => "`and`",
            TokenId::ANY_KW => "`any`",
            TokenId::ASCII_KW => "`ascii`",
            TokenId::AT_KW => "`at`",
            TokenId::BASE64_KW => "`base64`",
            TokenId::BASE64WIDE_KW => "`base64wide`",
            TokenId::CONDITION_KW => "`condition`",
            TokenId::CONTAINS_KW => "`contains`",
            TokenId::DEFINED_KW => "`defined`",
            TokenId::ENDSWITH_KW => "`endswith`",
            TokenId::ENTRYPOINT_KW => "`entrypoint`",
            TokenId::FALSE_KW => "`false`",
            TokenId::FILESIZE_KW => "`filesize`",
            TokenId::FOR_KW => "`for`",
            TokenId::FULLWORD_KW => "`fullword`",
            TokenId::GLOBAL_KW => "`global`",
            TokenId::ICONTAINS_KW => "`icontains`",
            TokenId::IENDSWITH_KW => "`iendswith`",
            TokenId::IEQUALS_KW => "`iequals`",
            TokenId::IMPORT_KW => "`import`",
            TokenId::IN_KW => "`in`",
            TokenId::ISTARTSWITH_KW => "`istartswith`",
            TokenId::MATCHES_KW => "`matches`",
            TokenId::META_KW => "`meta`",
            TokenId::NOCASE_KW => "`nocase`",
            TokenId::NONE_KW => "`none`",
            TokenId::NOT_KW => "`not`",
            TokenId::OF_KW => "`of`",
            TokenId::OR_KW => "`or`",
            TokenId::PRIVATE_KW => "`private`",
            TokenId::RULE_KW => "`rule`",
            TokenId::STARTSWITH_KW => "`startswith",
            TokenId::STRINGS_KW => "`strings`",
            TokenId::THEM_KW => "`them`",
            TokenId::TRUE_KW => "`true`",
            TokenId::WIDE_KW => "`wide`",
            TokenId::XOR_KW => "`xor`",

            // Bitwise operators.
            TokenId::SHL => "`<<`",
            TokenId::SHR => "`>>`",

            // Comparison operators.
            TokenId::EQ => "`==`",
            TokenId::NE => "`!=`",
            TokenId::LT => "`<`",
            TokenId::LE => "`<=`",
            TokenId::GT => "`>`",
            TokenId::GE => "`>=`",

            // Punctuation.
            TokenId::AMPERSAND => "&",
            TokenId::ASTERISK => "`*`",
            TokenId::BACKSLASH => "`\\`",
            TokenId::CARET => "`^`",
            TokenId::COLON => "`:`",
            TokenId::COMMA => "`,`",
            TokenId::DOT => "`.`",
            TokenId::EQUAL => "`=`",
            TokenId::HYPHEN => "`-`",
            TokenId::PERCENT => "`%`",
            TokenId::PIPE => "`|`",
            TokenId::PLUS => "`+`",
            TokenId::TILDE => "`~`",

            TokenId::L_BRACE => "`{`",
            TokenId::R_BRACE => "`}`",
            TokenId::L_BRACKET => "`[`",
            TokenId::R_BRACKET => "`]`",
            TokenId::L_PAREN => "`(`",
            TokenId::R_PAREN => "`)`",

            TokenId::REGEXP => "regexp",
            TokenId::FLOAT_LIT => "FLOAT",
            TokenId::INTEGER_LIT => "INTEGER",
            TokenId::STRING_LIT => "STRING",
            TokenId::IDENT => "identifier",
            TokenId::PATTERN_IDENT => "pattern identifier",
            TokenId::PATTERN_COUNT => "pattern count",
            TokenId::PATTERN_LENGTH => "pattern length",
            TokenId::PATTERN_OFFSET => "pattern offset",
            TokenId::HEX_BYTE => "BYTE",
            TokenId::COMMENT => "comment",
            TokenId::NEWLINE => "newline",
            TokenId::WHITESPACE => "whitespace",
            TokenId::UNKNOWN => "unknown",
            TokenId::INVALID_UTF8 => "invalid UTF-8",
        }
    }
}

/// Each of the tokens produced by the lexer.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Token {
    // Keywords.
    ALL_KW(Span) = TokenId::ALL_KW as u8,
    AND_KW(Span) = TokenId::AND_KW as u8,
    ANY_KW(Span) = TokenId::ANY_KW as u8,
    ASCII_KW(Span) = TokenId::ASCII_KW as u8,
    AT_KW(Span) = TokenId::AT_KW as u8,
    BASE64_KW(Span) = TokenId::BASE64_KW as u8,
    BASE64WIDE_KW(Span) = TokenId::BASE64WIDE_KW as u8,
    CONDITION_KW(Span) = TokenId::CONDITION_KW as u8,
    CONTAINS_KW(Span) = TokenId::CONTAINS_KW as u8,
    DEFINED_KW(Span) = TokenId::DEFINED_KW as u8,
    ENDSWITH_KW(Span) = TokenId::ENDSWITH_KW as u8,
    ENTRYPOINT_KW(Span) = TokenId::ENTRYPOINT_KW as u8,
    FALSE_KW(Span) = TokenId::FALSE_KW as u8,
    FILESIZE_KW(Span) = TokenId::FILESIZE_KW as u8,
    FOR_KW(Span) = TokenId::FOR_KW as u8,
    FULLWORD_KW(Span) = TokenId::FULLWORD_KW as u8,
    GLOBAL_KW(Span) = TokenId::GLOBAL_KW as u8,
    ICONTAINS_KW(Span) = TokenId::ICONTAINS_KW as u8,
    IENDSWITH_KW(Span) = TokenId::IENDSWITH_KW as u8,
    IEQUALS_KW(Span) = TokenId::IEQUALS_KW as u8,
    IMPORT_KW(Span) = TokenId::IMPORT_KW as u8,
    IN_KW(Span) = TokenId::IN_KW as u8,
    ISTARTSWITH_KW(Span) = TokenId::ISTARTSWITH_KW as u8,
    MATCHES_KW(Span) = TokenId::MATCHES_KW as u8,
    META_KW(Span) = TokenId::META_KW as u8,
    NOCASE_KW(Span) = TokenId::NOCASE_KW as u8,
    NONE_KW(Span) = TokenId::NONE_KW as u8,
    NOT_KW(Span) = TokenId::NOT_KW as u8,
    OF_KW(Span) = TokenId::OF_KW as u8,
    OR_KW(Span) = TokenId::OR_KW as u8,
    PRIVATE_KW(Span) = TokenId::PRIVATE_KW as u8,
    RULE_KW(Span) = TokenId::RULE_KW as u8,
    STARTSWITH_KW(Span) = TokenId::STARTSWITH_KW as u8,
    STRINGS_KW(Span) = TokenId::STRINGS_KW as u8,
    THEM_KW(Span) = TokenId::THEM_KW as u8,
    TRUE_KW(Span) = TokenId::TRUE_KW as u8,
    WIDE_KW(Span) = TokenId::WIDE_KW as u8,
    XOR_KW(Span) = TokenId::XOR_KW as u8,

    // Bitwise operators.
    SHL(Span) = TokenId::SHL as u8,
    SHR(Span) = TokenId::SHR as u8,

    // Comparison operators.
    EQ(Span) = TokenId::EQ as u8,
    NE(Span) = TokenId::NE as u8,
    LT(Span) = TokenId::LT as u8,
    LE(Span) = TokenId::LE as u8,
    GT(Span) = TokenId::GT as u8,
    GE(Span) = TokenId::GE as u8,

    // Literals.
    FLOAT_LIT(Span) = TokenId::FLOAT_LIT as u8,
    INTEGER_LIT(Span) = TokenId::INTEGER_LIT as u8,
    STRING_LIT(Span) = TokenId::STRING_LIT as u8,
    REGEXP(Span) = TokenId::REGEXP as u8,

    // Identifiers.
    IDENT(Span) = TokenId::IDENT as u8,
    PATTERN_IDENT(Span) = TokenId::PATTERN_IDENT as u8,
    PATTERN_OFFSET(Span) = TokenId::PATTERN_OFFSET as u8,
    PATTERN_COUNT(Span) = TokenId::PATTERN_COUNT as u8,
    PATTERN_LENGTH(Span) = TokenId::PATTERN_LENGTH as u8,

    // Punctuation.
    AMPERSAND(Span) = TokenId::AMPERSAND as u8,
    ASTERISK(Span) = TokenId::ASTERISK as u8,
    BACKSLASH(Span) = TokenId::BACKSLASH as u8,
    CARET(Span) = TokenId::CARET as u8,
    COLON(Span) = TokenId::COLON as u8,
    COMMA(Span) = TokenId::COMMA as u8,
    DOT(Span) = TokenId::DOT as u8,
    EQUAL(Span) = TokenId::EQUAL as u8,
    HYPHEN(Span) = TokenId::HYPHEN as u8,
    PERCENT(Span) = TokenId::PERCENT as u8,
    PIPE(Span) = TokenId::PIPE as u8,
    PLUS(Span) = TokenId::PLUS as u8,
    TILDE(Span) = TokenId::TILDE as u8,

    L_BRACE(Span) = TokenId::L_BRACE as u8,
    R_BRACE(Span) = TokenId::R_BRACE as u8,
    L_BRACKET(Span) = TokenId::L_BRACKET as u8,
    R_BRACKET(Span) = TokenId::R_BRACKET as u8,
    L_PAREN(Span) = TokenId::L_PAREN as u8,
    R_PAREN(Span) = TokenId::R_PAREN as u8,

    // Hex patterns
    HEX_BYTE(Span) = TokenId::HEX_BYTE as u8,

    // Trivia
    COMMENT(Span) = TokenId::COMMENT as u8,
    NEWLINE(Span) = TokenId::NEWLINE as u8,
    WHITESPACE(Span) = TokenId::WHITESPACE as u8,

    /// Not a real token. Used when a portion of the source code doesn't match
    /// any of the tokens.
    UNKNOWN(Span) = TokenId::UNKNOWN as u8,

    /// Not a real token. Used when a portion of the source code is not valid
    /// UTF-8.
    INVALID_UTF8(Span) = TokenId::INVALID_UTF8 as u8,
}

impl Token {
    /// Returns true if this is trivia token.
    ///
    /// Trivia tokens are those that are not really relevant and can be
    /// ignored, like whitespaces, newlines, and comments.
    pub fn is_trivia(&self) -> bool {
        matches!(
            self,
            Token::NEWLINE(_) | Token::WHITESPACE(_) | Token::COMMENT(_)
        )
    }

    pub fn span(&self) -> Span {
        match self {
            // Keywords
            Token::ALL_KW(span)
            | Token::AND_KW(span)
            | Token::ANY_KW(span)
            | Token::ASCII_KW(span)
            | Token::AT_KW(span)
            | Token::BASE64_KW(span)
            | Token::BASE64WIDE_KW(span)
            | Token::CONDITION_KW(span)
            | Token::CONTAINS_KW(span)
            | Token::DEFINED_KW(span)
            | Token::ENDSWITH_KW(span)
            | Token::ENTRYPOINT_KW(span)
            | Token::FALSE_KW(span)
            | Token::FILESIZE_KW(span)
            | Token::FOR_KW(span)
            | Token::FULLWORD_KW(span)
            | Token::GLOBAL_KW(span)
            | Token::ICONTAINS_KW(span)
            | Token::IENDSWITH_KW(span)
            | Token::IEQUALS_KW(span)
            | Token::IMPORT_KW(span)
            | Token::IN_KW(span)
            | Token::ISTARTSWITH_KW(span)
            | Token::MATCHES_KW(span)
            | Token::META_KW(span)
            | Token::NOCASE_KW(span)
            | Token::NONE_KW(span)
            | Token::NOT_KW(span)
            | Token::OF_KW(span)
            | Token::OR_KW(span)
            | Token::PRIVATE_KW(span)
            | Token::RULE_KW(span)
            | Token::STARTSWITH_KW(span)
            | Token::STRINGS_KW(span)
            | Token::THEM_KW(span)
            | Token::TRUE_KW(span)
            | Token::WIDE_KW(span)
            | Token::XOR_KW(span)

            // Bitwise operators
            | Token::SHL(span)
            | Token::SHR(span)

            // Comparison operators.
            | Token::EQ(span)
            | Token::NE(span)
            | Token::LT(span)
            | Token::LE(span)
            | Token::GT(span)
            | Token::GE(span)

            // Punctuation.
            | Token::AMPERSAND(span)
            | Token::ASTERISK(span)
            | Token::BACKSLASH(span)
            | Token::CARET(span)
            | Token::COLON(span)
            | Token::COMMA(span)
            | Token::DOT(span)
            | Token::EQUAL(span)
            | Token::HYPHEN(span)
            | Token::PERCENT(span)
            | Token::PIPE(span)
            | Token::PLUS(span)
            | Token::TILDE(span)

            | Token::L_BRACE(span)
            | Token::R_BRACE(span)
            | Token::L_BRACKET(span)
            | Token::R_BRACKET(span)
            | Token::L_PAREN(span)
            | Token::R_PAREN(span)

            // Literals
            | Token::REGEXP(span)

            | Token::FLOAT_LIT(span)
            | Token::INTEGER_LIT(span)
            | Token::STRING_LIT(span)
            // Identifiers
            | Token::IDENT(span)
            | Token::PATTERN_IDENT(span)
            | Token::PATTERN_COUNT(span)
            | Token::PATTERN_OFFSET(span)
            | Token::PATTERN_LENGTH(span)

            // Hex patterns
            | Token::HEX_BYTE(span)
            // Trivia
            | Token::COMMENT(span)
            | Token::WHITESPACE(span)
            | Token::NEWLINE(span)
            | Token::UNKNOWN(span)
            | Token::INVALID_UTF8(span) => span.clone(),
        }
    }
}

impl Token {
    /// Returns the token ID associated to this token.
    pub(crate) fn id(&self) -> TokenId {
        // SAFETY: Because `Token` is marked `repr(u8)`, `self` can be casted
        // to a pointer, and the `u8` pointed to by the pointer is the
        // discriminant.
        unsafe { *<*const _>::from(self).cast::<TokenId>() }
    }
}
