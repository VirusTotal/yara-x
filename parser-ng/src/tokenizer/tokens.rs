use crate::Span;

/// Each of the tokens produced by the lexer.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    // Keywords.
    ALL_KW(Span),
    AND_KW(Span),
    ANY_KW(Span),
    ASCII_KW(Span),
    AT_KW(Span),
    BASE64_KW(Span),
    BASE64WIDE_KW(Span),
    CONDITION_KW(Span),
    CONTAINS_KW(Span),
    DEFINED_KW(Span),
    ENDSWITH_KW(Span),
    ENTRYPOINT_KW(Span),
    FALSE_KW(Span),
    FILESIZE_KW(Span),
    FOR_KW(Span),
    FULLWORD_KW(Span),
    GLOBAL_KW(Span),
    ICONTAINS_KW(Span),
    IENDSWITH_KW(Span),
    IEQUALS_KW(Span),
    IMPORT_KW(Span),
    IN_KW(Span),
    ISTARTSWITH_KW(Span),
    MATCHES_KW(Span),
    META_KW(Span),
    NOCASE_KW(Span),
    NONE_KW(Span),
    NOT_KW(Span),
    OF_KW(Span),
    OR_KW(Span),
    PRIVATE_KW(Span),
    RULE_KW(Span),
    STARTSWITH_KW(Span),
    STRINGS_KW(Span),
    THEM_KW(Span),
    TRUE_KW(Span),
    WIDE_KW(Span),
    XOR_KW(Span),

    // Bitwise operators.
    SHL(Span),
    SHR(Span),

    // Comparison operators.
    EQ(Span),
    NE(Span),
    LT(Span),
    LE(Span),
    GT(Span),
    GE(Span),

    // Literals.
    FLOAT_LIT(Span),
    INTEGER_LIT(Span),
    STRING_LIT(Span),

    // Identifiers.
    IDENT(Span),
    PATTERN_IDENT(Span),

    // Punctuation.
    AMPERSAND(Span),
    ASTERISK(Span),
    BACKSLASH(Span),
    COLON(Span),
    COMMA(Span),
    DOT(Span),
    EQUAL(Span),
    MINUS(Span),
    PERCENT(Span),
    PIPE(Span),
    PLUS(Span),
    TILDE(Span),

    L_BRACE(Span),
    R_BRACE(Span),
    L_BRACKET(Span),
    R_BRACKET(Span),
    L_PAREN(Span),
    R_PAREN(Span),

    REGEXP(Span),

    // Hex patterns
    HEX_BYTE(Span),

    // Trivia
    COMMENT(Span),
    NEWLINE(Span),
    WHITESPACE(Span),

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
            | Token::PLUS(span)
            | Token::ASTERISK(span)
            | Token::BACKSLASH(span)
            | Token::AMPERSAND(span)
            | Token::COLON(span)
            | Token::COMMA(span)
            | Token::DOT(span)
            | Token::MINUS(span)
            | Token::PERCENT(span)
            | Token::PIPE(span)
            | Token::TILDE(span)

            | Token::EQUAL(span)
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

    pub fn as_str(&self) -> &'static str {
        match self {
            // Keywords.
            Token::ALL_KW(_) => "`all`",
            Token::AND_KW(_) => "`and`",
            Token::ANY_KW(_) => "`any`",
            Token::ASCII_KW(_) => "`ascii`",
            Token::AT_KW(_) => "`at`",
            Token::BASE64_KW(_) => "`base64`",
            Token::BASE64WIDE_KW(_) => "`base64wide`",
            Token::CONDITION_KW(_) => "`condition`",
            Token::CONTAINS_KW(_) => "`contains`",
            Token::DEFINED_KW(_) => "`defined`",
            Token::ENDSWITH_KW(_) => "`endswith`",
            Token::ENTRYPOINT_KW(_) => "`entrypoint`",
            Token::FALSE_KW(_) => "`false`",
            Token::FILESIZE_KW(_) => "`filesize`",
            Token::FOR_KW(_) => "`for`",
            Token::FULLWORD_KW(_) => "`fullword`",
            Token::GLOBAL_KW(_) => "`global`",
            Token::ICONTAINS_KW(_) => "`icontains`",
            Token::IENDSWITH_KW(_) => "`iendswith`",
            Token::IEQUALS_KW(_) => "`iequals`",
            Token::IMPORT_KW(_) => "`import`",
            Token::IN_KW(_) => "`in`",
            Token::ISTARTSWITH_KW(_) => "`istartswith`",
            Token::MATCHES_KW(_) => "`matches`",
            Token::META_KW(_) => "`meta`",
            Token::NOCASE_KW(_) => "`nocase`",
            Token::NONE_KW(_) => "`none`",
            Token::NOT_KW(_) => "`not`",
            Token::OF_KW(_) => "`of`",
            Token::OR_KW(_) => "`or`",
            Token::PRIVATE_KW(_) => "`private`",
            Token::RULE_KW(_) => "`rule`",
            Token::STARTSWITH_KW(_) => "`startswith",
            Token::STRINGS_KW(_) => "`strings`",
            Token::THEM_KW(_) => "`them`",
            Token::TRUE_KW(_) => "`true`",
            Token::WIDE_KW(_) => "`wide`",
            Token::XOR_KW(_) => "`xor`",

            // Bitwise operators.
            Token::SHL(_) => "`<<`",
            Token::SHR(_) => "`>>`",

            // Comparison operators.
            Token::EQ(_) => "`==`",
            Token::NE(_) => "`!=`",
            Token::LT(_) => "`<`",
            Token::LE(_) => "`<=`",
            Token::GT(_) => "`>`",
            Token::GE(_) => "`>=`",

            // Punctuation.
            Token::PLUS(_) => "`+`",
            Token::AMPERSAND(_) => "&",
            Token::ASTERISK(_) => "`*`",
            Token::BACKSLASH(_) => "`\\`",
            Token::COLON(_) => "`:`",
            Token::COMMA(_) => "`,`",
            Token::DOT(_) => "`.`",
            Token::EQUAL(_) => "`=`",
            Token::MINUS(_) => "`-`",
            Token::PERCENT(_) => "`%`",
            Token::PIPE(_) => "`|`",
            Token::TILDE(_) => "`~`",

            Token::L_BRACE(_) => "`{`",
            Token::R_BRACE(_) => "`}`",
            Token::L_BRACKET(_) => "`[`",
            Token::R_BRACKET(_) => "`]`",
            Token::L_PAREN(_) => "`(`",
            Token::R_PAREN(_) => "`)`",

            Token::REGEXP(_) => "regexp",
            Token::FLOAT_LIT(_) => "FLOAT",
            Token::INTEGER_LIT(_) => "INTEGER",
            Token::STRING_LIT(_) => "STRING",
            Token::IDENT(_) => "identifier",
            Token::PATTERN_IDENT(_) => "pattern identifier",
            Token::HEX_BYTE(_) => "BYTE",
            Token::COMMENT(_) => "comment",
            Token::NEWLINE(_) => "newline",
            Token::WHITESPACE(_) => "whitespace",
            Token::UNKNOWN(_) => "unknown",
            Token::INVALID_UTF8(_) => unreachable!(),
        }
    }
}
