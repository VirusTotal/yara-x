/*! Implements the YARA tokenizer.

Tokenization is the first step in the compilation process. The tokenizer takes
YARA source code and produces a sequence of tokens that is later processed by
the parser.

Each token is represented by a variant of the [`Token`] type.
*/

use logos::Logos;
use logos::Source;
use std::str;
use std::str::from_utf8;

use crate::Span;

mod tokens;

pub use tokens::Token;
pub(crate) use tokens::TokenId;

#[cfg(test)]
mod tests;

/// Takes YARA source code and produces a sequence of tokens.
///
/// The tokenizer has three modes of operation: normal mode, hex pattern mode,
/// and hex jump.
///
/// In normal mode the tokenizer recognizes most of the tokens in YARA's syntax,
/// like keywords (e.g: `rule`, `condition`, `for`, etc.), identifiers, string
/// literals, etc. In hex pattern mode, the tokenizer only recognizes the tokens
/// that can appear in a hex pattern, and in hex jump only the tokens that can
/// appear inside a hex jump.
///
/// This distinction is crucial because certain tokens, like `a0`, have
/// different meanings depending on the mode. Outside a hex pattern, `a0` is an
/// identifier; inside, it's a byte literal. Another example is `10` which is
/// an integer literal in normal mode, a hex byte in hex pattern mode, and
/// also an integer literal in hex jump mode.
///
/// The tokenizer itself is unable to know whether a token is inside a hex
/// pattern, or inside a hex jump, only the parser can know that. Therefore,
/// it is the parser's responsibility to switch the tokenizer to hex pattern
/// mode after parsing the opening brace (`{`) of a hex pattern. This is done
/// by invoking [`Tokenizer::enter_hex_pattern_mode`]. The tokenizer will
/// automatically revert to normal mode when it encounters the closing brace
/// (`}`). Similarly, the parser must call [`Tokenizer::enter_hex_jump_mode`]
/// after parsing the opening bracket (`[`) of a jump in a hex pattern, and
/// the tokenizer will go back to hex pattern mode when the closing bracket
/// (`]`) is found.
///
/// The source code passed to the tokenizer doesn't need to be valid UTF-8,
/// when the tokenizer finds some invalid UTF-8 sequence, it will return the
/// special token [`Token::INVALID_UTF8`] containing the invalid bytes, and
/// will continue tokenizing the remaining content.
pub struct Tokenizer<'src> {
    source: &'src [u8],
    lexer_start: usize,
    mode: Mode<'src>,
}

impl<'src> Tokenizer<'src> {
    /// Creates a new [`Tokenizer`].
    pub fn new(source: &'src [u8]) -> Self {
        // Can't handle source files greater than the maximum span size.
        assert!(source.len() < Span::MAX);
        Self {
            source,
            lexer_start: 0,
            mode: Mode::Normal(Logos::lexer(source)),
        }
    }

    /// Returns the source code passed to the tokenizer.
    #[inline]
    pub fn source(&self) -> &'src [u8] {
        self.source
    }

    /// Returns the next token.
    pub fn next_token(&mut self) -> Option<Token> {
        loop {
            match &mut self.mode {
                Mode::Normal(lexer) => match lexer.next()? {
                    Ok(token) => {
                        return Some(convert_normal_token(
                            token,
                            Span::from(lexer.span()).offset(self.lexer_start),
                        ));
                    }
                    Err(()) => return Some(unexpected_token(lexer)),
                },
                Mode::HexPattern(lexer) => match lexer.next()? {
                    Ok(token) => {
                        return Some(convert_hex_pattern_token(
                            token,
                            Span::from(lexer.span()).offset(self.lexer_start),
                        ))
                    }
                    Err(()) => {
                        // Found a token that was not expected in hex pattern
                        // mode, switch back to normal mode and try again. The
                        // start position for the new lexer is where the token
                        // was found.
                        self.lexer_start += match &self.mode {
                            Mode::HexPattern(lexer) => lexer.span().start,
                            _ => unreachable!(),
                        };
                        self.mode = Mode::Normal(Logos::lexer(
                            &self.source[self.lexer_start..],
                        ));
                    }
                },
                Mode::HexJump(lexer) => match lexer.next()? {
                    Ok(token) => {
                        return Some(convert_hex_jump_token(
                            token,
                            Span::from(lexer.span()).offset(self.lexer_start),
                        ))
                    }
                    Err(()) => {
                        // Found a token that was not expected in hex jump
                        // mode, switch back to hex pattern mode and try again.
                        // The start position for the new lexer is where the
                        // token was found.
                        self.lexer_start += match &self.mode {
                            Mode::HexJump(lexer) => lexer.span().start,
                            _ => unreachable!(),
                        };
                        self.mode = Mode::HexPattern(Logos::lexer(
                            &self.source[self.lexer_start..],
                        ));
                    }
                },
            }
        }
    }

    /// Switches the tokenizer to hex pattern operation mode.
    ///
    /// The parser must invoke this function after processing the opening
    /// brace (`{`) of a hex pattern. The tokenizer will automatically revert
    /// back to normal mode when encounters the closing brace (`}`).
    ///
    /// See [`Tokenizer`] for more details about operation modes.
    ///
    /// # Panics
    ///
    /// If the tokenizer is not currently in normal mode.
    pub fn enter_hex_pattern_mode(&mut self) {
        self.lexer_start += match &self.mode {
            Mode::Normal(lexer) => lexer.span().end,
            mode => {
                panic!(r"enter_hex_pattern_mode called from mode: {:?}", mode)
            }
        };
        self.mode =
            Mode::HexPattern(Logos::lexer(&self.source[self.lexer_start..]));
    }

    /// Switches the tokenizer to hex jump operation mode.
    ///
    /// The parser must invoke this function after processing the opening
    /// bracket (`[`) of a hex jump. The tokenizer will automatically revert
    /// back to hex pattern mode when encounters the closing bracket (`]`).
    ///
    /// See [`Tokenizer`] for more details about operation modes.
    ///
    /// # Panics
    ///
    /// If the tokenizer is not currently in hex pattern mode.
    pub fn enter_hex_jump_mode(&mut self) {
        self.lexer_start += match &self.mode {
            Mode::HexPattern(lexer) => lexer.span().end,
            mode => {
                panic!(r"enter_hex_jump_mode called from mode: {:?}", mode)
            }
        };
        self.mode =
            Mode::HexJump(Logos::lexer(&self.source[self.lexer_start..]));
    }
}

/// Describes the current mode of operation for a tokenizer.
///
/// [`Tokenizer`] uses the [`logos`] crate under the hood for doing the actual
/// work. It uses three different logos lexers, one for each of the three
/// modes of operation of the lexer: normal, hex pattern and hex jump.
#[derive(Debug)]
enum Mode<'src> {
    Normal(logos::Lexer<'src, NormalToken<'src>>),
    HexPattern(logos::Lexer<'src, HexPatternToken<'src>>),
    HexJump(logos::Lexer<'src, HexJumpToken<'src>>),
}

#[allow(clippy::upper_case_acronyms)]
#[derive(logos::Logos, Debug, PartialEq)]
#[logos(source = [u8])]
enum NormalToken<'src> {
    // Keywords
    #[token("all")]
    All,
    #[token("and")]
    And,
    #[token("any")]
    Any,
    #[token("ascii")]
    Ascii,
    #[token("at")]
    At,
    #[token("base64")]
    Base64,
    #[token("base64wide")]
    Base64Wide,
    #[token("condition")]
    Condition,
    #[token("contains")]
    Contains,
    #[token("defined")]
    Defined,
    #[token("endswith")]
    EndsWith,
    #[token("entrypoint")]
    Entrypoint,
    #[token("false")]
    False,
    #[token("filesize")]
    Filesize,
    #[token("for")]
    For,
    #[token("fullword")]
    Fullword,
    #[token("global")]
    Global,
    #[token("icontains")]
    IContains,
    #[token("iendswith")]
    IEndsWith,
    #[token("iequals")]
    IEquals,
    #[token("import")]
    Import,
    #[token("in")]
    In,
    #[token("istartswith")]
    IStarsWith,
    #[token("matches")]
    Matches,
    #[token("meta")]
    Meta,
    #[token("nocase")]
    Nocase,
    #[token("none")]
    None,
    #[token("not")]
    Not,
    #[token("of")]
    Of,
    #[token("or")]
    Or,
    #[token("private")]
    Private,
    #[token("rule")]
    Rule,
    #[token("startswith")]
    StartsWith,
    #[token("strings")]
    Strings,
    #[token("them")]
    Them,
    #[token("true")]
    True,
    #[token("wide")]
    Wide,
    #[token("xor")]
    Xor,

    // Bitwise
    #[token(">>")]
    Shl,
    #[token("<<")]
    Shr,

    // Comparison
    #[token("==")]
    Eq,
    #[token("!=")]
    Ne,
    #[token("<=")]
    Le,
    #[token(">=")]
    Ge,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,

    // Punctuation
    #[token("&")]
    Ampersand,
    #[token("*")]
    Asterisk,
    #[token("\\")]
    Backslash,
    #[token(":")]
    Colon,
    #[token(",")]
    Comma,
    #[token(".")]
    Dot,
    #[token("=")]
    Equal,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("%")]
    Percent,
    #[token("|")]
    Pipe,
    #[token("^")]
    Caret,
    #[token("~")]
    Tilde,

    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,

    // Pattern identifiers (i.e: $, $a, $b, $foo, $bar).
    #[regex(
        r#"(?x)                         # allow comments in the regexp
            \$                          # first character is $
            ([[:alpha:]]|\d|_)*         # any number of letters, digits, or _
        "#,
        |token| token.slice())
    ]
    PatternIdent(&'src [u8]),

    // Pattern count (i.e: #a, #b, #foo, #bar).
    #[regex(
        r#"(?x)                         # allow comments in the regexp
            \#                          # first character is #
            ([[:alpha:]]|\d|_)*         # any number of letters, digits, or _
        "#,
        |token| token.slice())
    ]
    PatternCount(&'src [u8]),

    // Pattern offset (i.e: @a, @b, @foo, @bar).
    #[regex(
        r#"(?x)                         # allow comments in the regexp
            @                           # first character is @
            ([[:alpha:]]|\d|_)*         # any number of letters, digits, or _
        "#,
        |token| token.slice())
    ]
    PatternOffset(&'src [u8]),

    // Pattern offset (i.e: @a, @b, @foo, @bar).
    #[regex(
        r#"(?x)                         # allow comments in the regexp
            !                           # first character is !
            ([[:alpha:]]|\d|_)*         # any number of letters, digits, or _
        "#,
        |token| token.slice())
    ]
    PatternLength(&'src [u8]),

    // Identifiers must start with underscore or letter, followed by any
    // number of underscores, letters, or digits.
    #[regex(
        r#"(?x)                         # allow comments in the regexp
            ([[:alpha:]]|_)             # first character is letter or _
            ([[:alpha:]]|\d|_)*         # any number of letters, digits, or _
        "#,
        |token| token.slice())
    ]
    Ident(&'src [u8]),

    // Float literals
    #[regex(
        r#"(?x)                         # allow comments in the regexp
            [0-9]+                      # one or more digits
            \.                          # a dot
            [0-9]+                      # one more digits
        "#,
        |token| token.slice())
    ]
    FloatLit(&'src [u8]),

    // Integer literals.
    #[regex(
        r#"(?x)
           (
             0x[a-fA-F0-9]+ |           # hexadecimal number
             0o[0-7]+       |           # octal number
             [0-9]+(KB|MB)?             # decimal number followed by optional KB or MB
           )
        "#,
        |token| token.slice())
    ]
    IntegerLit(&'src [u8]),

    // String literals start and ends with double quotes, in-between the quotes
    // they contain either an escape sequence, or anything that is not a
    // quote, newline or backslash.
    #[regex(
        r#"(?x)                         # allow comments in the regexp
        "                               # starts with double quotes
        (                               # any number of
          \\.                           #   escape sequence
          |                             #   or ..
          [^"\n\\]                      #   anything except quotes, newlines and backslashes
        )*
        "                               # ends with double quotes
        "#,
        |token| token.slice())
    ]
    StringLit(&'src [u8]),

    // Regular expression.
    #[regex(
        r#"(?x)                         # allow comments in the regexp
        /                               # starts with /
        (\\.|[^*/])                     # followed by escape sequence or anything that
                                        # is not * or /. This prevents collision with
                                        # commments.
        (                               # one or more..
          \\.                           #   escape sequence
          |                             #   or ..
          [^\\/\n]                      #   anything except \, / and newlines
        )+
        /                               # ends with /
        [[:alpha:]]*                    # zero or more modifiers like "s" and "i"
        "#,
        |token| token.slice())
    ]
    Regexp(&'src [u8]),

    // Block comment.
    #[regex(r#"(?x)                    # allow comments in the regexp
        /\*                            # starts with /*
        (                              # one or more..
            [^*]                       #   anything except asterisk
            |                          #   or..
            \*[^/]                     #   asterisk followed by something that is not /
        )*
        \*/                            # ends with */
        "#,
        |token| token.slice())
    ]
    BlockComment(&'src [u8]),

    // Single-line comment
    #[regex(r#"//[^\n]*"#, |token| token.slice())]
    Comment(&'src [u8]),

    //  /\*([^*]|\*[^/])*\*/
    #[regex("[ \t]+")]
    Whitespace,

    #[token("\n")]
    LF,

    #[token("\r")]
    CR,

    #[token("\r\n")]
    CRLF,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(logos::Logos, Debug, PartialEq)]
#[logos(source = [u8])]
enum HexPatternToken<'src> {
    // A hex byte is an optional tilde ~, followed by two hex digits or
    // question marks. The following are valid tokens:
    //
    // 10, A0, ef, 3?, ?3, ??, ~AB, ~A?, ~??
    //
    // Some tokens like ~?? are not actually valid, but the tokenizer accepts
    // them, and they are rejected later on during the compilation process.
    // This way we can provide meaningful error messages.
    #[regex("~?[?0-9a-fA-F]{2}")]
    Byte,

    #[token("|")]
    Pipe,

    #[token("(")]
    LParen,

    #[token(")")]
    RParen,

    #[token("[")]
    LBracket,

    #[token("]")]
    RBracket,

    #[regex("[ \t]+")]
    Whitespace,

    #[token("\n")]
    LF,

    #[token("\r")]
    CR,

    #[token("\r\n")]
    CRLF,

    // Block comment.
    #[regex(r#"(?x)                    # allow comments in the regexp
        /\*                            # starts with /*
        (                              # one or more..
            [^*]                       #   anything except asterisk
            |                          #   or..
            \*[^/]                     #   asterisk followed by something that is not /
        )*
        \*/                            # ends with */

        "#, |token| token.slice())]
    BlockComment(&'src [u8]),

    // Single-line comment
    #[regex(r#"//[^\n]*"#, |token| token.slice())]
    Comment(&'src [u8]),
}

#[allow(clippy::upper_case_acronyms)]
#[derive(logos::Logos, Debug, PartialEq)]
#[logos(source = [u8])]
enum HexJumpToken<'src> {
    #[token("-")]
    Hyphen,

    // Integer literals.
    #[regex(
        r#"(?x)
           (
             0x[a-fA-F0-9]+ |           # hexadecimal number
             0o[0-7]+       |           # octal number
             [0-9]+                     # decimal number
           )
        "#,
        |token| token.slice())
    ]
    IntegerLit(&'src [u8]),

    #[regex("[ \t]+")]
    Whitespace,

    #[token("\n")]
    LF,

    #[token("\r")]
    CR,

    #[token("\r\n")]
    CRLF,
}

fn unexpected_token<'src, T>(lexer: &mut logos::Lexer<'src, T>) -> Token
where
    T: Logos<'src>,
    T::Source: AsRef<[u8]>,
{
    let start = lexer.span().start;
    let end = lexer.source().len();
    let unexpected = lexer.source().as_ref().get(start..end).unwrap();
    // Make sure that `unexpected` contains a valid UTF-8 string, or take the
    // first few bytes that are valid and ignore the rest.
    // TODO: This could be implemented more efficiently using Utf8Chunks, but
    // it was introduced in Rust 1.79. With Utf8Chunks we can iterate over the
    // byte slice until finding an invalid UTF-8 character or a whitespace,
    // whatever comes first. We don't need to use `str::from_utf8`, which
    // validates the whole string until the end.
    // https://doc.rust-lang.org/std/str/struct.Utf8Chunks.html
    let unexpected = match from_utf8(unexpected) {
        Ok(unexpected) => unexpected,
        Err(err) => {
            if err.valid_up_to() == 0 {
                return Token::INVALID_UTF8(Span(
                    start as u32..(start + 1) as u32,
                ));
            } else {
                // unexpected[0..err.valid_up_to()] is guaranteed to be valid
                // UTF-8.
                unsafe {
                    str::from_utf8_unchecked(&unexpected[0..err.valid_up_to()])
                }
            }
        }
    };

    let unexpected = unexpected.split(char::is_whitespace).next().unwrap();

    // `unexpected` shouldn't be empty, if it happens is because the whitespace
    // was unexpected.
    debug_assert!(!unexpected.is_empty());

    lexer.bump(unexpected.len() - lexer.span().len());
    Token::UNKNOWN(Span(start as u32..(start + unexpected.len()) as u32))
}

fn convert_normal_token(token: NormalToken, span: Span) -> Token {
    match token {
        // Keywords.
        NormalToken::All => Token::ALL_KW(span),
        NormalToken::And => Token::AND_KW(span),
        NormalToken::Any => Token::ANY_KW(span),
        NormalToken::Ascii => Token::ASCII_KW(span),
        NormalToken::At => Token::AT_KW(span),
        NormalToken::Base64 => Token::BASE64_KW(span),
        NormalToken::Base64Wide => Token::BASE64WIDE_KW(span),
        NormalToken::Condition => Token::CONDITION_KW(span),
        NormalToken::Contains => Token::CONTAINS_KW(span),
        NormalToken::Defined => Token::DEFINED_KW(span),
        NormalToken::EndsWith => Token::ENDSWITH_KW(span),
        NormalToken::Entrypoint => Token::ENTRYPOINT_KW(span),
        NormalToken::False => Token::FALSE_KW(span),
        NormalToken::Filesize => Token::FILESIZE_KW(span),
        NormalToken::For => Token::FOR_KW(span),
        NormalToken::Fullword => Token::FULLWORD_KW(span),
        NormalToken::Global => Token::GLOBAL_KW(span),
        NormalToken::IContains => Token::ICONTAINS_KW(span),
        NormalToken::IEndsWith => Token::IENDSWITH_KW(span),
        NormalToken::IEquals => Token::IEQUALS_KW(span),
        NormalToken::Import => Token::IMPORT_KW(span),
        NormalToken::In => Token::IN_KW(span),
        NormalToken::IStarsWith => Token::ISTARTSWITH_KW(span),
        NormalToken::Matches => Token::MATCHES_KW(span),
        NormalToken::Meta => Token::META_KW(span),
        NormalToken::Nocase => Token::NOCASE_KW(span),
        NormalToken::None => Token::NONE_KW(span),
        NormalToken::Not => Token::NOT_KW(span),
        NormalToken::Of => Token::OF_KW(span),
        NormalToken::Or => Token::OR_KW(span),
        NormalToken::Private => Token::PRIVATE_KW(span),
        NormalToken::Rule => Token::RULE_KW(span),
        NormalToken::StartsWith => Token::STARTSWITH_KW(span),
        NormalToken::Strings => Token::STRINGS_KW(span),
        NormalToken::Them => Token::THEM_KW(span),
        NormalToken::True => Token::TRUE_KW(span),
        NormalToken::Wide => Token::WIDE_KW(span),
        NormalToken::Xor => Token::XOR_KW(span),

        // Bitwise.
        NormalToken::Shl => Token::SHL(span),
        NormalToken::Shr => Token::SHR(span),

        // Comparison.
        NormalToken::Eq => Token::EQ(span),
        NormalToken::Ne => Token::NE(span),
        NormalToken::Lt => Token::LT(span),
        NormalToken::Gt => Token::GT(span),
        NormalToken::Le => Token::LE(span),
        NormalToken::Ge => Token::GE(span),

        // Punctuation.
        NormalToken::Ampersand => Token::AMPERSAND(span),
        NormalToken::Asterisk => Token::ASTERISK(span),
        NormalToken::Backslash => Token::BACKSLASH(span),
        NormalToken::Caret => Token::CARET(span),
        NormalToken::Comma => Token::COMMA(span),
        NormalToken::Colon => Token::COLON(span),
        NormalToken::Dot => Token::DOT(span),
        NormalToken::Equal => Token::EQUAL(span),
        NormalToken::Minus => Token::HYPHEN(span),
        NormalToken::Percent => Token::PERCENT(span),
        NormalToken::Pipe => Token::PIPE(span),
        NormalToken::Plus => Token::PLUS(span),
        NormalToken::Tilde => Token::TILDE(span),

        NormalToken::LBrace => Token::L_BRACE(span),
        NormalToken::RBrace => Token::R_BRACE(span),
        NormalToken::LParen => Token::L_PAREN(span),
        NormalToken::RParen => Token::R_PAREN(span),
        NormalToken::LBracket => Token::L_BRACKET(span),
        NormalToken::RBracket => Token::R_BRACKET(span),

        NormalToken::Whitespace => Token::WHITESPACE(span),

        NormalToken::LF | NormalToken::CR | NormalToken::CRLF => {
            Token::NEWLINE(span)
        }

        NormalToken::Ident(ident) => {
            return match from_utf8(ident) {
                Ok(_) => Token::IDENT(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::PatternIdent(ident) => {
            return match from_utf8(ident) {
                Ok(_) => Token::PATTERN_IDENT(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::PatternCount(ident) => {
            return match from_utf8(ident) {
                Ok(_) => Token::PATTERN_COUNT(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::PatternOffset(ident) => {
            return match from_utf8(ident) {
                Ok(_) => Token::PATTERN_OFFSET(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::PatternLength(ident) => {
            return match from_utf8(ident) {
                Ok(_) => Token::PATTERN_LENGTH(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::FloatLit(lit) => {
            return match from_utf8(lit) {
                Ok(_) => Token::FLOAT_LIT(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::IntegerLit(lit) => {
            return match from_utf8(lit) {
                Ok(_) => Token::INTEGER_LIT(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::StringLit(lit) => {
            return match from_utf8(lit) {
                Ok(_) => Token::STRING_LIT(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::Regexp(lit) => {
            return match from_utf8(lit) {
                Ok(_) => Token::REGEXP(span),
                Err(_) => unreachable!(),
            }
        }
        NormalToken::BlockComment(c) | NormalToken::Comment(c) => {
            return match from_utf8(c) {
                Ok(_) => Token::COMMENT(span),
                Err(_) => unreachable!(),
            }
        }
    }
}

fn convert_hex_pattern_token(token: HexPatternToken, span: Span) -> Token {
    match token {
        HexPatternToken::Byte => Token::HEX_BYTE(span),
        HexPatternToken::Pipe => Token::PIPE(span),
        HexPatternToken::LParen => Token::L_PAREN(span),
        HexPatternToken::RParen => Token::R_PAREN(span),
        HexPatternToken::LBracket => Token::L_BRACKET(span),
        HexPatternToken::RBracket => Token::R_BRACKET(span),
        HexPatternToken::Whitespace => Token::WHITESPACE(span),
        HexPatternToken::LF | HexPatternToken::CR | HexPatternToken::CRLF => {
            Token::NEWLINE(span)
        }
        HexPatternToken::BlockComment(c) | HexPatternToken::Comment(c) => {
            return match from_utf8(c) {
                Ok(_) => Token::COMMENT(span),
                Err(_) => unreachable!(),
            }
        }
    }
}

fn convert_hex_jump_token(token: HexJumpToken, span: Span) -> Token {
    match token {
        HexJumpToken::Hyphen => Token::HYPHEN(span),
        HexJumpToken::Whitespace => Token::WHITESPACE(span),
        HexJumpToken::LF | HexJumpToken::CR | HexJumpToken::CRLF => {
            Token::NEWLINE(span)
        }
        HexJumpToken::IntegerLit(lit) => {
            return match from_utf8(lit) {
                Ok(_) => Token::INTEGER_LIT(span),
                Err(_) => unreachable!(),
            }
        }
    }
}
