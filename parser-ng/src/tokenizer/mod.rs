/*! Implements the YARA tokenizer.

Tokenization is the first step in the compilation process. The tokenizer takes
YARA source code and produces a sequence of tokens that is later processed by
the parser.

Each token is represented by a variant of the [`Token`] type.
*/

use logos::Logos;
use logos::Source;
use std::mem;
use std::str;
use std::str::from_utf8;

use crate::Span;

mod tokens;

pub use tokens::Token;

#[cfg(test)]
mod tests;

/// Takes YARA source code and produces a sequence of tokens.
///
/// The tokenizer has two modes of operation: normal mode and hex pattern mode.
/// In normal mode the tokenizer recognizes most of the tokens in YARA's syntax,
/// like keywords (e.g: `rule`, `condition`, `for`, etc.), identifiers, string
/// literals, etc. In hex pattern mode, the tokenizer only recognizes the tokens
/// that can appear in a hex pattern.
///
/// This distinction is crucial because certain tokens, like `a0`, have
/// different meanings depending on the mode. Outside a hex pattern, `a0` is an
/// identifier; inside, it's a byte literal.
///
/// The tokenizer itself is unable to know whether `a0` is inside a hex pattern,
/// only the parser can know that. Therefore, it is the parser's responsibility
/// to switch the tokenizer to hex pattern mode after parsing the opening brace
/// (`{`) of a hex pattern. This is done by invoking
/// [`Tokenizer::enter_hex_pattern_mode`]. The tokenizer will automatically
/// revert to normal mode when it encounters the closing brace (`}`).
///
/// The source code passed to the tokenizer doesn't need to be valid UTF-8,
/// when the tokenizer finds some invalid UTF-8 sequence, it will return the
/// special token [`Token::INVALID_UTF8`] containing the invalid bytes, and
/// will continue tokenizing the remaining content.
pub struct Tokenizer<'src> {
    source: &'src [u8],
    mode: Mode<'src>,
}

impl<'src> Tokenizer<'src> {
    /// Creates a new [`Tokenizer`].
    pub fn new(source: &'src [u8]) -> Self {
        // Can't handle source files greater than the maximum span size.
        assert!(source.len() < Span::MAX);
        Self { source, mode: Mode::Normal(Logos::lexer(source)) }
    }

    /// Returns the source code passed to the tokenizer.
    #[inline]
    pub fn source(&self) -> &'src [u8] {
        self.source
    }

    /// Returns the next token.
    pub fn next_token(&mut self) -> Option<Token> {
        match &mut self.mode {
            Mode::Normal(lexer) => match lexer.next()? {
                Ok(token) => {
                    Some(convert_normal_token(token, lexer.span().into()))
                }
                Err(()) => Some(unexpected_token(lexer)),
            },
            Mode::HexPattern(lexer) => match lexer.next()? {
                Ok(token) => {
                    Some(convert_hex_pattern_token(token, lexer.span().into()))
                }
                Err(()) => {
                    let span = lexer.span().into();
                    // If the unexpected input is the closing brace `}`
                    // every thing is ok, return the RBrace token and
                    // go back to normal parsing mode.
                    if lexer.slice() == b"}" {
                        self.toggle_mode();
                        Some(Token::R_BRACE(span))
                    } else {
                        Some(unexpected_token(lexer))
                    }
                }
            },
            Mode::Undefined => unreachable!(),
        }
    }

    /// Switches the tokenizer to hex pattern operation mode.
    ///
    /// The parser must invoke this function after processing the opening
    /// brace of a hex pattern. The tokenizer will automatically revert back to
    /// normal mode when encounters the closing brace.
    ///
    /// See [`Tokenizer`] for more details about operation modes.
    ///
    /// # Panics
    ///
    /// If the tokenizer is already in hex pattern operation mode.
    pub fn enter_hex_pattern_mode(&mut self) {
        assert!(matches!(self.mode, Mode::Normal(_)));
        self.toggle_mode();
    }

    /// Toggles the operation mode from normal to hex pattern and vice versa.
    fn toggle_mode(&mut self) {
        self.mode = match mem::take(&mut self.mode) {
            Mode::Normal(lexer) => {
                Mode::HexPattern(lexer.morph::<HexPatternToken>())
            }
            Mode::HexPattern(lexer) => {
                Mode::Normal(lexer.morph::<NormalToken>())
            }
            Mode::Undefined => unreachable!(),
        };
    }
}

/// Describes the current mode of operation for a tokenizer.
///
/// [`Tokenizer`] uses the [`logos`] crate under the hood for doing the actual
/// work. It uses two different logos lexers, one for the normal mode, and
/// another one for the hex pattern mode.
#[derive(Default)]
enum Mode<'src> {
    #[default]
    Undefined,
    Normal(logos::Lexer<'src, NormalToken<'src>>),
    HexPattern(logos::Lexer<'src, HexPatternToken>),
}

#[derive(logos::Logos, Debug, PartialEq)]
#[logos(source = [u8])]
enum NormalToken<'src> {
    // Keywords
    #[token("condition")]
    Condition,
    #[token("false")]
    False,
    #[token("global")]
    Global,
    #[token("import")]
    Import,
    #[token("meta")]
    Meta,
    #[token("private")]
    Private,
    #[token("rule")]
    Rule,
    #[token("true")]
    True,

    // Punctuation
    #[token(":")]
    Colon,
    #[token("=")]
    Equal,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,

    // Identifiers must start with underscore or letter, followed by any
    // number of underscores, letters, or digits.
    #[regex(
        r#"(?x)                         # allow comments in the regexp
            ([[:alpha:]]|_)             # first character is letter or _
            ([[:alpha:]]|\d|_)*         # any number of letters, digits, or _
        "#,
        |token| token.slice())
    ]
    Identifier(&'src [u8]),

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

    // String literals start and ends with double quotes, in-between the quotes
    // they contain either the \" escape sequence, or anything that is not a
    // quote or newline.
    #[regex(
        r#"(?x)                         # allow comments in the regexp
        "                               # starts with double quotes
        (                               # any number of
          \\"                           #   the \" escape sequence
          |                             #   or..
          [^"\n]                        #   anything except quotes or newlines
        )*
        "                               # ends with double quotes
        "#,
        |token| token.slice())
    ]
    StringLit(&'src [u8]),

    #[regex(" ")]
    Whitespace,

    #[token("\n")]
    Newline,
}

#[derive(logos::Logos, Debug, PartialEq)]
#[logos(source = [u8])]
enum HexPatternToken {
    #[regex("[0-9a-fA-F]{2}")]
    Byte,

    #[regex(" ")]
    Whitespace,

    #[token("\n")]
    Newline,
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

    lexer.bump(unexpected.len() - lexer.span().len());
    Token::UNKNOWN(Span(start as u32..(start + unexpected.len()) as u32))
}

fn convert_normal_token(token: NormalToken, span: Span) -> Token {
    match token {
        NormalToken::Condition => Token::CONDITION_KW(span),
        NormalToken::False => Token::FALSE_KW(span),
        NormalToken::Global => Token::GLOBAL_KW(span),
        NormalToken::Import => Token::IMPORT_KW(span),
        NormalToken::Meta => Token::META_KW(span),
        NormalToken::Private => Token::PRIVATE_KW(span),
        NormalToken::Rule => Token::RULE_KW(span),
        NormalToken::True => Token::TRUE_KW(span),
        NormalToken::Colon => Token::COLON(span),
        NormalToken::Equal => Token::EQUAL(span),
        NormalToken::LBrace => Token::L_BRACE(span),
        NormalToken::RBrace => Token::R_BRACE(span),
        NormalToken::Whitespace => Token::WHITESPACE(span),
        NormalToken::Newline => Token::NEWLINE(span),
        NormalToken::Identifier(ident) => {
            return match from_utf8(ident) {
                Ok(_) => Token::IDENT(span),
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
    }
}

fn convert_hex_pattern_token(token: HexPatternToken, span: Span) -> Token {
    match token {
        HexPatternToken::Byte => Token::HEX_BYTE(span),
        HexPatternToken::Whitespace => Token::WHITESPACE(span),
        HexPatternToken::Newline => Token::NEWLINE(span),
    }
}
