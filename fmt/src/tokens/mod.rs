use lazy_static::lazy_static;
use std::collections::VecDeque;
use std::str::from_utf8_unchecked;

use yara_x_parser::cst::{Event, SyntaxKind};

#[cfg(test)]
mod tests;

/// Each token used by the formatter belongs to one or more categories. Here we
/// define the existing categories and how they relate to each other.
///
/// Categories are organized in a hierarchical system, category A can be a
/// subcategory of B, which means that a token that belongs to category A also
/// belongs to category B. Base categories are those that don't have
/// subcategories, every token belongs to exactly one base category, and
/// possibly multiple super-categories that encompass two or more base
/// categories.
///
/// A category is represented with a bitmask where each bit corresponds to one
/// of the base categories, and super-categories are bitmasks with multiple
/// bits set to one, corresponding to the base categories contained in the
/// super-category.
pub(crate) mod categories {
    use bitflags::bitflags;
    use lazy_static::lazy_static;

    bitflags! {
        #[derive(Debug, Clone, Copy)]
        pub struct Category: u32 {
            const None                = 0b00000000000000000000000000000001;
            const Begin               = 0b00000000000000000000000000000010;
            const End                 = 0b00000000000000000000000000000100;
            const BlockBegin          = 0b00000000000000000000000000001000;
            const BlockEnd            = 0b00000000000000000000000000010000;
            const AlignmentBlockBegin = 0b00000000000000000000000000100000;
            const AlignmentBlockEnd   = 0b00000000000000000000000001000000;
            const AlignmentMarker     = 0b00000000000000000000000010000000;
            const Indentation         = 0b00000000000000000000000100000000;
            const Whitespace          = 0b00000000000000000000001000000000;
            const Comment             = 0b00000000000000000000010000000000;
            const Newline             = 0b00000000000000000000100000000000;
            const Punctuation         = 0b00000000000000000001000000000000;
            const Identifier          = 0b00000000000000000010000000000000;
            const Keyword             = 0b00000000000000000100000000000000;
            const Literal             = 0b00000000000000001000000000000000;
            const LGrouping           = 0b00000000000000010000000000000000;
            const RGrouping           = 0b00000000000000100000000000000000;
        }
    }
    lazy_static! {
        // These are the base categories (i.e: those that don't contain another category)
        pub static ref NONE: Category =
            Category::None;

        pub static ref END: Category =
            Category::End;

        pub static ref BLOCK_BEGIN: Category =
            Category::BlockBegin;

        pub static ref BLOCK_END: Category =
            Category::BlockEnd;

        pub static ref ALIGNMENT_BLOCK_BEGIN: Category =
            Category::AlignmentBlockBegin;

        pub static ref ALIGNMENT_BLOCK_END: Category =
            Category::AlignmentBlockBegin;

        pub static ref ALIGNMENT_MARKER: Category =
            Category::AlignmentMarker;

        pub static ref INDENTATION: Category =
            Category::Indentation;

        pub static ref WHITESPACE: Category =
            Category::Whitespace;

        pub static ref COMMENT: Category =
            Category::Comment;

        pub static ref NEWLINE: Category =
            Category::Newline;

        pub static ref KEYWORD: Category =
            Category::Keyword;

        pub static ref PUNCTUATION: Category =
            Category::Punctuation;

        pub static ref IDENTIFIER: Category =
            Category::Identifier;

        pub static ref LITERAL: Category =
            Category::Literal;

        pub static ref LGROUPING: Category =
            Category::LGrouping;

        pub static ref RGROUPING: Category =
            Category::RGrouping;

        // These are super-categories that are composed of other categories.
        pub static ref CONTROL: Category =
            Category::Begin |
            Category::End |
            Category::Indentation |
            Category::BlockBegin |
            Category::BlockEnd |
            Category::AlignmentBlockBegin |
            Category::AlignmentBlockEnd;

        pub static ref SPACING: Category =
            Category::Whitespace |
            Category::Newline;

        pub static ref TEXT: Category =
            Category::Keyword |
            Category::Punctuation |
            Category::LGrouping |
            Category::RGrouping |
            Category::Identifier |
            Category::Literal;
    }
}

lazy_static! {
    pub(crate) static ref ASTERISK: Token<'static> = Token::Punctuation(b"*");
    pub(crate) static ref COLON: Token<'static> = Token::Punctuation(b":");
    pub(crate) static ref COMMA: Token<'static> = Token::Punctuation(b",");
    pub(crate) static ref DOT: Token<'static> = Token::Punctuation(b".");
    pub(crate) static ref EQUAL: Token<'static> = Token::Punctuation(b"=");
    pub(crate) static ref HYPHEN: Token<'static> = Token::Punctuation(b"-");
    pub(crate) static ref LBRACE: Token<'static> = Token::Punctuation(b"{");
    pub(crate) static ref RBRACE: Token<'static> = Token::Punctuation(b"}");
    pub(crate) static ref LBRACKET: Token<'static> = Token::LGrouping(b"[");
    pub(crate) static ref RBRACKET: Token<'static> = Token::RGrouping(b"]");
    pub(crate) static ref LPAREN: Token<'static> = Token::LGrouping(b"(");
    pub(crate) static ref RPAREN: Token<'static> = Token::RGrouping(b")");
}

/// Type that represents the tokens used by the formatter.
///
/// The formatter takes the parse tree produced by the parser and converts it
/// to a stream of tokens that flow through a multi-step pipeline that transform
/// the stream into formatted code. Notice that these tokens are used
/// exclusively by the formatter, they are not related to the parser in
/// any form.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) enum Token<'a> {
    #[default]
    None,

    //////////////////////////////////////////////////////////////////////////////////////////
    // Control tokens
    //

    // Indicates the point where a grammar rule starts.
    Begin(SyntaxKind),

    // Indicates the point where a grammar rule ends.
    End(SyntaxKind),

    // Increases or decreases the indentation level. The argument indicates
    // the number of levels (not spaces), a negative number decreases the
    // level by the given amount.
    Indentation(i16),

    // A block is a fragment of code that will be put in a new line and indented if the whole
    // block doesn't fit in a single line. BlockBegin/BlockEnd are used in hex strings like
    // this...
    //
    //  { BlockBegin  XX XX XX XX XX XX ... XX XX XX XX XX XX  BlockEnd }
    //
    // This indicates the hex pattern must be formatted either like this... (if it fits in a line)
    //
    //  { XX XX XX XX XX XX ... XX XX XX XX XX XX }
    //
    // Or like this ... (if it doesn't fit in a line)
    //
    //  {
    //     XX XX XX ... XX XX XX
    //     XX XX XX ... XX XX XX
    //  }
    //
    #[allow(dead_code)] // TODO: remove when BlockBegin is used
    BlockBegin,
    #[allow(dead_code)] // TODO: remove when BlockEnd is used
    BlockEnd,

    // AlignmentBlockBegin/AlignmentBlockEnd indicates the starting/ending
    // point of alignment block. Within an alignment block all occurrences of
    // AlignmentMarker are forced to be in the same column by inserting spaces
    // before it if required. Alignment blocks are used for aligning pattern
    // declarations like this...
    //
    //  $short_identifier       = " ... "
    //  $very_long_identifier   = " ... "
    //  $even_longer_identifier = " ... "
    //
    // An AlignmentMarker is inserted just before each equal sign, in order to
    // force them to be aligned.
    //
    AlignmentBlockBegin,
    AlignmentBlockEnd,
    AlignmentMarker,

    //////////////////////////////////////////////////////////////////////////////////////////
    // Non-control tokens
    //
    Whitespace,
    #[allow(dead_code)]
    Tab,
    Comment(&'a [u8]),

    BlockComment(Vec<Vec<u8>>),
    HeadComment(Vec<Vec<u8>>),
    TailComment(Vec<Vec<u8>>),
    InlineComment(Vec<Vec<u8>>),

    Newline,
    Identifier(&'a [u8]),
    Keyword(&'a [u8]),
    Punctuation(&'a [u8]),
    Literal(&'a [u8]),

    // Left parenthesis and brackets.
    LGrouping(&'a [u8]),
    // Right parenthesis and brackets.
    RGrouping(&'a [u8]),
}

impl<'a> Token<'a> {
    /// Returns the category the token belongs to.
    pub fn category(&'a self) -> categories::Category {
        match self {
            Token::None => categories::Category::None,
            Token::Begin(..) => categories::Category::Begin,
            Token::End(..) => categories::Category::End,
            Token::BlockBegin => categories::Category::BlockBegin,
            Token::BlockEnd => categories::Category::BlockEnd,
            Token::AlignmentBlockBegin => {
                categories::Category::AlignmentBlockBegin
            }
            Token::AlignmentBlockEnd => {
                categories::Category::AlignmentBlockEnd
            }
            Token::AlignmentMarker => categories::Category::AlignmentMarker,
            Token::Indentation(..) => categories::Category::Indentation,
            Token::Whitespace => categories::Category::Whitespace,
            Token::Tab => categories::Category::Whitespace,
            Token::Comment(..)
            | Token::BlockComment(..)
            | Token::TailComment(..)
            | Token::HeadComment(..)
            | Token::InlineComment(..) => categories::Category::Comment,
            Token::Newline => categories::Category::Newline,
            Token::Identifier(..) => categories::Category::Identifier,
            Token::Keyword(..) => categories::Category::Keyword,
            Token::LGrouping(..) => categories::Category::LGrouping,
            Token::RGrouping(..) => categories::Category::RGrouping,
            Token::Punctuation(..) => categories::Category::Punctuation,
            Token::Literal(..) => categories::Category::Literal,
        }
    }

    /// Returns true if the token belongs to a given category or false if
    /// otherwise.
    #[inline(always)]
    pub fn is(&self, category: categories::Category) -> bool {
        category.intersects(self.category())
    }

    /// Negated version of `is`.
    #[inline(always)]
    pub fn is_not(&self, category: categories::Category) -> bool {
        !category.intersects(self.category())
    }

    /// Negated version of `eq`
    #[inline(always)]
    pub fn neq(&self, token: &Token) -> bool {
        !self.eq(token)
    }

    /// Returns the token as a byte slice.
    ///
    /// Some control tokens return an empty slice.
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            Token::Whitespace => b" ",
            Token::Tab => b"\t",
            Token::Newline => b"\n",
            Token::Identifier(s)
            | Token::Keyword(s)
            | Token::Punctuation(s)
            | Token::LGrouping(s)
            | Token::RGrouping(s)
            | Token::Literal(s)
            | Token::Comment(s) => s,
            // Control tokens.
            Token::None
            | Token::Begin(_)
            | Token::End(_)
            | Token::Indentation(_)
            | Token::BlockBegin
            | Token::BlockEnd
            | Token::AlignmentBlockBegin
            | Token::AlignmentBlockEnd
            | Token::AlignmentMarker
            | Token::BlockComment(_)
            | Token::HeadComment(_)
            | Token::TailComment(_)
            | Token::InlineComment(_) => b"",
        }
    }

    /// Returns the length of the token in text form
    ///
    /// The length of control tokens is zero.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Create a token from a parser rule and its associated span.
    fn new(kind: SyntaxKind, src: &'a [u8]) -> Token<'a> {
        match kind {
            // Trivia.
            SyntaxKind::COMMENT => Token::Comment(src),
            SyntaxKind::NEWLINE => Token::Newline,
            // Keywords.
            SyntaxKind::ALL_KW
            | SyntaxKind::AND_KW
            | SyntaxKind::ANY_KW
            | SyntaxKind::ASCII_KW
            | SyntaxKind::AT_KW
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
            | SyntaxKind::WITH_KW
            | SyntaxKind::XOR_KW => Token::Keyword(src),
            // Punctuation.
            SyntaxKind::ASTERISK
            | SyntaxKind::COLON
            | SyntaxKind::COMMA
            | SyntaxKind::DOT
            | SyntaxKind::EQUAL
            | SyntaxKind::L_BRACE
            | SyntaxKind::R_BRACE
            | SyntaxKind::MINUS
            | SyntaxKind::HYPHEN
            | SyntaxKind::PERCENT
            | SyntaxKind::PIPE
            | SyntaxKind::TILDE => Token::Punctuation(src),
            // Grouping
            SyntaxKind::L_BRACKET | SyntaxKind::L_PAREN => {
                Token::LGrouping(src)
            }
            SyntaxKind::R_BRACKET | SyntaxKind::R_PAREN => {
                Token::RGrouping(src)
            }
            // Identifiers.
            SyntaxKind::IDENT
            | SyntaxKind::PATTERN_IDENT
            | SyntaxKind::PATTERN_COUNT
            | SyntaxKind::PATTERN_OFFSET
            | SyntaxKind::PATTERN_LENGTH => Token::Identifier(src),

            // Whitespaces have a special treatment see Tokens::next.
            SyntaxKind::WHITESPACE => unreachable!(),
            // Literals.
            _ => Token::Literal(src),
        }
    }
}

/// A token stream is a sequence of tokens that can be iterated or written
/// to anything implementing the [`std::io::Write`] trait.
pub(crate) trait TokenStream<'a>: Iterator<Item = Token<'a>> {
    /// Write the tokens in text form to the given writer.
    fn write_to<W>(self, mut w: W) -> std::io::Result<()>
    where
        Self: Sized,
        W: std::io::Write,
    {
        let mut col_num = 0;
        for token in self {
            match token {
                Token::Newline => {
                    w.write_all(b"\n")?;
                    col_num = 0;
                }
                Token::Whitespace
                | Token::Tab
                | Token::Comment(_)
                | Token::Identifier(_)
                | Token::Keyword(_)
                | Token::Literal(_)
                | Token::LGrouping(_)
                | Token::RGrouping(_)
                | Token::Punctuation(_) => {
                    w.write_all(token.as_bytes())?;
                    col_num += token.len() as i16;
                }

                Token::BlockComment(lines)
                | Token::HeadComment(lines)
                | Token::TailComment(lines)
                | Token::InlineComment(lines) => {
                    let mut lines = lines.iter();
                    let message_col = col_num;

                    // The first line of the comment is already indented.
                    if let Some(first_line) = lines.next() {
                        col_num += first_line.len() as i16;
                        w.write_all(first_line)?;
                    }

                    // For all remaining lines in a multi-line comment we
                    // need to add the line-break and the corresponding
                    // indentation.
                    for line in lines {
                        w.write_all("\n".as_bytes())?;
                        w.write_all(
                            " ".repeat(message_col as usize).as_bytes(),
                        )?;
                        w.write_all(line)?;
                        col_num = message_col + line.len() as i16;
                    }
                }

                Token::None
                | Token::Indentation(_)
                | Token::Begin(_)
                | Token::End(_)
                | Token::BlockBegin
                | Token::BlockEnd
                | Token::AlignmentBlockBegin
                | Token::AlignmentBlockEnd
                | Token::AlignmentMarker => {
                    // Control tokens are not visible, nothing to write.
                }
            }
        }

        w.flush()
    }
}

// Any type that implements the Iterator<Item = Token<'a>> trait also
// implements the TokenStream trait.
impl<'a, T> TokenStream<'a> for T where T: Iterator<Item = Token<'a>> {}

/// An iterator that takes a sequence of events generated by the parser and
/// produces a sequence of tokens which constitute the input to the formatter.
pub(crate) struct Tokens<'src, E>
where
    E: Iterator<Item = Event>,
{
    source: &'src [u8],
    events: E,
    buffer: VecDeque<Token<'src>>,
}

impl<'src, E> Tokens<'src, E>
where
    E: Iterator<Item = Event>,
{
    pub fn new(source: &'src [u8], events: E) -> Self {
        Self { source, events, buffer: VecDeque::new() }
    }
}

impl<'src, E> Iterator for Tokens<'src, E>
where
    E: Iterator<Item = Event>,
{
    type Item = Token<'src>;

    fn next(&mut self) -> Option<Self::Item> {
        // Return a token from the buffer, if any.
        if let Some(token) = self.buffer.pop_front() {
            return Some(token);
        }
        loop {
            match self.events.next()? {
                Event::Begin(kind) => return Some(Token::Begin(kind)),
                Event::End(kind) => return Some(Token::End(kind)),
                Event::Token { kind, span } => {
                    let token_bytes = &self.source[span.range()];
                    // The whitespace token has a different treatment because
                    // the parser returns a single whitespace token when
                    // multiple whitespaces appear together. Here we separate
                    // them into individual spaces.
                    return if kind == SyntaxKind::WHITESPACE {
                        // SAFETY: It's safe to assume that the whitespace
                        // token is composed of valid UTF-8 characters. The
                        // tokenizer guarantees this.
                        let s = unsafe { from_utf8_unchecked(token_bytes) };
                        for _ in s.chars() {
                            self.buffer.push_back(Token::Whitespace);
                        }
                        self.buffer.pop_front()
                    } else {
                        Some(Token::new(kind, token_bytes))
                    };
                }
                Event::Error { .. } => { /* ignore errors */ }
            }
        }
    }
}
