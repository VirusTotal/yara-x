use std::iter::Peekable;

use lazy_static::lazy_static;

use yara_x_parser::cst::CST;
use yara_x_parser::GrammarRule;

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
    use bitmask::bitmask;
    use lazy_static::lazy_static;

    bitmask! {
        #[derive(Debug)]
        pub mask Category: u32 where flags BaseCategory  {
            None                = 0b00000000000000000000000000000001,
            Begin               = 0b00000000000000000000000000000010,
            End                 = 0b00000000000000000000000000000100,
            BlockBegin          = 0b00000000000000000000000000001000,
            BlockEnd            = 0b00000000000000000000000000010000,
            AlignmentBlockBegin = 0b00000000000000000000000000100000,
            AlignmentBlockEnd   = 0b00000000000000000000000001000000,
            AlignmentMarker     = 0b00000000000000000000000010000000,
            Indentation         = 0b00000000000000000000000100000000,
            Whitespace          = 0b00000000000000000000001000000000,
            Comment             = 0b00000000000000000000010000000000,
            Newline             = 0b00000000000000000000100000000000,
            Punctuation         = 0b00000000000000000001000000000000,
            Identifier          = 0b00000000000000000010000000000000,
            Operator            = 0b00000000000000000100000000000000,
            Keyword             = 0b00000000000000001000000000000000,
            Literal             = 0b00000000000000010000000000000000,
            LGrouping           = 0b00000000000000100000000000000000,
            RGrouping           = 0b00000000000001000000000000000000,
        }
    }
    lazy_static! {
        // These are the base categories (i.e: those that don't contain another category)
        pub static ref NONE: Category =
            Category::from(BaseCategory::None);

        pub static ref BEGIN: Category =
            Category::from(BaseCategory::Begin);

        pub static ref END: Category =
            Category::from(BaseCategory::End);

        pub static ref BLOCK_BEGIN: Category =
            Category::from(BaseCategory::BlockBegin);

        pub static ref BLOCK_END: Category =
            Category::from(BaseCategory::BlockEnd);

        pub static ref ALIGNMENT_BLOCK_BEGIN: Category =
            Category::from(BaseCategory::AlignmentBlockBegin);

        pub static ref ALIGNMENT_BLOCK_END: Category =
            Category::from(BaseCategory::AlignmentBlockBegin);

        pub static ref ALIGNMENT_MARKER: Category =
            Category::from(BaseCategory::AlignmentMarker);

        pub static ref INDENTATION: Category =
            Category::from(BaseCategory::Indentation);

        pub static ref WHITESPACE: Category =
            Category::from(BaseCategory::Whitespace);

        pub static ref COMMENT: Category =
            Category::from(BaseCategory::Comment);

        pub static ref NEWLINE: Category =
            Category::from(BaseCategory::Newline);

        pub static ref KEYWORD: Category =
            Category::from(BaseCategory::Keyword);

        pub static ref PUNCTUATION: Category =
            Category::from(BaseCategory::Punctuation);

        pub static ref IDENTIFIER: Category =
            Category::from(BaseCategory::Identifier);

        pub static ref OPERATOR: Category =
            Category::from(BaseCategory::Operator);

        pub static ref LITERAL: Category =
            Category::from(BaseCategory::Literal);

        pub static ref LGROUPING: Category =
            Category::from(BaseCategory::LGrouping);

        pub static ref RGROUPING: Category =
            Category::from(BaseCategory::RGrouping);

        // These are super-categories that are composed of other categories.
        pub static ref CONTROL: Category =
            *BEGIN |
            *END |
            *INDENTATION |
            *BLOCK_BEGIN |
            *BLOCK_END |
            *ALIGNMENT_BLOCK_BEGIN |
            *ALIGNMENT_BLOCK_END;

        pub static ref SPACING: Category =
            *WHITESPACE |
            *NEWLINE;

        pub static ref TEXT: Category =
            *KEYWORD |
            *PUNCTUATION |
            *LGROUPING |
            *RGROUPING |
            *IDENTIFIER |
            *OPERATOR |
            *LITERAL;
    }
}

lazy_static! {
    pub(crate) static ref COLON: Token<'static> = Token::Punctuation(":");
    pub(crate) static ref DOT: Token<'static> = Token::Punctuation(".");
    pub(crate) static ref DOT_DOT: Token<'static> = Token::Punctuation("..");
    pub(crate) static ref EQUAL: Token<'static> = Token::Punctuation("=");
    pub(crate) static ref HYPHEN: Token<'static> = Token::Punctuation("-");
    pub(crate) static ref LBRACE: Token<'static> = Token::Punctuation("{");
    pub(crate) static ref RBRACE: Token<'static> = Token::Punctuation("}");
    pub(crate) static ref LBRACKET: Token<'static> = Token::LGrouping("[");
    pub(crate) static ref RBRACKET: Token<'static> = Token::RGrouping("]");
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
    Begin(GrammarRule),

    // Indicates the point where a grammar rule ends.
    End(GrammarRule),

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
    BlockBegin,
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
    Comment(&'a str),

    BlockComment(Vec<String>),
    HeadComment(Vec<String>),
    TailComment(Vec<String>),
    InlineComment(Vec<String>),

    Newline,
    Identifier(&'a str),
    Keyword(&'a str),
    Punctuation(&'a str),
    Literal(&'a str),

    // Left parenthesis and brackets.
    LGrouping(&'a str),
    // Right parenthesis and brackets.
    RGrouping(&'a str),
}

impl<'a> Token<'a> {
    /// Returns the category the token belongs to.
    pub fn category(&'a self) -> categories::BaseCategory {
        match self {
            Token::None => categories::BaseCategory::None,
            Token::Begin(..) => categories::BaseCategory::Begin,
            Token::End(..) => categories::BaseCategory::End,
            Token::BlockBegin => categories::BaseCategory::BlockBegin,
            Token::BlockEnd => categories::BaseCategory::BlockEnd,
            Token::AlignmentBlockBegin => {
                categories::BaseCategory::AlignmentBlockBegin
            }
            Token::AlignmentBlockEnd => {
                categories::BaseCategory::AlignmentBlockEnd
            }
            Token::AlignmentMarker => {
                categories::BaseCategory::AlignmentMarker
            }
            Token::Indentation(..) => categories::BaseCategory::Indentation,
            Token::Whitespace => categories::BaseCategory::Whitespace,
            Token::Comment(..)
            | Token::BlockComment(..)
            | Token::TailComment(..)
            | Token::HeadComment(..)
            | Token::InlineComment(..) => categories::BaseCategory::Comment,
            Token::Newline => categories::BaseCategory::Newline,
            Token::Identifier(..) => categories::BaseCategory::Identifier,
            Token::Keyword(..) => categories::BaseCategory::Keyword,
            Token::LGrouping(..) => categories::BaseCategory::LGrouping,
            Token::RGrouping(..) => categories::BaseCategory::RGrouping,
            Token::Punctuation(..) => categories::BaseCategory::Punctuation,
            Token::Literal(..) => categories::BaseCategory::Literal,
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

    /// Returns the token as a string slice. Some control tokens return an
    /// empty string,
    pub fn as_str(&self) -> &'a str {
        match self {
            Token::Whitespace => " ",
            Token::Newline => "\n",
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
            | Token::InlineComment(_) => "",
        }
    }

    /// Returns the length of the token in text form
    ///
    /// The length of control tokens is zero.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Create a token from a parser rule and its associated span.
    fn from_rule(rule: GrammarRule, src: &'a str) -> Token<'a> {
        match rule {
            // Comment.
            GrammarRule::COMMENT => Token::Comment(src),
            // Whitespace.
            GrammarRule::WHITESPACE => match src {
                // The CST treats newlines as a type of whitespace, but the
                // formatter has different type of tokens for newlines and
                // whitespaces.
                "\r" | "\n" => Token::Newline,
                " " | "\t" => Token::Whitespace,
                _ => unreachable!(),
            },
            // Keywords.
            GrammarRule::k_ALL
            | GrammarRule::k_AND
            | GrammarRule::k_ANY
            | GrammarRule::k_ASCII
            | GrammarRule::k_AT
            | GrammarRule::k_BASE64
            | GrammarRule::k_BASE64WIDE
            | GrammarRule::k_CONDITION
            | GrammarRule::k_CONTAINS
            | GrammarRule::k_DEFINED
            | GrammarRule::k_ENDSWITH
            | GrammarRule::k_ENTRYPOINT
            | GrammarRule::k_FALSE
            | GrammarRule::k_FILESIZE
            | GrammarRule::k_FOR
            | GrammarRule::k_FULLWORD
            | GrammarRule::k_GLOBAL
            | GrammarRule::k_ICONTAINS
            | GrammarRule::k_IENDSWITH
            | GrammarRule::k_IEQUALS
            | GrammarRule::k_IMPORT
            | GrammarRule::k_IN
            | GrammarRule::k_ISTARTSWITH
            | GrammarRule::k_MATCHES
            | GrammarRule::k_META
            | GrammarRule::k_NOCASE
            | GrammarRule::k_NONE
            | GrammarRule::k_NOT
            | GrammarRule::k_OF
            | GrammarRule::k_OR
            | GrammarRule::k_PRIVATE
            | GrammarRule::k_RULE
            | GrammarRule::k_STARTSWITH
            | GrammarRule::k_STRINGS
            | GrammarRule::k_THEM
            | GrammarRule::k_TRUE
            | GrammarRule::k_WIDE
            | GrammarRule::k_XOR => Token::Keyword(src),
            // Punctuation.
            GrammarRule::ASTERISK
            | GrammarRule::COLON
            | GrammarRule::COMMA
            | GrammarRule::DOT
            | GrammarRule::DOT_DOT
            | GrammarRule::EQUAL
            | GrammarRule::DOUBLE_QUOTES
            | GrammarRule::LBRACE
            | GrammarRule::RBRACE
            | GrammarRule::MINUS
            | GrammarRule::HYPHEN
            | GrammarRule::PERCENT
            | GrammarRule::PIPE
            | GrammarRule::TILDE => Token::Punctuation(src),
            // Grouping
            GrammarRule::LBRACKET | GrammarRule::LPAREN => {
                Token::LGrouping(src)
            }
            GrammarRule::RBRACKET | GrammarRule::RPAREN => {
                Token::RGrouping(src)
            }
            // Identifiers.
            GrammarRule::ident
            | GrammarRule::pattern_ident
            | GrammarRule::pattern_count
            | GrammarRule::pattern_offset
            | GrammarRule::pattern_length => Token::Identifier(src),
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
                    w.write_all("\n".as_bytes())?;
                    col_num = 0;
                }
                Token::Whitespace
                | Token::Comment(_)
                | Token::Identifier(_)
                | Token::Keyword(_)
                | Token::Literal(_)
                | Token::LGrouping(_)
                | Token::RGrouping(_)
                | Token::Punctuation(_) => {
                    w.write_all(token.as_str().as_bytes())?;
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
                        w.write_all(first_line.as_bytes())?;
                    }

                    // For all remaining lines in a multi-line comment we
                    // need to add the line-break and the corresponding
                    // indentation.
                    for line in lines {
                        w.write_all("\n".as_bytes())?;
                        w.write_all(
                            " ".repeat(message_col as usize).as_bytes(),
                        )?;
                        w.write_all(line.as_bytes())?;
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

/// An iterator that takes a parse tree generated by the parser and produces a
/// sequence of tokens.
pub(crate) struct Tokens<'a> {
    // Each item in this stack contains a parser rule (i.e: rule_decl,
    // boolean_expr, identifier, etc) and the parse tree corresponding to this
    // rule.
    stack: Vec<(Option<super::GrammarRule>, Peekable<CST<'a>>)>,
}

impl<'a> Tokens<'a> {
    pub fn new(parse_tree: CST<'a>) -> Self {
        Self { stack: vec![(None, parse_tree.peekable())] }
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stack.is_empty() {
            return None;
        }
        // Get the CST at the top of the stack, without removing it from the
        // stack. It will be removed from the stack when all the rules in the
        // parse tree are processed.
        let (_, cst) = self.stack.last_mut().unwrap();

        // Ignore the End-Of-Input (EOI) rule.
        let mut cst = cst.filter(|i| i.as_rule() != GrammarRule::EOI);

        // Get the next (rule, span) pair from the CST at the top of the stack.
        if let Some(pair) = cst.next() {
            let src = pair.as_str();
            let rule = pair.as_rule();
            let mut sub_tree = pair.into_inner().peekable();
            // If the current rule contains inner rules we must process the
            // inner rules first, so the current rule is put in the stack for
            // later processing.
            if sub_tree.peek().is_some() {
                self.stack.push((Some(rule), sub_tree));
                Some(Token::Begin(rule))
            } else {
                Some(Token::from_rule(rule, src))
            }
        } else {
            // No more pairs in the parse tree at the top of the stack, remove
            // it from the stack and return a token indicating the end of the
            // rule.
            let (rule, _) = self.stack.pop().unwrap();
            // Return Some(Token::End(rule)) if rule is not None, or return
            // None if otherwise.
            rule.map(Token::End)
        }
    }
}
