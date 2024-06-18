use std::fmt::{Debug, Display, Formatter};

use yara_x_macros::Error as DeriveError;

use crate::ast::Span;
use crate::parser::grammar::Rule;
use crate::report::Level;
use crate::report::ReportBuilder;

/// An error occurred while parsing YARA rules.
///
/// Each variant also contains additional pieces of information that are
/// relevant for that specific error. This information is usually contained
/// inside the detailed report itself, but having access to the individual
/// pieces is useful for applications that can't rely on text-based reports.
#[derive(Eq, PartialEq)]
pub struct Error(Box<ErrorInfo>);

impl Error {
    /// Returns a unique error code identifying the type of error.
    #[inline]
    pub fn code(&self) -> &'static str {
        self.0.code()
    }

    /// Returns additional information about the error.
    #[inline]
    pub fn info(&self) -> &ErrorInfo {
        self.0.as_ref()
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

/// Additional information about an error occurred during parsing.
#[rustfmt::skip]
#[derive(DeriveError, Eq, PartialEq)]
pub enum ErrorInfo {
    #[error("E001", "syntax error")]
    #[label("{error_msg}", error_span)]
    SyntaxError {
        detailed_report: String,
        error_msg: String,
        error_span: Span
    },

    #[error("E002", "duplicate tag `{tag}`")]
    #[label("duplicate tag", tag_span)]
    DuplicateTag {
        detailed_report: String,
        tag: String,
        tag_span: Span,
    },
    
    #[error("E003", "duplicate pattern `{pattern_ident}`")]
    #[label(
        "duplicate declaration of `{pattern_ident}`",
        new_pattern_span
    )]
    #[label(
        "`{pattern_ident}` declared here for the first time",
        existing_pattern_span,
        style="note"
    )]
    DuplicatePattern {
        detailed_report: String,
        pattern_ident: String,
        new_pattern_span: Span,
        existing_pattern_span: Span,
    },

    #[error("E004", "invalid pattern modifier")]
    #[label("{error_msg}", error_span)]
    InvalidModifier {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("E005", "duplicate pattern modifier")]
    #[label("duplicate modifier", modifier_span)]
    DuplicateModifier {
        detailed_report: String,
        modifier_span: Span,
    },

    #[error("E006", "invalid modifier combination: `{modifier1}` `{modifier2}`")]
    #[label("`{modifier1}` modifier used here", modifier1_span)]
    #[label("`{modifier2}` modifier used here", modifier2_span)]
    #[note(note)]
    InvalidModifierCombination {
        detailed_report: String,
        modifier1: String,
        modifier2: String,
        modifier1_span: Span,
        modifier2_span: Span,
        note: Option<String>,
    },

    #[error("E007", "invalid base64 alphabet")]
    #[label("{error_msg}", error_span)]
    InvalidBase64Alphabet {
        detailed_report: String,
        error_msg: String,
        error_span: Span},
    
    #[error("E008", "unused pattern `{pattern_ident}`")]
    #[label("this pattern was not used in the condition", pattern_ident_span)]
    UnusedPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: Span,
    },

    #[error("E009", "unknown pattern `{pattern_ident}`")]
    #[label("this pattern is not declared in the `strings` section", pattern_ident_span)]
    UnknownPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: Span,
    },

    #[error("E010", "invalid pattern `{pattern_ident}`")]
    #[label("{error_msg}", error_span)]
    #[note(note)]
    InvalidPattern {
        detailed_report: String,
        pattern_ident: String,
        error_msg: String,
        error_span: Span,
        note: Option<String>,
    },

    #[error("E011", "invalid range")]
    #[label("{error_msg}", error_span)]
    InvalidRange {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("E012", "invalid integer")]
    #[label("{error_msg}", error_span)]
    InvalidInteger {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("E013", "invalid float")]
    #[label("{error_msg}", error_span)]
    InvalidFloat {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("E014", "invalid escape sequence")]
    #[label("{error_msg}", error_span)]
    InvalidEscapeSequence {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("E015", "unexpected escape sequence")]
    #[label("escape sequences are not allowed in this string", error_span)]
    UnexpectedEscapeSequence {
        detailed_report: String,
        error_span: Span,
    },

    #[error("E016", "invalid regexp modifier `{modifier}`")]
    #[label("invalid modifier", error_span)]
    InvalidRegexpModifier {
        detailed_report: String,
        modifier: String,
        error_span: Span,
    },
    
    #[error("E017", "invalid UTF-8")]
    #[label("invalid UTF-8 character", error_span)]
    InvalidUTF8 {
        detailed_report: String,
        error_span: Span},
}

impl From<ErrorInfo> for Error {
    fn from(value: ErrorInfo) -> Self {
        Self(Box::new(value))
    }
}

impl ErrorInfo {
    pub(crate) fn syntax_error_message<F>(
        expected: &[Rule],
        unexpected: &[Rule],
        mut f: F,
    ) -> String
    where
        F: FnMut(&Rule) -> &str,
    {
        // Remove COMMENT and WHITESPACE from the lists of expected and not
        // expected rules. We don't want error messages like:
        //
        //    expected identifier or COMMENT
        //    expected { or WHITESPACE
        //
        // The alternative solution is silencing those rules in grammar.pest,
        // but that means that Pest will completely ignore them and we won't
        // get comments nor spaces in the parse tree. We want those rules in
        // the parse tree, but we don't want them in error messages. This is
        // probably an area of improvement for Pest.
        let expected: Vec<&str> = expected
            .iter()
            .filter(|&&rule| rule != Rule::COMMENT && rule != Rule::WHITESPACE)
            .map(&mut f)
            .collect();

        let unexpected: Vec<&str> = unexpected
            .iter()
            .filter(|&&rule| rule != Rule::COMMENT && rule != Rule::WHITESPACE)
            .map(&mut f)
            .collect();

        match (unexpected.is_empty(), expected.is_empty()) {
            (false, false) => format!(
                "unexpected {}; expected {}",
                Self::join_with_or(&unexpected, false),
                Self::join_with_or(&expected, false)
            ),
            (false, true) => {
                format!(
                    "unexpected {}",
                    Self::join_with_or(&unexpected, false)
                )
            }
            (true, false) => {
                format!("expected {}", Self::join_with_or(&expected, false))
            }
            (true, true) => "unknown parsing error".to_owned(),
        }
    }

    /// Utility function that receives an array of strings and joins them
    /// together separated by commas and with "or" before the last one.
    /// For example, if input is `["s1", "s2", "s3"]` the result is:
    ///
    /// ```text
    /// str1, str2 or str3
    /// ```
    ///
    /// If `quotes` is true, the strings are enclosed in back tilts, like this:
    ///
    /// ```text
    /// `str1`, `str2` or `str3`
    /// ```
    ///
    pub fn join_with_or<S: ToString>(s: &[S], quotes: bool) -> String {
        let mut strings = if quotes {
            s.iter()
                .map(|s| format!("`{}`", s.to_string()))
                .collect::<Vec<String>>()
        } else {
            s.iter().map(|s| s.to_string()).collect::<Vec<String>>()
        };

        // Sort alphabetically.
        strings.sort();

        // Deduplicate repeated items.
        strings.dedup();

        match strings.len() {
            1 => strings[0].to_owned(),
            2 => format!("{} or {}", strings[0], strings[1]),
            l => {
                format!(
                    "{}, or {}",
                    strings[..l - 1].join(", "),
                    strings[l - 1]
                )
            }
        }
    }

    /// Given a grammar rule returns a more appropriate string that will be used
    /// in error messages.
    pub(crate) fn printable_string(rule: &Rule) -> &str {
        match rule {
            // Keywords
            Rule::k_ALL => "`all`",
            Rule::k_ANY => "`any`",
            Rule::k_ASCII => "`ascii`",
            Rule::k_AT => "`at`",
            Rule::k_BASE64 => "`base64`",
            Rule::k_BASE64WIDE => "`base64wide`",
            Rule::k_CONDITION => "`condition`",
            Rule::k_DEFINED => "`defined`",
            Rule::k_ENTRYPOINT => "`entrypoint`",
            Rule::k_FALSE => "`false`",
            Rule::k_FILESIZE => "`filesize`",
            Rule::k_FOR => "`for`",
            Rule::k_FULLWORD => "`fullword`",
            Rule::k_GLOBAL => "`global`",
            Rule::k_IMPORT => "`import`",
            Rule::k_IN => "`in`",
            Rule::k_META => "`meta`",
            Rule::k_NOCASE => "`nocase`",
            Rule::k_NONE => "`none`",
            Rule::k_NOT => "`not`",
            Rule::k_OF => "`of`",
            Rule::k_PRIVATE => "`private`",
            Rule::k_RULE => "`rule`",
            Rule::k_STRINGS => "`strings`",
            Rule::k_THEM => "`them`",
            Rule::k_TRUE => "`true`",
            Rule::k_WIDE => "`wide`",
            Rule::k_XOR => "`xor`",

            Rule::boolean_expr | Rule::boolean_term => "boolean expression",

            Rule::expr | Rule::primary_expr | Rule::term => "expression",

            Rule::hex_byte => "byte",
            Rule::hex_tokens => "bytes",
            Rule::ident => "identifier",
            Rule::integer_lit => "number",
            Rule::float_lit => "number",
            Rule::rule_decl => "rule declaration",
            Rule::source_file => "YARA rules",
            Rule::string_lit => "string literal",
            Rule::multiline_string_lit => "string literal",
            Rule::regexp => "regular expression",
            Rule::pattern_mods => "pattern modifiers",

            Rule::pattern_ident | Rule::pattern_ident_wildcarded => {
                "pattern identifier"
            }

            Rule::ADD
            | Rule::k_AND
            | Rule::k_OR
            | Rule::SUB
            | Rule::DIV
            | Rule::MUL
            | Rule::MOD
            | Rule::SHL
            | Rule::SHR
            | Rule::BITWISE_AND
            | Rule::BITWISE_OR
            | Rule::BITWISE_XOR
            | Rule::BITWISE_NOT
            | Rule::EQ
            | Rule::NE
            | Rule::GE
            | Rule::GT
            | Rule::LE
            | Rule::LT
            | Rule::k_STARTSWITH
            | Rule::k_ISTARTSWITH
            | Rule::k_ENDSWITH
            | Rule::k_IENDSWITH
            | Rule::k_IEQUALS
            | Rule::k_CONTAINS
            | Rule::k_ICONTAINS
            | Rule::k_MATCHES => "operator",

            Rule::PIPE => "pipe `|`",
            Rule::COMMA => "comma `,`",
            Rule::DOT => "dot `.`",
            Rule::DOT_DOT => "`..`",
            Rule::EQUAL => "equal `=` ",
            Rule::PERCENT => "percent `%`",
            Rule::MINUS => "`-`",
            Rule::COLON => "colon `:`",
            Rule::HYPHEN => "hyphen `-`",
            Rule::ASTERISK => "asterisk `*`",
            Rule::DOUBLE_QUOTES => "quotes `\"`",
            Rule::TILDE => "tilde `~`",

            Rule::LPAREN => "opening parenthesis `(`",
            Rule::RPAREN => "closing parenthesis `)`",
            Rule::LBRACE => "opening brace `{`",
            Rule::RBRACE => "closing brace `}`",
            Rule::LBRACKET => "opening bracket `[`",
            Rule::RBRACKET => "closing bracket `]`",
            Rule::EOI => "end of file",

            Rule::COMMENT
            | Rule::WHITESPACE
            | Rule::keyword
            | Rule::arithmetic_op
            | Rule::bitwise_op
            | Rule::comparison_op
            | Rule::string_op
            | Rule::block_comment
            | Rule::single_line_comment
            | Rule::import_stmt
            | Rule::ident_chars
            | Rule::pattern_count
            | Rule::pattern_offset
            | Rule::pattern_length
            | Rule::rule_mods
            | Rule::rule_tags
            | Rule::meta_defs
            | Rule::meta_def
            | Rule::pattern_defs
            | Rule::pattern_def
            | Rule::hex_pattern
            | Rule::hex_alternative
            | Rule::hex_jump
            | Rule::indexing_expr
            | Rule::func_call_expr
            | Rule::of_expr
            | Rule::for_expr
            | Rule::iterable
            | Rule::quantifier
            | Rule::range
            | Rule::expr_tuple
            | Rule::boolean_expr_tuple
            | Rule::pattern_ident_tuple => {
                unreachable!()
            }
        }
    }
}
