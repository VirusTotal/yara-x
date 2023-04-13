use std::fmt::{Debug, Display, Formatter};
use yara_x_macros::Error as Err;

use crate::ast::Span;
use crate::report::ReportBuilder;
use crate::report::ReportType;
use crate::SourceCode;

use super::GrammarRule;

/// An error occurred while parsing YARA rules.
///
/// Each variant also contains additional pieces of information that are
/// relevant for that specific error. This information is usually contained
/// inside the detailed report itself, but having access to the individual
/// pieces is useful for applications that can't rely on text-based reports.
pub struct Error(Box<ErrorInfo>);

impl Error {
    pub(crate) fn new(info: ErrorInfo) -> Self {
        Self(Box::new(info))
    }

    /// Returns a string with a detailed text-mode report like this one ...
    ///
    /// ```text
    /// error: duplicate tag `tag1`
    ///    ╭─[line:1:18]
    ///    │
    ///  1 │ rule test : tag1 tag1 { condition: true }
    ///    ·                  ──┬─
    ///    ·                    ╰─── duplicate tag
    /// ───╯
    /// ```
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns additional information about the error.
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
#[derive(Err)]
pub enum ErrorInfo {
    #[error("syntax error")]
    #[label("{error_msg}", error_span)]
    SyntaxError {
        detailed_report: String,
        error_msg: String,
        error_span: Span
    },

    #[error("duplicate tag `{tag}`")]
    #[label("duplicate tag", tag_span)]
    DuplicateTag {
        detailed_report: String,
        tag: String,
        tag_span: Span,
    },

    #[error("duplicate rule `{rule_ident}`")]
    #[label(
        "duplicate declaration of `{rule_ident}`",
        new_rule_name_span
    )]
    #[label(
        "`{rule_ident}` declared here for the first time",
        existing_rule_name_span,
        style="note"
    )]
    DuplicateRule {
        detailed_report: String,
        rule_ident: String,
        new_rule_name_span: Span,
        existing_rule_name_span: Span,
    },

    #[error("duplicate pattern `{pattern_ident}`")]
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

    #[error("invalid pattern modifier")]
    #[label("{error_msg}", error_span)]
    InvalidModifier {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("duplicate pattern modifier")]
    #[label("duplicate modifier", modifier_span)]
    DuplicateModifier {
        detailed_report: String,
        modifier_span: Span,
    },

    #[error(
        "invalid modifier combination: `{modifier1}` `{modifier2}`",
    )]
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

    #[error("invalid base64 alphabet")]
    #[label("{error_msg}", error_span)]
    InvalidBase64Alphabet {
        detailed_report: String,
        error_msg: String,
        error_span: Span},
    
    #[error("unused pattern `{pattern_ident}`")]
    #[label("this pattern was not used in the condition", pattern_ident_span)]
    UnusedPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: Span,
    },

    #[error("invalid pattern `{pattern_ident}`")]
    #[label("{error_msg}", error_span)]
    #[note(note)]
    InvalidPattern {
        detailed_report: String,
        pattern_ident: String,
        error_msg: String,
        error_span: Span,
        note: Option<String>,
    },

    #[error("invalid range")]
    #[label("{error_msg}", error_span)]
    InvalidRange {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("invalid integer")]
    #[label("{error_msg}", error_span)]
    InvalidInteger {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("invalid float")]
    #[label("{error_msg}", error_span)]
    InvalidFloat {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("invalid escape sequence")]
    #[label("{error_msg}", error_span)]
    InvalidEscapeSequence {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
    },

    #[error("unexpected escape sequence")]
    #[label("escape sequences are not allowed in this string", error_span)]
    UnexpectedEscapeSequence {
        detailed_report: String,
        error_span: Span,
    },

    #[error("invalid regexp modifier `{modifier}`")]
    #[label("invalid modifier", error_span)]
    InvalidRegexpModifier {
        detailed_report: String,
        modifier: String,
        error_span: Span,
    },
    
    #[error("invalid UTF-8")]
    #[label("invalid UTF-8 character", error_span)]
    InvalidUTF8 {
        detailed_report: String,
        error_span: Span},
}

impl ErrorInfo {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SyntaxError { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::DuplicateTag { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::DuplicateRule { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::DuplicatePattern { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidModifier { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::DuplicateModifier { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidModifierCombination { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidBase64Alphabet { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::UnusedPattern { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidPattern { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidRange { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidInteger { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidFloat { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidEscapeSequence { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::UnexpectedEscapeSequence { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidRegexpModifier { detailed_report, .. } => {
                detailed_report.as_str()
            }
            Self::InvalidUTF8 { detailed_report, .. } => {
                detailed_report.as_str()
            }
        }
    }
}

impl ErrorInfo {
    pub(crate) fn syntax_error_message<F>(
        expected: &[GrammarRule],
        unexpected: &[GrammarRule],
        mut f: F,
    ) -> String
    where
        F: FnMut(&GrammarRule) -> &str,
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
            .filter(|&&rule| {
                rule != GrammarRule::COMMENT && rule != GrammarRule::WHITESPACE
            })
            .map(&mut f)
            .collect();

        let unexpected: Vec<&str> = unexpected
            .iter()
            .filter(|&&rule| {
                rule != GrammarRule::COMMENT && rule != GrammarRule::WHITESPACE
            })
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
        let mut strings: _ = if quotes {
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
    pub(crate) fn printable_string(rule: &GrammarRule) -> &str {
        match rule {
            // Keywords
            GrammarRule::k_ALL => "`all`",
            GrammarRule::k_ANY => "`any`",
            GrammarRule::k_ASCII => "`ascii`",
            GrammarRule::k_AT => "`at`",
            GrammarRule::k_BASE64 => "`base64`",
            GrammarRule::k_BASE64WIDE => "`base64wide`",
            GrammarRule::k_CONDITION => "`condition`",
            GrammarRule::k_FALSE => "`false`",
            GrammarRule::k_FILESIZE => "`filesize`",
            GrammarRule::k_FOR => "`for`",
            GrammarRule::k_FULLWORD => "`fullword`",
            GrammarRule::k_GLOBAL => "`global`",
            GrammarRule::k_IMPORT => "`import`",
            GrammarRule::k_IN => "`in`",
            GrammarRule::k_META => "`meta`",
            GrammarRule::k_NOCASE => "`nocase`",
            GrammarRule::k_NOT => "`not`",
            GrammarRule::k_OF => "`of`",
            GrammarRule::k_PRIVATE => "`private`",
            GrammarRule::k_RULE => "`rule`",
            GrammarRule::k_STRINGS => "`strings`",
            GrammarRule::k_THEM => "`them`",
            GrammarRule::k_TRUE => "`true`",
            GrammarRule::k_WIDE => "`wide`",
            GrammarRule::k_XOR => "`xor`",

            GrammarRule::boolean_expr | GrammarRule::boolean_term => {
                "boolean expression"
            }

            GrammarRule::expr
            | GrammarRule::primary_expr
            | GrammarRule::term => "expression",

            GrammarRule::hex_byte => "byte",
            GrammarRule::hex_tokens => "bytes",
            GrammarRule::ident => "identifier",
            GrammarRule::integer_lit => "number",
            GrammarRule::float_lit => "number",
            GrammarRule::rule_decl => "rule declaration",
            GrammarRule::source_file => "YARA rules",
            GrammarRule::pattern_ident => "pattern identifier",
            GrammarRule::string_lit => "string literal",
            GrammarRule::regexp => "regular expression",
            GrammarRule::pattern_mods => "pattern modifiers",

            GrammarRule::ADD
            | GrammarRule::k_AND
            | GrammarRule::k_OR
            | GrammarRule::SUB
            | GrammarRule::DIV
            | GrammarRule::MUL
            | GrammarRule::MOD
            | GrammarRule::SHL
            | GrammarRule::SHR
            | GrammarRule::BITWISE_AND
            | GrammarRule::BITWISE_OR
            | GrammarRule::BITWISE_XOR
            | GrammarRule::EQ
            | GrammarRule::NE
            | GrammarRule::GE
            | GrammarRule::GT
            | GrammarRule::LE
            | GrammarRule::LT
            | GrammarRule::k_STARTSWITH
            | GrammarRule::k_ISTARTSWITH
            | GrammarRule::k_ENDSWITH
            | GrammarRule::k_IENDSWITH
            | GrammarRule::k_IEQUALS
            | GrammarRule::k_CONTAINS
            | GrammarRule::k_ICONTAINS
            | GrammarRule::k_MATCHES => "operator",

            GrammarRule::PIPE => "pipe `|`",
            GrammarRule::COMMA => "comma `,`",
            GrammarRule::DOT => "dot `.`",
            GrammarRule::DOT_DOT => "`..`",
            GrammarRule::EQUAL => "equal `=` ",
            GrammarRule::PERCENT => "percent `%`",
            GrammarRule::MINUS => "`-`",
            GrammarRule::COLON => "colon `:`",

            GrammarRule::LPAREN => "opening parenthesis `(`",
            GrammarRule::RPAREN => "closing parenthesis `)`",
            GrammarRule::LBRACE => "opening brace `{`",
            GrammarRule::RBRACE => "closing brace `}`",
            GrammarRule::LBRACKET => "opening bracket `[`",
            GrammarRule::RBRACKET => "closing bracket `]`",
            GrammarRule::EOI => "end of file",

            _ => unreachable!("case `{:?}` is not handled", rule),
        }
    }
}
