use std::fmt::{Debug, Display, Formatter};
use std::io;

use thiserror::Error;

use yara_x_macros::Error as DeriveError;
use yara_x_parser::ast;

use crate::compiler::report::{Level, ReportBuilder, SourceRef};
use crate::compiler::warnings::InvalidWarningCode;
use crate::VariableError;

/// Errors returned while serializing/deserializing compiled rules.
#[derive(Error, Debug)]
pub enum SerializationError {
    /// The data being deserialized doesn't contain YARA-X serialized rules.
    #[error("not a YARA-X compiled rules file")]
    InvalidFormat,

    /// The data seems to be YARA-X serialized rules, but it's invalid or
    /// corrupted.
    #[error("invalid YARA-X compiled rules file")]
    InvalidEncoding(#[from] bincode::Error),

    /// I/O error while trying to read or write serialized data.
    #[error(transparent)]
    IoError(#[from] io::Error),
}

/// Error returned by [`crate::Compiler::emit_wasm_file`].
#[derive(Error, Debug)]
#[error(transparent)]
#[doc(hidden)]
pub struct EmitWasmError(#[from] anyhow::Error);

/// Errors returned by the compiler.
#[derive(Error, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum Error {
    #[error(transparent)]
    CompileError(#[from] Box<CompileError>),

    #[error(transparent)]
    VariableError(#[from] VariableError),

    #[error(transparent)]
    InvalidWarningCode(#[from] InvalidWarningCode),
}

/// An error occurred during the compilation process.
#[derive(DeriveError, Eq, PartialEq)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum CompileError {
    #[error("E001", "syntax error")]
    #[label_error("{error_msg}", error_span)]
    SyntaxError {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E002", "wrong type")]
    #[label_error(
        "expression should be {expected_types}, but is `{actual_type}`",
        expression_span
    )]
    WrongType {
        detailed_report: String,
        expected_types: String,
        actual_type: String,
        expression_span: SourceRef,
    },

    #[error("E003", "mismatching types")]
    #[label_error("this expression is `{type1}`", type1_span)]
    #[label_error("this expression is `{type2}`", type2_span)]
    MismatchingTypes {
        detailed_report: String,
        type1: String,
        type2: String,
        type1_span: SourceRef,
        type2_span: SourceRef,
    },

    #[error("E004", "wrong arguments")]
    #[label_error("wrong arguments in this call", args_span)]
    #[note(note)]
    WrongArguments {
        detailed_report: String,
        args_span: SourceRef,
        note: Option<String>,
    },

    #[error("E005", "assignment mismatch")]
    #[label_error("this expects {expected_values} value(s)", error_span)]
    #[label_error("this produces {actual_values} value(s)", iterable_span)]
    AssignmentMismatch {
        detailed_report: String,
        expected_values: u8,
        actual_values: u8,
        iterable_span: SourceRef,
        error_span: SourceRef,
    },

    #[error("E006", "unexpected negative number")]
    #[label_error("this number can not be negative", span)]
    UnexpectedNegativeNumber { detailed_report: String, span: SourceRef },

    #[error("E007", "number out of range")]
    #[label_error(
        "this number is out of the allowed range [{min}-{max}]",
        span
    )]
    NumberOutOfRange {
        detailed_report: String,
        min: i64,
        max: i64,
        span: SourceRef,
    },

    #[error("E008", "unknown field or method `{identifier}`")]
    #[label_error("this field or method doesn't exist", span)]
    UnknownField {
        detailed_report: String,
        identifier: String,
        span: SourceRef,
    },

    #[error("E009", "unknown identifier `{identifier}`")]
    #[label_error("this identifier has not been declared", span)]
    #[note(note)]
    UnknownIdentifier {
        detailed_report: String,
        identifier: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[error("E010", "unknown module `{identifier}`")]
    #[label_error("module `{identifier}` not found", span)]
    UnknownModule {
        detailed_report: String,
        identifier: String,
        span: SourceRef,
    },

    #[error("E011", "invalid range")]
    #[label_error("{error_msg}", span)]
    InvalidRange {
        detailed_report: String,
        error_msg: String,
        span: SourceRef,
    },

    #[error("E012", "duplicate rule `{new_rule}`")]
    #[label_note(
        "`{new_rule}` declared here for the first time",
        existing_rule_span
    )]
    #[label_error("duplicate declaration of `{new_rule}`", new_rule_span)]
    DuplicateRule {
        detailed_report: String,
        new_rule: String,
        new_rule_span: SourceRef,
        existing_rule_span: SourceRef,
    },

    #[error("E013", "rule `{ident}` conflicts with an existing identifier")]
    #[label_error(
        "identifier already in use by a module or global variable",
        ident_span
    )]
    ConflictingRuleIdentifier {
        detailed_report: String,
        ident: String,
        ident_span: SourceRef,
    },

    #[error("E014", "invalid regular expression")]
    #[label_error("{error}", span)]
    #[note(note)]
    InvalidRegexp {
        detailed_report: String,
        error: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[error(
        "E015",
        "mixing greedy and non-greedy quantifiers in regular expression"
    )]
    #[label_error("this is {quantifier1_greediness}", quantifier1_span)]
    #[label_error("this is {quantifier2_greediness}", quantifier2_span)]
    MixedGreediness {
        detailed_report: String,
        quantifier1_greediness: String,
        quantifier2_greediness: String,
        quantifier1_span: SourceRef,
        quantifier2_span: SourceRef,
    },

    #[error("E016", "no matching patterns")]
    #[label_error("there's no pattern in this set", span)]
    #[note(note)]
    EmptyPatternSet {
        detailed_report: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[error("E017", "`entrypoint` is unsupported`")]
    #[label_error("the `entrypoint` keyword is not supported anymore", span)]
    #[label_help(
        "use `pe.entry_point` or `elf.entry_point` or `macho.entry_point`",
        span
    )]
    EntrypointUnsupported { detailed_report: String, span: SourceRef },

    #[error("E018", "slow pattern")]
    #[label_error("this pattern may slow down the scan", span)]
    SlowPattern { detailed_report: String, span: SourceRef },

    #[error("E117", "invalid pattern modifier")]
    #[label_error("{error_msg}", error_span)]
    InvalidModifier {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error(
        "E019",
        "invalid modifier combination: `{modifier1}` `{modifier2}`"
    )]
    #[label_error("`{modifier1}` modifier used here", modifier1_span)]
    #[label_error("`{modifier2}` modifier used here", modifier2_span)]
    #[note(note)]
    InvalidModifierCombination {
        detailed_report: String,
        modifier1: String,
        modifier2: String,
        modifier1_span: SourceRef,
        modifier2_span: SourceRef,
        note: Option<String>,
    },

    #[error("E020", "duplicate pattern modifier")]
    #[label_error("duplicate modifier", modifier_span)]
    DuplicateModifier { detailed_report: String, modifier_span: SourceRef },

    #[error("E021", "duplicate tag `{tag}`")]
    #[label_error("duplicate tag", tag_span)]
    DuplicateTag { detailed_report: String, tag: String, tag_span: SourceRef },

    #[error("E022", "unused pattern `{pattern_ident}`")]
    #[label_error(
        "this pattern was not used in the condition",
        pattern_ident_span
    )]
    UnusedPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: SourceRef,
    },

    #[error("E023", "duplicate pattern `{pattern_ident}`")]
    #[label_error(
        "duplicate declaration of `{pattern_ident}`",
        new_pattern_span
    )]
    #[label_note(
        "`{pattern_ident}` declared here for the first time",
        existing_pattern_span
    )]
    DuplicatePattern {
        detailed_report: String,
        pattern_ident: String,
        new_pattern_span: SourceRef,
        existing_pattern_span: SourceRef,
    },

    #[error("E024", "invalid pattern `{pattern_ident}`")]
    #[label_error("{error_msg}", error_span)]
    #[note(note)]
    InvalidPattern {
        detailed_report: String,
        pattern_ident: String,
        error_msg: String,
        error_span: SourceRef,
        note: Option<String>,
    },

    #[error("E025", "unknown pattern `{pattern_ident}`")]
    #[label_error(
        "this pattern is not declared in the `strings` section",
        pattern_ident_span
    )]
    UnknownPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: SourceRef,
    },

    #[error("E026", "invalid base64 alphabet")]
    #[label_error("{error_msg}", error_span)]
    InvalidBase64Alphabet {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E027", "invalid integer")]
    #[label_error("{error_msg}", error_span)]
    InvalidInteger {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E028", "invalid float")]
    #[label_error("{error_msg}", error_span)]
    InvalidFloat {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E029", "invalid escape sequence")]
    #[label_error("{error_msg}", error_span)]
    InvalidEscapeSequence {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E030", "invalid regexp modifier `{modifier}`")]
    #[label_error("invalid modifier", error_span)]
    InvalidRegexpModifier {
        detailed_report: String,
        modifier: String,
        error_span: SourceRef,
    },

    #[error("E031", "unexpected escape sequence")]
    #[label_error(
        "escape sequences are not allowed in this string",
        error_span
    )]
    UnexpectedEscapeSequence { detailed_report: String, error_span: SourceRef },

    #[error("E032", "invalid UTF-8")]
    #[label_error("invalid UTF-8 character", error_span)]
    InvalidUTF8 { detailed_report: String, error_span: SourceRef },
}

impl CompileError {
    pub(crate) fn from(
        report_builder: &ReportBuilder,
        err: ast::Error,
    ) -> Self {
        match err {
            ast::Error::SyntaxError { message, span } => {
                CompileError::syntax_error(
                    report_builder,
                    message,
                    span.into(),
                )
            }
            ast::Error::InvalidInteger { message, span } => {
                CompileError::invalid_integer(
                    report_builder,
                    message,
                    span.into(),
                )
            }
            ast::Error::InvalidFloat { message, span } => {
                CompileError::invalid_float(
                    report_builder,
                    message,
                    span.into(),
                )
            }
            ast::Error::InvalidRegexpModifier { message, span } => {
                CompileError::invalid_regexp_modifier(
                    report_builder,
                    message,
                    span.into(),
                )
            }
            ast::Error::InvalidEscapeSequence { message, span } => {
                CompileError::invalid_escape_sequence(
                    report_builder,
                    message,
                    span.into(),
                )
            }
            ast::Error::UnexpectedEscapeSequence(span) => {
                CompileError::unexpected_escape_sequence(
                    report_builder,
                    span.into(),
                )
            }
            ast::Error::InvalidUTF8(span) => {
                CompileError::invalid_utf_8(report_builder, span.into())
            }
        }
    }
}

impl CompileError {
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
}
