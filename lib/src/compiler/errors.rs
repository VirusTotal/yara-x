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
    #[label("{error_msg}", error_span)]
    SyntaxError {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E100", "wrong type")]
    #[label(
        "expression should be {expected_types}, but is `{actual_type}`",
        expression_span
    )]
    WrongType {
        detailed_report: String,
        expected_types: String,
        actual_type: String,
        expression_span: SourceRef,
    },

    #[error("E101", "mismatching types")]
    #[label("this expression is `{type1}`", type1_span)]
    #[label("this expression is `{type2}`", type2_span)]
    MismatchingTypes {
        detailed_report: String,
        type1: String,
        type2: String,
        type1_span: SourceRef,
        type2_span: SourceRef,
    },

    #[error("E102", "wrong arguments")]
    #[label("wrong arguments in this call", args_span)]
    #[note(note)]
    WrongArguments {
        detailed_report: String,
        args_span: SourceRef,
        note: Option<String>,
    },

    #[error("E103", "assignment mismatch")]
    #[label("this expects {expected_values} value(s)", error_span)]
    #[label("this produces {actual_values} value(s)", iterable_span)]
    AssignmentMismatch {
        detailed_report: String,
        expected_values: u8,
        actual_values: u8,
        iterable_span: SourceRef,
        error_span: SourceRef,
    },

    #[error("E104", "unexpected negative number")]
    #[label("this number can not be negative", span)]
    UnexpectedNegativeNumber { detailed_report: String, span: SourceRef },

    #[error("E105", "number out of range")]
    #[label("this number is out of the allowed range [{min}-{max}]", span)]
    NumberOutOfRange {
        detailed_report: String,
        min: i64,
        max: i64,
        span: SourceRef,
    },

    #[error("E106", "unknown field or method `{identifier}`")]
    #[label("this field or method doesn't exist", span)]
    UnknownField {
        detailed_report: String,
        identifier: String,
        span: SourceRef,
    },

    #[error("E107", "unknown identifier `{identifier}`")]
    #[label("this identifier has not been declared", span)]
    #[note(note)]
    UnknownIdentifier {
        detailed_report: String,
        identifier: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[error("E108", "unknown module `{identifier}`")]
    #[label("module `{identifier}` not found", span)]
    UnknownModule {
        detailed_report: String,
        identifier: String,
        span: SourceRef,
    },

    #[error("E109", "invalid range")]
    #[label("{error_msg}", span)]
    InvalidRange {
        detailed_report: String,
        error_msg: String,
        span: SourceRef,
    },

    #[error("E110", "duplicate rule `{new_rule}`")]
    #[label(
        "`{new_rule}` declared here for the first time",
        existing_rule_span,
        style = "note"
    )]
    #[label("duplicate declaration of `{new_rule}`", new_rule_span)]
    DuplicateRule {
        detailed_report: String,
        new_rule: String,
        new_rule_span: SourceRef,
        existing_rule_span: SourceRef,
    },

    #[error("E111", "rule `{ident}` conflicts with an existing identifier")]
    #[label(
        "identifier already in use by a module or global variable",
        ident_span
    )]
    ConflictingRuleIdentifier {
        detailed_report: String,
        ident: String,
        ident_span: SourceRef,
    },

    #[error("E112", "invalid regular expression")]
    #[label("{error}", span)]
    #[note(note)]
    InvalidRegexp {
        detailed_report: String,
        error: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[error(
        "E113",
        "mixing greedy and non-greedy quantifiers in regular expression"
    )]
    #[label("this is {quantifier1_greediness}", quantifier1_span)]
    #[label("this is {quantifier2_greediness}", quantifier2_span)]
    MixedGreediness {
        detailed_report: String,
        quantifier1_greediness: String,
        quantifier2_greediness: String,
        quantifier1_span: SourceRef,
        quantifier2_span: SourceRef,
    },

    #[error("E114", "no matching patterns")]
    #[label("there's no pattern in this set", span)]
    #[note(note)]
    EmptyPatternSet {
        detailed_report: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[error("E115", "`entrypoint` is unsupported`")]
    #[label("the `entrypoint` keyword is not supported anymore", span)]
    #[note(note)]
    EntrypointUnsupported {
        detailed_report: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[error("E116", "slow pattern")]
    #[label("this pattern may slow down the scan", span)]
    SlowPattern { detailed_report: String, span: SourceRef },

    #[error("E117", "invalid pattern modifier")]
    #[label("{error_msg}", error_span)]
    InvalidModifier {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error(
        "E118",
        "invalid modifier combination: `{modifier1}` `{modifier2}`"
    )]
    #[label("`{modifier1}` modifier used here", modifier1_span)]
    #[label("`{modifier2}` modifier used here", modifier2_span)]
    #[note(note)]
    InvalidModifierCombination {
        detailed_report: String,
        modifier1: String,
        modifier2: String,
        modifier1_span: SourceRef,
        modifier2_span: SourceRef,
        note: Option<String>,
    },

    #[error("E119", "duplicate pattern modifier")]
    #[label("duplicate modifier", modifier_span)]
    DuplicateModifier { detailed_report: String, modifier_span: SourceRef },

    #[error("E120", "duplicate tag `{tag}`")]
    #[label("duplicate tag", tag_span)]
    DuplicateTag { detailed_report: String, tag: String, tag_span: SourceRef },

    #[error("E121", "unused pattern `{pattern_ident}`")]
    #[label("this pattern was not used in the condition", pattern_ident_span)]
    UnusedPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: SourceRef,
    },

    #[error("E122", "duplicate pattern `{pattern_ident}`")]
    #[label("duplicate declaration of `{pattern_ident}`", new_pattern_span)]
    #[label(
        "`{pattern_ident}` declared here for the first time",
        existing_pattern_span,
        style = "note"
    )]
    DuplicatePattern {
        detailed_report: String,
        pattern_ident: String,
        new_pattern_span: SourceRef,
        existing_pattern_span: SourceRef,
    },

    #[error("E123", "invalid pattern `{pattern_ident}`")]
    #[label("{error_msg}", error_span)]
    #[note(note)]
    InvalidPattern {
        detailed_report: String,
        pattern_ident: String,
        error_msg: String,
        error_span: SourceRef,
        note: Option<String>,
    },

    #[error("E124", "unknown pattern `{pattern_ident}`")]
    #[label(
        "this pattern is not declared in the `strings` section",
        pattern_ident_span
    )]
    UnknownPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: SourceRef,
    },

    #[error("E125", "invalid base64 alphabet")]
    #[label("{error_msg}", error_span)]
    InvalidBase64Alphabet {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E012", "invalid integer")]
    #[label("{error_msg}", error_span)]
    InvalidInteger {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E013", "invalid float")]
    #[label("{error_msg}", error_span)]
    InvalidFloat {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E014", "invalid escape sequence")]
    #[label("{error_msg}", error_span)]
    InvalidEscapeSequence {
        detailed_report: String,
        error_msg: String,
        error_span: SourceRef,
    },

    #[error("E016", "invalid regexp modifier `{modifier}`")]
    #[label("invalid modifier", error_span)]
    InvalidRegexpModifier {
        detailed_report: String,
        modifier: String,
        error_span: SourceRef,
    },

    #[error("E015", "unexpected escape sequence")]
    #[label("escape sequences are not allowed in this string", error_span)]
    UnexpectedEscapeSequence { detailed_report: String, error_span: SourceRef },

    #[error("E017", "invalid UTF-8")]
    #[label("invalid UTF-8 character", error_span)]
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
