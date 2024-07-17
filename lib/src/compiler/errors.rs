use std::fmt::{Debug, Display, Formatter};
use std::io;

use thiserror::Error;

use yara_x_macros::Error as DeriveError;
use yara_x_parser::ast::Span;
use yara_x_parser::report::Level;
use yara_x_parser::report::ReportBuilder;

pub use yara_x_parser::Error as ParseError;

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
    ParseError(#[from] ParseError),

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
    #[error("E100", "wrong type")]
    #[label(
        "expression should be {expected_types}, but is `{actual_type}`",
        expression_span
    )]
    WrongType {
        detailed_report: String,
        expected_types: String,
        actual_type: String,
        expression_span: Span,
    },

    #[error("E101", "mismatching types")]
    #[label("this expression is `{type1}`", type1_span)]
    #[label("this expression is `{type2}`", type2_span)]
    MismatchingTypes {
        detailed_report: String,
        type1: String,
        type2: String,
        type1_span: Span,
        type2_span: Span,
    },

    #[error("E102", "wrong arguments")]
    #[label("wrong arguments in this call", args_span)]
    #[note(note)]
    WrongArguments {
        detailed_report: String,
        args_span: Span,
        note: Option<String>,
    },

    #[error("E103", "assignment mismatch")]
    #[label("this expects {expected_values} value(s)", error_span)]
    #[label("this produces {actual_values} value(s)", iterable_span)]
    AssignmentMismatch {
        detailed_report: String,
        expected_values: u8,
        actual_values: u8,
        iterable_span: Span,
        error_span: Span,
    },

    #[error("E104", "unexpected negative number")]
    #[label("this number can not be negative", span)]
    UnexpectedNegativeNumber { detailed_report: String, span: Span },

    #[error("E105", "number out of range")]
    #[label("this number is out of the allowed range [{min}-{max}]", span)]
    NumberOutOfRange {
        detailed_report: String,
        min: i64,
        max: i64,
        span: Span,
    },

    #[error("E106", "unknown field or method `{identifier}`")]
    #[label("this field or method doesn't exist", span)]
    UnknownField { detailed_report: String, identifier: String, span: Span },

    #[error("E107", "unknown identifier `{identifier}`")]
    #[label("this identifier has not been declared", span)]
    #[note(note)]
    UnknownIdentifier {
        detailed_report: String,
        identifier: String,
        span: Span,
        note: Option<String>,
    },

    #[error("E108", "unknown module `{identifier}`")]
    #[label("module `{identifier}` not found", span)]
    UnknownModule { detailed_report: String, identifier: String, span: Span },

    #[error("E109", "invalid range")]
    #[label("{error_msg}", span)]
    InvalidRange { detailed_report: String, error_msg: String, span: Span },

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
        new_rule_span: Span,
        existing_rule_span: Span,
    },

    #[error("E111", "rule `{ident}` conflicts with an existing identifier")]
    #[label(
        "identifier already in use by a module or global variable",
        ident_span
    )]
    ConflictingRuleIdentifier {
        detailed_report: String,
        ident: String,
        ident_span: Span,
    },

    #[error("E112", "invalid regular expression")]
    #[label("{error}", span)]
    #[note(note)]
    InvalidRegexp {
        detailed_report: String,
        error: String,
        span: Span,
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
        quantifier1_span: Span,
        quantifier2_span: Span,
    },

    #[error("E114", "no matching patterns")]
    #[label("there's no pattern in this set", span)]
    #[note(note)]
    EmptyPatternSet {
        detailed_report: String,
        span: Span,
        note: Option<String>,
    },

    #[error("E115", "`entrypoint` is unsupported`")]
    #[label("the `entrypoint` keyword is not supported anymore", span)]
    #[note(note)]
    EntrypointUnsupported {
        detailed_report: String,
        span: Span,
        note: Option<String>,
    },

    #[error("E116", "slow pattern")]
    #[label("this pattern may slow down the scan", span)]
    SlowPattern { detailed_report: String, span: Span },

    #[error("E117", "invalid pattern modifier")]
    #[label("{error_msg}", error_span)]
    InvalidModifier {
        detailed_report: String,
        error_msg: String,
        error_span: Span,
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
        modifier1_span: Span,
        modifier2_span: Span,
        note: Option<String>,
    },

    #[error("E119", "duplicate pattern modifier")]
    #[label("duplicate modifier", modifier_span)]
    DuplicateModifier { detailed_report: String, modifier_span: Span },

    #[error("E120", "duplicate tag `{tag}`")]
    #[label("duplicate tag", tag_span)]
    DuplicateTag { detailed_report: String, tag: String, tag_span: Span },

    #[error("E121", "unused pattern `{pattern_ident}`")]
    #[label("this pattern was not used in the condition", pattern_ident_span)]
    UnusedPattern {
        detailed_report: String,
        pattern_ident: String,
        pattern_ident_span: Span,
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
        new_pattern_span: Span,
        existing_pattern_span: Span,
    },

    #[error("E123", "invalid pattern `{pattern_ident}`")]
    #[label("{error_msg}", error_span)]
    #[note(note)]
    InvalidPattern {
        detailed_report: String,
        pattern_ident: String,
        error_msg: String,
        error_span: Span,
        note: Option<String>,
    },
}
