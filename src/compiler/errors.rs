use thiserror::Error;

use yara_derive::Error as CompileError;

use crate::ast::Span;
use crate::parser;

/// Errors returned by the compiler.
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] parser::Error),

    #[error(transparent)]
    CompileError(#[from] CompileError),
}

/// An error occurred during the compilation process.
#[derive(CompileError)]
pub enum CompileError {
    #[error("wrong type")]
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

    #[error("mismatching types")]
    #[label("this expression is `{type1}`", type1_span)]
    #[label("this expression is `{type2}`", type2_span)]
    MismatchingTypes {
        detailed_report: String,
        type1: String,
        type2: String,
        type1_span: Span,
        type2_span: Span,
    },

    #[error("unexpected negative number")]
    #[label("this number can not be negative", span)]
    UnexpectedNegativeNumber { detailed_report: String, span: Span },

    #[error("number out of range")]
    #[label("this number is out of the allowed range [{min}-{max}]", span)]
    NumberOutOfRange {
        detailed_report: String,
        min: i64,
        max: i64,
        span: Span,
    },

    #[error("unknown identifier `{identifier}`")]
    #[label("this identifier has not been declared", span)]
    UnknownIdentifier {
        detailed_report: String,
        identifier: String,
        span: Span,
    },
}
