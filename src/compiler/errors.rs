use crate::parser;
use crate::parser::Span;
use thiserror::Error;
use yara_derive::Error as CompileError;

/// Represents the errors returned by [`Compiler::compile`].
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[error("parse error")]
    ParseError(#[from] parser::Error),

    #[error("compile error")]
    CompileError(#[from] CompileError),
}

#[derive(CompileError, Debug)]
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

    #[error("mismatching operator types")]
    #[label("this expression is `{type1}`", type1_span)]
    #[label("this expression is `{type2}`", type2_span)]
    MismatchingTypes {
        detailed_report: String,
        type1: String,
        type2: String,
        type1_span: Span,
        type2_span: Span,
    },
}
