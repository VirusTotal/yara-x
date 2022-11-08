use yara_derive::Error;

use crate::parser::Span;

/// An warning raised while compiling YARA rules.
#[rustfmt::skip]
#[derive(Error, Debug)]
pub enum Warning {
    #[warning("potentially wrong expression")]
    #[label("this implies that multiple patterns must match", quantifier_span)]
    #[label("but they must match at the same offset", at_span)]
    PotentiallyWrongExpression {
        detailed_report: String,
        quantifier_span: Span,
        at_span: Span,
    },

    #[warning("invariant boolean expression")]
    #[label("this expression is always {value}", span)]
    #[note(note)]
    InvariantBooleanExpression {
        detailed_report: String,
        value: bool,
        span: Span,
        note: Option<String>,
    },
}
