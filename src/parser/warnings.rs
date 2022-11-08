use yara_derive::Error;

use crate::parser::Span;

/// An warning raised while parsing YARA rules.
#[rustfmt::skip]
#[derive(Error, Debug)]
pub enum Warning {
    #[warning("consecutive jumps in hex pattern `{pattern_ident}`")]
    #[label("these consecutive jumps will be treated as {coalesced_jump}", jumps_span)]
    ConsecutiveJumps {
        detailed_report: String,
        pattern_ident: String,
        coalesced_jump: String,
        jumps_span: Span,
    },
}
