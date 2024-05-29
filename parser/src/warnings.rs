use std::fmt::{Debug, Display, Formatter};
use yara_x_macros::Error;

use crate::ast::Span;
use crate::report::Level;
use crate::report::ReportBuilder;

/// A warning raised while parsing YARA rules.
#[rustfmt::skip]
#[derive(Error)]
pub enum Warning {
    #[warning("consecutive jumps in hex pattern `{pattern_ident}`")]
    #[label("these consecutive jumps will be treated as {coalesced_jump}", jumps_span)]
    ConsecutiveJumps {
        detailed_report: String,
        pattern_ident: String,
        coalesced_jump: String,
        jumps_span: Span,
    },
    
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

    #[warning("non-boolean expression used as boolean")]
    #[label("this expression is `{expression_type}` but is being used as `bool`", span)]
    #[note(note)]
    NonBooleanAsBoolean {
        detailed_report: String,
        expression_type: String,
        span: Span,
        note: Option<String>,
    },
    
    #[warning("duplicate import statement")]
    #[label(
      "duplicate import",
      new_import_span
    )]
    #[label(
      "`{module_name}` imported here for the first time",
      existing_import_span,
      style="note"
    )]
    DuplicateImport {
        detailed_report: String,
        module_name: String,
        new_import_span: Span,
        existing_import_span: Span,
    },

    #[warning("redundant case-insensitive modifier")]
    #[label("the `i` suffix indicates that the pattern is case-insensitive", i_span)]
    #[label("the `nocase` modifier does the same", nocase_span)]
    RedundantCaseModifier {
        detailed_report: String,
        nocase_span: Span,
        i_span: Span,
    },

    #[warning("slow pattern")]
    #[label("this pattern may slow down the scan", span)]
    SlowPattern {
        detailed_report: String,
        span: Span,
    },

    #[warning("module `{module_name}` is not supported")]
    #[label("module `{module_name}` used here", span)]
    #[note(note)]
    IgnoredModule {
        detailed_report: String,
        module_name: String,
        span: Span,
        note: Option<String>,
    },

    #[warning("rule `{ignored_rule}` will be ignored due to an indirect dependency on module `{module_name}`")]
    #[label("this other rule depends on module `{module_name}`, which is unsupported", span)]
    IgnoredRule {
        detailed_report: String,
        ignored_rule: String,
        dependency: String,
        module_name: String,
        span: Span,
    },
}

/// Represents a list of warnings.
pub struct Warnings {
    warnings: Vec<Warning>,
    max_warnings: usize,
}

impl Default for Warnings {
    fn default() -> Self {
        Self { warnings: Vec::new(), max_warnings: 100 }
    }
}

impl Warnings {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.warnings.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.warnings.len()
    }

    #[inline]
    pub fn add(&mut self, f: impl Fn() -> Warning) {
        if self.warnings.len() < self.max_warnings {
            self.warnings.push(f());
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[Warning] {
        self.warnings.as_slice()
    }

    pub fn append(&mut self, mut warnings: Self) {
        for w in warnings.warnings.drain(0..) {
            if self.warnings.len() == self.max_warnings {
                break;
            }
            self.warnings.push(w)
        }
    }
}

impl From<Warnings> for Vec<Warning> {
    fn from(value: Warnings) -> Self {
        value.warnings
    }
}
