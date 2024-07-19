use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};

use thiserror::Error;

use yara_x_macros::Error as DeriveError;

use crate::compiler::report::Level;
use crate::compiler::report::{ReportBuilder, SourceRef};

/// A warning raised while compiling YARA rules.
#[rustfmt::skip]
#[allow(missing_docs)]
#[derive(DeriveError)]
pub enum Warning {
    #[warning("consecutive_jumps", "consecutive jumps in hex pattern `{pattern_ident}`")]
    #[label("these consecutive jumps will be treated as {coalesced_jump}", jumps_span)]
    ConsecutiveJumps {
        detailed_report: String,
        pattern_ident: String,
        coalesced_jump: String,
        jumps_span: SourceRef ,
    },

    #[warning("unsatisfiable_expr", "potentially unsatisfiable expression")]
    #[label("this implies that multiple patterns must match", quantifier_span)]
    #[label("but they must match at the same offset", at_span)]
    PotentiallyUnsatisfiableExpression {
        detailed_report: String,
        quantifier_span: SourceRef,
        at_span: SourceRef,
    },

    #[warning("invariant_expr", "invariant boolean expression")]
    #[label("this expression is always {value}", span)]
    #[note(note)]
    InvariantBooleanExpression {
        detailed_report: String,
        value: bool,
        span: SourceRef,
        note: Option<String>,
    },

    #[warning("non_bool_expr", "non-boolean expression used as boolean")]
    #[label("this expression is `{expression_type}` but is being used as `bool`", span)]
    #[note(note)]
    NonBooleanAsBoolean {
        detailed_report: String,
        expression_type: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[warning("duplicate_import", "duplicate import statement")]
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
        new_import_span: SourceRef,
        existing_import_span: SourceRef,
    },

    #[warning("redundant_modifier", "redundant case-insensitive modifier")]
    #[label("the `i` suffix indicates that the pattern is case-insensitive", i_span)]
    #[label("the `nocase` modifier does the same", nocase_span)]
    RedundantCaseModifier {
        detailed_report: String,
        nocase_span: SourceRef,
        i_span: SourceRef,
    },

    #[warning("slow_pattern", "slow pattern")]
    #[label("this pattern may slow down the scan", span)]
    SlowPattern {
        detailed_report: String,
        span: SourceRef,
    },

    #[warning("unsupported_module", "module `{module_name}` is not supported")]
    #[label("module `{module_name}` used here", span)]
    #[note(note)]
    IgnoredModule {
        detailed_report: String,
        module_name: String,
        span: SourceRef,
        note: Option<String>,
    },

    #[warning(
        "ignored_rule",
        "rule `{ignored_rule}` will be ignored due to an indirect dependency on module `{module_name}`"
    )]
    #[label("this other rule depends on module `{module_name}`, which is unsupported", span)]
    IgnoredRule {
        detailed_report: String,
        ignored_rule: String,
        dependency: String,
        module_name: String,
        span: SourceRef,
    },
}

/// Error returned by [`Warnings::switch_warning`] when the warning code is
/// not valid.
#[derive(Error, Debug, Eq, PartialEq)]
#[error("`{0}` is not a valid warning code")]
pub struct InvalidWarningCode(String);

/// Represents a list of warnings.
pub struct Warnings {
    warnings: Vec<Warning>,
    max_warnings: usize,
    disabled_warnings: HashSet<String>,
}

impl Default for Warnings {
    fn default() -> Self {
        Self {
            warnings: Vec::new(),
            max_warnings: 100,
            disabled_warnings: HashSet::default(),
        }
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
    pub fn add(&mut self, f: impl FnOnce() -> Warning) {
        if self.warnings.len() < self.max_warnings {
            let warning = f();
            if !self.disabled_warnings.contains(warning.code()) {
                self.warnings.push(warning);
            }
        }
    }

    /// Enables or disables a specific warning identified by `code`.
    ///
    /// Returns `true` if the warning was previously enabled, or `false` if
    /// otherwise. Returns an error if the code doesn't correspond to any
    /// of the existing warnings.
    #[inline]
    pub fn switch_warning(
        &mut self,
        code: &str,
        enabled: bool,
    ) -> Result<bool, InvalidWarningCode> {
        if !Warning::is_valid_code(code) {
            return Err(InvalidWarningCode(code.to_string()));
        }
        if enabled {
            Ok(!self.disabled_warnings.remove(code))
        } else {
            Ok(self.disabled_warnings.insert(code.to_string()))
        }
    }

    /// Enable or disables all warnings.
    pub fn switch_all_warnings(&mut self, enabled: bool) {
        if enabled {
            self.disabled_warnings.clear();
        } else {
            for c in Warning::all_codes() {
                self.disabled_warnings.insert(c.to_string());
            }
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
