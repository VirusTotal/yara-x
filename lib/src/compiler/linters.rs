use regex::Regex;

use yara_x_parser::ast;
use yara_x_parser::ast::WithSpan;

use crate::compiler::report::ReportBuilder;
use crate::compiler::warnings;
use crate::compiler::Warning;

/// Trait implemented by all linters.
///
/// All types in [`crate::linters`] implement this trait and can be passed
/// to [`crate::Compiler::add_linter`].
#[allow(private_bounds)]
pub trait Linter: LinterInternal {}

// Types that implement [`LinterInternal`] automatically implement [`Linter`].
impl<T: LinterInternal> Linter for T {}

/// This is the actual trait implemented by all linters. [`Linter`] is a
/// supertrait of [`LinterInternal`], while the former is visible to the public
/// API, the latter is for internal use. This prevents users of this create
/// from implementing their own linters and keep the signature of the trait
/// private. This is because [`ReportBuilder`] is an internal type that we
/// don't want to expose publicly, and because users can't define their own
/// warnings.
pub(crate) trait LinterInternal {
    fn check(
        &self,
        report_builder: &ReportBuilder,
        rule: &ast::Rule,
    ) -> Option<Warning>;
}

/// A linter that ensures that all rule names match a given regular expression.
///
/// ```
/// # use yara_x::Compiler;
/// # use yara_x::linters::RuleNameMatches;
/// let mut compiler = Compiler::new();
/// let warnings = compiler
///     .add_linter(RuleNameMatches::new("APT_.*").unwrap())
///     // This produces a warning because the rule name doesn't match the regex.
///     .add_source(r#"rule foo { strings: $foo = "foo" condition: $foo }"#)
///     .unwrap()
///     .warnings();
///
/// assert_eq!(
///     warnings[0].to_string(),
///     r#"warning[invalid_rule_name]: rule name does not match regex `APT_.*`
///  --> line:1:6
///   |
/// 1 | rule foo { strings: $foo = "foo" condition: $foo }
///   |      --- this rule name does not match regex `APT_.*`
///   |"#);
/// ```
pub struct RuleNameMatches {
    regex: String,
    compiled_regex: Regex,
}

impl RuleNameMatches {
    /// Creates a linter that makes sure that all rule names match the given
    /// regular expression.
    pub fn new<R: Into<String>>(regex: R) -> Result<Self, regex::Error> {
        let regex = regex.into();
        let compiled_regex = Regex::new(regex.as_str())?;
        Ok(Self { regex, compiled_regex })
    }
}

impl LinterInternal for RuleNameMatches {
    fn check(
        &self,
        report_builder: &ReportBuilder,
        rule: &ast::Rule,
    ) -> Option<Warning> {
        if !self.compiled_regex.is_match(rule.identifier.name) {
            Some(warnings::InvalidRuleName::build(
                report_builder,
                rule.identifier.span().into(),
                self.regex.clone(),
            ))
        } else {
            None
        }
    }
}

/// A linter that ensures that all rules have a certain metadata.
///
/// ```
/// # use yara_x::Compiler;
/// # use yara_x::linters::{RequiredMetadata, RuleNameMatches};
/// let mut compiler = Compiler::new();
/// let warnings = compiler
///     .add_linter(RequiredMetadata::new("author").note("`author` must be a string describing the rule's author"))
///     // This produces a warning because the rule name doesn't have the
///     // required metadata.
///     .add_source(r#"rule foo { strings: $foo = "foo" condition: $foo }"#)
///     .unwrap()
///     .warnings();
///
/// assert_eq!(
///     warnings[0].to_string(),
///     r#"warning[required_metadata]: required metadata is missing
///  --> line:1:6
///   |
/// 1 | rule foo { strings: $foo = "foo" condition: $foo }
///   |      --- required metadata `author` not found
///   |
///   = note: `author` must be a string describing the rule's author"#);
/// ```
pub struct RequiredMetadata {
    identifier: String,
    note: Option<String>,
}

impl RequiredMetadata {
    /// Creates a linter that ensures that all rules have a metadata with
    /// the given identifier.
    pub fn new<I: Into<String>>(identifier: I) -> Self {
        Self { identifier: identifier.into(), note: None }
    }

    /// Add a note that will be appended to the warning message when the
    /// metadata is not found.
    pub fn note<N: Into<String>>(mut self, note: N) -> Self {
        self.note = Some(note.into());
        self
    }
}

impl LinterInternal for RequiredMetadata {
    fn check(
        &self,
        report_builder: &ReportBuilder,
        rule: &ast::Rule,
    ) -> Option<Warning> {
        if rule
            .meta
            .iter()
            .flatten()
            .any(|meta| meta.identifier.name == self.identifier.as_str())
        {
            None
        } else {
            Some(warnings::MissingMetadata::build(
                report_builder,
                rule.identifier.span().into(),
                self.identifier.clone(),
                self.note.clone(),
            ))
        }
    }
}
