use regex::{Error, Regex};

use yara_x_parser::ast;
use yara_x_parser::ast::{Meta, WithSpan};

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

/// A linter that ensures that rule names match a given regular expression.
///
/// ```
/// # use yara_x::Compiler;
/// use yara_x::linters::rule_name;
/// let mut compiler = Compiler::new();
/// let warnings = compiler
///     .add_linter(rule_name("APT_.*").unwrap())
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
pub struct RuleName {
    regex: String,
    compiled_regex: Regex,
}

impl RuleName {
    fn new<R: Into<String>>(regex: R) -> Result<Self, regex::Error> {
        let regex = regex.into();
        let compiled_regex = Regex::new(regex.as_str())?;
        Ok(Self { regex, compiled_regex })
    }
}

impl LinterInternal for RuleName {
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

type Predicate<'a> = dyn Fn(&Meta) -> bool + 'a;

/// A linter that validates metadata entries.
///
/// ```
/// # use yara_x::Compiler;
/// use yara_x::linters::metadata;
/// let mut compiler = Compiler::new();
/// let warnings = compiler
///     .add_linter(metadata("author").required(true))
///     // This produces a warning because the rule name doesn't have the
///     // required metadata.
///     .add_source(r#"rule foo { strings: $foo = "foo" condition: $foo }"#)
///     .unwrap()
///     .warnings();
///
/// assert_eq!(
///     warnings[0].to_string(),
///     r#"warning[missing_metadata]: required metadata is missing
///  --> line:1:6
///   |
/// 1 | rule foo { strings: $foo = "foo" condition: $foo }
///   |      --- required metadata `author` not found
///   |"#);
/// ```
pub struct Metadata<'a> {
    identifier: String,
    predicate: Option<Box<Predicate<'a>>>,
    required: bool,
    message: Option<String>,
    note: Option<String>,
}

impl<'a> Metadata<'a> {
    fn new<I: Into<String>>(identifier: I) -> Self {
        Self {
            identifier: identifier.into(),
            predicate: None,
            required: false,
            message: None,
            note: None,
        }
    }

    /// Specifies whether the metadata is required in all rules.
    pub fn required(mut self, yes: bool) -> Self {
        self.required = yes;
        self
    }

    /// Sets a predicate that determines whether the metadata is valid or not.
    ///
    /// The predicate must return `true` if the metadata is considered valid.
    /// If it returns `false`, the metadata is deemed invalid and a warning 
    /// will be raised with the specified message.
    ///
    /// ```
    /// # use yara_x::Compiler;
    /// use yara_x_parser::ast::MetaValue;
    /// use yara_x::linters::metadata;
    /// let mut compiler = Compiler::new();
    /// let warnings = compiler
    ///     .add_linter(
    ///         // The validator for the `author` metadata returns true only
    ///         // when its value is a string.
    ///         metadata("author").validator(|meta| {
    ///            matches!(meta.value, MetaValue::String(_))
    ///         },
    ///         "author must be a string"))
    ///     // This produces a warning because the `author` metadata
    ///     // is a boolean, and it must be a string.
    ///     .add_source(r#"rule foo {
    ///         meta:
    ///            author = false
    ///         strings:
    ///            $foo = "foo"
    ///         condition:
    ///            $foo
    ///         }"#)
    ///     .unwrap()
    ///     .warnings();
    ///
    /// assert_eq!(
    ///     warnings[0].to_string(),
    ///     r#"warning[invalid_metadata]: metadata `author` is not valid
    ///  --> line:3:12
    ///   |
    /// 3 |            author = false
    ///   |            ------ author must be a string
    ///   |"#);
    /// ```
    pub fn validator<P, M>(mut self, predicate: P, message: M) -> Self
    where
        P: Fn(&Meta) -> bool + 'a,
        M: Into<String>,
    {
        self.predicate = Some(Box::new(predicate));
        self.message = Some(message.into());
        self
    }
}

impl LinterInternal for Metadata<'_> {
    fn check(
        &self,
        report_builder: &ReportBuilder,
        rule: &ast::Rule,
    ) -> Option<Warning> {
        let mut found = false;
        for meta in rule.meta.iter().flatten() {
            if meta.identifier.name == self.identifier.as_str() {
                if let Some(predicate) = &self.predicate {
                    if !predicate(meta) {
                        return Some(warnings::InvalidMetadata::build(
                            report_builder,
                            meta.identifier.name.to_string(),
                            meta.identifier.span().into(),
                            self.message
                                .clone()
                                .unwrap_or("invalid metadata".to_string()),
                        ));
                    }
                }
                found = true;
            }
        }

        if self.required && !found {
            return Some(warnings::MissingMetadata::build(
                report_builder,
                rule.identifier.span().into(),
                self.identifier.clone(),
                self.note.clone(),
            ));
        }

        None
    }
}

/// Creates a linter that validates metadata entries.
///
/// See [`Metadata`] for details.
pub fn metadata<'a, I: Into<String>>(identifier: I) -> Metadata<'a> {
    Metadata::new(identifier)
}

/// Creates a linter that makes sure that rule names match the given
/// regular expression.
///
/// See [`RuleName`] for details.
pub fn rule_name<R: Into<String>>(regex: R) -> Result<RuleName, Error> {
    RuleName::new(regex)
}
