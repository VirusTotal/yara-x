use regex::{Error, Regex};

use yara_x_parser::ast::{self, Meta, WithSpan};

use crate::compiler::report::ReportBuilder;
use crate::compiler::Warning;
use crate::compiler::{errors, warnings};
use crate::errors::CompileError;

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
/// API, the latter is for internal use. This prevents users of this crate
/// from implementing their own linters and keep the signature of the trait
/// private. This is because [`ReportBuilder`] is an internal type that we
/// don't want to expose publicly, and because users can't define their own
/// warnings.
pub(crate) trait LinterInternal {
    fn check(
        &self,
        report_builder: &ReportBuilder,
        rule: &ast::Rule,
    ) -> LinterResult;
}

/// Represents the result of a linter.
pub(crate) enum LinterResult {
    Ok,
    Warn(Warning),
    Warns(Vec<Warning>),
    Err(CompileError),
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
///   |      --- this rule name does not match regex `APT_.*`"#);
/// ```
pub struct RuleName {
    regex: String,
    error: bool,
    compiled_regex: Regex,
}

impl RuleName {
    fn new<R: Into<String>>(regex: R) -> Result<Self, regex::Error> {
        let regex = regex.into();
        let compiled_regex = Regex::new(regex.as_str())?;
        Ok(Self { regex, compiled_regex, error: false })
    }

    /// Specifies whether the linter should produce an error instead of a warning.
    ///
    /// By default, the linter raises warnings about rule names that don't match
    /// the regular expression. This setting allows turning such warnings into
    /// errors.
    pub fn error(mut self, yes: bool) -> Self {
        self.error = yes;
        self
    }
}

impl LinterInternal for RuleName {
    fn check(
        &self,
        report_builder: &ReportBuilder,
        rule: &ast::Rule,
    ) -> LinterResult {
        if !self.compiled_regex.is_match(rule.identifier.name) {
            if self.error {
                LinterResult::Err(errors::InvalidRuleName::build(
                    report_builder,
                    report_builder.span_to_code_loc(rule.identifier.span()),
                    self.regex.clone(),
                ))
            } else {
                LinterResult::Warn(warnings::InvalidRuleName::build(
                    report_builder,
                    report_builder.span_to_code_loc(rule.identifier.span()),
                    self.regex.clone(),
                ))
            }
        } else {
            LinterResult::Ok
        }
    }
}

type Predicate<'a> = dyn Fn(&Meta) -> bool + 'a;

/// A linter that ensures tags meet specified requirements in either an allowed
/// list of tags or in a regex.
///
/// ```
/// # use yara_x::Compiler;
/// use yara_x::linters;
/// let mut compiler = Compiler::new();
/// let warnings = compiler
///     .add_linter(linters::tags_allowed(vec!["foo".to_string(), "bar".to_string()]))
///     // This produces a warning because the rule tags are not from the
///     // allowed list
///     .add_source(r#"rule foo : test { strings: $foo = "foo" condition: $foo }"#)
///     .unwrap()
///     .warnings();
///
/// assert_eq!(
///     warnings[0].to_string(),
///     r#"warning[unknown_tag]: tag not in allowed list
///  --> line:1:12
///   |
/// 1 | rule foo : test { strings: $foo = "foo" condition: $foo }
///   |            ---- tag `test` not in allowed list
///   |
///   = note: allowed tags: foo, bar"#);
pub struct Tags {
    allowed: Vec<String>,
    regex: Option<String>,
    compiled_regex: Option<Regex>,
    error: bool,
}

impl Tags {
    /// A list of strings that tags for each rule must match one of.
    pub(crate) fn from_list(list: Vec<String>) -> Self {
        Self { allowed: list, regex: None, compiled_regex: None, error: false }
    }

    /// Regular expression that tags for each rule must match.
    pub(crate) fn from_regex<R: Into<String>>(
        regex: R,
    ) -> Result<Self, regex::Error> {
        let regex = regex.into();
        let compiled_regex = Some(Regex::new(regex.as_str())?);
        let tags = Self {
            allowed: Vec::new(),
            regex: Some(regex),
            compiled_regex,
            error: false,
        };
        Ok(tags)
    }

    /// Specifies whether the linter should produce an error instead of a
    /// warning.
    ///
    /// By default, the linter raises warnings about tags that don't match the
    /// regular expression. This setting allows turning such warnings into
    /// errors.
    pub fn error(mut self, yes: bool) -> Self {
        self.error = yes;
        self
    }
}

impl LinterInternal for Tags {
    fn check(
        &self,
        report_builder: &ReportBuilder,
        rule: &ast::Rule,
    ) -> LinterResult {
        if rule.tags.is_none() {
            return LinterResult::Ok;
        }

        let mut results: Vec<Warning> = Vec::new();
        let tags = rule.tags.as_ref().unwrap();
        if !self.allowed.is_empty() {
            for tag in tags.iter() {
                if !self.allowed.contains(&tag.name.to_string()) {
                    if self.error {
                        return LinterResult::Err(errors::UnknownTag::build(
                            report_builder,
                            report_builder.span_to_code_loc(tag.span()),
                            tag.name.to_string(),
                            Some(format!(
                                "allowed tags: {}",
                                self.allowed.join(", ")
                            )),
                        ));
                    } else {
                        results.push(warnings::UnknownTag::build(
                            report_builder,
                            report_builder.span_to_code_loc(tag.span()),
                            tag.name.to_string(),
                            Some(format!(
                                "allowed tags: {}",
                                self.allowed.join(", ")
                            )),
                        ));
                    }
                }
            }
        } else {
            let compiled_regex = self.compiled_regex.as_ref().unwrap();

            for tag in tags.iter() {
                if !compiled_regex.is_match(tag.name) {
                    if self.error {
                        return LinterResult::Err(errors::InvalidTag::build(
                            report_builder,
                            report_builder.span_to_code_loc(tag.span()),
                            tag.name.to_string(),
                            self.regex.as_ref().unwrap().clone(),
                        ));
                    } else {
                        results.push(warnings::InvalidTag::build(
                            report_builder,
                            report_builder.span_to_code_loc(tag.span()),
                            tag.name.to_string(),
                            self.regex.as_ref().unwrap().clone(),
                        ));
                    }
                }
            }
        }

        if results.is_empty() {
            LinterResult::Ok
        } else {
            LinterResult::Warns(results)
        }
    }
}

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
///   |      --- required metadata `author` not found"#);
/// ```
pub struct Metadata<'a> {
    identifier: String,
    predicate: Option<Box<Predicate<'a>>>,
    required: bool,
    error: bool,
    message: Option<String>,
    note: Option<String>,
}

impl<'a> Metadata<'a> {
    fn new<I: Into<String>>(identifier: I) -> Self {
        Self {
            identifier: identifier.into(),
            predicate: None,
            required: false,
            error: false,
            message: None,
            note: None,
        }
    }

    /// Specifies whether the metadata is required in all rules.
    pub fn required(mut self, yes: bool) -> Self {
        self.required = yes;
        self
    }

    /// Specifies whether the linter should produce an error instead of a warning.
    ///
    /// By default, the linter raises warnings about required metadata that is
    /// missing, or metadata that doesn't pass the validation. This setting allows
    /// turning such warnings into errors.
    pub fn error(mut self, yes: bool) -> Self {
        self.error = yes;
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
    ///  --> line:3:21
    ///   |
    /// 3 |            author = false
    ///   |                     ----- author must be a string"#);
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
    ) -> LinterResult {
        let mut found = false;
        for meta in rule.meta.iter().flatten() {
            if meta.identifier.name == self.identifier.as_str() {
                if let Some(predicate) = &self.predicate {
                    if !predicate(meta) {
                        return if self.error {
                            LinterResult::Err(errors::InvalidMetadata::build(
                                report_builder,
                                meta.identifier.name.to_string(),
                                report_builder
                                    .span_to_code_loc(meta.value.span()),
                                self.message
                                    .clone()
                                    .unwrap_or("invalid metadata".to_string()),
                            ))
                        } else {
                            LinterResult::Warn(
                                warnings::InvalidMetadata::build(
                                    report_builder,
                                    meta.identifier.name.to_string(),
                                    report_builder
                                        .span_to_code_loc(meta.value.span()),
                                    self.message.clone().unwrap_or(
                                        "invalid metadata".to_string(),
                                    ),
                                ),
                            )
                        };
                    }
                }
                found = true;
            }
        }

        if self.required && !found {
            return if self.error {
                LinterResult::Err(errors::MissingMetadata::build(
                    report_builder,
                    report_builder.span_to_code_loc(rule.identifier.span()),
                    self.identifier.clone(),
                    self.note.clone(),
                ))
            } else {
                LinterResult::Warn(warnings::MissingMetadata::build(
                    report_builder,
                    report_builder.span_to_code_loc(rule.identifier.span()),
                    self.identifier.clone(),
                    self.note.clone(),
                ))
            };
        }

        LinterResult::Ok
    }
}

/// Creates a tag linter from a list of allowed tags.
pub fn tags_allowed(list: Vec<String>) -> Tags {
    Tags::from_list(list)
}

/// Creates a tag linter that makes sure that each tag matches the given regular
/// expression.
pub fn tag_regex<R: Into<String>>(regex: R) -> Result<Tags, Error> {
    Tags::from_regex(regex)
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
