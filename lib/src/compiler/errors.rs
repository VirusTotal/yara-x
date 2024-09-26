#![cfg_attr(any(), rustfmt::skip)]

use std::fmt::{Debug, Display, Formatter};
use std::io;
use serde::Serialize;

use thiserror::Error;

use yara_x_macros::ErrorEnum;
use yara_x_macros::ErrorStruct;
use yara_x_parser::ast;

use crate::compiler::report::{Level, Report, ReportBuilder, CodeLoc, Label, Footer};

/// Error returned while serializing/deserializing compiled rules.
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

    /// Error occurred while deserializing WASM code.
    #[error("invalid YARA-X compiled rules file")]
    InvalidWASM(#[from] anyhow::Error),
}

/// Error returned by [`crate::Compiler::emit_wasm_file`].
#[derive(Error, Debug)]
#[error(transparent)]
#[doc(hidden)]
pub struct EmitWasmError(#[from] anyhow::Error);

/// Error returned when rule compilation fails.
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(ErrorEnum, Error, Clone, PartialEq, Eq)]
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum CompileError {
    AssignmentMismatch(Box<AssignmentMismatch>),
    ConflictingRuleIdentifier(Box<ConflictingRuleIdentifier>),
    CustomError(Box<CustomError>),
    DuplicateModifier(Box<DuplicateModifier>),
    DuplicatePattern(Box<DuplicatePattern>),
    DuplicateRule(Box<DuplicateRule>),
    DuplicateTag(Box<DuplicateTag>),
    EmptyPatternSet(Box<EmptyPatternSet>),
    EntrypointUnsupported(Box<EntrypointUnsupported>),
    InvalidBase64Alphabet(Box<InvalidBase64Alphabet>),
    InvalidEscapeSequence(Box<InvalidEscapeSequence>),
    InvalidFloat(Box<InvalidFloat>),
    InvalidInteger(Box<InvalidInteger>),
    InvalidModifier(Box<InvalidModifier>),
    InvalidModifierCombination(Box<InvalidModifierCombination>),
    InvalidPattern(Box<InvalidPattern>),
    InvalidRange(Box<InvalidRange>),
    InvalidRegexp(Box<InvalidRegexp>),
    InvalidRegexpModifier(Box<InvalidRegexpModifier>),
    InvalidUTF8(Box<InvalidUTF8>),
    MismatchingTypes(Box<MismatchingTypes>),
    MixedGreediness(Box<MixedGreediness>),
    NumberOutOfRange(Box<NumberOutOfRange>),
    PotentiallySlowLoop(Box<PotentiallySlowLoop>),
    SlowPattern(Box<SlowPattern>),
    SyntaxError(Box<SyntaxError>),
    TooManyPatterns(Box<TooManyPatterns>),
    UnexpectedEscapeSequence(Box<UnexpectedEscapeSequence>),
    UnexpectedNegativeNumber(Box<UnexpectedNegativeNumber>),
    UnknownField(Box<UnknownField>),
    UnknownIdentifier(Box<UnknownIdentifier>),
    UnknownModule(Box<UnknownModule>),
    UnknownPattern(Box<UnknownPattern>),
    UnusedPattern(Box<UnusedPattern>),
    WrongArguments(Box<WrongArguments>),
    WrongType(Box<WrongType>),
}

impl CompileError {
    pub(crate) fn from(
        report_builder: &ReportBuilder,
        err: ast::Error,
    ) -> Self {
        match err {
            ast::Error::SyntaxError { message, span } => {
                SyntaxError::build(report_builder, message, span.into())
            }
            ast::Error::InvalidInteger { message, span } => {
                InvalidInteger::build(report_builder, message, span.into())
            }
            ast::Error::InvalidFloat { message, span } => {
                InvalidFloat::build(report_builder, message, span.into())
            }
            ast::Error::InvalidRegexpModifier { message, span } => {
                InvalidRegexpModifier::build(
                    report_builder,
                    message,
                    span.into(),
                )
            }
            ast::Error::InvalidEscapeSequence { message, span } => {
                InvalidEscapeSequence::build(
                    report_builder,
                    message,
                    span.into(),
                )
            }
            ast::Error::UnexpectedEscapeSequence(span) => {
                UnexpectedEscapeSequence::build(report_builder, span.into())
            }
            ast::Error::InvalidUTF8(span) => {
                InvalidUTF8::build(report_builder, span.into())
            }
        }
    }

    /// Utility function that receives an array of strings and joins them
    /// together separated by commas and with "or" before the last one.
    /// For example, if input is `["s1", "s2", "s3"]` the result is:
    ///
    /// ```text
    /// str1, str2 or str3
    /// ```
    ///
    /// If `quotes` is true, the strings are enclosed in back tilts, like this:
    ///
    /// ```text
    /// `str1`, `str2` or `str3`
    /// ```
    ///
    pub(crate) fn join_with_or<S: ToString>(s: &[S], quotes: bool) -> String {
        let mut strings = if quotes {
            s.iter()
                .map(|s| format!("`{}`", s.to_string()))
                .collect::<Vec<String>>()
        } else {
            s.iter().map(|s| s.to_string()).collect::<Vec<String>>()
        };

        // Sort alphabetically.
        strings.sort();

        // Deduplicate repeated items.
        strings.dedup();

        match strings.len() {
            1 => strings[0].to_owned(),
            2 => format!("{} or {}", strings[0], strings[1]),
            l => {
                format!(
                    "{}, or {}",
                    strings[..l - 1].join(", "),
                    strings[l - 1]
                )
            }
        }
    }
}

/// A syntax error was found in the rule.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E001", title = "syntax error")]
#[label("{error}", error_loc)]
pub struct SyntaxError {
    report: Report,
    error: String,
    error_loc: CodeLoc,
}

/// Some expression has an unexpected type.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E002", title = "wrong type")]
#[label(
    "expression should be {expected_types}, but it is {actual_type}",
    error_loc
)]
#[footer(help, Level::Help)]
pub struct WrongType {
    report: Report,
    expected_types: String,
    actual_type: String,
    error_loc: CodeLoc,
    help: Option<String>,
}

/// Operands have mismatching types.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E003", title = "mismatching types")]
#[label("this expression is `{type1}`", type1_loc)]
#[label("this expression is `{type2}`", type2_loc)]
pub struct MismatchingTypes {
    report: Report,
    type1: String,
    type2: String,
    type1_loc: CodeLoc,
    type2_loc: CodeLoc,
}

/// Wrong arguments when calling a function.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E004", title = "wrong arguments")]
#[label("wrong arguments in this call", error_loc)]
#[footer(note)]
pub struct WrongArguments {
    report: Report,
    error_loc: CodeLoc,
    note: Option<String>,
}

/// Mismatch between number of variables and number of values in a loop
/// expression.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E005", title = "assignment mismatch")]
#[label("this expects {expected_values} value(s)", error_loc)]
#[label("this produces {actual_values} value(s)", iterable_loc)]
pub struct AssignmentMismatch {
    report: Report,
    expected_values: u8,
    actual_values: u8,
    iterable_loc: CodeLoc,
    error_loc: CodeLoc,
}

/// Negative number used where positive number was expected.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E006", title = "unexpected negative number")]
#[label("this number can not be negative", error_loc)]
pub struct UnexpectedNegativeNumber {
    report: Report,
    error_loc: CodeLoc,
}

/// A number is out of the allowed range.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E007", title = "number out of range")]
#[label("this number is out of the allowed range [{min}-{max}]", error_loc)]
pub struct NumberOutOfRange {
    report: Report,
    min: i64,
    max: i64,
    error_loc: CodeLoc,
}

/// Unknown field or method name.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E008", title = "unknown field or method `{identifier}`")]
#[label("this field or method doesn't exist", error_loc)]
pub struct UnknownField {
    report: Report,
    identifier: String,
    error_loc: CodeLoc,
}

/// Unknown identifier.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E009", title = "unknown identifier `{identifier}`")]
#[label("this identifier has not been declared", identifier_loc)]
#[footer(note)]
pub struct UnknownIdentifier {
    report: Report,
    identifier: String,
    identifier_loc: CodeLoc,
    note: Option<String>,
}

impl UnknownIdentifier {
    /// Name of the unknown identifier.
    #[inline]
    pub fn identifier(&self) -> &str {
        self.identifier.as_str()
    }
    /// Location of the unknown identifier.
    pub(crate) fn identifier_location(&self) -> &CodeLoc {
        &self.identifier_loc
    }
}

/// Unknown module.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E010", title = "unknown module `{identifier}`")]
#[label("module `{identifier}` not found", error_loc)]
pub struct UnknownModule {
    report: Report,
    identifier: String,
    error_loc: CodeLoc,
}

/// Invalid range.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E011", title = "invalid range")]
#[label("{error}", error_loc)]
pub struct InvalidRange {
    report: Report,
    error: String,
    error_loc: CodeLoc,
}

/// Two rules have the same name.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E012", title = "duplicate rule `{new_rule}`")]
#[label(
    "duplicate declaration of `{new_rule}`",
    duplicate_rule_loc,
    Level::Error
)]
#[label(
    "`{new_rule}` declared here for the first time",
    existing_rule_loc,
    Level::Note
)]
pub struct DuplicateRule {
    report: Report,
    new_rule: String,
    duplicate_rule_loc: CodeLoc,
    existing_rule_loc: CodeLoc,
}


/// A rule has the same name as a module or global variable.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(
    code = "E013",
    title = "rule `{identifier}` conflicts with an existing identifier"
)]
#[label("identifier already in use by a module or global variable", error_loc)]
pub struct ConflictingRuleIdentifier {
    report: Report,
    identifier: String,
    error_loc: CodeLoc,
}

/// A regular expression is invalid.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E014", title = "invalid regular expression")]
#[label("{error}", error_loc)]
#[footer(note)]
pub struct InvalidRegexp {
    report: Report,
    error: String,
    error_loc: CodeLoc,
    note: Option<String>,
}

/// A regular expression contains a mixture of greedy and non-greedy quantifiers.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(
    code = "E015",
    title = "mixing greedy and non-greedy quantifiers in regular expression"
)]
#[label("this is {quantifier1_greediness}", quantifier1_loc)]
#[label("this is {quantifier2_greediness}", quantifier2_loc)]
pub struct MixedGreediness {
    report: Report,
    quantifier1_greediness: String,
    quantifier2_greediness: String,
    quantifier1_loc: CodeLoc,
    quantifier2_loc: CodeLoc,
}

/// A set of patterns doesn't contain any patterns.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E016", title = "no matching patterns")]
#[label("there's no pattern in this set", error_loc)]
#[footer(note)]
pub struct EmptyPatternSet {
    report: Report,
    error_loc: CodeLoc,
    note: Option<String>,
}

/// The `entrypoint` keyword is not supported.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E017", title = "`entrypoint` is unsupported")]
#[label("the `entrypoint` keyword is not supported anymore", error_loc)]
#[label(
    "use `pe.entry_point` or `elf.entry_point` or `macho.entry_point`",
    error_loc,
    Level::Help
)]
pub struct EntrypointUnsupported {
    report: Report,
    error_loc: CodeLoc,
}

/// Some pattern may be potentially slow.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E018", title = "slow pattern")]
#[label("this pattern may slow down the scan", error_loc)]
pub struct SlowPattern {
    report: Report,
    error_loc: CodeLoc,
}

/// A pattern has modifiers that can't be used together.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(
    code = "E019",
    title = "invalid modifier combination: `{modifier1}` `{modifier2}`"
)]
#[label("`{modifier1}` modifier used here", modifier1_loc)]
#[label("`{modifier2}` modifier used here", modifier2_loc)]
#[footer(note)]
pub struct InvalidModifierCombination {
    report: Report,
    modifier1: String,
    modifier2: String,
    modifier1_loc: CodeLoc,
    modifier2_loc: CodeLoc,
    note: Option<String>,
}

/// A pattern has duplicate modifiers.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E020", title = "duplicate pattern modifier")]
#[label("duplicate modifier", error_loc)]
pub struct DuplicateModifier {
    report: Report,
    error_loc: CodeLoc,
}

/// A rule has duplicate tags.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E021", title = "duplicate tag `{tag}`")]
#[label("duplicate tag", error_loc)]
pub struct DuplicateTag {
    report: Report,
    tag: String,
    error_loc: CodeLoc,
}

/// A rule defines a pattern that is not used in the condition.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E022", title = "unused pattern `{pattern_ident}`")]
#[label("this pattern was not used in the condition", error_loc)]
pub struct UnusedPattern {
    report: Report,
    pattern_ident: String,
    error_loc: CodeLoc,
}

/// A rule has two patterns with the same identifier.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E023", title = "duplicate pattern `{pattern_ident}`")]
#[label("duplicate declaration of `{pattern_ident}`", error_loc)]
#[label(
    "`{pattern_ident}` declared here for the first time",
    note_loc,
    Level::Note
)]
pub struct DuplicatePattern {
    report: Report,
    pattern_ident: String,
    error_loc: CodeLoc,
    note_loc: CodeLoc,
}

/// A rule has an invalid pattern.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E024", title = "invalid pattern `{pattern_ident}`")]
#[label("{error}", error_loc)]
#[footer(note)]
pub struct InvalidPattern {
    report: Report,
    pattern_ident: String,
    error: String,
    error_loc: CodeLoc,
    note: Option<String>,
}

/// Some rule condition uses a pattern that was not defined.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E025", title = "unknown pattern `{pattern_ident}`")]
#[label("this pattern is not declared in the `strings` section", error_loc)]
pub struct UnknownPattern {
    report: Report,
    pattern_ident: String,
    error_loc: CodeLoc,
}

/// Wrong alphabet for the `base64` or `base64wide` modifiers.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E026", title = "invalid base64 alphabet")]
#[label("{error}", error_loc)]
pub struct InvalidBase64Alphabet {
    report: Report,
    error: String,
    error_loc: CodeLoc,
}

/// Invalid integer.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E027", title = "invalid integer")]
#[label("{error}", error_loc)]
pub struct InvalidInteger {
    report: Report,
    error: String,
    error_loc: CodeLoc,
}

/// Invalid float.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E028", title = "invalid float")]
#[label("{error}", error_loc)]
pub struct InvalidFloat {
    report: Report,
    error: String,
    error_loc: CodeLoc,
}

/// A text pattern contains an invalid escape sequence.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E029", title = "invalid escape sequence")]
#[label("{error}", error_loc)]
pub struct InvalidEscapeSequence {
    report: Report,
    error: String,
    error_loc: CodeLoc,
}

/// Invalid modifier for a regular expression.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E030", title = "invalid regexp modifier `{modifier}`")]
#[label("invalid modifier", error_loc)]
pub struct InvalidRegexpModifier {
    report: Report,
    modifier: String,
    error_loc: CodeLoc,
}

/// A string literal contains escaped sequences and it shouldn't.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E031", title = "unexpected escape sequence")]
#[label("escape sequences are not allowed in this string", error_loc)]
pub struct UnexpectedEscapeSequence {
    report: Report,
    error_loc: CodeLoc,
}


/// Source code contains invalid UTF-8 characters.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E032", title = "invalid UTF-8")]
#[label("invalid UTF-8 character", error_loc)]
pub struct InvalidUTF8 {
    report: Report,
    error_loc: CodeLoc,
}

/// Some pattern has an invalid modifier.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E033", title = "invalid pattern modifier")]
#[label("{error}", error_loc)]
pub struct InvalidModifier {
    report: Report,
    error: String,
    error_loc: CodeLoc,
}

/// A rule contains a loop that could be very slow.
///
/// This error indicates that a rule contains a `for` loop that may be very
/// slow because it iterates over a range with an upper bound that depends on
/// `filesize`. For very large files this may mean hundreds of millions of
/// iterations.
///
/// # Example
///
/// ```text
/// error[E034]: potentially slow loop
///  --> test.yar:1:34
///   |
/// 1 | rule t { condition: for any i in (0..filesize-1) : ( int32(i) == 0xcafebabe ) }
///   |                                  --------------- this range can be very large
///   |
/// ```
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E034", title = "potentially slow loop")]
#[label(
"this range can be very large",
    loc
)]
pub struct PotentiallySlowLoop {
    report: Report,
    loc: CodeLoc,
}

/// A rule has too many patterns.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E035", title = "too many patterns in a rule")]
#[label("this rule has more than {max_num_patterns} patterns", error_loc)]
pub struct TooManyPatterns {
    report: Report,
    max_num_patterns: usize,
    error_loc: CodeLoc,
}

/// A custom error has occurred.
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(CompileError)]
#[error(code = "E100", title = "{title}")]
#[label("{error}", error_loc)]
pub struct CustomError {
    report: Report,
    title: String,
    error: String,
    error_loc: CodeLoc,
}