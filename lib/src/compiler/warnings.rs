#![cfg_attr(any(), rustfmt::skip)]
#![allow(clippy::duplicated_attributes)]

use std::fmt::{Debug, Display, Formatter};
use serde::Serialize;

use thiserror::Error;

use yara_x_macros::ErrorEnum;
use yara_x_macros::ErrorStruct;

use crate::compiler::report::{Level, Report, ReportBuilder, CodeLoc, Label, Footer};

/// A warning raised while compiling YARA rules.
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(ErrorEnum, Error, PartialEq, Eq)]
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum Warning {
    BooleanIntegerComparison(Box<BooleanIntegerComparison>),
    ConsecutiveJumps(Box<ConsecutiveJumps>),
    DeprecatedField(Box<DeprecatedField>),
    DuplicateImport(Box<DuplicateImport>),
    IgnoredModule(Box<IgnoredModule>),
    IgnoredRule(Box<IgnoredRule>),
    InvalidMetadata(Box<InvalidMetadata>),
    InvalidRuleName(Box<InvalidRuleName>),
    InvalidTag(Box<InvalidTag>),
    InvariantBooleanExpression(Box<InvariantBooleanExpression>),
    MissingMetadata(Box<MissingMetadata>),
    NonBooleanAsBoolean(Box<NonBooleanAsBoolean>),
    PotentiallySlowLoop(Box<PotentiallySlowLoop>),
    PotentiallyUnsatisfiableExpression(Box<PotentiallyUnsatisfiableExpression>),
    RedundantCaseModifier(Box<RedundantCaseModifier>),
    SlowPattern(Box<SlowPattern>),
    TextPatternAsHex(Box<TextPatternAsHex>),
    TooManyIterations(Box<TooManyIterations>),
    UnsatisfiableExpression(Box<UnsatisfiableExpression>),
    UnknownTag(Box<UnknownTag>),
}

/// A hex pattern contains two or more consecutive jumps.
///
/// For instance, in `{01 02 [0-2] [1-3] 03 04 }` the jumps `[0-2]` and `[1-3]`
/// appear one after the other. Consecutive jumps are useless, and they can be
/// folded into a single one. In this case they can be replaced by `[1-5]`.
///
/// ## Example
///
/// ```text
/// warning[consecutive_jumps]: consecutive jumps in hex pattern `$a`
/// --> line:3:18
///   |
/// 3 |     $a = { 0F 84 [4] [0-7] 8D }
///   |                  --------- these consecutive jumps will be treated as [4-11]
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "consecutive_jumps",
    title = "consecutive jumps in hex pattern `{pattern_ident}`",
)]
#[label(
    "these consecutive jumps will be treated as {coalesced_jump}",
    coalesced_jump_loc
)]
pub struct ConsecutiveJumps {
    report: Report,
    pattern_ident: String,
    coalesced_jump: String,
    coalesced_jump_loc: CodeLoc,
}

impl ConsecutiveJumps {
    /// Identifier of the pattern containing the consecutive jumps.
    #[inline]
    pub fn pattern(&self) -> &str {
        self.pattern_ident.as_str()
    }
}

/// A rule contains a loop that could be very slow.
///
/// This warning indicates that a rule contains a `for` loop that may be very
/// slow because it iterates over a range with an upper bound that depends on
/// `filesize`. For very large files this may mean hundreds of millions of
/// iterations.
///
/// # Example
///
/// ```text
/// warning[potentially_slow_loop]: potentially slow loop
///  --> test.yar:1:34
///   |
/// 1 | rule t { condition: for any i in (0..filesize-1) : ( int32(i) == 0xcafebabe ) }
///   |                                  --------------- this range can be very large
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "potentially_slow_loop",
    title = "potentially slow loop",
)]
#[label(
    "this range can be very large",
    loc
)]
pub struct PotentiallySlowLoop {
    report: Report,
    loc: CodeLoc,
}

/// A boolean expression may be impossible to match.
///
/// For instance, the condition `2 of ($a, $b) at 0` is impossible
/// to match, unless that both `$a` and `$b` are the same pattern,
/// or one is a prefix of the other. In most cases this expression
/// is unsatisfiable because two different matches can match at the
/// same file offset.
///
/// ## Example
///
/// ```text
/// warning[unsatisfiable_expr]: potentially unsatisfiable expression
/// --> line:6:5
///   |
/// 6 |     2 of ($*) at 0
///   |     - this implies that multiple patterns must match
///   |               ---- but they must match at the same offset
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "unsatisfiable_expr",
    title = "potentially unsatisfiable expression"
)]
#[label(
    "this implies that multiple patterns must match",
    quantifier_loc
)]
#[label(
    "but they must match at the same offset",
    at_loc
)]
pub struct PotentiallyUnsatisfiableExpression {
    report: Report,
    quantifier_loc: CodeLoc,
    at_loc: CodeLoc,
}

/// A boolean expression can't be satisfied.
///
/// ## Example
///
/// ```text
/// warning[unsatisfiable_expr]: unsatisfiable expression
/// --> test.yar:6:34
/// |
/// 6 | rule x { condition: "AD" == hash.sha256(0,filesize) }
/// |                     ----         ------------------ this is a lowercase string
/// |                     |
/// |                     this contains uppercase characters
/// |
/// = note: a lowercase strings can't be equal to a string containing uppercase characters
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "unsatisfiable_expr",
    title = "unsatisfiable expression"
)]
#[label(
    "{label_1}",
    loc_1
)]
#[label(
    "{label_2}",
    loc_2
)]
#[footer(note)]
pub struct UnsatisfiableExpression {
    report: Report,
    label_1: String,
    label_2: String,
    loc_1: CodeLoc,
    loc_2: CodeLoc,
    note: Option<String>,
}


/// A boolean expression always has the same value.
///
/// This warning indicates that some boolean expression is always true or false,
/// regardless of the data being scanned.
///
/// ## Example
///
/// ```text
/// warning[invariant_expr]: invariant boolean expression
///  --> line:6:5
///   |
/// 6 |     3 of them
///   |     --------- this expression is always false
///   |
///   = note: the expression requires 3 matching patterns out of 2
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "invariant_expr",
    title = "invariant boolean expression"
)]
#[label(
    "this expression is always {expr_value}",
    expr_loc
)]
#[footer(note)]
pub struct InvariantBooleanExpression {
    report: Report,
    expr_value: bool,
    expr_loc: CodeLoc,
    note: Option<String>,
}

/// A non-boolean expression is being used as a boolean.
///
/// ## Example
///
/// ```text
/// warning[non_bool_expr]: non-boolean expression used as boolean
/// --> line:3:14
///   |
/// 3 |   condition: 2 and 3
///   |              - this expression is `integer` but is being used as `bool`
///   |
///   = note: non-zero integers are considered `true`, while zero is `false`
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "non_bool_expr",
    title = "non-boolean expression used as boolean"
)]
#[label(
    "this expression is `{expr_type}` but is being used as `bool`",
    expr_loc
)]
#[footer(note)]
pub struct NonBooleanAsBoolean {
    report: Report,
    expr_type: String,
    expr_loc: CodeLoc,
    note: Option<String>,
}

/// Comparison between boolean and integer.
///
/// This warning indicates that some expression is a comparison between
/// boolean and integer values.
///
/// ## Example
///
/// ```text
/// warning[bool_int_comparison]: comparison between boolean and integer
/// --> line:4:13
///   |
/// 4 |  condition: test_proto2.array_bool[0] == 1
///   |             ------------------------------ this comparison can be replaced with: `test_proto2.array_bool[0]`
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "bool_int_comparison",
    title = "comparison between boolean and integer"
)]
#[label(
    "this comparison can be replaced with: `{replacement}`",
    expr_loc
)]
pub struct BooleanIntegerComparison {
    report: Report,
    replacement: String,
    expr_loc: CodeLoc,
}

/// Duplicate import statement.
///
/// This warning indicates that some module has been imported multiple times.
///
/// ## Example
///
/// ```text
/// warning[duplicate_import]: duplicate import statement
/// --> line:1:21
///   |
/// 1 | import "test_proto2"
///   | -------------------- note: `test_proto2` imported here for the first time
/// 2 | import "test_proto2"
///   | -------------------- duplicate import
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "duplicate_import",
    title = "duplicate import statement"
)]
#[label(
    "duplicate import",
    new_import_loc
)]
#[label(
    "`{module_name}` imported here for the first time",
    existing_import_loc,
    Level::NOTE
)]
pub struct DuplicateImport {
    report: Report,
    module_name: String,
    new_import_loc: CodeLoc,
    existing_import_loc: CodeLoc,
}


/// Redundant case-insensitive modifier for a regular expression.
///
/// A regular expression can be made case-insensitive in two ways: by using the
/// `nocase` modifier or by appending the `i` suffix to the pattern. Both
/// methods achieve the same result, making it redundant to use them
/// simultaneously.
///
/// For example, the following patterns are equivalent:
///
/// ```text
/// $re = /some regexp/i
/// $re = /some regexp/ nocase
/// ```
///
/// ## Example
///
/// ```text
/// warning[redundant_modifier]: redundant case-insensitive modifier
/// --> line:3:15
///   |
/// 3 |     $a = /foo/i nocase
///   |               - the `i` suffix indicates that the pattern is case-insensitive
///   |                 ------ the `nocase` modifier does the same
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "redundant_modifier",
    title = "redundant case-insensitive modifier"
)]
#[label(
    "the `i` suffix indicates that the pattern is case-insensitive",
    i_loc
)]
#[label(
    "the `nocase` modifier does the same",
    nocase_loc
)]
pub struct RedundantCaseModifier {
    report: Report,
    nocase_loc: CodeLoc,
    i_loc: CodeLoc,
}

/// Some pattern may be potentially slow.
///
/// This warning indicates that a pattern may be very slow to match, and can
/// degrade rule's the performance. In most cases this is caused by patterns
/// that doesn't contain any large fixed sub-pattern that be used for speeding
/// up the scan. For example, `{00 [1-10] 01}` is very slow because the only
/// fixed sub-patterns (`00` and `01`) are only one byte long.
///
/// ## Example
///
/// ```text
/// warning[slow_pattern]: slow pattern
/// --> line:3:5
///   |
/// 3 |     $a = {00 [1-10] 01}
///   |     ------------------ this pattern may slow down the scan
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "slow_pattern",
    title = "slow pattern"
)]
#[label(
    "this pattern may slow down the scan",
    pattern_loc
)]
#[footer(note)]
pub struct SlowPattern {
    report: Report,
    pattern_loc: CodeLoc,
    note: Option<String>,
}

/// An unsupported module has been used.
///
/// If you use [`crate::Compiler::ignore_module`] for telling the compiler
/// that some module is not supported, the compiler will raise this warning
/// when the module is used in some of your rules.
///
/// ## Example
///
/// ```text
/// warning[unsupported_module]: module `magic` is not supported
/// --> line:4:5
///   |
/// 4 |     magic.type()
///   |     ----- module `magic` used here
///   |
/// = note: the whole rule `foo` will be ignored
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "unsupported_module",
    title = "module `{module_name}` is not supported"
)]
#[label(
    "module `{module_name}` used here",
    module_name_loc
)]
#[footer(note)]
pub struct IgnoredModule {
    report: Report,
    module_name: String,
    module_name_loc: CodeLoc,
    note: Option<String>,
}

/// A rule indirectly depends on some unsupported module.
///
/// If you use [`crate::Compiler::ignore_module`] for telling the compiler
/// that some module is not supported, the compiler will raise this warning
/// when a rule `A` uses some rule `B` that uses the module.
///
/// ## Example
///
/// ```text
/// warning[ignored_rule]: rule `foo` will be ignored due to an indirect dependency on module `magic`
/// --> line:9:5
///   |
/// 9 |     bar
///   |     --- this other rule depends on module `magic`, which is unsupported
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "ignored_rule",
    title = "rule `{ignored_rule}` will be ignored due to an indirect dependency on module `{module_name}`"
)]
#[label(
    "this other rule depends on module `{module_name}`, which is unsupported",
    ignored_rule_loc
)]
pub struct IgnoredRule {
    report: Report,
    module_name: String,
    ignored_rule: String,
    ignored_rule_loc: CodeLoc,
}

/// Some hex pattern can be written as a text literal.
///
/// For instance `{61 62 63}` can be written as "abc". Text literals are
/// preferred over hex patterns because they are more legible.
///
/// ## Example
///
/// ```text
/// warning[text_as_hex]: hex pattern could be written as text literal
///  --> test.yar:6:4
///   |
/// 6 |    $d = { 61 61 61 }
///   |    --------------- this pattern can be written as a text literal
///   |    --------------- help: replace with "aaa"
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "text_as_hex",
    title = "hex pattern could be written as text literal"
)]
#[label(
    "this pattern can be written as a text literal",
    pattern_loc
)]
#[label(
    "replace with \"{text}\"",
    pattern_loc,
    Level::HELP
)]
pub struct TextPatternAsHex {
    report: Report,
    text: String,
    pattern_loc: CodeLoc,
}

/// Some metadata entry is invalid. This is only used if the compiler is
/// configured to check for valid metadata (see: [`crate::linters::Metadata`]).
///
/// ## Example
///
/// ```text
/// warning[invalid_metadata]: metadata `author` is not valid
/// --> test.yar:4:5
///   |
/// 4 |     author = 1234
///   |              ---- `author` must be a string
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "invalid_metadata",
    title = "metadata `{name}` is not valid"
)]
#[label(
    "{label}",
    label_loc
)]
pub struct InvalidMetadata {
    report: Report,
    name: String,
    label_loc: CodeLoc,
    label: String,
}

/// Missing metadata. This is only used if the compiler is configured to check
/// for required metadata (see:  [`crate::linters::Metadata`]).
///
/// ## Example
///
/// ```text
/// warning[missing_metadata]: required metadata is missing
///  --> test.yar:12:6
///    |
/// 12 | rule pants {
///    |      ----- required metadata "date" not found
///    |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "missing_metadata",
    title = "required metadata is missing"
)]
#[label(
    "required metadata `{name}` not found",
    rule_loc
)]
#[footer(note)]
pub struct MissingMetadata {
    report: Report,
    rule_loc: CodeLoc,
    name: String,
    note: Option<String>,
}

/// Rule name does not match regex. This is only used if the compiler is
/// configured to check for it (see: [`crate::linters::RuleName`]).
///
/// ## Example
///
/// ```text
/// warning[invalid_rule_name]: rule name does not match regex `APT_.*`
///  --> test.yar:13:6
///    |
/// 13 | rule pants {
///    |      ----- this rule name does not match regex `APT_.*`
///    |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "invalid_rule_name",
    title = "rule name does not match regex `{regex}`"
)]
#[label(
    "this rule name does not match regex `{regex}`",
    rule_loc
)]
pub struct InvalidRuleName {
    report: Report,
    rule_loc: CodeLoc,
    regex: String,
}

/// A loop or nested loops have a total number of iterations exceeding a
/// predefined threshold.
///
/// This warning indicates that a rule contains a `for` loop, or a set of nested
/// `for` loops, that may be very slow because the total number of iterations
/// is very large.
///
/// # Example
///
/// ```text
/// warning[too_many_iterations]: loop has too many iterations
///  --> test.yar:1:20
///   |
/// 1 | rule t { condition: for any i in (0..1000) : ( for any j in (0..1000) : ( true ) ) }
///   |                    -------------------------------------------------------------- this loop iterates 1000000 times, which may be slow
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "too_many_iterations",
    title = "loop has too many iterations",
)]
#[label(
    "this loop iterates {iterations} times, which may be slow",
    loc
)]
pub struct TooManyIterations {
    report: Report,
    iterations: i64,
    loc: CodeLoc,
}

/// Unknown tag. This is only used if the compiler is configured to check
/// for required tags (see: [`crate::linters::Tags`]).
///
/// ## Example
///
/// ```text
/// warning[unknown_tag]: tag not in allowed list
///  --> rules/test.yara:1:10
///   |
/// 1 | rule a : foo {
///   |          --- tag `foo` not in allowed list
///   |
///   = note: allowed tags: test, bar
/// ```
#[derive(ErrorStruct, Clone, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "unknown_tag",
    title = "tag not in allowed list"
)]
#[label(
    "tag `{name}` not in allowed list",
    tag_loc
)]
#[footer(note)]
pub struct UnknownTag {
    report: Report,
    tag_loc: CodeLoc,
    name: String,
    note: Option<String>,
}

/// Tag does not match regex. This is only used if the compiler is configured to
/// check for it (see: [`crate::linters::Tags`]).
///
/// ## Example
///
/// ```text
/// warning[invalid_tag]: tag `foo` does not match regex `bar`
///  --> rules/test.yara:1:10
///   |
/// 1 | rule a : foo {
///   |          --- tag `foo` does not match regex `bar`
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "invalid_tag",
    title = "tag `{name}` does not match regex `{regex}`"
)]
#[label(
    "tag `{name}` does not match regex `{regex}`",
    tag_loc
)]
pub struct InvalidTag {
    report: Report,
    tag_loc: CodeLoc,
    name: String,
    regex: String,
}

/// A deprecated field was used in a YARA rule.
/// check for it (see: [`crate::linters::Tags`]).
///
/// ## Example
///
/// ```text
/// warning[deprecated_field]: field `foo` is deprecated
///  --> rules/test.yara:1:10
///   |
/// 3 | vt.metadata.foo
///   |             --- `foo` is deprecated, use `bar` instead
///   |
/// ```
#[derive(ErrorStruct, Debug, PartialEq, Eq)]
#[associated_enum(Warning)]
#[warning(
    code = "deprecated_field",
    title = "field `{name}` is deprecated`"
)]
#[label(
    "{msg}",
    loc
)]
pub struct DeprecatedField {
    report: Report,
    name: String,
    loc: CodeLoc,
    msg: String,
}