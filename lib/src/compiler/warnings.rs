#![cfg_attr(any(), rustfmt::skip)]

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
    ConsecutiveJumps(Box<ConsecutiveJumps>),
    PotentiallySlowLoop(Box<PotentiallySlowLoop>),
    PotentiallyUnsatisfiableExpression(Box<PotentiallyUnsatisfiableExpression>),
    InvariantBooleanExpression(Box<InvariantBooleanExpression>),
    NonBooleanAsBoolean(Box<NonBooleanAsBoolean>),
    BooleanIntegerComparison(Box<BooleanIntegerComparison>),
    DuplicateImport(Box<DuplicateImport>),
    RedundantCaseModifier(Box<RedundantCaseModifier>),
    SlowPattern(Box<SlowPattern>),
    IgnoredModule(Box<IgnoredModule>),
    IgnoredRule(Box<IgnoredRule>),
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
    Level::Note
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
pub struct SlowPattern {
    report: Report,
    pattern_loc: CodeLoc,
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


