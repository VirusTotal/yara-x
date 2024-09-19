/*! Intermediate representation (IR) for a set of YARA rules.

The IR is a tree representing a set of YARA rules. This tree is similar to the
AST, but it contains type information for expressions and identifiers, something
that the AST doesn't have. The IR is generated from the AST, and the compiled
[Rules] are generated from the IR. This means that the IR is further away from
the original source code than the AST, and closer to the emitted code. The build
process goes like:

  `source code -> CST -> AST -> IR -> compiled rules`

Contrary to the AST, the IR doesn't have a one-to-one correspondence to the
original source code, the compiler is free to transform the IR in ways that
maintain the semantics of the original source code but doesn't match the code
exactly. This could be done for example for optimization purposes. Another
example is constant folding, which is done while the IR is being built,
converting expressions like `2+2+2` into the constant `6`.

The portions of the IR representing regular expressions and hex patterns
are entrusted to the [regex_syntax] crate, particularly to its [Hir] type. This
crate parses regular expressions and produce the corresponding [Hir]. For hex
patterns the [Hir] is generated from the AST by the [`hex2hir`] module.

Using a common representation for both regular expressions and hex patterns
allows using the same regex engine for matching both types of patterns.

[Rules]: crate::compiler::Rules
[regex_syntax]: https://docs.rs/regex-syntax/latest/regex_syntax/
[Hir]: regex_syntax::hir::Hir
*/

use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::ops::RangeInclusive;

use bitmask::bitmask;
use bstr::BString;
use serde::{Deserialize, Serialize};

use crate::compiler::context::{CompileContext, Var, VarStackFrame};
use crate::symbols::Symbol;
use crate::types::{Type, TypeValue, Value};

pub(in crate::compiler) use ast2ir::bool_expr_from_ast;
pub(in crate::compiler) use ast2ir::patterns_from_ast;

use yara_x_parser::ast::Ident;
use yara_x_parser::Span;

use crate::compiler::errors::{CompileError, NumberOutOfRange};
use crate::compiler::ir::dfs::{DepthFirstSearch, Event};
use crate::re;

mod ast2ir;
mod dfs;
mod hex2hir;

#[cfg(test)]
mod tests;

bitmask! {
    /// Flags associated to rule patterns.
    ///
    /// Each of these flags correspond to one of the allowed YARA pattern
    /// modifiers, and generally they are set if the corresponding modifier
    /// appears alongside the pattern in the source code. The only exception is
    /// the `Ascii` flag, which will be set when `Wide` is not set regardless
    /// of what the source code says. This follows the semantics of YARA
    /// pattern modifiers, in which a pattern is considered `ascii` by default
    /// when neither `ascii` nor `wide` modifiers are used.
    ///
    /// In resume either the `Ascii` or the `Wide` flags (or both) will be set.
    #[derive(Debug, Hash, Serialize, Deserialize)]
    pub mask PatternFlagSet: u16 where flags PatternFlags  {
        Ascii                = 0x0001,
        Wide                 = 0x0002,
        Nocase               = 0x0004,
        Base64               = 0x0008,
        Base64Wide           = 0x0010,
        Xor                  = 0x0020,
        Fullword             = 0x0040,
        Private              = 0x0080,
        NonAnchorable        = 0x0100,
    }
}

/// Represents a pattern in the context of a specific rule.
///
/// It encapsulates a [`Pattern`] alongside an identifier and information
/// regarding whether the pattern is anchored. The key distinction between
/// this type and [`Pattern`] lies in the context: while the latter defines
/// a pattern in a generic context, this structure represents a pattern
/// within the confines of a specific rule. If two distinct rules declare
/// precisely the same pattern, including any modifiers, they will reference
/// the same [`Pattern`] instance.
pub(in crate::compiler) struct PatternInRule<'src> {
    identifier: Ident<'src>,
    pattern: Pattern,
    span: Span,
    in_use: bool,
}

impl<'src> PatternInRule<'src> {
    #[inline]
    pub fn identifier(&self) -> &Ident<'src> {
        &self.identifier
    }

    #[inline]
    pub fn into_pattern(self) -> Pattern {
        self.pattern
    }

    #[inline]
    pub fn pattern(&self) -> &Pattern {
        &self.pattern
    }

    #[inline]
    pub fn span(&self) -> &Span {
        &self.span
    }

    #[inline]
    pub fn anchored_at(&self) -> Option<usize> {
        self.pattern.anchored_at()
    }

    #[inline]
    pub fn in_use(&self) -> bool {
        self.in_use
    }

    /// Anchor the pattern to a given offset. This means that the pattern can
    /// match only at that offset and nowhere else. This is a no-op for
    /// patterns that are flagged as non-anchorable.
    ///
    /// Also, if this function is called twice with different offsets, the
    /// pattern becomes non-anchorable because it can't be anchored to two
    /// different offsets.
    ///
    /// This is used when the condition contains an expression like `$a at 0`
    /// in order to indicate that the pattern (the `$a` pattern in this case)
    /// can match only at a fixed offset.
    pub fn anchor_at(&mut self, offset: usize) -> &mut Self {
        self.pattern.anchor_at(offset);
        self
    }

    /// Make the pattern non-anchorable. Any existing anchor is removed and
    /// future calls to [`PatternInRule::anchor_at`] are ignored.
    ///
    /// This function is used to indicate that a certain pattern can't be
    /// anchored at any fixed offset because it is used in ways that require
    /// finding all the possible matches. For example, in a condition like
    /// `#a > 0 and $a at 0`, the use of `#a` (which returns the number of
    /// occurrences of `$a`), makes `$a` non-anchorable because we need to find
    /// all occurrences of `$a`.
    pub fn make_non_anchorable(&mut self) -> &mut Self {
        self.pattern.make_non_anchorable();
        self
    }

    /// Marks the pattern as used.
    ///
    /// When a pattern is used in the condition this function is called to
    /// indicate that the pattern is in use.
    pub fn mark_as_used(&mut self) -> &mut Self {
        self.in_use = true;
        self
    }
}

/// Represents a pattern in YARA.
///
/// This type represents a pattern independently of the rule in which it was
/// declared. Multiple rules declaring exactly the same pattern will share the
/// same instance of [`Pattern`]. For representing a pattern in the context of
/// a specific rule we have [`PatternInRule`], which contains a [`Pattern`] and
/// additional information about how the pattern is used in a rule.
#[derive(Clone, Eq, Hash, PartialEq)]
pub(in crate::compiler) enum Pattern {
    /// A literal pattern is one that doesn't contain wildcards, alternatives,
    /// or any kind of variable content. For example, the text pattern `"foo"`,
    /// the regular expression `/foo/`, and the hex pattern `{01 02 03}` are
    /// all literal.
    Literal(LiteralPattern),
    /// A regexp pattern is one that contains wildcards and/or alternatives,
    /// like regular expression `/foo.*bar/` and hex pattern `{01 ?? 03}`.
    Regexp(RegexpPattern),
}

impl Pattern {
    #[inline]
    pub fn flags(&self) -> &PatternFlagSet {
        match self {
            Pattern::Literal(literal) => &literal.flags,
            Pattern::Regexp(regexp) => &regexp.flags,
        }
    }

    #[inline]
    pub fn flags_mut(&mut self) -> &mut PatternFlagSet {
        match self {
            Pattern::Literal(literal) => &mut literal.flags,
            Pattern::Regexp(regexp) => &mut regexp.flags,
        }
    }

    #[inline]
    pub fn anchored_at(&self) -> Option<usize> {
        match self {
            Pattern::Literal(literal) => literal.anchored_at,
            Pattern::Regexp(regexp) => regexp.anchored_at,
        }
    }

    /// Anchor the pattern to a given offset. This means that the pattern can
    /// match only at that offset and nowhere else. This is a no-op for
    /// patterns that are flagged as non-anchorable.
    ///
    /// Also, if this function is called twice with different offsets, the
    /// pattern becomes non-anchorable because it can't be anchored to two
    /// different offsets.
    ///
    /// This is used when the condition contains an expression like `$a at 0`
    /// in order to indicate that the pattern (the `$a` pattern in this case)
    /// can match only at a fixed offset.
    pub fn anchor_at(&mut self, offset: usize) {
        let is_anchorable =
            !self.flags().contains(PatternFlags::NonAnchorable);

        let anchored_at = match self {
            Pattern::Literal(literal) => &mut literal.anchored_at,
            Pattern::Regexp(regexp) => &mut regexp.anchored_at,
        };

        match anchored_at {
            Some(o) if *o != offset => {
                *anchored_at = None;
                self.flags_mut().set(PatternFlags::NonAnchorable);
            }
            None => {
                if is_anchorable {
                    *anchored_at = Some(offset);
                }
            }
            _ => {}
        }
    }

    /// Make the pattern non-anchorable. Any existing anchor is removed and
    /// future calls to [`PatternInRule::anchor_at`] are ignored.
    ///
    /// This function is used to indicate that a certain pattern can't be
    /// anchored at any fixed offset because it is used in ways that require
    /// finding all the possible matches. For example, in a condition like
    /// `#a > 0 and $a at 0`, the use of `#a` (which returns the number of
    /// occurrences of `$a`), makes `$a` non-anchorable because we need to
    /// find all occurrences of `$a`.
    pub fn make_non_anchorable(&mut self) {
        match self {
            Pattern::Literal(literal) => literal.anchored_at = None,
            Pattern::Regexp(regexp) => regexp.anchored_at = None,
        };
        self.flags_mut().set(PatternFlags::NonAnchorable);
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(in crate::compiler) struct LiteralPattern {
    pub flags: PatternFlagSet,
    pub text: BString,
    pub anchored_at: Option<usize>,
    pub xor_range: Option<RangeInclusive<u8>>,
    pub base64_alphabet: Option<String>,
    pub base64wide_alphabet: Option<String>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(in crate::compiler) struct RegexpPattern {
    pub flags: PatternFlagSet,
    pub hir: re::hir::Hir,
    pub anchored_at: Option<usize>,
}

/// The index of a pattern in the rule that declares it.
///
/// The first pattern in the rule has index 0, the second has index 1, and
/// so on.
#[derive(Debug, Clone, Copy)]
pub(in crate::compiler) struct PatternIdx(usize);

impl PatternIdx {
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl From<usize> for PatternIdx {
    #[inline]
    fn from(value: usize) -> Self {
        Self(value)
    }
}

/// Intermediate representation (IR) for an expression.
pub(in crate::compiler) enum Expr {
    /// Constant value (i.e: the value is known at compile time).
    /// The value in `TypeValue` is not `None`.
    Const(TypeValue),

    /// `filesize` expression.
    Filesize,

    /// Boolean `not` expression.
    Not {
        operand: Box<Expr>,
    },

    /// Boolean `and` expression.
    And {
        operands: Vec<Expr>,
    },

    /// Boolean `or` expression.
    Or {
        operands: Vec<Expr>,
    },

    /// Arithmetic minus.
    Minus {
        operand: Box<Expr>,
    },

    /// Arithmetic addition (`+`) expression.
    Add {
        operands: Vec<Expr>,
    },

    /// Arithmetic subtraction (`-`) expression.
    Sub {
        operands: Vec<Expr>,
    },

    /// Arithmetic multiplication (`*`) expression.
    Mul {
        operands: Vec<Expr>,
    },

    /// Arithmetic division (`\`) expression.
    Div {
        operands: Vec<Expr>,
    },

    /// Arithmetic modulus (`%`) expression.
    Mod {
        operands: Vec<Expr>,
    },

    /// Bitwise not (`~`) expression.
    BitwiseNot {
        operand: Box<Expr>,
    },

    /// Bitwise and (`&`) expression.
    BitwiseAnd {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Bitwise shift left (`<<`) expression.
    Shl {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Bitwise shift right (`>>`) expression.
    Shr {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Bitwise or (`|`) expression.
    BitwiseOr {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Bitwise xor (`^`) expression.
    BitwiseXor {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Equal (`==`) expression.
    Eq {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Not equal (`!=`) expression.
    Ne {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Less than (`<`) expression.
    Lt {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Greater than (`>`) expression.
    Gt {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Less or equal (`<=`) expression.
    Le {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Greater or equal (`>=`) expression.
    Ge {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `contains` expression.
    Contains {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `icontains` expression
    IContains {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `startswith` expression.
    StartsWith {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `istartswith` expression
    IStartsWith {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `endswith` expression.
    EndsWith {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `iendswith` expression
    IEndsWith {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `iequals` expression.
    IEquals {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// `matches` expression.
    Matches {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Field access expression (e.g. `foo.bar.baz`)
    FieldAccess {
        operands: Vec<Expr>,
    },

    /// A `defined` expression (e.g. `defined foo`)
    Defined {
        operand: Box<Expr>,
    },

    Ident {
        symbol: Symbol,
    },

    /// Pattern match expression (e.g. `$a`)
    PatternMatch {
        pattern: PatternIdx,
        anchor: MatchAnchor,
    },

    /// Pattern match expression where the pattern is variable (e.g: `$`).
    PatternMatchVar {
        symbol: Symbol,
        anchor: MatchAnchor,
    },

    /// Pattern count expression (e.g. `#a`, `#a in (0..10)`)
    PatternCount {
        pattern: PatternIdx,
        range: Option<Range>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `#`, `# in (0..10)`)
    PatternCountVar {
        symbol: Symbol,
        range: Option<Range>,
    },

    /// Pattern offset expression (e.g. `@a`, `@a[1]`)
    PatternOffset {
        pattern: PatternIdx,
        index: Option<Box<Expr>>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `@`, `@[1]`)
    PatternOffsetVar {
        symbol: Symbol,
        index: Option<Box<Expr>>,
    },

    /// Pattern length expression (e.g. `!a`, `!a[1]`)
    PatternLength {
        pattern: PatternIdx,
        index: Option<Box<Expr>>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `!`, `![1]`)
    PatternLengthVar {
        symbol: Symbol,
        index: Option<Box<Expr>>,
    },

    /// Function call.
    FuncCall(Box<FuncCall>),

    /// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`)
    Of(Box<Of>),

    /// A `for <quantifier> of ...` expression. (e.g. `for any of ($a, $b) : ( ... )`)
    ForOf(Box<ForOf>),

    /// A `for <quantifier> <vars> in ...` expression. (e.g. `for all i in (1..100) : ( ... )`)
    ForIn(Box<ForIn>),

    /// A `with <identifiers> : ...` expression. (e.g. `with $a, $b : ( ... )`)
    With(Box<With>),

    /// Array or dictionary lookup expression (e.g. `array[1]`, `dict["key"]`)
    Lookup(Box<Lookup>),
}

/// A lookup operation in an array or dictionary.
#[derive(Debug)]
pub(in crate::compiler) struct Lookup {
    pub type_value: TypeValue,
    pub primary: Box<Expr>,
    pub index: Box<Expr>,
}

/// An expression representing a function call.
#[derive(Debug)]
pub(in crate::compiler) struct FuncCall {
    /// The callable expression, which must resolve in some function identifier.
    pub callable: Expr,
    /// The arguments passed to the function in this call.
    pub args: Vec<Expr>,
    /// Type and value for the function's result.
    pub type_value: TypeValue,
    /// Due to function overloading, the same function may have multiple
    /// signatures. This field indicates the index of the signature that
    /// matched the provided arguments.
    pub signature_index: usize,
}

/// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`,
/// `any of (true, false)`)
#[derive(Debug)]
pub(in crate::compiler) struct Of {
    pub quantifier: Quantifier,
    pub items: OfItems,
    pub anchor: MatchAnchor,
    pub stack_frame: VarStackFrame,
}

/// A `for .. of` expression (e.g `for all of them : (..)`,
/// `for 1 of ($a,$b) : (..)`)
#[derive(Debug)]
pub(in crate::compiler) struct ForOf {
    pub quantifier: Quantifier,
    pub variable: Var,
    pub pattern_set: Vec<PatternIdx>,
    pub condition: Expr,
    pub stack_frame: VarStackFrame,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
#[derive(Debug)]
pub(in crate::compiler) struct ForIn {
    pub quantifier: Quantifier,
    pub variables: Vec<Var>,
    pub iterable: Iterable,
    pub condition: Expr,
    pub stack_frame: VarStackFrame,
}

/// A `with` expression (e.g `with $a, $b : (..)`)
#[derive(Debug)]
pub(in crate::compiler) struct With {
    pub declarations: Vec<(Var, Expr)>,
    pub condition: Expr,
}

/// A quantifier used in `for` and `of` expressions.
#[derive(Debug)]
pub(in crate::compiler) enum Quantifier {
    None,
    All,
    Any,
    Percentage(Expr),
    Expr(Expr),
}

/// In expressions like `$a at 0` and `$b in (0..10)`, this type represents the
/// anchor (e.g. `at <expr>`, `in <range>`).
///
/// The anchor is the part of the expression that restricts the offset range
/// where the match can occur.
/// (e.g. `at <expr>`, `in <range>`).
#[derive(Debug)]
pub(in crate::compiler) enum MatchAnchor {
    None,
    At(Box<Expr>),
    In(Range),
}

impl MatchAnchor {
    /// If this anchor is `at <expr>`, and `<expr>` is a constant value,
    /// return this value. Otherwise, returns `None`.
    pub fn at(&self) -> Option<i64> {
        match self {
            Self::At(expr) => {
                let value = expr.type_value();
                if value.is_const() {
                    value.try_as_integer()
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Items in a `of` expression.
#[derive(Debug)]
pub(in crate::compiler) enum OfItems {
    PatternSet(Vec<PatternIdx>),
    BoolExprTuple(Vec<Expr>),
}

/// A pair of values conforming a range (e.g. `(0..10)`).
#[derive(Debug)]
pub(in crate::compiler) struct Range {
    pub lower_bound: Box<Expr>,
    pub upper_bound: Box<Expr>,
}

/// Possible iterable expressions that can use in a [`ForIn`].
#[derive(Debug)]
pub(in crate::compiler) enum Iterable {
    Range(Range),
    ExprTuple(Vec<Expr>),
    Expr(Expr),
}

impl Expr {
    /// Creates a new [`Expr::Not`].
    pub fn not(operand: Expr) -> Self {
        Self::Not { operand: Box::new(operand) }
    }

    /// Creates a new [`Expr::And`].
    pub fn and(operands: Vec<Expr>) -> Self {
        Self::And { operands }
    }

    /// Creates a new [`Expr::Or`].
    pub fn or(operands: Vec<Expr>) -> Self {
        Self::Or { operands }
    }

    /// Creates a new [`Expr::Minus`].
    pub fn minus(operand: Expr) -> Self {
        Self::Minus { operand: Box::new(operand) }
    }

    /// Creates a new [`Expr::Defined`].
    pub fn defined(operand: Expr) -> Self {
        Self::Defined { operand: Box::new(operand) }
    }

    /// Creates a new [`Expr::BitwiseNot`].
    pub fn bitwise_not(operand: Expr) -> Self {
        Self::BitwiseNot { operand: Box::new(operand) }
    }

    /// Creates a new [`Expr::BitwiseAnd`].
    pub fn bitwise_and(lhs: Expr, rhs: Expr) -> Self {
        Self::BitwiseAnd { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::BitwiseOr`].
    pub fn bitwise_or(lhs: Expr, rhs: Expr) -> Self {
        Self::BitwiseOr { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::BitwiseXor`].
    pub fn bitwise_xor(lhs: Expr, rhs: Expr) -> Self {
        Self::BitwiseXor { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Shl`].
    pub fn shl(lhs: Expr, rhs: Expr) -> Self {
        Self::Shl { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Shr`].
    pub fn shr(lhs: Expr, rhs: Expr) -> Self {
        Self::Shr { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Add`].
    pub fn add(operands: Vec<Expr>) -> Self {
        Self::Add { operands }
    }

    /// Creates a new [`Expr::Sub`].
    pub fn sub(operands: Vec<Expr>) -> Self {
        Self::Sub { operands }
    }

    /// Creates a new [`Expr::Mul`].
    pub fn mul(operands: Vec<Expr>) -> Self {
        Self::Mul { operands }
    }

    /// Creates a new [`Expr::Div`].
    pub fn div(operands: Vec<Expr>) -> Self {
        Self::Div { operands }
    }

    /// Creates a new [`Expr::Mod`].
    pub fn modulus(operands: Vec<Expr>) -> Self {
        Self::Mod { operands }
    }

    /// Creates a new [`Expr::FieldAccess`].
    pub fn field_access(operands: Vec<Expr>) -> Self {
        Self::FieldAccess { operands }
    }

    /// Creates a new [`Expr::Eq`].
    pub fn eq(lhs: Expr, rhs: Expr) -> Self {
        Self::Eq { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Ne`].
    pub fn ne(lhs: Expr, rhs: Expr) -> Self {
        Self::Ne { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Ge`].
    pub fn ge(lhs: Expr, rhs: Expr) -> Self {
        Self::Ge { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Gt`].
    pub fn gt(lhs: Expr, rhs: Expr) -> Self {
        Self::Gt { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Le`].
    pub fn le(lhs: Expr, rhs: Expr) -> Self {
        Self::Le { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Lt`].
    pub fn lt(lhs: Expr, rhs: Expr) -> Self {
        Self::Lt { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::Contains`].
    pub fn contains(lhs: Expr, rhs: Expr) -> Self {
        Self::Contains { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::IContains`].
    pub fn icontains(lhs: Expr, rhs: Expr) -> Self {
        Self::IContains { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::StartsWith`].
    pub fn starts_with(lhs: Expr, rhs: Expr) -> Self {
        Self::StartsWith { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::IStartsWith`].
    pub fn istarts_with(lhs: Expr, rhs: Expr) -> Self {
        Self::IStartsWith { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::EndsWith`].
    pub fn ends_with(lhs: Expr, rhs: Expr) -> Self {
        Self::EndsWith { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::IEndsWith`].
    pub fn iends_with(lhs: Expr, rhs: Expr) -> Self {
        Self::IEndsWith { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Creates a new [`Expr::IEquals`].
    pub fn iequals(lhs: Expr, rhs: Expr) -> Self {
        Self::IEquals { lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }

    /// Returns an iterator that does a DFS traversal of the IR tree.
    ///
    /// See [`DepthFirstSearch`] for details.
    pub fn dfs_iter(&self) -> DepthFirstSearch {
        DepthFirstSearch::new(self)
    }

    /// Finds the first expression in DFS order that matches the given
    /// `predicate`, but avoids traversing the descendants of nodes
    /// matching the condition indicated by `prune_if`.
    pub fn dfs_find<P, C>(&self, predicate: P, prune_if: C) -> Option<&Expr>
    where
        P: Fn(&Expr) -> bool,
        C: Fn(&Expr) -> bool,
    {
        let mut dfs = self.dfs_iter();

        while let Some(evt) = dfs.next() {
            if let Event::Enter(expr) = evt {
                if predicate(expr) {
                    return Some(expr);
                }
                if prune_if(expr) {
                    dfs.prune();
                }
            }
        }

        None
    }

    /// Returns the type of this expression.
    pub fn ty(&self) -> Type {
        match self {
            Expr::Const(type_value) => type_value.ty(),

            Expr::Defined { .. }
            | Expr::Not { .. }
            | Expr::And { .. }
            | Expr::Or { .. }
            | Expr::Eq { .. }
            | Expr::Ne { .. }
            | Expr::Ge { .. }
            | Expr::Gt { .. }
            | Expr::Le { .. }
            | Expr::Lt { .. }
            | Expr::Contains { .. }
            | Expr::IContains { .. }
            | Expr::StartsWith { .. }
            | Expr::IStartsWith { .. }
            | Expr::EndsWith { .. }
            | Expr::IEndsWith { .. }
            | Expr::IEquals { .. }
            | Expr::Matches { .. }
            | Expr::PatternMatch { .. }
            | Expr::PatternMatchVar { .. }
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_)
            | Expr::With(_) => Type::Bool,

            Expr::Minus { operand, .. } => match operand.ty() {
                Type::Integer => Type::Integer,
                _ => Type::Float,
            },

            Expr::Add { operands }
            | Expr::Sub { operands }
            | Expr::Mul { operands }
            | Expr::Div { operands } => {
                // If any of the operands is float, the result is also float.
                if operands.iter().any(|op| matches!(op.ty(), Type::Float)) {
                    Type::Float
                } else {
                    Type::Integer
                }
            }

            Expr::Filesize
            | Expr::PatternCount { .. }
            | Expr::PatternCountVar { .. }
            | Expr::PatternOffset { .. }
            | Expr::PatternOffsetVar { .. }
            | Expr::PatternLength { .. }
            | Expr::PatternLengthVar { .. }
            | Expr::Mod { .. }
            | Expr::BitwiseNot { .. }
            | Expr::BitwiseAnd { .. }
            | Expr::BitwiseOr { .. }
            | Expr::BitwiseXor { .. }
            | Expr::Shl { .. }
            | Expr::Shr { .. } => Type::Integer,

            Expr::FieldAccess { operands, .. } => {
                operands.last().unwrap().ty()
            }
            Expr::Ident { symbol, .. } => symbol.type_value().ty(),
            Expr::FuncCall(fn_call) => fn_call.type_value.ty(),
            Expr::Lookup(lookup) => lookup.type_value.ty(),
        }
    }

    pub fn type_value(&self) -> TypeValue {
        match self {
            Expr::Const(type_value) => type_value.clone(),

            Expr::Defined { .. }
            | Expr::Not { .. }
            | Expr::And { .. }
            | Expr::Or { .. }
            | Expr::Eq { .. }
            | Expr::Ne { .. }
            | Expr::Ge { .. }
            | Expr::Gt { .. }
            | Expr::Le { .. }
            | Expr::Lt { .. }
            | Expr::Contains { .. }
            | Expr::IContains { .. }
            | Expr::StartsWith { .. }
            | Expr::IStartsWith { .. }
            | Expr::EndsWith { .. }
            | Expr::IEndsWith { .. }
            | Expr::IEquals { .. }
            | Expr::Matches { .. }
            | Expr::PatternMatch { .. }
            | Expr::PatternMatchVar { .. }
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_)
            | Expr::With(_) => TypeValue::Bool(Value::Unknown),

            Expr::Minus { operand, .. } => match operand.ty() {
                Type::Integer => TypeValue::Integer(Value::Unknown),
                _ => TypeValue::Float(Value::Unknown),
            },

            Expr::Add { operands }
            | Expr::Sub { operands }
            | Expr::Mul { operands }
            | Expr::Div { operands } => {
                // If any of the operands is float, the expression's type is
                // float.
                if operands.iter().any(|op| matches!(op.ty(), Type::Float)) {
                    TypeValue::Float(Value::Unknown)
                } else {
                    TypeValue::Integer(Value::Unknown)
                }
            }

            Expr::Filesize
            | Expr::PatternCount { .. }
            | Expr::PatternCountVar { .. }
            | Expr::PatternOffset { .. }
            | Expr::PatternOffsetVar { .. }
            | Expr::PatternLength { .. }
            | Expr::PatternLengthVar { .. }
            | Expr::Mod { .. }
            | Expr::BitwiseNot { .. }
            | Expr::BitwiseAnd { .. }
            | Expr::BitwiseOr { .. }
            | Expr::BitwiseXor { .. }
            | Expr::Shl { .. }
            | Expr::Shr { .. } => TypeValue::Integer(Value::Unknown),

            Expr::FieldAccess { operands, .. } => {
                operands.last().unwrap().type_value()
            }
            Expr::Ident { symbol, .. } => symbol.type_value().clone(),
            Expr::FuncCall(fn_call) => fn_call.type_value.clone(),
            Expr::Lookup(lookup) => lookup.type_value.clone(),
        }
    }

    pub fn fold(
        self,
        ctx: &mut CompileContext,
        span: Span,
    ) -> Result<Self, CompileError> {
        match self {
            Expr::Minus { ref operand } => match operand.type_value() {
                TypeValue::Integer(Value::Const(v)) => {
                    Ok(Expr::Const(TypeValue::const_integer_from(-v)))
                }
                TypeValue::Float(Value::Const(v)) => {
                    Ok(Expr::Const(TypeValue::const_float_from(-v)))
                }
                _ => Ok(self),
            },
            Expr::And { mut operands } => {
                // Retain the operands whose value is not constant, or is
                // constant but false, remove those that are known to be
                // true. True values in the list of operands don't alter
                // the result of the AND operation.
                operands.retain(|op| {
                    let type_value = op.type_value().cast_to_bool();
                    !type_value.is_const() || !type_value.as_bool()
                });

                // No operands left, all were true and therefore the AND is
                // also true.
                if operands.is_empty() {
                    return Ok(Expr::Const(TypeValue::const_bool_from(true)));
                }

                // If any of the remaining operands is constant it has to be
                // false because true values were removed, the result is false
                // regardless of the operands with unknown values.
                if operands.iter().any(|op| op.type_value().is_const()) {
                    return Ok(Expr::Const(TypeValue::const_bool_from(false)));
                }

                Ok(Expr::And { operands })
            }
            Expr::Or { mut operands } => {
                // Retain the operands whose value is not constant, or is
                // constant but true, remove those that are known to be false.
                // False values in the list of operands don't alter the result
                // of the OR operation.
                operands.retain(|op| {
                    let type_value = op.type_value().cast_to_bool();
                    !type_value.is_const() || type_value.as_bool()
                });

                // No operands left, all were false and therefore the OR is
                // also false.
                if operands.is_empty() {
                    return Ok(Expr::Const(TypeValue::const_bool_from(false)));
                }

                // If any of the remaining operands is constant it has to be
                // true because false values were removed, the result is true
                // regardless of the operands with unknown values.
                if operands.iter().any(|op| op.type_value().is_const()) {
                    return Ok(Expr::Const(TypeValue::const_bool_from(true)));
                }

                Ok(Expr::Or { operands })
            }
            Expr::Add { operands } => {
                // If not all operands are constant, there's nothing to fold.
                if !operands.iter().all(|op| op.type_value().is_const()) {
                    return Ok(Expr::Add { operands });
                }

                Self::fold_arithmetic(ctx, span, operands, |acc, x| acc + x)
            }
            Expr::Sub { operands } => {
                // If not all operands are constant, there's nothing to fold.
                if !operands.iter().all(|op| op.type_value().is_const()) {
                    return Ok(Expr::Sub { operands });
                }

                Self::fold_arithmetic(ctx, span, operands, |acc, x| acc - x)
            }
            Expr::Mul { operands } => {
                // If not all operands are constant, there's nothing to fold.
                if !operands.iter().all(|op| op.type_value().is_const()) {
                    return Ok(Expr::Mul { operands });
                }

                Self::fold_arithmetic(ctx, span, operands, |acc, x| acc * x)
            }
            _ => Ok(self),
        }
    }

    pub fn fold_arithmetic<F>(
        ctx: &mut CompileContext,
        span: Span,
        operands: Vec<Expr>,
        f: F,
    ) -> Result<Self, CompileError>
    where
        F: FnMut(f64, f64) -> f64,
    {
        debug_assert!(!operands.is_empty());

        let mut is_float = false;

        let result = operands
            .iter()
            .map(|operand| match operand.type_value() {
                TypeValue::Integer(Value::Const(v)) => v as f64,
                TypeValue::Float(Value::Const(v)) => {
                    is_float = true;
                    v
                }
                _ => unreachable!(),
            })
            .reduce(f)
            // It's safe to call unwrap because there must be at least
            // one iterator.
            .unwrap();

        if is_float {
            Ok(Expr::Const(TypeValue::const_float_from(result)))
        } else if result >= i64::MIN as f64 && result <= i64::MAX as f64 {
            Ok(Expr::Const(TypeValue::const_integer_from(result as i64)))
        } else {
            Err(NumberOutOfRange::build(
                ctx.report_builder,
                i64::MIN,
                i64::MAX,
                span.into(),
            ))
        }
    }
}

impl Debug for Expr {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut level = 1;

        let anchor_str = |anchor: &MatchAnchor| match anchor {
            MatchAnchor::None => "",
            MatchAnchor::At(_) => " AT",
            MatchAnchor::In(_) => " IN",
        };

        let range_str = |range: &Option<_>| {
            if range.is_some() { " IN" } else { "" }
        };

        let index_str = |index: &Option<_>| {
            if index.is_some() { " INDEX" } else { "" }
        };

        for event in self.dfs_iter() {
            match event {
                Event::Leave(_) => level -= 1,
                Event::Enter(expr) => {
                    for _ in 0..level {
                        write!(f, "  ")?;
                    }
                    level += 1;
                    match expr {
                        Expr::Const(c) => writeln!(f, "CONST {}", c)?,
                        Expr::Filesize => writeln!(f, "FILESIZE")?,
                        Expr::Not { .. } => writeln!(f, "NOT")?,
                        Expr::And { .. } => writeln!(f, "AND")?,
                        Expr::Or { .. } => writeln!(f, "OR")?,
                        Expr::Minus { .. } => writeln!(f, "MINUS")?,
                        Expr::Add { .. } => writeln!(f, "ADD")?,
                        Expr::Sub { .. } => writeln!(f, "SUB")?,
                        Expr::Mul { .. } => writeln!(f, "MUL")?,
                        Expr::Div { .. } => writeln!(f, "DIV")?,
                        Expr::Mod { .. } => writeln!(f, "MOD")?,
                        Expr::Shl { .. } => writeln!(f, "SHL")?,
                        Expr::Shr { .. } => writeln!(f, "SHR")?,
                        Expr::Eq { .. } => writeln!(f, "EQ")?,
                        Expr::Ne { .. } => writeln!(f, "NE")?,
                        Expr::Lt { .. } => writeln!(f, "LT")?,
                        Expr::Gt { .. } => writeln!(f, "GT")?,
                        Expr::Le { .. } => writeln!(f, "LE")?,
                        Expr::Ge { .. } => writeln!(f, "GE")?,
                        Expr::BitwiseNot { .. } => writeln!(f, "BITWISE_NOT")?,
                        Expr::BitwiseAnd { .. } => writeln!(f, "BITWISE_AND")?,
                        Expr::BitwiseOr { .. } => writeln!(f, "BITWISE_OR")?,
                        Expr::BitwiseXor { .. } => writeln!(f, "BITWISE_XOR")?,
                        Expr::Contains { .. } => writeln!(f, "CONTAINS")?,
                        Expr::IContains { .. } => writeln!(f, "ICONTAINS")?,
                        Expr::StartsWith { .. } => writeln!(f, "STARTS_WITH")?,
                        Expr::IStartsWith { .. } => writeln!(f, "ISTARTS_WITH")?,
                        Expr::EndsWith { .. } => writeln!(f, "ENDS_WITH")?,
                        Expr::IEndsWith { .. } => writeln!(f, "IENDS_WITH")?,
                        Expr::IEquals { .. } => writeln!(f, "IEQUALS")?,
                        Expr::Matches { .. } => writeln!(f, "MATCHES")?,
                        Expr::Defined { .. } => writeln!(f, "DEFINED")?,
                        Expr::FieldAccess { .. } => writeln!(f, "FIELD_ACCESS")?,
                        Expr::Ident { symbol } => writeln!(f, "IDENT {:?}", symbol)?,
                        Expr::FuncCall(_) => writeln!(f, "FN_CALL")?,
                        Expr::Of(_) => writeln!(f, "OF")?,
                        Expr::ForOf(_) => writeln!(f, "FOR_OF")?,
                        Expr::ForIn(_) => writeln!(f, "FOR_IN")?,
                        Expr::With(_) => writeln!(f, "WITH")?,
                        Expr::Lookup(_) => writeln!(f, "LOOKUP")?,
                        Expr::PatternMatch { pattern, anchor } => writeln!(
                            f,
                            "PATTERN_MATCH {:?}{}",
                            pattern,
                            anchor_str(anchor),
                        )?,
                        Expr::PatternMatchVar { symbol, anchor } => writeln!(
                            f,
                            "PATTERN_MATCH {:?}{}",
                            symbol,
                            anchor_str(anchor),
                        )?,
                        Expr::PatternCount { pattern, range } => writeln!(
                            f,
                            "PATTERN_COUNT {:?}{}",
                            pattern,
                            range_str(range),
                        )?,
                        Expr::PatternCountVar { symbol, range } => writeln!(
                            f,
                            "PATTERN_COUNT {:?}{}",
                            symbol,
                            range_str(range),
                        )?,
                        Expr::PatternOffset { pattern, index } => writeln!(
                            f,
                            "PATTERN_OFFSET {:?}{}",
                            pattern,
                            index_str(index),
                        )?,
                        Expr::PatternOffsetVar { symbol, index } => writeln!(
                            f,
                            "PATTERN_OFFSET {:?}{}",
                            symbol,
                            index_str(index),
                        )?,
                        Expr::PatternLength { pattern, index } => writeln!(
                            f,
                            "PATTERN_LENGTH {:?}{}",
                            pattern,
                            index_str(index),
                        )?,
                        Expr::PatternLengthVar { symbol, index } => writeln!(
                            f,
                            "PATTERN_LENGTH {:?}{}",
                            symbol,
                            index_str(index),
                        )?,
                    }
                }
            }
        }

        Ok(())
    }
}
