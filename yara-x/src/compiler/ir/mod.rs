/*! Intermediate representation (IR) for a set of YARA rules.

The IR is a tree representing a set of YARA rules. This tree is similar to the
AST, but it contains type information for expressions and identifiers, something
that the AST doesn't have. The IR is generated from the AST, and the compiled
[Rules] are generated from the IR. This means that the IR is further away from
the original source code than the AST, and closer to the emitted code. The build
process goes like:

  `source code -> CST -> AST -> IR -> compiled rules`

Contrary to the AST, the IR doesn't have an one-to-one correspondence to the
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
allows using the same regexp engine for matching both types of patterns.

[Rules]: crate::compiler::Rules
[regex_syntax]: https://docs.rs/regex-syntax/latest/regex_syntax/
[Hir]: regex_syntax::hir::Hir
*/

use std::borrow::Cow;
use std::ops::RangeInclusive;

use bitmask::bitmask;
use bstr::BStr;
use serde::{Deserialize, Serialize};

use crate::compiler::context::{Var, VarStackFrame};
use crate::compiler::PatternId;
use crate::symbols::Symbol;
use crate::types::{Type, TypeValue, Value};

pub(in crate::compiler) use ast2ir::expr_from_ast;
pub(in crate::compiler) use ast2ir::patterns_from_ast;
pub(in crate::compiler) use ast2ir::warn_if_not_bool;

use crate::re;

mod ast2ir;
mod hex2hir;
pub mod mask;

bitmask! {
    /// Flags associated to rule patterns.
    ///
    /// Each of these flags correspond to one of the allowed YARA pattern
    /// modifiers, and generally they are set if the corresponding modifier
    /// appears alongside the pattern in the source code. The only exception is
    /// the `Ascii` flag, which will be set when `Wide` is not set regardless
    /// of what the source code says. This follows the semantics of YARA
    /// pattern modifiers, in which a pattern is considered `ascii` by default
    /// when neither `ascii` or `wide` modifiers are used.
    ///
    /// In resume either the `Ascii` or the `Wide` flags (or both) will be set.
    #[derive(Debug, Serialize, Deserialize)]
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

/// Intermediate representation (IR) for a pattern.
pub(in crate::compiler) enum Pattern<'src> {
    /// A literal pattern is one the doesn't contain wildcards, alternatives,
    /// or any kind of variable content. For example, the text pattern `"foo"`,
    /// the regular expression `/foo/`, and the hex pattern `{01 02 03}` are
    /// all literal.
    Literal(LiteralPattern<'src>),
    /// A regexp pattern is one that contains wildcards and/or alternatives,
    /// like regular expression `/foo.*bar/` and hex pattern `{01 ?? 03}`.
    Regexp(RegexpPattern<'src>),
}

impl<'src> Pattern<'src> {
    pub fn identifier(&self) -> &'src str {
        match self {
            Pattern::Literal(pattern) => pattern.ident,
            Pattern::Regexp(pattern) => pattern.ident,
        }
    }

    /// Anchor the pattern to a given offset. This means that the pattern can
    /// match only at that offset and nowhere else. This is a no-op for
    /// regexp patterns, and for patterns that are flagged as non-anchorable.
    ///
    /// Also, if this function is called twice with different offsets, the
    /// pattern becomes non-anchorable because it can't be anchored to two
    /// different offsets.
    ///
    /// This is used when the condition contains an expression like `$a at 0`
    /// in order to indicate that the pattern (the `$a` pattern in this case)
    /// can match only at a fixed offset.
    pub fn anchor_at(&mut self, offset: usize) {
        if let Pattern::Literal(p) = self {
            match p.anchored_at {
                Some(o) if o != offset => {
                    p.anchored_at = None;
                    p.flags.set(PatternFlags::NonAnchorable);
                }
                None => {
                    if !p.flags.contains(PatternFlags::NonAnchorable) {
                        p.anchored_at = Some(offset);
                    }
                }
                _ => {}
            }
        }
    }

    /// Make the pattern non-anchorable. Any existing anchor is removed and
    /// future calls to [`Pattern::anchor_at`] are ignored.
    ///
    /// This function is used to indicate that a certain pattern can't be
    /// anchored at any fixed offset because it is used in ways that require
    /// require finding all the possible matches. For example, in a condition
    /// condition like `#a > 0 and $a at 0`, the use of `#a` (which returns
    /// the number of occurrences of `$a`), makes `$a` non-anchorable because
    /// we need to find all occurrences of `$a`.
    pub fn make_non_anchorable(&mut self) {
        match self {
            Pattern::Literal(p) => {
                p.flags.set(PatternFlags::NonAnchorable);
                p.anchored_at = None;
            }
            Pattern::Regexp(p) => {
                p.flags.set(PatternFlags::NonAnchorable);
                p.anchored_at = None;
            }
        }
    }
}

/// Intermediate representation (IR) for a text pattern.
pub(in crate::compiler) struct LiteralPattern<'src> {
    pub ident: &'src str,
    pub flags: PatternFlagSet,
    pub text: Cow<'src, BStr>,
    pub xor_range: Option<RangeInclusive<u8>>,
    pub base64_alphabet: Option<&'src str>,
    pub base64wide_alphabet: Option<&'src str>,
    pub anchored_at: Option<usize>,
}

/// Intermediate representation (IR) for a regular expression.
///
/// The IR for a regular expression is entrusted to the `regex_syntax` crate,
/// particularly to its [`regex_syntax::hir::Hir`] type.
pub(in crate::compiler) struct RegexpPattern<'src> {
    pub ident: &'src str,
    pub flags: PatternFlagSet,
    pub hir: re::hir::Hir,
    pub anchored_at: Option<usize>,
}

/// Intermediate representation (IR) for an expression.
pub(in crate::compiler) enum Expr {
    /// Constant value (i.e: the value is known at compile time). The value
    /// in `type_value` is not `None`.
    Const {
        type_value: TypeValue,
    },

    Filesize,
    Entrypoint,

    /// Boolean `not` expression
    Not {
        operand: Box<Expr>,
    },

    /// Boolean `and` expression
    And {
        operands: Vec<Expr>,
    },

    /// Boolean `or` expression
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

    /// Field access expression (e.g. `foo.bar`)
    FieldAccess {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
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
        pattern_id: PatternId,
        anchor: MatchAnchor,
    },

    /// Pattern match expression where the pattern is variable (e.g: `$`).
    PatternMatchVar {
        symbol: Symbol,
        anchor: MatchAnchor,
    },

    /// Pattern count expression (e.g. `#a`, `#a in (0..10)`)
    PatternCount {
        pattern_id: PatternId,
        range: Option<Range>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `#`, `# in (0..10)`)
    PatternCountVar {
        symbol: Symbol,
        range: Option<Range>,
    },

    /// Pattern offset expression (e.g. `@a`, `@a[1]`)
    PatternOffset {
        pattern_id: PatternId,
        index: Option<Box<Expr>>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `@`, `@[1]`)
    PatternOffsetVar {
        symbol: Symbol,
        index: Option<Box<Expr>>,
    },

    /// Pattern length expression (e.g. `!a`, `!a[1]`)
    PatternLength {
        pattern_id: PatternId,
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

    /// Array or dictionary lookup expression (e.g. `array[1]`, `dict["key"]`)
    Lookup(Box<Lookup>),
}

/// A lookup operation in an array or dictionary.
pub(in crate::compiler) struct Lookup {
    pub type_value: TypeValue,
    pub primary: Box<Expr>,
    pub index: Box<Expr>,
}

/// An expression representing a function call.
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
pub(in crate::compiler) struct Of {
    pub quantifier: Quantifier,
    pub items: OfItems,
    pub anchor: MatchAnchor,
    pub stack_frame: VarStackFrame,
}

/// A `for .. of` expression (e.g `for all of them : (..)`,
/// `for 1 of ($a,$b) : (..)`)
pub(in crate::compiler) struct ForOf {
    pub quantifier: Quantifier,
    pub variable: Var,
    pub pattern_set: Vec<PatternId>,
    pub condition: Expr,
    pub stack_frame: VarStackFrame,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
pub(in crate::compiler) struct ForIn {
    pub quantifier: Quantifier,
    pub variables: Vec<Var>,
    pub iterable: Iterable,
    pub condition: Expr,
    pub stack_frame: VarStackFrame,
}

/// A quantifier used in `for` and `of` expressions.
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
pub(in crate::compiler) enum OfItems {
    PatternSet(Vec<PatternId>),
    BoolExprTuple(Vec<Expr>),
}

/// A pair of values conforming a range (e.g. `(0..10)`).
pub(in crate::compiler) struct Range {
    pub lower_bound: Box<Expr>,
    pub upper_bound: Box<Expr>,
}

/// Possible iterable expressions that can use in a [`ForIn`].
pub(in crate::compiler) enum Iterable {
    Range(Range),
    ExprTuple(Vec<Expr>),
    Expr(Expr),
}

impl Expr {
    pub fn ty(&self) -> Type {
        match self {
            Expr::Const { type_value, .. } => type_value.ty(),

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
            | Expr::ForIn(_) => Type::Bool,

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
            | Expr::Entrypoint
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

            Expr::FieldAccess { rhs, .. } => rhs.ty(),
            Expr::Ident { symbol, .. } => symbol.type_value().ty(),
            Expr::FuncCall(fn_call) => fn_call.type_value.ty(),
            Expr::Lookup(lookup) => lookup.type_value.ty(),
        }
    }

    pub fn type_value(&self) -> TypeValue {
        match self {
            Expr::Const { type_value, .. } => type_value.clone(),

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
            | Expr::ForIn(_) => TypeValue::Bool(Value::Unknown),

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
            | Expr::Entrypoint
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

            Expr::FieldAccess { rhs, .. } => rhs.type_value(),
            Expr::Ident { symbol, .. } => symbol.type_value().clone(),
            Expr::FuncCall(fn_call) => fn_call.type_value.clone(),
            Expr::Lookup(lookup) => lookup.type_value.clone(),
        }
    }

    pub fn fold(self) -> Self {
        match self {
            Expr::And { mut operands } => {
                // Retain the operands whose value is unknown or false, and
                // remove those that are known to be true. True values in
                // the list of operands don't alter the result of the AND
                // operation.
                operands.retain(|op| {
                    !op.type_value()
                        .cast_to_bool()
                        .try_as_bool()
                        .unwrap_or(false)
                });

                // No operands left, all were true and therefore the AND is
                // also true.
                if operands.is_empty() {
                    return Expr::Const {
                        // TODO: create a method in TypeValue for making this simpler?
                        type_value: TypeValue::Bool(Value::Const(true)),
                    };
                }

                // If any of the remaining operands is constant it has to be
                // false because true values were removed, the result is false
                // regardless of the operands with unknown values.
                if operands.iter().any(|op| op.type_value().is_const()) {
                    return Expr::Const {
                        // TODO: create a method in TypeValue for making this simpler?
                        type_value: TypeValue::Bool(Value::Const(false)),
                    };
                }

                Expr::And { operands }
            }
            Expr::Or { mut operands } => {
                // Retain the operands whose value is unknown or true, and
                // remove those that are known to be false. False values in
                // the list of operands don't alter the result of the OR
                // operation.
                operands.retain(|op| {
                    op.type_value()
                        .cast_to_bool()
                        .try_as_bool()
                        .unwrap_or(true)
                });

                // No operands left, all were false and therefore the OR is
                // also false.
                if operands.is_empty() {
                    return Expr::Const {
                        // TODO: create a method in TypeValue for making this simpler?
                        type_value: TypeValue::Bool(Value::Const(false)),
                    };
                }

                // If any of the remaining operands is constant it has to be
                // true because false values were removed, the result is true
                // regardless of the operands with unknown values.
                if operands.iter().any(|op| op.type_value().is_const()) {
                    return Expr::Const {
                        // TODO: create a method in TypeValue for making this simpler?
                        type_value: TypeValue::Bool(Value::Const(true)),
                    };
                }

                Expr::Or { operands }
            }

            Expr::Add { operands } => {
                let mut sum = 0.0;
                let mut is_float = false;
                for operand in &operands {
                    match operand.type_value() {
                        TypeValue::Integer(Value::Const(v)) => {
                            sum += v as f64;
                        }
                        TypeValue::Float(Value::Const(v)) => {
                            is_float = true;
                            sum += v;
                        }
                        _ => return Expr::Add { operands },
                    }
                }
                if is_float {
                    Expr::Const {
                        type_value: TypeValue::Float(Value::Const(sum)),
                    }
                } else {
                    Expr::Const {
                        type_value: TypeValue::Integer(Value::Const(
                            sum as i64,
                        )),
                    }
                }
            }
            _ => self,
        }
    }
}
