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

use crate::compiler::{PatternId, Var, VarStackFrame};
use crate::symbols::Symbol;
use crate::types::{Type, TypeValue, Value};

pub(in crate::compiler) use ast2ir::expr_from_ast;
pub(in crate::compiler) use ast2ir::patterns_from_ast;
pub(in crate::compiler) use ast2ir::warn_if_not_bool;
pub(in crate::compiler) use utils::split_at_large_gaps;
pub(in crate::compiler) use utils::TrailingPattern;

mod ast2ir;
mod hex2hir;
mod utils;

bitmask! {
    #[derive(Debug)]
    pub mask PatternFlagSet: u16 where flags PatternFlags  {
        Ascii                = 0x0001,
        Wide                 = 0x0002,
        Nocase               = 0x0004,
        Base64               = 0x0008,
        Base64Wide           = 0x0010,
        Xor                  = 0x0020,
        Fullword             = 0x0040,
        Private              = 0x0080,
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
}

/// Intermediate representation (IR) for a text pattern.
pub(in crate::compiler) struct LiteralPattern<'src> {
    pub ident: &'src str,
    pub flags: PatternFlagSet,
    pub text: Cow<'src, BStr>,
    pub xor_range: Option<RangeInclusive<u8>>,
    pub base64_alphabet: Option<&'src str>,
    pub base64wide_alphabet: Option<&'src str>,
}

/// Intermediate representation (IR) for a regular expression.
///
/// The IR for a regular expression is entrusted to the `regex_syntax` crate,
/// particularly to its [`regex_syntax::hir::Hir`] type.
pub(in crate::compiler) struct RegexpPattern<'src> {
    pub ident: &'src str,
    pub flags: PatternFlagSet,
    pub hir: regex_syntax::hir::Hir,
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
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Boolean `or` expression
    Or {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Arithmetic minus.
    Minus {
        operand: Box<Expr>,
    },

    /// Arithmetic addition (`+`) expression.
    Add {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Arithmetic subtraction (`-`) expression.
    Sub {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Arithmetic multiplication (`*`) expression.
    Mul {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Arithmetic division (`\`) expression.
    Div {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
    },

    /// Arithmetic modulus (`%`) expression.
    Mod {
        rhs: Box<Expr>,
        lhs: Box<Expr>,
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

            Expr::Add { lhs, rhs, .. }
            | Expr::Sub { lhs, rhs, .. }
            | Expr::Mul { lhs, rhs, .. }
            | Expr::Div { lhs, rhs, .. } => match (lhs.ty(), rhs.ty()) {
                // If both operands are integer, the expression's type is
                // integer.
                (Type::Integer, Type::Integer) => Type::Integer,
                // In all the remaining cases at least one of the operands
                // is float, therefore the result is float.
                _ => Type::Float,
            },

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

            Expr::Add { lhs, rhs, .. }
            | Expr::Sub { lhs, rhs, .. }
            | Expr::Mul { lhs, rhs, .. }
            | Expr::Div { lhs, rhs, .. } => match (lhs.ty(), rhs.ty()) {
                // If both operands are integer, the expression's type is
                // integer.
                (Type::Integer, Type::Integer) => {
                    TypeValue::Integer(Value::Unknown)
                }
                // In all the remaining cases at least one of the operands
                // is float, therefore the result is float.
                _ => TypeValue::Float(Value::Unknown),
            },

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
}
