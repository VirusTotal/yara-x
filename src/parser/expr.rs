use crate::parser::span::*;
use crate::parser::CSTNode;
use crate::{SymbolTable, Value};
use bstr::{BString, ByteSlice};
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use yara_derive::*;

macro_rules! arithmetic_op {
    ($sym_tbl:expr, $lhs:expr, $op:tt, $checked_op:ident, $rhs:expr) => {{
        use Value::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value($sym_tbl)?;
        let rhs = $rhs.value($sym_tbl)?;
        // This point is reached only if both sides of the operation have
        // some value...
        match (lhs, rhs) {
            // ... check for different combinations of integer and float
            // operands. The result is integer if both operand are
            // integers and float if otherwise.
            //
            // In operations where the operands are integers we must use
            // the checked variant of the operator (e.g. `checked_add`,
            // `checked_div`, etc) in order to prevent panics due to division
            // by zero or integer overflows.
            //
            // Floating-point operations won't cause panic in Rust.
            (Integer(lhs), Integer(rhs)) => Some(Integer(lhs.$checked_op(rhs)?)),
            (Integer(lhs), Float(rhs)) => Some(Float((lhs as f32) $op rhs)),
            (Float(lhs), Integer(rhs)) => Some(Float(lhs $op (rhs as f32))),
            (Float(lhs), Float(rhs)) => Some(Float(lhs $op rhs)),
            // Operands should be either integer or float, return None
            _ => None,
        }
    }};
}

macro_rules! boolean_op {
    ($sym_tbl:expr, $lhs:expr, $operator:tt, $rhs:expr) => {{
        use Value::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value($sym_tbl)?;
        let rhs = $rhs.value($sym_tbl)?;
        // This point is reached only if both sides of the operation have
        // some value.
        match (lhs, rhs) {
            // If both of values are booleans, return the result of the
            // operation.
            (Bool(lhs), Bool(rhs)) => Some(Bool(lhs $operator rhs)),
            _ => None,
       }
   }};
}

macro_rules! shift_op {
    ($sym_tbl:expr, $lhs:expr, $operator:ident, $rhs:expr) => {{
        use Value::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value($sym_tbl)?;
        let rhs = $rhs.value($sym_tbl)?;
        // This point is reached only if both sides of the operation have
        // some value.
        match (lhs, rhs) {
            (Integer(lhs), Integer(rhs)) => {
                let overflow: bool;
                let mut result = 0;
                // First convert `rhs` to u32, which is the type accepted
                // by both overflowing_shr and overflowing_lhr. If the
                // conversion fails, it's because its value is too large and
                // does not fit in a u32, or because it's negative. In both
                // cases the result of the shift operation is 0.
                if let Ok(rhs) = rhs.try_into() {
                    // Now that rhs is an u32 we can call overflowing_shr or
                    // overflowing_lhr.
                    (result, overflow) = lhs.$operator(rhs);
                    // The semantics << and >> in YARA is that the right-side
                    // operand can be larger than the number of bits in the
                    // left-side, and in those cases the result is 0.
                    if overflow {
                        result = 0;
                    }
                }
                Some(Integer(result))
            }
            // This point should not be reached, a shift operation is
            // expected to have integer operands.
            (l, r) => unreachable!("{:?}, {:?}", l, r),
        }
    }};
}

macro_rules! bitwise_op {
    ($sym_tbl:expr, $lhs:expr, $operator:ident, $rhs:expr) => {{
        use Value::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value($sym_tbl)?;
        let rhs = $rhs.value($sym_tbl)?;
        // This point is reached only if both sides of the operation have
        // some value.
        match (lhs, rhs) {
            (Integer(l), Integer(r)) => Some(Integer(l.$operator(r))),
            (l, r) => unreachable!("{:?}, {:?}", l, r),
        }
    }};
}

macro_rules! comparison_op {
    ($sym_tbl:expr, $lhs:expr, $operator:tt, $rhs:expr) => {{
        use Value::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value($sym_tbl)?;
        let rhs = $rhs.value($sym_tbl)?;
        // This point is reached only if both sides of the operation
        // have some value.
        match (lhs, rhs) {
            (Integer(lhs), Integer(rhs)) => Some(Bool(lhs $operator rhs)),
            (Float(lhs), Float(rhs)) => Some(Bool(lhs $operator rhs)),
            (Float(lhs), Integer(rhs)) => Some(Bool(lhs $operator (rhs as f32))),
            (Integer(lhs), Float(rhs)) => Some(Bool((lhs as f32) $operator rhs)),
            (String(lhs), String(rhs)) => Some(Bool(lhs $operator rhs)),
            _ => None,
        }
    }};
}

macro_rules! string_op {
    ($sym_tbl:expr, $lhs:expr, $operator:ident, $rhs:expr, $case_insensitive:expr) => {{
        use Value::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value($sym_tbl)?;
        let rhs = $rhs.value($sym_tbl)?;
        // This point is reached only if both sides of the operation
        // have some value.

        match (lhs, rhs) {
            (String(lhs), String(rhs)) => {
                if $case_insensitive {
                    let lhs = lhs.to_ascii_lowercase();
                    let rhs = rhs.to_ascii_lowercase();
                    Some(Bool(lhs.$operator(rhs)))
                } else {
                    Some(Bool(lhs.$operator(rhs)))
                }
            }
            _ => None,
        }
    }};
}

/// An expression.
#[derive(Debug, HasSpan)]
pub enum Expr<'src> {
    True {
        span: Span,
    },

    False {
        span: Span,
    },

    Filesize {
        span: Span,
    },

    Entrypoint {
        span: Span,
    },

    /// Integer literal (e.g. `1`, `-1`, `10KB`, `0xFFFF`, `0b1000`)
    LiteralInt(Box<LiteralInt<'src>>),

    /// Float literal (e.g. `1.0`, `-1.0`)
    LiteralFlt(Box<LiteralFlt<'src>>),

    /// String literal (e.g. `"abcd"`).
    LiteralStr(Box<LiteralStr<'src>>),

    /// Identifier (e.g. `some_identifier`).
    Ident(Box<Ident<'src>>),

    /// Pattern match expression (e.g. `$a`, `$a at 0`, `$a in (0..10)`)
    PatternMatch(Box<PatternMatch<'src>>),

    /// Pattern count expression (e.g. `#a`, `#a in (0..10)`)
    PatternCount(Box<IdentWithRange<'src>>),

    /// Pattern offset expression (e.g. `@a`, `@a[1]`)
    PatternOffset(Box<IdentWithIndex<'src>>),

    /// Pattern length expression (e.g. `!a`, `!a[1]`)
    PatternLength(Box<IdentWithIndex<'src>>),

    /// Array or dictionary indexing expression (e.g. `array[1]`, `dict["key"]`)
    LookupIndex(Box<LookupIndex<'src>>),

    /// A field lookup expression (e.g. `foo.bar`)
    FieldAccess(Box<BinaryExpr<'src>>),

    /// A function call expression (e.g. `foo()`, `bar(1,2)`)
    FnCall(Box<FnCall<'src>>),

    /// Boolean `not` expression.
    Not(Box<UnaryExpr<'src>>),

    /// Boolean `and` expression.
    And(Box<BinaryExpr<'src>>),

    /// Boolean `or` expression.
    Or(Box<BinaryExpr<'src>>),

    /// Arithmetic minus.
    Minus(Box<UnaryExpr<'src>>),

    /// Arithmetic add (`+`) expression.
    Add(Box<BinaryExpr<'src>>),

    /// Arithmetic subtraction (`-`) expression.
    Sub(Box<BinaryExpr<'src>>),

    /// Arithmetic multiplication (`*`) expression.
    Mul(Box<BinaryExpr<'src>>),

    /// Arithmetic division (`\`) expression.
    Div(Box<BinaryExpr<'src>>),

    /// Arithmetic modulus (`%`) expression.
    Modulus(Box<BinaryExpr<'src>>),

    /// Bitwise not (`~`) expression.
    BitwiseNot(Box<UnaryExpr<'src>>),

    /// Bitwise shift left (`<<`) expression.
    Shl(Box<BinaryExpr<'src>>),

    /// Bitwise shift right (`>>`) expression.
    Shr(Box<BinaryExpr<'src>>),

    /// Bitwise and (`&`) expression.
    BitwiseAnd(Box<BinaryExpr<'src>>),

    /// Bitwise or (`|`) expression.
    BitwiseOr(Box<BinaryExpr<'src>>),

    /// Bitwise xor (`^`) expression.
    BitwiseXor(Box<BinaryExpr<'src>>),

    /// Equal (`==`) expression.
    Eq(Box<BinaryExpr<'src>>),

    /// Not equal (`!=`) expression.
    Neq(Box<BinaryExpr<'src>>),

    /// Less than (`<`) expression.
    Lt(Box<BinaryExpr<'src>>),

    /// Greater than (`>`) expression.
    Gt(Box<BinaryExpr<'src>>),

    /// Less or equal (`<=`) expression.
    Le(Box<BinaryExpr<'src>>),

    /// Greater or equal (`>=`) expression.
    Ge(Box<BinaryExpr<'src>>),

    /// `contains` expression.
    Contains(Box<BinaryExpr<'src>>),

    /// `icontains` expression
    IContains(Box<BinaryExpr<'src>>),

    /// `startswith` expression.
    StartsWith(Box<BinaryExpr<'src>>),

    /// `istartswith` expression
    IStartsWith(Box<BinaryExpr<'src>>),

    /// `endswith` expression.
    EndsWith(Box<BinaryExpr<'src>>),

    /// `iendswith` expression
    IEndsWith(Box<BinaryExpr<'src>>),

    /// `iequals` expression.
    IEquals(Box<BinaryExpr<'src>>),

    /// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`)
    Of(Box<Of<'src>>),

    /// A `for <quantifier> of ...` expression. (e.g. `for any of ($a, $b) : ( ... )`)
    ForOf(Box<ForOf<'src>>),

    /// A `for <quantifier> <vars> in ...` expression. (e.g. `for all i in (1..100) : ( ... )`)
    ForIn(Box<ForIn<'src>>),
}

/// A pattern match expression (e.g. `$a`, `$b at 0`, `$c in (0..10)`).
#[derive(Debug, HasSpan)]
pub struct PatternMatch<'src> {
    pub(crate) span: Span,
    pub identifier: Ident<'src>,
    pub anchor: Option<MatchAnchor<'src>>,
}

/// In expressions like `$a at 0` or `$b in (0..10)`, this struct represents
/// the anchor, which is the part of the expression that follows the identifier
/// (e.g. `at <expr>`, `in <range>`).
#[derive(Debug, HasSpan)]
pub enum MatchAnchor<'src> {
    At(Box<At<'src>>),
    In(Box<In<'src>>),
}

/// In expressions like `$a at 0`, this structs represents the anchor
/// (e.g. `at <expr>`).
#[derive(Debug, HasSpan)]
pub struct At<'src> {
    pub(crate) span: Span,
    pub expr: Expr<'src>,
}

/// A pair of values conforming a range (e.g. `(0..10)`).
#[derive(Debug, HasSpan)]
pub struct Range<'src> {
    pub(crate) span: Span,
    pub lower_bound: Expr<'src>,
    pub upper_bound: Expr<'src>,
}

/// In expressions like `$a in (0..10)`, this structs represents the anchor
/// e.g. `in <range>`).
#[derive(Debug, HasSpan)]
pub struct In<'src> {
    pub(crate) span: Span,
    pub range: Range<'src>,
}

/// An identifier (e.g. `some_ident`).
#[derive(Debug, Clone, Hash, Eq, PartialEq, HasSpan)]
pub struct Ident<'src> {
    pub(crate) span: Span,
    pub name: &'src str,
}

/// Creates an [`Ident`] directly from a [`CSTNode`].
impl<'src> From<CSTNode<'src>> for Ident<'src> {
    fn from(node: CSTNode<'src>) -> Self {
        Self { span: node.as_span().into(), name: node.as_str() }
    }
}

/// An expression where an identifier can be accompanied by a range
/// (e.g. `#a in <range>`).
///
/// The range is optional thought, so expressions like `#a` are also
/// represented by this struct.
#[derive(Debug, HasSpan)]
pub struct IdentWithRange<'src> {
    pub(crate) span: Span,
    pub name: &'src str,
    pub range: Option<Range<'src>>,
}

/// An expression where an identifier can be accompanied by an index
/// (e.g. `@a[2]`).
///
/// The index is optional thought, so expressions like `@a` are also
/// represented by this struct.
#[derive(Debug, HasSpan)]
pub struct IdentWithIndex<'src> {
    pub(crate) span: Span,
    pub name: &'src str,
    pub index: Option<Expr<'src>>,
}

/// An integer literal.
#[derive(Debug, HasSpan)]
pub struct LiteralInt<'src> {
    pub(crate) span: Span,
    pub literal: &'src str,
    pub value: i64,
}

/// An float literal.
#[derive(Debug, HasSpan)]
pub struct LiteralFlt<'src> {
    pub(crate) span: Span,
    pub literal: &'src str,
    pub value: f32,
}

/// A string literal.
#[derive(Debug, HasSpan)]
pub struct LiteralStr<'src> {
    pub(crate) span: Span,
    pub literal: &'src str,
    pub value: BString,
}

/// An expression with a single operand.
#[derive(Debug, HasSpan)]
pub struct UnaryExpr<'src> {
    pub(crate) span: Span,
    pub operand: Expr<'src>,
}

/// An expression with two operands.
#[derive(Debug)]
pub struct BinaryExpr<'src> {
    /// Left-hand side.
    pub lhs: Expr<'src>,
    /// Right-hand side.
    pub rhs: Expr<'src>,
}

/// An expression representing a function call.
#[derive(Debug, HasSpan)]
pub struct FnCall<'src> {
    pub(crate) span: Span,
    pub callable: Expr<'src>,
    pub args: Vec<Expr<'src>>,
}

/// An index lookup operation
#[derive(Debug, HasSpan)]
pub struct LookupIndex<'src> {
    pub(crate) span: Span,
    pub primary: Expr<'src>,
    pub index: Expr<'src>,
}

/// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`,
/// `any of (true, false)`)
#[derive(Debug, HasSpan)]
pub struct Of<'src> {
    pub(crate) span: Span,
    pub quantifier: Quantifier<'src>,
    pub items: OfItems<'src>,
    pub anchor: Option<MatchAnchor<'src>>,
}

/// A `for .. of` expression (e.g `for all of them : (..)`,
/// `for 1 of ($a,$b) : (..)`)
#[derive(Debug, HasSpan)]
pub struct ForOf<'src> {
    pub(crate) span: Span,
    pub quantifier: Quantifier<'src>,
    pub pattern_set: PatternSet<'src>,
    pub condition: Expr<'src>,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
#[derive(Debug, HasSpan)]
pub struct ForIn<'src> {
    pub(crate) span: Span,
    pub quantifier: Quantifier<'src>,
    pub variables: Vec<Ident<'src>>,
    pub iterable: Iterable<'src>,
    pub condition: Expr<'src>,
}

#[derive(Debug)]
pub enum OfItems<'src> {
    PatternSet(PatternSet<'src>),
    BoolExprTuple(Vec<Expr<'src>>),
}

/// A quantifier used in `for` and `of` expressions.
#[derive(Debug, HasSpan)]
pub enum Quantifier<'src> {
    None {
        span: Span,
    },
    All {
        span: Span,
    },
    Any {
        span: Span,
    },
    /// Used in expressions like `10% of them`.
    Percentage(Expr<'src>),
    /// Used in expressions like `10 of them`.
    Expr(Expr<'src>),
}

/// Possible iterable expressions that can use in a [`ForIn`].
#[derive(Debug)]
pub enum Iterable<'src> {
    Range(Range<'src>),
    ExprTuple(Vec<Expr<'src>>),
    Ident(Box<Ident<'src>>),
}

/// Either a set of pattern identifiers (possibly with wildcards), or the
/// special set `them`, which includes all the patterns declared in the rule.
#[derive(Debug)]
pub enum PatternSet<'src> {
    Them,
    Set(Vec<PatternSetItem<'src>>),
}

/// Each individual item in a set of patterns.
///
/// In the pattern set `($a, $b*)`, `$a` and `$b*` are represented by a
/// [`PatternSetItem`].
#[derive(Debug, HasSpan)]
pub struct PatternSetItem<'src> {
    pub(crate) span: Span,
    pub identifier: &'src str,
}

impl<'src> PatternSet<'src> {}

impl<'src> Expr<'src> {
    /// Returns the value of the expression if it can be determined at compile
    /// time.
    ///
    /// When expressions are literals (e.g. `true`, `2`, `"abc"`), or
    /// operations that depend only on literals (e.g `2+3`, `true or false`),
    /// the value for the expression can be computed at compile time and will
    /// be returned by this function. If the value can't be computed, the
    /// result will be `None`.
    pub fn value<'a>(&'a self, sym_tbl: &'a SymbolTable) -> Option<Value> {
        match self {
            Self::True { .. } => Some(Value::Bool(true)),
            Self::False { .. } => Some(Value::Bool(false)),
            Self::LiteralInt(lit) => Some(Value::Integer(lit.value)),
            Self::LiteralFlt(lit) => Some(Value::Float(lit.value)),
            Self::LiteralStr(lit) => Some(Value::String(lit.value.as_bstr())),

            Self::Ident(ident) => {
                if let Some(sym) = sym_tbl.lookup(ident.name) {
                    sym.value().cloned()
                } else {
                    None
                }
            }

            // Expressions with values unknown at compile time.
            Self::Filesize { .. }
            | Self::Entrypoint { .. }
            | Self::FnCall(_)
            | Self::LookupIndex(_)
            | Self::FieldAccess(_)
            | Self::PatternMatch(_)
            | Self::PatternCount(_)
            | Self::PatternOffset(_)
            | Self::PatternLength(_)
            | Self::Of(_)
            | Self::ForOf(_)
            | Self::ForIn(_) => None,

            // Arithmetic operations.
            Self::Add(expr) => {
                arithmetic_op!(sym_tbl, expr.lhs, +, checked_add, expr.rhs)
            }
            Self::Sub(expr) => {
                arithmetic_op!(sym_tbl, expr.lhs, -, checked_sub, expr.rhs)
            }
            Self::Mul(expr) => {
                arithmetic_op!(sym_tbl, expr.lhs, *, checked_mul, expr.rhs)
            }
            Self::Div(expr) => {
                arithmetic_op!(sym_tbl, expr.lhs, /, checked_div, expr.rhs)
            }
            Self::Modulus(expr) => {
                arithmetic_op!(sym_tbl, expr.lhs, %, checked_rem, expr.rhs)
            }
            Self::Minus(expr) => match expr.operand.value(sym_tbl) {
                Some(Value::Integer(v)) => Some(Value::Integer(-v)),
                Some(Value::Float(v)) => Some(Value::Float(-v)),
                _ => None,
            },

            // Bitwise operations.
            // TODO: check for non-negative operands in bitwise operations.
            Self::Shl(expr) => {
                shift_op!(sym_tbl, expr.lhs, overflowing_shl, expr.rhs)
            }
            Self::Shr(expr) => {
                shift_op!(sym_tbl, expr.lhs, overflowing_shr, expr.rhs)
            }
            Self::BitwiseAnd(expr) => {
                bitwise_op!(sym_tbl, expr.lhs, bitand, expr.rhs)
            }
            Self::BitwiseOr(expr) => {
                bitwise_op!(sym_tbl, expr.lhs, bitor, expr.rhs)
            }
            Self::BitwiseXor(expr) => {
                bitwise_op!(sym_tbl, expr.lhs, bitxor, expr.rhs)
            }
            Self::BitwiseNot(expr) => match expr.operand.value(sym_tbl) {
                Some(Value::Integer(v)) => Some(Value::Integer(!v)),
                _ => None,
            },

            // Boolean operations.
            Self::And(expr) => {
                boolean_op!(sym_tbl, expr.lhs, &&, expr.rhs)
            }
            Self::Or(expr) => {
                boolean_op!(sym_tbl, expr.lhs, ||, expr.rhs)
            }
            Self::Not(expr) => {
                if let Value::Bool(v) = expr.operand.value(sym_tbl)? {
                    Some(Value::Bool(!v))
                } else {
                    None
                }
            }

            // Comparison operations.
            Self::Eq(expr) => {
                comparison_op!(sym_tbl, expr.lhs, ==, expr.rhs)
            }
            Self::Neq(expr) => {
                comparison_op!(sym_tbl, expr.lhs, !=, expr.rhs)
            }
            Self::Lt(expr) => {
                comparison_op!(sym_tbl, expr.lhs, <, expr.rhs)
            }
            Self::Le(expr) => {
                comparison_op!(sym_tbl, expr.lhs, <=, expr.rhs)
            }
            Self::Gt(expr) => {
                comparison_op!(sym_tbl, expr.lhs, >, expr.rhs)
            }
            Self::Ge(expr) => {
                comparison_op!(sym_tbl, expr.lhs, >=, expr.rhs)
            }

            // String operations.
            Self::Contains(expr) => {
                string_op!(sym_tbl, expr.lhs, contains_str, expr.rhs, false)
            }
            Self::IContains(expr) => {
                string_op!(sym_tbl, expr.lhs, contains_str, expr.rhs, true)
            }
            Self::StartsWith(expr) => {
                string_op!(sym_tbl, expr.lhs, starts_with_str, expr.rhs, false)
            }
            Self::IStartsWith(expr) => {
                string_op!(sym_tbl, expr.lhs, starts_with_str, expr.rhs, true)
            }
            Self::EndsWith(expr) => {
                string_op!(sym_tbl, expr.lhs, ends_with_str, expr.rhs, false)
            }
            Self::IEndsWith(expr) => {
                string_op!(sym_tbl, expr.lhs, ends_with_str, expr.rhs, true)
            }

            _ => unreachable!(),
        }
    }
}
