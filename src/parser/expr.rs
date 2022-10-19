use crate::parser::span::*;
use crate::parser::CSTNode;
use ascii_tree::Tree::{Leaf, Node};
use bstr::{BStr, BString, ByteSlice};
use std::fmt::Display;
use std::fmt::Formatter;
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use yara_derive::*;

macro_rules! arithmetic_op {
    ($lhs:expr, $op:tt, $checked_op:ident, $rhs:expr) => {{
        use ExprValue::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value()?;
        let rhs = $rhs.value()?;
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
            (Integer(l), Integer(r)) => Some(Integer(l.$checked_op(r)?)),
            (Integer(l), Float(r)) => Some(Float((l as f32) $op r)),
            (Float(l), Integer(r)) => Some(Float(l $op (r as f32))),
            (Float(l), Float(r)) => Some(Float(l $op r)),
            // Operands should be either integer or float, panic if
            // otherwise.
            (l, r) => unreachable!("{:?}, {:?}", l, r),
        }
    }};
}

macro_rules! boolean_op {
    ($lhs:expr, $operator:tt, $rhs:expr) => {{
        use ExprValue::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value()?;
        let rhs = $rhs.value()?;
        // This point is reached only if both sides of the operation have
        // some value.
        match (lhs, rhs) {
            // If both of values are booleans, return the result of the
            // operation.
            (Bool(lhs), Bool(rhs)) => Some(Bool(lhs $operator rhs)),
            // This point should not be reached, a boolean operation is
            // expected to have boolean operands.
            (lhs, rhs) => unreachable!("{:?}, {:?}", lhs, rhs),
       }
   }};
}

macro_rules! shift_op {
    ($lhs:expr, $operator:ident, $rhs:expr) => {{
        use ExprValue::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value()?;
        let rhs = $rhs.value()?;
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
    ($lhs:expr, $operator:ident, $rhs:expr) => {{
        use ExprValue::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value()?;
        let rhs = $rhs.value()?;
        // This point is reached only if both sides of the operation have
        // some value.
        match (lhs, rhs) {
            (Integer(l), Integer(r)) => Some(Integer(l.$operator(r))),
            (l, r) => unreachable!("{:?}, {:?}", l, r),
        }
    }};
}

macro_rules! comparison_op {
    ($lhs:expr, $operator:tt, $rhs:expr) => {{
        use ExprValue::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value()?;
        let rhs = $rhs.value()?;
        // This point is reached only if both sides of the operation
        // have some value.
        match (lhs, rhs) {
            (Integer(lhs), Integer(rhs)) => Some(Bool(lhs $operator rhs)),
            (Float(lhs), Float(rhs)) => Some(Bool(lhs $operator rhs)),
            (Float(lhs), Integer(rhs)) => Some(Bool(lhs $operator (rhs as f32))),
            (Integer(lhs), Float(rhs)) => Some(Bool((lhs as f32) $operator rhs)),
            (String(lhs), String(rhs)) => Some(Bool(lhs $operator rhs)),
            (lhs, rhs) => unreachable!("{:?}, {:?}", lhs, rhs),
        }
    }};
}

macro_rules! string_op {
    ($lhs:expr, $operator:ident, $rhs:expr, $case_insensitive:expr) => {{
        use ExprValue::*;
        // Get the values for lhs and rhs, which are of type `Expr`. If
        // some of them are None, return None.
        let lhs = $lhs.value()?;
        let rhs = $rhs.value()?;
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
            (lhs, rhs) => unreachable!("{:?}, {:?}", lhs, rhs),
        }
    }};
}

/// Represents the value associated to an expression, when it can be determined
/// at compile time. For example, the value of `2+2` can be determined during
/// compilation, it would be `Integer(4)`.
#[derive(Debug, Clone)]
pub enum ExprValue<'a> {
    Bool(bool),
    Integer(i64),
    Float(f32),
    String(&'a BStr),
}

impl<'a> Display for ExprValue<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Integer(v) => write!(f, "{}", v),
            Self::Float(v) => write!(f, "{:.1}", v),
            Self::String(v) => write!(f, "{:?}", v),
        }
    }
}

impl<'a> ExprValue<'a> {
    pub fn as_integer(&self) -> i64 {
        if let Self::Integer(i) = self {
            return *i;
        } else {
            panic!("{:?}", self);
        }
    }
}

/// All the different kinds of expressions that can be found in YARA.
///
/// For example, the kind for expression `2+2` is `Integer`, for `2.0 / 2` is
/// `Float` and for `true or false` is `Bool`.
#[derive(Debug)]
pub enum ExprKind {
    Bool,
    Integer,
    Float,
    String,
}

impl Display for ExprKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "boolean"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::String => write!(f, "string"),
        }
    }
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

    /// String match expression (e.g. `$a`, `$a at 0`, `$a in (0..10)`)
    StringMatch(Box<StringMatch<'src>>),

    /// String count expression (e.g. `#a`, `#a in (0..10)`)
    StringCount(Box<IdentWithRange<'src>>),

    /// String offset expression (e.g. `@a`, `@a[1]`)
    StringOffset(Box<IdentWithIndex<'src>>),

    /// String length expression (e.g. `!a`, `!a[1]`)
    StringLength(Box<IdentWithIndex<'src>>),

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

/// A string match expression (e.g. `$a`, `$b at 0`, `$c in (0..10)`).
#[derive(Debug, HasSpan)]
pub struct StringMatch<'src> {
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
    pub string_set: StringSet<'src>,
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
    StringSet(StringSet<'src>),
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

impl<'src> Quantifier<'src> {
    pub fn ascii_tree(&self) -> ascii_tree::Tree {
        match self {
            Quantifier::None { .. } => Leaf(vec!["none".to_string()]),
            Quantifier::All { .. } => Leaf(vec!["all".to_string()]),
            Quantifier::Any { .. } => Leaf(vec!["any".to_string()]),
            Quantifier::Percentage(expr) => {
                Node("percentage".to_string(), vec![expr.ascii_tree()])
            }
            Quantifier::Expr(expr) => expr.ascii_tree(),
        }
    }
}

/// Either a set of string identifiers (possibly with wildcards), or the
/// special set `them`, which includes all the strings declared in the rule.
#[derive(Debug)]
pub enum StringSet<'src> {
    Them,
    Set(Vec<StringSetItem<'src>>),
}

#[derive(Debug, HasSpan)]
pub struct StringSetItem<'src> {
    pub(crate) span: Span,
    pub identifier: &'src str,
}

impl<'src> StringSet<'src> {
    pub fn ascii_tree(&self) -> ascii_tree::Tree {
        match self {
            Self::Them => Leaf(vec!["them".to_string()]),
            Self::Set(set) => {
                Leaf(set.iter().map(|s| s.identifier.to_string()).collect())
            }
        }
    }
}

impl<'src> Expr<'src> {
    /*
    /// Returns the kind of the expression, which must be one of the listed
    /// in the [`ExprKind`] enum.
    pub fn kind(&self) -> ExprKind {
        match self {
            // Expressions that return a boolean.
            Expr::StringIdent(_)
            | Expr::True { .. }
            | Expr::False { .. }
            | Expr::Not(_)
            | Expr::And(_)
            | Expr::Or(_)
            | Expr::Eq(_)
            | Expr::Neq(_)
            | Expr::Lt(_)
            | Expr::Le(_)
            | Expr::Gt(_)
            | Expr::Ge(_) => ExprKind::Bool,

            // Expressions that return an integer.
            Expr::LiteralInt(_)
            | Expr::Filesize { .. }
            | Expr::Entrypoint { .. }
            | Expr::Modulus(_)
            | Expr::Shr(_)
            | Expr::Shl(_)
            | Expr::BitwiseNot(_)
            | Expr::BitwiseAnd(_)
            | Expr::BitwiseOr(_)
            | Expr::BitwiseXor(_)
            | Expr::StringCount(_)
            | Expr::StringOffset(_)
            | Expr::StringLength(_) => ExprKind::Integer,

            // Expressions that return a float.
            Expr::LiteralFlt(_) => ExprKind::Float,

            // Expressions that return a string.
            Expr::LiteralStr(_) => ExprKind::String,

            // The minus expression returns the type of its operand, it
            // could be ExprType::Integer or ExprType::Float.
            Expr::Minus(expr) => expr.operand.kind(),

            // Arithmetic operations return an integer if both operands are
            // integers. If any of the operands is a float the result is
            // also a float.
            Expr::Add(expr)
            | Expr::Sub(expr)
            | Expr::Div(expr)
            | Expr::Mul(expr) => {
                if let ExprKind::Float = expr.lhs.kind() {
                    ExprKind::Float
                } else if let ExprKind::Float = expr.rhs.kind() {
                    ExprKind::Float
                } else {
                    ExprKind::Integer
                }
            }
        }
    }
     */

    /// Returns the value of the expression if it can be determined at compile
    /// time.
    ///
    /// When expressions are literals (e.g. `true`, `2`, `"abc"`), or
    /// operations that depend only on literals (e.g `2+3`, `true or false`),
    /// the value for the expression can be computed at compile time and will
    /// be returned by this function. If the value can't be computed, the
    /// result will be `None`.
    pub fn value(&self) -> Option<ExprValue> {
        match self {
            Self::True { .. } => Some(ExprValue::Bool(true)),
            Self::False { .. } => Some(ExprValue::Bool(false)),
            Self::LiteralInt(lit) => Some(ExprValue::Integer(lit.value)),
            Self::LiteralFlt(lit) => Some(ExprValue::Float(lit.value)),
            Self::LiteralStr(lit) => {
                Some(ExprValue::String(lit.value.as_bstr()))
            }

            // Expressions with values unknown at compile time.
            Self::Ident { .. }
            | Self::Filesize { .. }
            | Self::Entrypoint { .. }
            | Self::FnCall(_)
            | Self::LookupIndex(_)
            | Self::FieldAccess(_)
            | Self::StringMatch(_)
            | Self::StringCount(_)
            | Self::StringOffset(_)
            | Self::StringLength(_)
            | Self::Of(_)
            | Self::ForOf(_)
            | Self::ForIn(_) => None,

            // Arithmetic operations.
            Self::Add(expr) => {
                arithmetic_op!(expr.lhs, +, checked_add, expr.rhs)
            }
            Self::Sub(expr) => {
                arithmetic_op!(expr.lhs, -, checked_sub, expr.rhs)
            }
            Self::Mul(expr) => {
                arithmetic_op!(expr.lhs, *, checked_mul, expr.rhs)
            }
            Self::Div(expr) => {
                arithmetic_op!(expr.lhs, /, checked_div, expr.rhs)
            }
            Self::Modulus(expr) => {
                arithmetic_op!(expr.lhs, %, checked_rem, expr.rhs)
            }
            Self::Minus(expr) => match expr.operand.value() {
                Some(ExprValue::Integer(v)) => Some(ExprValue::Integer(-v)),
                Some(ExprValue::Float(v)) => Some(ExprValue::Float(-v)),
                _ => None,
            },

            // Bitwise operations.
            Self::Shl(expr) => {
                shift_op!(expr.lhs, overflowing_shl, expr.rhs)
            }
            Self::Shr(expr) => {
                shift_op!(expr.lhs, overflowing_shr, expr.rhs)
            }
            Self::BitwiseAnd(expr) => {
                bitwise_op!(expr.lhs, bitand, expr.rhs)
            }
            Self::BitwiseOr(expr) => {
                bitwise_op!(expr.lhs, bitor, expr.rhs)
            }
            Self::BitwiseXor(expr) => {
                bitwise_op!(expr.lhs, bitxor, expr.rhs)
            }
            Self::BitwiseNot(expr) => match expr.operand.value() {
                Some(ExprValue::Integer(v)) => Some(ExprValue::Integer(!v)),
                _ => None,
            },

            // Boolean operations.
            Self::And(expr) => boolean_op!(expr.lhs, &&, expr.rhs),
            Self::Or(expr) => boolean_op!(expr.lhs, ||, expr.rhs),
            Self::Not(expr) => {
                if let ExprValue::Bool(v) = expr.operand.value()? {
                    Some(ExprValue::Bool(!v))
                } else {
                    None
                }
            }

            // Comparison operations.
            Self::Eq(expr) => comparison_op!(expr.lhs, ==, expr.rhs),
            Self::Neq(expr) => comparison_op!(expr.lhs, !=, expr.rhs),
            Self::Lt(expr) => comparison_op!(expr.lhs, <, expr.rhs),
            Self::Le(expr) => comparison_op!(expr.lhs, <=, expr.rhs),
            Self::Gt(expr) => comparison_op!(expr.lhs, >, expr.rhs),
            Self::Ge(expr) => comparison_op!(expr.lhs, >=, expr.rhs),

            // String operations.
            Self::Contains(expr) => {
                string_op!(expr.lhs, contains_str, expr.rhs, false)
            }
            Self::IContains(expr) => {
                string_op!(expr.lhs, contains_str, expr.rhs, true)
            }
            Self::StartsWith(expr) => {
                string_op!(expr.lhs, starts_with_str, expr.rhs, false)
            }
            Self::IStartsWith(expr) => {
                string_op!(expr.lhs, starts_with_str, expr.rhs, true)
            }
            Self::EndsWith(expr) => {
                string_op!(expr.lhs, ends_with_str, expr.rhs, false)
            }
            Self::IEndsWith(expr) => {
                string_op!(expr.lhs, ends_with_str, expr.rhs, true)
            }

            _ => unreachable!(),
        }
    }

    /// Returns a representation of the expression as an ASCII tree.
    pub fn ascii_tree(&self) -> ascii_tree::Tree {
        let value = if let Some(v) = self.value() {
            format! {"{}", v}
        } else {
            "unknown".to_string()
        };
        match self {
            Self::True { .. } => Leaf(vec!["true".to_string()]),
            Self::False { .. } => Leaf(vec!["false".to_string()]),
            Self::Entrypoint { .. } => Leaf(vec!["entrypoint".to_string()]),
            Self::Filesize { .. } => Leaf(vec!["filesize".to_string()]),
            Self::LiteralInt(lit) => Leaf(vec![lit.literal.to_string()]),
            Self::LiteralFlt(lit) => Leaf(vec![lit.literal.to_string()]),
            Self::LiteralStr(lit) => Leaf(vec![lit.literal.to_string()]),
            Self::Ident(ident) => Leaf(vec![ident.name.to_string()]),
            Self::Not(expr) => Node(
                format!("not (value: {})", value),
                vec![expr.operand.ascii_tree()],
            ),
            Self::And(expr) => Node(
                format!("and (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Or(expr) => Node(
                format!("or (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Minus(expr) => Node(
                format!("minus (value: {})", value),
                vec![expr.operand.ascii_tree()],
            ),
            Self::Add(expr) => Node(
                format!("add (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Sub(expr) => Node(
                format!("sub (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Mul(expr) => Node(
                format!("mul (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Div(expr) => Node(
                format!("div (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Shl(expr) => Node(
                format!("shl (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Shr(expr) => Node(
                format!("shr (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::BitwiseNot(expr) => Node(
                format!("bitwise_not (value: {})", value),
                vec![expr.operand.ascii_tree()],
            ),
            Self::BitwiseAnd(expr) => Node(
                format!("bitwise_and (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::BitwiseOr(expr) => Node(
                format!("bitwise_or (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::BitwiseXor(expr) => Node(
                format!("bitwise_xor (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Modulus(expr) => Node(
                format!("mod (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Eq(expr) => Node(
                format!("eq (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Neq(expr) => Node(
                format!("neq (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Lt(expr) => Node(
                format!("lt (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Le(expr) => Node(
                format!("le (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Gt(expr) => Node(
                format!("gt (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Ge(expr) => Node(
                format!("ge (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::Contains(expr) => Node(
                format!("contains (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::IContains(expr) => Node(
                format!("icontains (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::StartsWith(expr) => Node(
                format!("startswith (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::IStartsWith(expr) => Node(
                format!("istartswith (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::EndsWith(expr) => Node(
                format!("endswith (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::IEndsWith(expr) => Node(
                format!("iendswith (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::IEquals(expr) => Node(
                format!("iequals (value: {})", value),
                vec![expr.lhs.ascii_tree(), expr.rhs.ascii_tree()],
            ),
            Self::StringMatch(s) => {
                if let Some(anchor) = &s.anchor {
                    match anchor {
                        MatchAnchor::At(anchor_at) => Node(
                            format!("{} at <expr>", s.identifier.name),
                            vec![Node(
                                "<expr>".to_string(),
                                vec![anchor_at.expr.ascii_tree()],
                            )],
                        ),
                        MatchAnchor::In(anchor_in) => Node(
                            format!(
                                "{} in (<start>, <end>)",
                                s.identifier.name
                            ),
                            vec![
                                Node(
                                    "<start>".to_string(),
                                    vec![anchor_in
                                        .range
                                        .lower_bound
                                        .ascii_tree()],
                                ),
                                Node(
                                    "<end>".to_string(),
                                    vec![anchor_in
                                        .range
                                        .upper_bound
                                        .ascii_tree()],
                                ),
                            ],
                        ),
                    }
                } else {
                    Leaf(vec![s.identifier.name.to_string()])
                }
            }
            Self::StringCount(s) => {
                if let Some(range) = &s.range {
                    Node(
                        format!("{} in <range>", s.name),
                        vec![Node(
                            "<range>".to_string(),
                            vec![
                                range.lower_bound.ascii_tree(),
                                range.upper_bound.ascii_tree(),
                            ],
                        )],
                    )
                } else {
                    Leaf(vec![s.name.to_string()])
                }
            }
            Self::StringOffset(s) | Self::StringLength(s) => {
                if let Some(index) = &s.index {
                    Node(
                        format!("{}[<index>]", s.name),
                        vec![Node(
                            "<index>".to_string(),
                            vec![index.ascii_tree()],
                        )],
                    )
                } else {
                    Leaf(vec![s.name.to_string()])
                }
            }
            Self::LookupIndex(l) => Node(
                "<expr>[<index>]".to_string(),
                vec![
                    Node("<expr>".to_string(), vec![l.primary.ascii_tree()]),
                    Node("<index>".to_string(), vec![l.index.ascii_tree()]),
                ],
            ),
            Self::FieldAccess(expr) => Node(
                "<struct>.<field>".to_string(),
                vec![
                    Node("<struct>".to_string(), vec![expr.lhs.ascii_tree()]),
                    Node("<field>".to_string(), vec![expr.rhs.ascii_tree()]),
                ],
            ),
            Self::FnCall(expr) => {
                // Create a vector where each argument is accompanied by a label
                // "<arg0>", "<arg1>", "<arg2>", and so on.
                let labelled_args: Vec<(String, &Expr<'src>)> = expr
                    .args
                    .iter()
                    .enumerate()
                    .map(|(i, arg)| (format!("<arg{i}>"), arg))
                    .collect();

                // Build string with all the labels separated by commas.
                let comma_sep_labels = labelled_args
                    .iter()
                    .map(|(label, _)| label.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ");

                let mut children = vec![Node(
                    "<callable>".to_string(),
                    vec![expr.callable.ascii_tree()],
                )];

                for (label, arg) in labelled_args.into_iter() {
                    children.push(Node(label, vec![arg.ascii_tree()]))
                }

                Node(format!("<callable>({})", comma_sep_labels), children)
            }
            Self::Of(of) => {
                let set_ascii_tree = match &of.items {
                    OfItems::StringSet(set) => Node(
                        "<items: string_set>".to_string(),
                        vec![set.ascii_tree()],
                    ),
                    OfItems::BoolExprTuple(set) => Node(
                        "<items: boolean_expr_set>".to_string(),
                        set.iter().map(|x| x.ascii_tree()).collect(),
                    ),
                };

                let mut children = vec![
                    Node(
                        "<quantifier>".to_string(),
                        vec![of.quantifier.ascii_tree()],
                    ),
                    set_ascii_tree,
                ];

                let node_title = if let Some(anchor) = &of.anchor {
                    match anchor {
                        MatchAnchor::At(anchor_at) => {
                            children.push(Node(
                                "<expr>".to_string(),
                                vec![anchor_at.expr.ascii_tree()],
                            ));
                            "<quantifier> of <items> at <expr>".to_string()
                        }
                        MatchAnchor::In(anchor_in) => {
                            children.push(Node(
                                "<start>".to_string(),
                                vec![anchor_in.range.lower_bound.ascii_tree()],
                            ));
                            children.push(Node(
                                "<end>".to_string(),
                                vec![anchor_in.range.upper_bound.ascii_tree()],
                            ));
                            "<quantifier> of <items> in (<start>..<end>)"
                                .to_string()
                        }
                    }
                } else {
                    "<quantifier> of <items>".to_string()
                };

                Node(node_title, children)
            }
            Self::ForOf(for_of) => Node(
                "for <quantifier> of <items> : ( <condition> )".to_string(),
                vec![
                    Node(
                        "<quantifier>".to_string(),
                        vec![for_of.quantifier.ascii_tree()],
                    ),
                    Node(
                        "<items>".to_string(),
                        vec![for_of.string_set.ascii_tree()],
                    ),
                    Node(
                        "<condition>".to_string(),
                        vec![for_of.condition.ascii_tree()],
                    ),
                ],
            ),
            Self::ForIn(f) => {
                let mut children = vec![
                    Node(
                        "<quantifier>".to_string(),
                        vec![f.quantifier.ascii_tree()],
                    ),
                    Node(
                        "<vars>".to_string(),
                        vec![Leaf(
                            f.variables
                                .iter()
                                .map(|v| v.name.to_string())
                                .collect(),
                        )],
                    ),
                ];

                let node_title = match &f.iterable {
                    Iterable::Range(range) => {
                        children.push(Node(
                            "<start>".to_string(),
                            vec![range.lower_bound.ascii_tree()],
                        ));
                        children.push(Node(
                            "<end>".to_string(),
                            vec![range.upper_bound.ascii_tree()],
                        ));
                        "for <quantifier> <vars> in (<start>..<end>) : ( <condition> )".to_string()
                    }
                    Iterable::ExprTuple(args) => {
                        let labelled_args: Vec<(String, &Expr<'src>)> = args
                            .iter()
                            .enumerate()
                            .map(|(i, arg)| (format!("<expr{i}>"), arg))
                            .collect();

                        let comma_sep_labels = labelled_args
                            .iter()
                            .map(|(label, _)| label.as_str())
                            .collect::<Vec<&str>>()
                            .join(", ");

                        for (label, arg) in labelled_args.into_iter() {
                            children.push(Node(label, vec![arg.ascii_tree()]))
                        }

                        format!("for <quantifier> <vars> in ({comma_sep_labels}) : ( <condition> )")
                    }
                    Iterable::Ident(ident) => {
                        children.push(Node(
                            "<identifier>".to_string(),
                            vec![Leaf(vec![ident.name.to_string()])],
                        ));
                        "for <quantifier> <vars> in <identifier> : ( <condition> )".to_string()
                    }
                };

                children.push(Node(
                    "<condition>".to_string(),
                    vec![f.condition.ascii_tree()],
                ));

                Node(node_title, children)
            }
        }
    }
}
