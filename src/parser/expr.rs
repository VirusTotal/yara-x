use crate::parser::span::*;
use crate::parser::CSTNode;
use crate::{Type, Value};
use bstr::{BString, ByteSlice};
use yara_derive::*;

/// An expression in the AST.
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
#[derive(Debug, Clone, HasSpan)]
pub struct Ident<'src> {
    pub(crate) ty: Type,
    pub(crate) value: Value<'src>,
    pub(crate) span: Span,
    pub name: &'src str,
}

/// Creates an [`Ident`] directly from a [`CSTNode`].
impl<'src> From<CSTNode<'src>> for Ident<'src> {
    fn from(node: CSTNode<'src>) -> Self {
        Self {
            ty: Type::Unknown,
            value: Value::Unknown,
            span: node.as_span().into(),
            name: node.as_str(),
        }
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
    pub(crate) ty: Type,
    pub(crate) value: Value<'src>,
    pub(crate) span: Span,
    pub operand: Expr<'src>,
}

/// An expression with two operands.
#[derive(Debug)]
pub struct BinaryExpr<'src> {
    pub(crate) ty: Type,
    pub(crate) value: Value<'src>,
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
    /// Returns the type and value of an expression if known.
    ///
    /// The type and value of an expression may be known at parse time if it
    /// depends on literals, for example the expression `2+2` is known to be
    /// an integer and its value is `4`; `true or false or not true` is known
    /// to be boolean with value `true`.
    ///
    /// In some other cases the type is known by the value is not, for example
    /// in the expression `$a and $b`, the type is boolean, but the value is
    /// unknown because it depends on whether the patterns are matched or not.
    ///
    /// When the expression contains identifiers, either external or provided
    /// by some module, the type of the identifier is not known until compile
    /// time, when all identifiers must be defined.
    ///
    pub fn type_value(&self) -> (Type, Value) {
        match self {
            Expr::True { .. } => (Type::Bool, Value::Bool(true)),
            Expr::False { .. } => (Type::Bool, Value::Bool(false)),

            Expr::Filesize { .. } | Expr::Entrypoint { .. } => {
                (Type::Integer, Value::Unknown)
            }

            Expr::LiteralInt(i) => (Type::Integer, Value::Integer(i.value)),
            Expr::LiteralFlt(f) => (Type::Float, Value::Float(f.value)),
            Expr::LiteralStr(s) => {
                (Type::String, Value::String(s.value.as_bstr()))
            }

            Expr::PatternMatch(_)
            | Expr::LookupIndex(_)
            | Expr::FnCall(_)
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_) => (Type::Bool, Value::Unknown),

            Expr::PatternCount(_)
            | Expr::PatternOffset(_)
            | Expr::PatternLength(_) => (Type::Integer, Value::Unknown),

            Expr::Not(expr) | Expr::BitwiseNot(expr) | Expr::Minus(expr) => {
                (expr.ty.clone(), expr.value.clone())
            }

            Expr::Ident(ident) => (ident.ty.clone(), ident.value.clone()),

            Expr::FieldAccess(expr)
            | Expr::And(expr)
            | Expr::Or(expr)
            | Expr::Eq(expr)
            | Expr::Neq(expr)
            | Expr::Lt(expr)
            | Expr::Gt(expr)
            | Expr::Le(expr)
            | Expr::Ge(expr)
            | Expr::Contains(expr)
            | Expr::IContains(expr)
            | Expr::StartsWith(expr)
            | Expr::IStartsWith(expr)
            | Expr::EndsWith(expr)
            | Expr::IEndsWith(expr)
            | Expr::IEquals(expr)
            | Expr::Add(expr)
            | Expr::Sub(expr)
            | Expr::Mul(expr)
            | Expr::Div(expr)
            | Expr::Modulus(expr)
            | Expr::Shl(expr)
            | Expr::Shr(expr)
            | Expr::BitwiseAnd(expr)
            | Expr::BitwiseOr(expr)
            | Expr::BitwiseXor(expr) => (expr.ty.clone(), expr.value.clone()),
        }
    }
}
