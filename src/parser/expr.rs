use std::fmt::{Display, Formatter};

use bstr::BString;

use yara_derive::*;

use crate::parser::CSTNode;
use crate::parser::span::*;

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
    pub(crate) type_hint: TypeHint,
    pub(crate) span: Span,
    pub name: &'src str,
}

/// Creates an [`Ident`] directly from a [`CSTNode`].
impl<'src> From<CSTNode<'src>> for Ident<'src> {
    fn from(node: CSTNode<'src>) -> Self {
        Self {
            type_hint: TypeHint::UnknownType,
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

/// A float literal.
#[derive(Debug, HasSpan)]
pub struct LiteralFlt<'src> {
    pub(crate) span: Span,
    pub literal: &'src str,
    pub value: f64,
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
    pub(crate) type_hint: TypeHint,
    pub operand: Expr<'src>,
}

/// An expression with two operands.
#[derive(Debug)]
pub struct BinaryExpr<'src> {
    pub(crate) type_hint: TypeHint,
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

/// A type hint indicates the type, and possibly the value, of some expression
/// in the AST.
///
/// The parser is able to determine the type and value of expressions that
/// depend only on literals. For example, expressions like `2`, `false`, or
/// `"foobar"` are literals, and therefore their types and value are known at
/// parse time. With more complex expressions like `2+2` or `false or not true`
/// this is also possible, and the corresponding expressions will be annotated
/// with hints `Integer(Some(4))` and `Bool(Some(false))`, respectively.
///
/// In other cases the type can be determined, but not the value. For example
/// `$a or $b` is of type boolean but its value is not known at parse time,
/// so it will be annotated with `Bool(None)`.
///
/// When the type is not known, the hint will be `UnknownType`.
#[derive(Debug, Clone)]
pub enum TypeHint {
    UnknownType,
    Bool(Option<bool>),
    Integer(Option<i64>),
    Float(Option<f64>),
    String(Option<BString>),
    Struct,
}

impl TypeHint {
    /// Returns the type associated to a  [`TypeHint`]
    ///
    /// This is useful when we are interested only on the type and not the
    /// value.
    pub fn ty(&self) -> Type {
        match &self {
            TypeHint::UnknownType => Type::Unknown,
            TypeHint::Bool(_) => Type::Bool,
            TypeHint::Integer(_) => Type::Integer,
            TypeHint::Float(_) => Type::Float,
            TypeHint::String(_) => Type::String,
            TypeHint::Struct => Type::Struct,
        }
    }
}

/// Types returned by [`TypeHint::ty`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Type {
    Unknown,
    Bool,
    Integer,
    Float,
    String,
    Struct,
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Bool => write!(f, "boolean"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::String => write!(f, "string"),
            Self::Struct => write!(f, "struct"),
        }
    }
}

impl Display for TypeHint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType => write!(f, "unknown"),
            Self::Bool(value) => {
                if let Some(value) = value {
                    write!(f, "boolean({})", value)
                } else {
                    write!(f, "boolean(unknown)")
                }
            }
            Self::Integer(value) => {
                if let Some(value) = value {
                    write!(f, "integer({})", value)
                } else {
                    write!(f, "integer(unknown)")
                }
            }
            Self::Float(value) => {
                if let Some(value) = value {
                    write!(f, "float({:.1})", value)
                } else {
                    write!(f, "float(unknown)")
                }
            }
            Self::String(value) => {
                if let Some(value) = value {
                    write!(f, "string({})", value)
                } else {
                    write!(f, "string(unknown)")
                }
            }
            Self::Struct => write!(f, "struct"),
        }
    }
}

impl<'src> Expr<'src> {
    pub fn type_hint(&self) -> TypeHint {
        match self {
            Expr::True { .. } => TypeHint::Bool(Some(true)),
            Expr::False { .. } => TypeHint::Bool(Some(false)),

            Expr::Filesize { .. } | Expr::Entrypoint { .. } => {
                TypeHint::Integer(None)
            }

            Expr::LiteralInt(i) => TypeHint::Integer(Some(i.value)),
            Expr::LiteralFlt(f) => TypeHint::Float(Some(f.value)),
            Expr::LiteralStr(s) => TypeHint::String(Some(s.value.clone())),

            Expr::PatternMatch(_)
            | Expr::LookupIndex(_)
            | Expr::FnCall(_)
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_) => TypeHint::Bool(None),

            Expr::PatternCount(_)
            | Expr::PatternOffset(_)
            | Expr::PatternLength(_) => TypeHint::Integer(None),

            Expr::Not(expr) | Expr::BitwiseNot(expr) | Expr::Minus(expr) => {
                expr.type_hint.clone()
            }

            Expr::Ident(ident) => ident.type_hint.clone(),

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
            | Expr::BitwiseXor(expr) => expr.type_hint.clone(),
        }
    }
}
