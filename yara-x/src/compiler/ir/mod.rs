/*! Intermediate representation (IR) for a set of YARA rules.

The IR is a tree representing a set of YARA rules. This tree is similar to the
AST, but it contains type information for expressions and identifiers, something
that the AST doesn't have. The IR is generated using the AST as input, and the
code emission phase uses the IR as input. This means that the IR is further
away from the original source code than the AST, and closer to the emitted
code. The build process goes like:

  `source code -> CST -> AST -> IR -> code emission`

Contrary to the AST, the IR doesn't have a one to one correspondence to the
original source code, the compiler is free to transform the IR in ways that
maintain the semantics of the original source code but doesn't match the code
exactly. This could be done for example for optimization purposes. Another
example is constant folding, which is done while the IR is being built,
converting expressions like `2+2+2` into the constant `6`.
*/

mod ascii_tree;
mod ast2ir;

use crate::symbols::Symbol;
use yara_x_parser::ast::Span;
use yara_x_parser::types::{Type, TypeValue};

use crate::compiler::PatternId;
pub(in crate::compiler) use ast2ir::expr_from_ast;

/*
/// This type represents the intermediate representation (IR) for a set
/// of YARA rules.
pub(crate) struct IR {
    ident_pool: StringPool<IdentId>,
    rules: Vec<Rule>,
}

pub(crate) struct Rule {
    ident_span: Span,
    /// ID of the rule identifier in the identifiers pool.
    pub(crate) ident_id: IdentId,
    /// ID of the rule namespace in the identifiers pool.
    pub(crate) namespace_id: IdentId,
    /// Rule's condition.
    pub(crate) condition: Expr,
}

 */

pub(in crate::compiler) enum Expr {
    /// Constant value (i.e: the value is known at compile time)
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
    },

    /// Pattern match expression where the pattern is variable (e.g: `$`).
    PatternMatchVar {
        symbol: Symbol,
    },

    /// Pattern match at a given offset (e.g. `$a at 0`)
    PatternMatchAt {
        pattern_id: PatternId,
        offset: Box<Expr>,
    },

    /// Pattern match at a given offset where the pattern is variable
    /// (e.g. `$ at 0`)
    PatternMatchAtVar {
        symbol: Symbol,
        offset: Box<Expr>,
    },

    /// Pattern match within a given range (e.g. `$a in (0..100)`)
    PatternMatchIn {
        pattern_id: PatternId,
        range: Range,
    },

    /// Pattern match within a given range where the pattern is variable
    /// (e.g. `$ in (0..100)`)
    PatternMatchInVar {
        symbol: Symbol,
        range: Range,
    },

    /// Function call.
    FnCall(Box<FnCall>),

    /// A `for <quantifier> <vars> in ...` expression. (e.g. `for all i in (1..100) : ( ... )`)
    ForIn(Box<ForIn>),
}

/// A quantifier used in `for` and `of` expressions.
pub(in crate::compiler) enum Quantifier {
    None,
    All,
    Any,
    Percentage(Expr),
    Expr(Expr),
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

/// An expression representing a function call.
pub(in crate::compiler) struct FnCall {
    // The callable expression, which must resolve in some function identifier.
    pub callable: Expr,
    // The arguments passed to the function in this call.
    pub args: Vec<Expr>,
    // Type and value for the function's result.
    pub type_value: TypeValue,
    // Due to function overloading, the same function may have multiple
    // signatures. This field indicates the index of the signature that
    // matched the provided arguments.
    pub signature_index: usize,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
pub(in crate::compiler) struct ForIn {
    pub span: Span,
    pub quantifier: Quantifier,
    pub variables: Vec<Symbol>,
    pub iterable: Iterable,
    pub condition: Expr,
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
            | Expr::PatternMatch { .. }
            | Expr::PatternMatchAt { .. }
            | Expr::PatternMatchIn { .. }
            | Expr::PatternMatchVar { .. }
            | Expr::PatternMatchAtVar { .. }
            | Expr::PatternMatchInVar { .. }
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
            | Expr::Mod { .. }
            | Expr::BitwiseNot { .. }
            | Expr::BitwiseAnd { .. }
            | Expr::BitwiseOr { .. }
            | Expr::BitwiseXor { .. }
            | Expr::Shl { .. }
            | Expr::Shr { .. } => Type::Integer,

            Expr::FieldAccess { rhs, .. } => rhs.ty(),
            Expr::Ident { symbol, .. } => symbol.type_value().ty(),
            Expr::FnCall(fn_call) => fn_call.type_value.ty(),
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
            | Expr::PatternMatch { .. }
            | Expr::PatternMatchAt { .. }
            | Expr::PatternMatchIn { .. }
            | Expr::PatternMatchVar { .. }
            | Expr::PatternMatchAtVar { .. }
            | Expr::PatternMatchInVar { .. }
            | Expr::ForIn(_) => TypeValue::Bool(None),

            Expr::Minus { operand, .. } => match operand.ty() {
                Type::Integer => TypeValue::Integer(None),
                _ => TypeValue::Float(None),
            },

            Expr::Add { lhs, rhs, .. }
            | Expr::Sub { lhs, rhs, .. }
            | Expr::Mul { lhs, rhs, .. }
            | Expr::Div { lhs, rhs, .. } => match (lhs.ty(), rhs.ty()) {
                // If both operands are integer, the expression's type is
                // integer.
                (Type::Integer, Type::Integer) => TypeValue::Integer(None),
                // In all the remaining cases at least one of the operands
                // is float, therefore the result is float.
                _ => TypeValue::Float(None),
            },

            Expr::Filesize
            | Expr::Entrypoint
            | Expr::Mod { .. }
            | Expr::BitwiseNot { .. }
            | Expr::BitwiseAnd { .. }
            | Expr::BitwiseOr { .. }
            | Expr::BitwiseXor { .. }
            | Expr::Shl { .. }
            | Expr::Shr { .. } => TypeValue::Integer(None),

            Expr::FieldAccess { rhs, .. } => rhs.type_value(),
            Expr::Ident { symbol, .. } => symbol.type_value().clone(),
            Expr::FnCall(fn_call) => fn_call.type_value.clone(),
        }
    }
}
