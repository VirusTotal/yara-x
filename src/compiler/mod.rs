/*! Compiles YARA source code into binary form.

YARA rules must be compiled before they can be used for scanning data. This
module implements the YARA compiler.
*/
use bstr::ByteSlice;
use std::cell::RefCell;
use std::fmt;
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;

use crate::parser::{
    arithmetic_op, bitwise_not, bitwise_op, boolean_not, boolean_op,
    comparison_op, minus_op, shift_op, string_op, OfItems, Span,
};
use crate::parser::{Error as ParserError, Range};
use crate::parser::{
    Expr, HasSpan, Iterable, MatchAnchor, Parser, Quantifier, SourceCode,
};
use crate::report::ReportBuilder;
use crate::{Symbol, SymbolTable, Type, Value};

#[doc(inline)]
pub use crate::compiler::errors::*;

mod errors;

#[cfg(test)]
mod tests;

macro_rules! check_expression {
    ($ctx:expr, $( $pattern:path )|+, $expr:expr) => {
        {
            use crate::compiler::errors::Error;
            let span = $expr.span();
            let (ty, val) = expr_semantic_check($ctx, $expr)?;
            if !matches!(ty, $( $pattern )|+) {
                return Err(Error::CompileError(CompileError::wrong_type(
                    $ctx.report_builder,
                    $ctx.src,
                    ParserError::join_with_or(&[ $( $pattern.to_string() ),+ ], true),
                    ty.to_string(),
                    span,
                )));
            }
            Ok::<(Type, Value), Error>((ty, val))
        }
    };
}

/// A YARA compiler.
pub struct Compiler<'a> {
    colorize_errors: bool,
    report_builder: ReportBuilder,
    sym_tbl: SymbolTable<'a>,
}

impl<'a> fmt::Debug for Compiler<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Compiler")
    }
}

impl<'a> Compiler<'a> {
    /// Creates a new YARA compiler.
    pub fn new() -> Self {
        Self {
            colorize_errors: false,
            report_builder: ReportBuilder::new(),
            sym_tbl: SymbolTable::new(),
        }
    }

    /// Specifies whether the compiler should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn colorize_errors(&mut self, b: bool) -> &mut Self {
        self.colorize_errors = b;
        self
    }

    /// Adds a YARA source code to be compiled.
    ///
    /// This function can be called multiple times.
    pub fn add(&'a mut self, src: &'a str) -> Result<&mut Self, Error> {
        let mut ast = Parser::new()
            .colorize_errors(self.colorize_errors)
            .set_report_builder(&self.report_builder)
            .build_ast(src, None)?;

        let src = SourceCode { text: src, origin: None };

        let ctx = Context {
            sym_tbl: RefCell::new(&self.sym_tbl),
            report_builder: &self.report_builder,
            src: &src,
        };

        for ns in ast.namespaces.values_mut() {
            for rule in ns.rules.values_mut() {
                // Check that the condition is boolean expression. This traverses
                // the condition's AST recursively checking the semantic validity
                // of all AST nodes.
                check_expression!(&ctx, Type::Bool, &mut rule.condition)?;
            }
        }

        Ok(self)
    }
}

macro_rules! check_operands {
    ($ctx:ident, $( $pattern:path )|+, $expr1:expr, $expr2:expr) => {{
        let span1 = $expr1.span();
        let span2 = $expr2.span();
        let (ty1, value1) = check_expression!($ctx, $( $pattern )|+, $expr1)?;
        let (ty2, value2) = check_expression!($ctx, $( $pattern )|+, $expr2)?;

        // Both types must be known.
        assert!(!matches!(ty1, Type::Unknown));
        assert!(!matches!(ty2, Type::Unknown));

        let mismatching_types = match ty1 {
            // Float and Integer are compatible types, operators can
            // have different operand types where one is Integer and
            // the other is Float.
            Type::Integer | Type::Float => {
                !matches!(ty2, Type::Integer | Type::Float)
            }
            // In all other cases types must be equal to be considered
            // compatible.
            _ => ty1 != ty2,
        };

        if mismatching_types {
            return Err(Error::CompileError(CompileError::mismatching_types(
                $ctx.report_builder,
                $ctx.src,
                ty1.to_string(),
                ty2.to_string(),
                span1,
                span2,
            )));
        }

        Ok::<_, Error>(((ty1, value1), (ty2, value2)))
    }};
}

macro_rules! check_non_negative_integer {
    ($ctx:ident, $expr:expr) => {{
        let span = $expr.span();
        let (ty, value) = check_expression!($ctx, Type::Integer, $expr)?;
        if let Value::Integer(value) = value {
            if value < 0 {
                return Err(Error::CompileError(
                    CompileError::unexpected_negative_number(
                        $ctx.report_builder,
                        $ctx.src,
                        span,
                    ),
                ));
            }
        } else {
            unreachable!();
        };
        Ok::<_, Error>((ty, value))
    }};
}

macro_rules! check_integer_in_range {
    ($ctx:ident, $expr:expr, $min:expr, $max:expr) => {{
        let span = $expr.span();
        let (ty, value) = check_expression!($ctx, Type::Integer, $expr)?;
        if let Value::Integer(value) = value {
            if !($min..=$max).contains(&value) {
                return Err(Error::CompileError(
                    CompileError::number_out_of_range(
                        $ctx.report_builder,
                        $ctx.src,
                        $min,
                        $max,
                        span,
                    ),
                ));
            }
        } else {
            unreachable!();
        };
        Ok::<_, Error>((ty, value))
    }};
}

macro_rules! check_boolean_op {
    ($ctx:ident, $expr:ident, $op:tt) => {{
        let ((_, lhs_value), (_, rhs_value)) =
            check_operands!($ctx, Type::Bool, &mut $expr.lhs, &mut $expr.rhs)?;

        ($expr.ty, $expr.value) = boolean_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_comparison_op {
    ($ctx:ident, $expr:ident, $op:tt) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $ctx,
            Type::Integer | Type::Float | Type::String,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) = comparison_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_shift_op {
    ($ctx:ident, $expr:ident, $op:ident) => {{
        let span = $expr.rhs.span();
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $ctx,
            Type::Integer,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        if let Value::Integer(value) = rhs_value {
            if value < 0 {
                return Err(Error::CompileError(
                    CompileError::unexpected_negative_number(
                        $ctx.report_builder,
                        $ctx.src,
                        span,
                    ),
                ));
            }
        } else {
            unreachable!();
        };

        ($expr.ty, $expr.value) = shift_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_bitwise_op {
    ($ctx:ident, $expr:ident, $op:ident) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $ctx,
            Type::Integer,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) = bitwise_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_arithmetic_op {
    ($ctx:ident, $expr:ident, $op:tt, $checked_op:ident) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $ctx,
            Type::Integer | Type::Float,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) =
            arithmetic_op!(lhs_value, $op, $checked_op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_string_op {
    ($ctx:ident, $expr:ident, $op:ident, $case_insensitive:expr) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $ctx,
            Type::String,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) =
            string_op!(lhs_value, $op, rhs_value, $case_insensitive);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

/// Makes sure that an expression is semantically valid.
///
/// This functions traverses the AST and makes sure that the expression
/// and all its sub-expressions are semantically correct. It makes sure
/// that...
///
/// * Operands have the correct types, for example, boolean operations
///   can't have operands of type string, arithmetic operations must
///   have integer or float operands, bitwise operations accept only
///   integers, and so on.
/// * Array indexes are non-negative integers.
/// * Dictionary keys have the correct type.
/// * Operands in bitwise operations are non-negative integers.
/// * Range bounds are non-negative integers and upper bound is greater
///   than lower bound.
/// * All identifiers have been previously defined.
///
/// It also updates type and value annotations for the expression and
/// its sub-expressions in the AST. The AST returned by the parser may
/// have type and value information for some expressions that depend only
/// on literals, but that information is unknown for expressions that
/// depend on external variables and identifiers defined by modules.
/// However, at compile time we have a symbol table that contains type
/// information for all identifiers, so the AST can be updated with the
/// missing information.
fn expr_semantic_check<'a>(
    ctx: &'a Context<'a>,
    expr: &'a mut Expr<'a>,
) -> Result<(Type, Value<'a>), Error> {
    match expr {
        Expr::True { .. }
        | Expr::False { .. }
        | Expr::Filesize { .. }
        | Expr::Entrypoint { .. }
        | Expr::LiteralFlt(_)
        | Expr::LiteralInt(_)
        | Expr::LiteralStr(_) => Ok(expr.type_value()),

        Expr::PatternCount(p) => {
            if let Some(ref mut range) = p.range {
                range_semantic_check(ctx, range)?;
            }
            Ok((Type::Integer, Value::Unknown))
        }

        Expr::PatternOffset(p) | Expr::PatternLength(p) => {
            // In expressions like @a[i] and !a[i] the index i must
            // be an integer >= 1.
            if let Some(ref mut index) = p.index {
                check_integer_in_range!(ctx, index, 1, i64::MAX)?;
            }
            Ok((Type::Integer, Value::Unknown))
        }

        Expr::PatternMatch(p) => {
            match &mut p.anchor {
                Some(MatchAnchor::In(ref mut anchor_in)) => {
                    range_semantic_check(ctx, &mut anchor_in.range)?;
                }
                Some(MatchAnchor::At(anchor_at)) => {
                    check_non_negative_integer!(ctx, &mut anchor_at.expr)?;
                }
                None => {}
            }
            Ok((Type::Bool, Value::Unknown))
        }

        Expr::Not(expr) => {
            let (_, value) =
                check_expression!(ctx, Type::Bool, &mut expr.operand)?;

            (expr.ty, expr.value) = boolean_not!(value);

            Ok((expr.ty.clone(), expr.value.clone()))
        }

        Expr::And(expr) => {
            check_boolean_op!(ctx, expr, &&)
        }

        Expr::Or(expr) => {
            check_boolean_op!(ctx, expr, ||)
        }

        Expr::Eq(expr) => {
            check_comparison_op!(ctx, expr, ==)
        }

        Expr::Neq(expr) => {
            check_comparison_op!(ctx, expr, !=)
        }

        Expr::Lt(expr) => {
            check_comparison_op!(ctx, expr, <)
        }

        Expr::Le(expr) => {
            check_comparison_op!(ctx, expr, <=)
        }

        Expr::Gt(expr) => {
            check_comparison_op!(ctx, expr, >)
        }

        Expr::Ge(expr) => {
            check_comparison_op!(ctx, expr, >=)
        }

        Expr::Shl(expr) => {
            check_shift_op!(ctx, expr, overflowing_shl)
        }

        Expr::Shr(expr) => {
            check_shift_op!(ctx, expr, overflowing_shr)
        }

        Expr::BitwiseNot(expr) => {
            let (_, value) =
                check_expression!(ctx, Type::Integer, &mut expr.operand)?;

            (expr.ty, expr.value) = bitwise_not!(value);

            Ok((expr.ty.clone(), expr.value.clone()))
        }

        Expr::BitwiseAnd(expr) => {
            check_bitwise_op!(ctx, expr, bitand)
        }

        Expr::BitwiseOr(expr) => {
            check_bitwise_op!(ctx, expr, bitor)
        }

        Expr::BitwiseXor(expr) => {
            check_bitwise_op!(ctx, expr, bitxor)
        }

        Expr::Minus(expr) => {
            let (ty, value) = check_expression!(
                ctx,
                Type::Integer | Type::Float,
                &mut expr.operand
            )?;

            (expr.ty, expr.value) = minus_op!(value);

            Ok((expr.ty.clone(), expr.value.clone()))
        }

        Expr::Add(expr) => {
            check_arithmetic_op!(ctx, expr, +, checked_add)
        }

        Expr::Sub(expr) => {
            check_arithmetic_op!(ctx, expr, -, checked_sub)
        }

        Expr::Mul(expr) => {
            check_arithmetic_op!(ctx, expr, *, checked_mul)
        }

        Expr::Div(expr) => {
            check_arithmetic_op!(ctx, expr, /, checked_div)
        }

        Expr::Modulus(expr) => {
            check_arithmetic_op!(ctx, expr, %, checked_rem)
        }

        Expr::Contains(expr) => {
            check_string_op!(ctx, expr, contains_str, false)
        }

        Expr::IContains(expr) => {
            check_string_op!(ctx, expr, contains_str, true)
        }

        Expr::StartsWith(expr) => {
            check_string_op!(ctx, expr, starts_with, false)
        }

        Expr::IStartsWith(expr) => {
            check_string_op!(ctx, expr, starts_with, true)
        }

        Expr::EndsWith(expr) => {
            check_string_op!(ctx, expr, ends_with, false)
        }

        Expr::IEndsWith(expr) => {
            check_string_op!(ctx, expr, ends_with, true)
        }

        Expr::IEquals(expr) => {
            check_string_op!(ctx, expr, eq, true)
        }

        Expr::Ident(ident) => {
            let (ty, value) =
                if let Some(sym) = ctx.sym_tbl.borrow().lookup(ident.name) {
                    match sym {
                        Symbol::Struct(table) => {
                            (Type::Struct, Value::Struct(table))
                        }
                        Symbol::Variable(var) => {
                            (var.ty.clone(), var.value.clone())
                        }
                    }
                } else {
                    // identifier not found
                    todo!()
                };

            Ok((ty, value))
        }

        Expr::LookupIndex(_) => {
            todo!()
        }
        Expr::FieldAccess(expr) => {
            // The left side must be a struct.
            let (_, value) =
                check_expression!(ctx, Type::Struct, &mut expr.lhs)?;

            // Replace the current symbol table with the one obtained from the
            // struct. The current table is saved and restored later.
            let saved_sym_tbl = ctx.sym_tbl.replace(value.as_struct());

            // Now check the right hand expression. Notice that during call to
            // expr_semantic_check, the current symbol table is the one corresponding
            // to the struct.
            (expr.ty, expr.value) = expr_semantic_check(ctx, &mut expr.rhs)?;

            // Restore the symbol table back.
            ctx.sym_tbl.replace(saved_sym_tbl);

            dbg!(&expr.value);

            Ok((expr.ty.clone(), expr.value.clone()))
        }
        Expr::FnCall(_) => {
            todo!()
        }

        Expr::Of(of) => {
            quantifier_semantic_check(ctx, &mut of.quantifier)?;

            if let OfItems::BoolExprTuple(exprs) = &mut of.items {
                for expr in exprs.iter_mut() {
                    check_expression!(ctx, Type::Bool, expr)?;
                }
            }

            match &mut of.anchor {
                Some(MatchAnchor::In(anchor_in)) => {
                    range_semantic_check(ctx, &mut anchor_in.range)?;
                }
                Some(MatchAnchor::At(anchor_at)) => {
                    check_non_negative_integer!(ctx, &mut anchor_at.expr)?;
                }
                None => {}
            }
            Ok((Type::Bool, Value::Unknown))
        }

        Expr::ForOf(for_of) => {
            quantifier_semantic_check(ctx, &mut for_of.quantifier)?;
            check_expression!(ctx, Type::Bool, &mut for_of.condition)?;
            Ok((Type::Bool, Value::Unknown))
        }

        Expr::ForIn(for_in) => {
            quantifier_semantic_check(ctx, &mut for_in.quantifier)?;
            iterable_semantic_check(ctx, &mut for_in.iterable)?;
            check_expression!(ctx, Type::Bool, &mut for_in.condition)?;
            Ok((Type::Bool, Value::Unknown))
        }
    }
}

fn range_semantic_check<'a>(
    ctx: &'a Context<'a>,
    range: &'a mut Range<'a>,
) -> Result<(), Error> {
    check_expression!(ctx, Type::Integer, &mut range.lower_bound)?;
    check_expression!(ctx, Type::Integer, &mut range.upper_bound)?;
    Ok(())
}

fn quantifier_semantic_check<'a>(
    ctx: &'a Context<'a>,
    quantifier: &'a mut Quantifier<'a>,
) -> Result<Type, Error> {
    match quantifier {
        Quantifier::Expr(expr) => {
            check_non_negative_integer!(ctx, expr)?;
        }
        Quantifier::Percentage(expr) => {
            // Percentage should be in the range 0-100%
            check_integer_in_range!(ctx, expr, 0, 100)?;
        }
        _ => {}
    };
    Ok(Type::Integer)
}

fn iterable_semantic_check<'a>(
    ctx: &'a Context<'a>,
    iterable: &'a mut Iterable<'a>,
) -> Result<Type, Error> {
    match iterable {
        Iterable::Range(range) => {
            range_semantic_check(ctx, range)?;
            Ok(Type::Iterable(Box::new(Type::Integer)))
        }
        Iterable::ExprTuple(tuple) => {
            let mut prev: Option<(Type, Span)> = None;
            // Make sure that all expressions in the tuple have the same
            // type and that type is acceptable.
            for expr in tuple.iter_mut() {
                let span = expr.span();
                let (ty, _) = check_expression!(
                    ctx,
                    Type::Integer | Type::Float | Type::String | Type::Bool,
                    expr
                )?;
                if let Some((prev_ty, prev_span)) = prev {
                    if prev_ty != ty {
                        return Err(Error::CompileError(
                            CompileError::mismatching_types(
                                ctx.report_builder,
                                ctx.src,
                                prev_ty.to_string(),
                                ty.to_string(),
                                prev_span,
                                span,
                            ),
                        ));
                    }
                }
                prev = Some((ty, span));
            }

            // Get the type of the last item in the tuple.
            let (ty, _) = prev.unwrap();

            // If last item is of type X, the iterable's type is
            // Iterable(X).
            Ok(Type::Iterable(Box::new(ty)))
        }
        Iterable::Ident(_) => {
            todo!()
        }
    }
}

struct Context<'a> {
    sym_tbl: RefCell<&'a SymbolTable<'a>>,
    report_builder: &'a ReportBuilder,
    src: &'a SourceCode<'a>,
}
