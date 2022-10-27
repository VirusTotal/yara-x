/*! Compiles YARA source code into binary form.

YARA rules must be compiled before they can be used for scanning data. This
module implements the YARA compiler.
*/
use bstr::ByteSlice;
use std::fmt;
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;

use crate::parser::Error as ParserError;
use crate::parser::{
    arithmetic_op, bitwise_not, bitwise_op, boolean_not, boolean_op,
    comparison_op, minus_op, shift_op, string_op, Expr, HasSpan, Iterable,
    MatchAnchor, OfItems, Parser, Quantifier, Range, SourceCode, Span, Type,
    TypeHint,
};
use crate::report::ReportBuilder;
use crate::{Struct, Value, Variable};

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
            let type_hint = expr_semantic_check($ctx, $expr)?;
            if !matches!(type_hint.ty(), $( $pattern )|+) {
                return Err(Error::CompileError(CompileError::wrong_type(
                    $ctx.report_builder,
                    $ctx.src,
                    ParserError::join_with_or(&[ $( $pattern ),+ ], true),
                    type_hint.ty().to_string(),
                    span,
                )));
            }
            Ok::<TypeHint, Error>(type_hint)
        }
    };
}

/// A YARA compiler.
pub struct Compiler<'a> {
    colorize_errors: bool,
    report_builder: ReportBuilder,
    sym_tbl: Struct<'a>,
}

impl fmt::Debug for Compiler<'_> {
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
            sym_tbl: Struct::new(),
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

    pub fn define(&mut self, ident: &'a str) -> &mut Self {
        let var = Variable { ty: Type::Integer, value: Value::Integer(1) };
        self.sym_tbl.insert(ident, var);
        self
    }

    /*pub fn define_str(&mut self, ident: &'a str, s: &'a BStr) -> &mut Self {
        let sym = Symbol::Variable(Variable {
            ty: Type::String,
            value: Value::String(s),
        });
        self.sym_tbl.insert(ident, sym);
        self
    }*/

    /// Adds a YARA source code to be compiled.
    ///
    /// This function can be called multiple times.
    pub fn add(&mut self, src: &str) -> Result<&mut Self, Error> {
        let mut ast = Parser::new()
            .colorize_errors(self.colorize_errors)
            .set_report_builder(&self.report_builder)
            .build_ast(src, None)?;

        let src = SourceCode { text: src, origin: None };

        let mut ctx = Context {
            sym_tbl: &self.sym_tbl,
            report_builder: &self.report_builder,
            src: &src,
        };

        for ns in ast.namespaces.values_mut() {
            for module_name in ns.imports.iter() {
                // insert module_name in arena.
            }

            let ctx_ref = &mut ctx;
            for rule in ns.rules.values_mut() {
                // Check that the condition is boolean expression. This traverses
                // the condition's AST recursively checking the semantic validity
                // of all AST nodes.
                check_expression!(ctx_ref, Type::Bool, &mut rule.condition)?;
            }
        }

        Ok(self)
    }
}

macro_rules! check_operands {
    ($ctx:ident, $( $pattern:path )|+, $expr1:expr, $expr2:expr) => {{
        let span1 = $expr1.span();
        let span2 = $expr2.span();

        let type_hint1 = check_expression!($ctx, $( $pattern )|+, $expr1)?;
        let type_hint2 = check_expression!($ctx, $( $pattern )|+, $expr2)?;

        // Both types must be known.
        assert!(!matches!(type_hint1, TypeHint::UnknownType));
        assert!(!matches!(type_hint2, TypeHint::UnknownType));

        let mismatching_types = match type_hint1 {
            // Float and Integer are compatible types, operators can
            // have different operand types where one is Integer and
            // the other is Float.
            TypeHint::Integer(_) | TypeHint::Float(_) => {
                !matches!(type_hint1, TypeHint::Integer(_) | TypeHint::Float(_))
            }
            // In all other cases types must be equal to be considered
            // compatible. In this comparison the optional values in the
            // hint are not taken into account.
            _ => type_hint1.ty() != type_hint2.ty(),
        };

        if mismatching_types {
            return Err(Error::CompileError(CompileError::mismatching_types(
                $ctx.report_builder,
                $ctx.src,
                type_hint1.ty().to_string(),
                type_hint2.ty().to_string(),
                span1,
                span2,
            )));
        }

        Ok::<_, Error>((type_hint1, type_hint2))
    }};
}

macro_rules! check_non_negative_integer {
    ($ctx:ident, $expr:expr) => {{
        let span = $expr.span();
        let type_hint = check_expression!($ctx, Type::Integer, $expr)?;
        if let TypeHint::Integer(Some(value)) = type_hint {
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
        Ok::<_, Error>(type_hint)
    }};
}

macro_rules! check_integer_in_range {
    ($ctx:ident, $expr:expr, $min:expr, $max:expr) => {{
        let span = $expr.span();
        let type_hint = check_expression!($ctx, Type::Integer, $expr)?;
        if let TypeHint::Integer(Some(value)) = type_hint {
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
        Ok::<_, Error>(type_hint)
    }};
}

macro_rules! check_boolean_op {
    ($ctx:ident, $expr:expr, $op:tt) => {{
        let (lhs, rhs) =
            check_operands!($ctx, Type::Bool, &mut $expr.lhs, &mut $expr.rhs)?;

        $expr.type_hint = boolean_op!(lhs, $op, rhs);

        Ok($expr.type_hint.clone())
    }};
}

macro_rules! check_comparison_op {
    ($ctx:ident, $expr:expr, $op:tt) => {{
        let (lhs, rhs) = check_operands!(
            $ctx,
            Type::Integer | Type::Float | Type::String,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        $expr.type_hint = comparison_op!(lhs, $op, rhs);

        Ok($expr.type_hint.clone())
    }};
}

macro_rules! check_shift_op {
    ($ctx:ident, $expr:expr, $op:ident) => {{
        let span = $expr.rhs.span();
        let (lhs, rhs) = check_operands!(
            $ctx,
            Type::Integer,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        if let TypeHint::Integer(Some(value)) = rhs {
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

        $expr.type_hint = shift_op!(lhs, $op, rhs);

        Ok($expr.type_hint.clone())
    }};
}

macro_rules! check_bitwise_op {
    ($ctx:ident, $expr:expr, $op:ident) => {{
        let (lhs, rhs) = check_operands!(
            $ctx,
            Type::Integer,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        $expr.type_hint = bitwise_op!(lhs, $op, rhs);

        Ok($expr.type_hint.clone())
    }};
}

macro_rules! check_arithmetic_op {
    ($ctx:ident, $expr:expr, $op:tt, $checked_op:ident) => {{
        let (lhs, rhs) = check_operands!(
            $ctx,
            Type::Integer | Type::Float,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        $expr.type_hint = arithmetic_op!(lhs, $op, $checked_op, rhs);

        Ok($expr.type_hint.clone())
    }};
}

macro_rules! check_string_op {
    ($ctx:ident, $expr:expr, $op:ident, $case_insensitive:expr) => {{
        let (lhs, rhs) = check_operands!(
            $ctx,
            Type::String,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        $expr.type_hint = string_op!(lhs, $op, rhs, $case_insensitive);

        Ok($expr.type_hint.clone())
    }};
}

/// Structure that contains information about the current compilation process.
struct Context<'a> {
    sym_tbl: &'a Struct<'a>,
    report_builder: &'a ReportBuilder,
    src: &'a SourceCode<'a>,
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
/// It also updates type hints for the expression and its sub-expressions
/// in the AST. The AST returned by the parser may have type and value
/// information for some expressions that depend only on literals, but that
/// information is unknown for expressions that depend on external variables
/// and identifiers defined by modules. However, at compile time we have a
/// symbol table that contains type information for all identifiers, so the
/// AST can be updated with the missing information.
fn expr_semantic_check<'a>(
    ctx: &mut Context<'a>,
    expr: &'a mut Expr<'a>,
) -> Result<TypeHint, Error> {
    match expr {
        Expr::True { .. }
        | Expr::False { .. }
        | Expr::Filesize { .. }
        | Expr::Entrypoint { .. }
        | Expr::LiteralFlt(_)
        | Expr::LiteralInt(_)
        | Expr::LiteralStr(_) => Ok(expr.type_hint()),

        Expr::PatternCount(p) => {
            if let Some(ref mut range) = p.range {
                range_semantic_check(ctx, range)?;
            }
            Ok(TypeHint::Integer(None))
        }

        Expr::PatternOffset(p) | Expr::PatternLength(p) => {
            // In expressions like @a[i] and !a[i] the index i must
            // be an integer >= 1.
            if let Some(ref mut index) = p.index {
                check_integer_in_range!(ctx, index, 1, i64::MAX)?;
            }
            Ok(TypeHint::Integer(None))
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
            Ok(TypeHint::Bool(None))
        }

        Expr::Not(expr) => {
            let type_hint =
                check_expression!(ctx, Type::Bool, &mut expr.operand)?;

            expr.type_hint = boolean_not!(type_hint);

            Ok(expr.type_hint.clone())
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
            let type_hint =
                check_expression!(ctx, Type::Integer, &mut expr.operand)?;

            expr.type_hint = bitwise_not!(type_hint);

            Ok(expr.type_hint.clone())
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
            let type_hint = check_expression!(
                ctx,
                Type::Integer | Type::Float,
                &mut expr.operand
            )?;

            expr.type_hint = minus_op!(type_hint);

            Ok(expr.type_hint.clone())
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
            ident.type_hint =
                if let Some(var) = ctx.sym_tbl.get_field(ident.name) {
                    todo!()
                } else {
                    return Err(Error::CompileError(
                        CompileError::unknown_identifier(
                            ctx.report_builder,
                            ctx.src,
                            ident.name.to_string(),
                            ident.span(),
                        ),
                    ));
                };

            Ok(ident.type_hint.clone())
        }

        Expr::LookupIndex(_) => {
            todo!()
        }
        Expr::FieldAccess(expr) => {
            // The left side must be a struct.
            let type_hint =
                check_expression!(ctx, Type::Struct, &mut expr.lhs)?;

            // Save the current symbol table
            //let saved_sym_tbl = ctx.sym_tbl;

            // Set the symbol table obtained from the struct as the current one.
            //ctx.sym_tbl = value.as_struct();

            // Now check the right hand expression. During the call to
            // expr_semantic_check the current symbol table is the one
            // corresponding to the struct.
            expr.type_hint = expr_semantic_check(ctx, &mut expr.rhs)?;

            // Go back to the original symbol table.
            //ctx.sym_tbl = saved_sym_tbl;

            Ok(expr.type_hint.clone())
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
            Ok(TypeHint::Bool(None))
        }

        Expr::ForOf(for_of) => {
            quantifier_semantic_check(ctx, &mut for_of.quantifier)?;
            check_expression!(ctx, Type::Bool, &mut for_of.condition)?;
            Ok(TypeHint::Bool(None))
        }

        Expr::ForIn(for_in) => {
            quantifier_semantic_check(ctx, &mut for_in.quantifier)?;
            iterable_semantic_check(ctx, &mut for_in.iterable)?;

            /*for variable in &for_in.variables {
                ctx.sym_tbl.insert(
                    variable.name,
                    Symbol::Variable(Variable {
                        ty: variable.ty.clone(),
                        value: Value::Unknown,
                    }),
                );
            }*/

            check_expression!(ctx, Type::Bool, &mut for_in.condition)?;
            Ok(TypeHint::Bool(None))
        }
    }
}

fn range_semantic_check<'a>(
    ctx: &mut Context<'a>,
    range: &'a mut Range<'a>,
) -> Result<(), Error> {
    check_expression!(ctx, Type::Integer, &mut range.lower_bound)?;
    check_expression!(ctx, Type::Integer, &mut range.upper_bound)?;
    Ok(())
}

fn quantifier_semantic_check<'a>(
    ctx: &mut Context<'a>,
    quantifier: &'a mut Quantifier<'a>,
) -> Result<TypeHint, Error> {
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
    Ok(TypeHint::Integer(None))
}

fn iterable_semantic_check<'a>(
    ctx: &mut Context<'a>,
    iterable: &'a mut Iterable<'a>,
) -> Result<TypeHint, Error> {
    match iterable {
        Iterable::Range(range) => {
            range_semantic_check(ctx, range)?;
            Ok(TypeHint::Integer(None))
        }
        Iterable::ExprTuple(tuple) => {
            let mut prev: Option<(TypeHint, Span)> = None;
            // Make sure that all expressions in the tuple have the same
            // type and that type is acceptable.
            for expr in tuple.iter_mut() {
                let span = expr.span();
                let type_hint = check_expression!(
                    ctx,
                    Type::Integer | Type::Float | Type::String | Type::Bool,
                    expr
                )?;
                if let Some((prev_type_hint, prev_span)) = prev {
                    let prev_ty = prev_type_hint.ty();
                    let ty = type_hint.ty();
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
                prev = Some((type_hint, span));
            }

            // Get the type of the last item in the tuple.
            let (type_hint, _) = prev.unwrap();
            Ok(type_hint)
        }
        Iterable::Ident(_) => {
            todo!()
        }
    }
}
