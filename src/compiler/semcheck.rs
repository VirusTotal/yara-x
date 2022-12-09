use std::rc::Rc;

use crate::ast::*;
use crate::compiler::{CompileError, Context, Error, ParserError};
use crate::symbols::{Symbol, SymbolLookup, SymbolTable, SymbolValue};
use crate::types::{Type, Value};
use crate::warnings::Warning;

macro_rules! semcheck {
    ($ctx:expr, $( $accepted_types:path )|+, $expr:expr) => {
        {
            use crate::types::Type;
            use crate::compiler::errors::Error;
            use crate::compiler::semcheck::semcheck_expr;
            let span = (&*$expr).span();
            let ty = semcheck_expr($ctx, $expr)?;
            if !matches!(ty, $( $accepted_types )|+) {
                return Err(Error::CompileError(CompileError::wrong_type(
                    $ctx.report_builder,
                    $ctx.src,
                    ParserError::join_with_or(&[ $( $accepted_types ),+ ], true),
                    ty.to_string(),
                    span,
                )));
            }
            Ok::<Type, Error>(ty)
        }
    };
}

pub(crate) use semcheck;

macro_rules! semcheck_operands {
    ($ctx:ident, $expr1:expr, $expr2:expr, $( $accepted_types:path )|+, $compatible_types:expr) => {{
        let span1 = (&*$expr1).span();
        let span2 = (&*$expr2).span();

        let ty1 = semcheck!($ctx, $( $accepted_types )|+, $expr1)?;
        let ty2 = semcheck!($ctx, $( $accepted_types )|+, $expr2)?;

        // Both types must be known.
        assert!(!matches!(ty1, Type::Unknown));
        assert!(!matches!(ty2, Type::Unknown));

        let types_are_compatible = {
            // If the types are the same, they are compatible.
            (ty1 == ty2) ||
            (
                // If both types are in the list of compatible types,
                // they are compatible too.
                $compatible_types.iter().any(|&ty: &Type| ty == ty1)
                && $compatible_types.iter().any(|&ty: &Type| ty == ty2)
            )
        };

        if !types_are_compatible {
            return Err(Error::CompileError(CompileError::mismatching_types(
                $ctx.report_builder,
                $ctx.src,
                ty1.to_string(),
                ty2.to_string(),
                span1,
                span2,
            )));
        }

        Ok::<_, Error>((ty1, ty2))
    }};
}

macro_rules! check_non_negative_integer {
    ($ctx:ident, $expr:expr) => {{
        let ty = semcheck!($ctx, Type::Integer, $expr)?;
        let span = (&*$expr).span();
        let value = (&*$expr).value();
        if let Value::Integer(value) = *value {
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
        Ok::<_, Error>(ty)
    }};
}

macro_rules! check_integer_in_range {
    ($ctx:ident, $expr:expr, $min:expr, $max:expr) => {{
        let ty = semcheck!($ctx, Type::Integer, $expr)?;
        let span = (&*$expr).span();
        let value = (&*$expr).value();
        if let Value::Integer(value) = *value {
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
        Ok::<_, Error>(ty)
    }};
}

macro_rules! gen_semcheck_boolean_op {
    ($name:ident, $op:tt) => {
        fn $name(
            ctx: &mut Context,
            expr: &mut Box<BinaryExpr>,
        ) -> Result<Type, Error> {
            warning_if_not_boolean(ctx, &expr.lhs);
            warning_if_not_boolean(ctx, &expr.rhs);

            let (lhs_ty, rhs_ty) = semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                // Boolean operations accept integer, float and string operands.
                // If operands are not boolean they are casted to boolean.
                Type::Bool | Type::Integer | Type::Float | Type::String,
                // All operands types can mixed in a boolean operation, as they
                // are casted to boolean.
                &[Type::Bool, Type::Integer, Type::Float, Type::String]
            )?;

            let ty = lhs_ty.$op(rhs_ty);
            let value = expr.lhs.value().$op(expr.rhs.value());

            expr.set_type_and_value(ty, value);
            Ok(expr.ty())
        }
    };
}

gen_semcheck_boolean_op!(semcheck_boolean_and, and);
gen_semcheck_boolean_op!(semcheck_boolean_or, or);

macro_rules! gen_semcheck_comparison_op {
    ($name:ident, $op:tt) => {
        fn $name(
            ctx: &mut Context,
            expr: &mut Box<BinaryExpr>,
        ) -> Result<Type, Error> {
            let (lhs_ty, rhs_ty) = semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                // Integers, floats and strings can be compared.
                Type::Integer | Type::Float | Type::String,
                // Integers can be compared with floats, but string can be
                // compared only with another string.
                &[Type::Integer, Type::Float]
            )?;

            let ty = lhs_ty.$op(rhs_ty);
            let value = expr.lhs.value().$op(expr.rhs.value());

            expr.set_type_and_value(ty, value);
            Ok(expr.ty())
        }
    };
}

gen_semcheck_comparison_op!(semcheck_comparison_eq, eq);
gen_semcheck_comparison_op!(semcheck_comparison_ne, ne);
gen_semcheck_comparison_op!(semcheck_comparison_gt, gt);
gen_semcheck_comparison_op!(semcheck_comparison_lt, lt);
gen_semcheck_comparison_op!(semcheck_comparison_ge, ge);
gen_semcheck_comparison_op!(semcheck_comparison_le, le);

macro_rules! gen_semcheck_shift_op {
    ($name:ident, $op:tt) => {
        fn $name(
            ctx: &mut Context,
            expr: &mut Box<BinaryExpr>,
        ) -> Result<Type, Error> {
            let span = expr.rhs.span();

            let (lhs_ty, rhs_ty) = semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                Type::Integer,
                &[]
            )?;

            if let Value::Integer(value) = *expr.rhs.value() {
                if value < 0 {
                    return Err(Error::CompileError(
                        CompileError::unexpected_negative_number(
                            ctx.report_builder,
                            ctx.src,
                            span,
                        ),
                    ));
                }
            } else {
                unreachable!();
            };

            let ty = lhs_ty.$op(rhs_ty);
            let value = expr.lhs.value().$op(expr.rhs.value());

            expr.set_type_and_value(ty, value);
            Ok(expr.ty())
        }
    };
}

gen_semcheck_shift_op!(semcheck_shl, shl);
gen_semcheck_shift_op!(semcheck_shr, shr);

macro_rules! gen_semcheck_bitwise_op {
    ($name:ident, $op:ident) => {
        fn $name(
            ctx: &mut Context,
            expr: &mut Box<BinaryExpr>,
        ) -> Result<Type, Error> {
            let (lhs_ty, rhs_ty) = semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                Type::Integer,
                &[]
            )?;

            let ty = lhs_ty.$op(rhs_ty);
            let value = expr.lhs.value().$op(expr.rhs.value());

            expr.set_type_and_value(ty, value);
            Ok(expr.ty())
        }
    };
}

gen_semcheck_bitwise_op!(semcheck_bitwise_and, bitwise_and);
gen_semcheck_bitwise_op!(semcheck_bitwise_or, bitwise_or);
gen_semcheck_bitwise_op!(semcheck_bitwise_xor, bitwise_xor);

macro_rules! gen_semcheck_string_op {
    ($name:ident, $op:ident) => {
        fn $name(
            ctx: &mut Context,
            expr: &mut Box<BinaryExpr>,
            case_insensitive: bool,
        ) -> Result<Type, Error> {
            let (lhs_ty, rhs_ty) = semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                Type::String,
                &[]
            )?;

            let ty = lhs_ty.$op(rhs_ty);
            let value =
                expr.lhs.value().$op(expr.rhs.value(), case_insensitive);

            expr.set_type_and_value(ty, value);
            Ok(expr.ty())
        }
    };
}

gen_semcheck_string_op!(semcheck_string_contains, contains_str);
gen_semcheck_string_op!(semcheck_string_startswith, starts_with_str);
gen_semcheck_string_op!(semcheck_string_endswith, ends_with_str);
gen_semcheck_string_op!(semcheck_string_equals, equals_str);

macro_rules! gen_semcheck_arithmetic_op {
    ($name:ident, $op:tt, $( $accepted_types:path )|+) => {
        fn $name(
            ctx: &mut Context,
            expr: &mut Box<BinaryExpr>,
        ) -> Result<Type, Error> {
             let (lhs_ty, rhs_ty) = semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                $( $accepted_types )|+,
                &[Type::Integer, Type::Float]
            )?;

            let ty = lhs_ty.$op(rhs_ty);
            let value = expr.lhs.value().$op(expr.rhs.value());

            expr.set_type_and_value(ty, value);
            Ok(expr.ty())
        }
    };
}

gen_semcheck_arithmetic_op!(
    semcheck_arithmetic_add,
    add,
    Type::Integer | Type::Float
);

gen_semcheck_arithmetic_op!(
    semcheck_arithmetic_sub,
    sub,
    Type::Integer | Type::Float
);

gen_semcheck_arithmetic_op!(
    semcheck_arithmetic_mul,
    mul,
    Type::Integer | Type::Float
);

gen_semcheck_arithmetic_op!(
    semcheck_arithmetic_div,
    div,
    Type::Integer | Type::Float
);

gen_semcheck_arithmetic_op!(semcheck_arithmetic_rem, rem, Type::Integer);

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
/// AST can be updated with information that was missing at parse time.
///
pub(super) fn semcheck_expr(
    ctx: &mut Context,
    expr: &mut Expr,
) -> Result<Type, Error> {
    match expr {
        Expr::True { .. } | Expr::False { .. } => Ok(Type::Bool),
        Expr::Filesize { .. } | Expr::Entrypoint { .. } => Ok(Type::Integer),

        Expr::Literal(lit) => Ok(lit.ty),

        Expr::PatternCount(p) => {
            if let Some(ref mut range) = p.range {
                semcheck_range(ctx, range)?;
            }
            Ok(Type::Integer)
        }

        Expr::PatternOffset(p) | Expr::PatternLength(p) => {
            // In expressions like @a[i] and !a[i] the index i must
            // be an integer >= 1.
            if let Some(ref mut index) = p.index {
                check_integer_in_range!(ctx, index, 1, i64::MAX)?;
            }
            Ok(Type::Integer)
        }

        Expr::PatternMatch(p) => {
            match &mut p.anchor {
                Some(MatchAnchor::In(anchor_in)) => {
                    semcheck_range(ctx, &mut anchor_in.range)?;
                }
                Some(MatchAnchor::At(anchor_at)) => {
                    check_non_negative_integer!(ctx, &mut anchor_at.expr)?;
                }
                None => {}
            }
            Ok(Type::Bool)
        }

        Expr::Not(expr) => {
            warning_if_not_boolean(ctx, &expr.operand);
            // The `not` operator accepts integers, float and strings because
            // those types can be casted to bool.
            semcheck!(
                ctx,
                Type::Bool | Type::Integer | Type::Float | Type::String,
                &mut expr.operand
            )?;
            let value = expr.operand.value().not();
            expr.set_type_and_value(Type::Bool, value);
            Ok(Type::Bool)
        }

        Expr::And(expr) => semcheck_boolean_and(ctx, expr),
        Expr::Or(expr) => semcheck_boolean_or(ctx, expr),

        Expr::Eq(expr) => semcheck_comparison_eq(ctx, expr),
        Expr::Ne(expr) => semcheck_comparison_ne(ctx, expr),
        Expr::Lt(expr) => semcheck_comparison_lt(ctx, expr),
        Expr::Le(expr) => semcheck_comparison_le(ctx, expr),
        Expr::Gt(expr) => semcheck_comparison_gt(ctx, expr),
        Expr::Ge(expr) => semcheck_comparison_ge(ctx, expr),

        Expr::Shl(expr) => semcheck_shl(ctx, expr),
        Expr::Shr(expr) => semcheck_shr(ctx, expr),

        Expr::BitwiseNot(expr) => {
            semcheck!(ctx, Type::Integer, &mut expr.operand)?;
            let value = expr.operand.value().bitwise_not();
            expr.set_type_and_value(Type::Integer, value);
            Ok(Type::Integer)
        }

        Expr::BitwiseAnd(expr) => semcheck_bitwise_and(ctx, expr),
        Expr::BitwiseOr(expr) => semcheck_bitwise_or(ctx, expr),
        Expr::BitwiseXor(expr) => semcheck_bitwise_xor(ctx, expr),

        Expr::Minus(expr) => {
            let ty = semcheck!(
                ctx,
                Type::Integer | Type::Float,
                &mut expr.operand
            )?;
            let value = expr.operand.value().minus();
            expr.set_type_and_value(ty, value);
            Ok(ty)
        }

        Expr::Add(expr) => semcheck_arithmetic_add(ctx, expr),
        Expr::Sub(expr) => semcheck_arithmetic_sub(ctx, expr),
        Expr::Mul(expr) => semcheck_arithmetic_mul(ctx, expr),
        Expr::Div(expr) => semcheck_arithmetic_div(ctx, expr),
        Expr::Modulus(expr) => semcheck_arithmetic_rem(ctx, expr),

        Expr::Contains(expr) => semcheck_string_contains(ctx, expr, false),
        Expr::IContains(expr) => semcheck_string_contains(ctx, expr, true),
        Expr::StartsWith(expr) => semcheck_string_startswith(ctx, expr, false),
        Expr::IStartsWith(expr) => semcheck_string_startswith(ctx, expr, true),
        Expr::EndsWith(expr) => semcheck_string_endswith(ctx, expr, false),
        Expr::IEndsWith(expr) => semcheck_string_endswith(ctx, expr, true),
        Expr::IEquals(expr) => semcheck_string_equals(ctx, expr, true),

        Expr::Ident(ident) => {
            let (ty, value): (Type, Value) = {
                let current_struct = ctx.current_struct.take();

                let symbol = if let Some(structure) = &current_struct {
                    structure.lookup(ident.name)
                } else {
                    ctx.symbol_table.lookup(ident.name)
                };

                if let Some(symbol) = symbol {
                    match symbol.value() {
                        SymbolValue::Value(value) => {
                            (symbol.ty(), value.clone())
                        }
                        SymbolValue::Struct(symbol_table) => {
                            ctx.current_struct = Some(symbol_table.clone());
                            (Type::Struct, Value::Unknown)
                        }
                        SymbolValue::Array(array) => {
                            ctx.current_array = Some(array.clone());
                            (Type::Array, Value::Unknown)
                        }
                    }
                } else {
                    return Err(Error::CompileError(
                        CompileError::unknown_identifier(
                            ctx.report_builder,
                            ctx.src,
                            ident.name.to_string(),
                            ident.span(),
                        ),
                    ));
                }
            };

            ident.set_type_and_value(ty, value);

            Ok(ty)
        }

        Expr::Lookup(expr) => {
            semcheck_expr(ctx, &mut expr.primary)?;

            if let Type::Array = semcheck_expr(ctx, &mut expr.primary)? {
                // The index must be of type integer.
                semcheck!(ctx, Type::Integer, &mut expr.index)?;

                let array = ctx.array.take().unwrap();
                let item_type = array.item_type();

                // The type of the LookupIndex expression (i.e: array[index])
                // is the type of the array's items.
                expr.set_type_and_value(item_type, Value::Unknown);

                Ok(expr.ty())
            } else {
                Err(Error::CompileError(CompileError::wrong_type(
                    ctx.report_builder,
                    ctx.src,
                    format!("`{}`", Type::Array),
                    expr.primary.ty().to_string(),
                    expr.primary.span(),
                )))
            }
        }
        Expr::FieldAccess(expr) => {
            // The left side must be a struct.
            semcheck!(ctx, Type::Struct, &mut expr.lhs)?;

            // Now check the right hand expression. During the call to
            // semcheck_expr the current symbol table is the one corresponding
            // to the struct.
            let ty = semcheck_expr(ctx, &mut expr.rhs)?;
            let value = expr.rhs.value().clone();

            expr.set_type_and_value(ty, value);
            Ok(ty)
        }

        Expr::FnCall(_) => {
            todo!()
        }

        Expr::Of(of) => semcheck_of(ctx, of),

        Expr::ForOf(for_of) => {
            semcheck_quantifier(ctx, &mut for_of.quantifier)?;
            semcheck!(ctx, Type::Bool, &mut for_of.condition)?;
            Ok(Type::Bool)
        }

        Expr::ForIn(for_in) => {
            semcheck_quantifier(ctx, &mut for_in.quantifier)?;
            let ty = semcheck_iterable(ctx, &mut for_in.iterable)?;

            match &for_in.iterable {
                Iterable::Ident(_) => {
                    // TODO: check that identifier is of the correct type and the
                    // number of variables is the correct one.
                }
                _ => {}
            }

            let mut loop_vars = SymbolTable::new();

            // TODO: raise warning when the loop identifier (e.g: "i") hides
            // an existing identifier with the same name.
            for var in &for_in.variables {
                loop_vars.insert(
                    var.as_str(),
                    Symbol::new(ty, SymbolValue::Value(Value::Unknown)),
                );
            }

            // Put the loop variables into scope.
            ctx.symbol_table.push(Rc::new(loop_vars));

            semcheck!(ctx, Type::Bool, &mut for_in.condition)?;

            // Leaving the condition's scope. Remove loop variables.
            ctx.symbol_table.pop();

            Ok(Type::Bool)
        }
    }
}

fn semcheck_range(ctx: &mut Context, range: &mut Range) -> Result<(), Error> {
    semcheck!(ctx, Type::Integer, &mut range.lower_bound)?;
    semcheck!(ctx, Type::Integer, &mut range.upper_bound)?;
    // TODO: ensure that upper bound is greater than lower bound.
    Ok(())
}

fn semcheck_quantifier(
    ctx: &mut Context,
    quantifier: &mut Quantifier,
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
    }

    Ok(Type::Integer)
}

fn semcheck_of(ctx: &mut Context, of: &mut Of) -> Result<Type, Error> {
    semcheck_quantifier(ctx, &mut of.quantifier)?;
    // `x of (<boolean expr>, <boolean expr>, ...)`: make sure that all
    // expressions in the tuple are actually boolean.
    if let OfItems::BoolExprTuple(tuple) = &mut of.items {
        for expr in tuple.iter_mut() {
            semcheck!(ctx, Type::Bool, expr)?;
        }
    }

    match &mut of.anchor {
        Some(MatchAnchor::In(anchor_in)) => {
            semcheck_range(ctx, &mut anchor_in.range)?;
        }
        Some(MatchAnchor::At(anchor_at)) => {
            check_non_negative_integer!(ctx, &mut anchor_at.expr)?;
        }
        None => {}
    }

    // Compute the number of items in the `of` statement.
    let items_count = match of.items {
        // `x of them`: the number of items is the number of declared patterns
        // because `them` refers to all of them.
        OfItems::PatternSet(PatternSet::Them) => {
            ctx.current_rule.patterns.len() as i64
        }
        // `x of ($a*, $b)`: the number of items is the number of declared
        // pattern that match the items in the tuple.
        OfItems::PatternSet(PatternSet::Set(ref set)) => {
            let mut matching_patterns = 0;
            for (ident_id, _) in &ctx.current_rule.patterns {
                if set
                    .iter()
                    .filter(|p| p.matches(ctx.resolve_ident(*ident_id)))
                    .count()
                    > 0
                {
                    matching_patterns += 1;
                }
            }
            matching_patterns
        }
        // `x of (<boolean expr>, <boolean expr>, ...)`: the number of items is
        // the number of expressions in the tuple.
        OfItems::BoolExprTuple(ref tuple) => tuple.len() as i64,
    };

    // If the quantifier expression is greater than the number of items,
    // the `of` expression is always false.
    if let Quantifier::Expr(expr) = &of.quantifier {
        if let Value::Integer(value) = *expr.value() {
            if value > items_count {
                ctx.warnings.push(Warning::invariant_boolean_expression(
                    ctx.report_builder,
                    ctx.src,
                    false,
                    of.span(),
                    Some(format!(
                        "the expression requires {} matching patterns out of {}",
                        value, items_count
                    )),
                ));
            }
        }
    }

    // The anchor `at <expr>` is being used with a quantifier that is not `any`
    // or `none`, but this usually doesn't make sense. For example consider the
    // expression...
    //
    //   all of ($a, $b) at 0
    //
    // This means that both $a and $b must match at offset 0, which won't happen
    // unless $a and $b are overlapping patterns. In the other hand, these
    // expressions make perfect sense...
    //
    //  none of ($a, $b) at 0
    //  any of ($a, $b) at 0
    //
    // Raise a warning in those cases that are probably wrong.
    //
    if matches!(of.anchor, Some(MatchAnchor::At(_))) {
        let raise_warning = match of.quantifier {
            // `all of <items> at <expr>`: the warning is raised only if there
            // are more than one item. `all of ($a) at 0` doesn't raise a
            // warning.
            Quantifier::All { .. } => items_count > 1,
            // `<expr> of <items> at <expr>: the warning is raised if <expr> is
            // 2 or more.
            Quantifier::Expr(ref expr) => match *expr.value() {
                Value::Integer(value) => value >= 2,
                _ => false,
            },
            // `<expr>% of <items> at <expr>: the warning is raised if the
            // <expr> percent of the items is 2 or more.
            Quantifier::Percentage(ref expr) => match *expr.value() {
                Value::Integer(percentage) => {
                    items_count as f64 * (percentage) as f64 / 100.0 >= 2.0
                }
                _ => false,
            },
            Quantifier::None { .. } | Quantifier::Any { .. } => false,
        };

        if raise_warning {
            ctx.warnings.push(Warning::potentially_wrong_expression(
                ctx.report_builder,
                ctx.src,
                of.quantifier.span(),
                of.anchor.as_ref().unwrap().span(),
            ));
        }
    }

    Ok(Type::Bool)
}

fn semcheck_iterable(
    ctx: &mut Context,
    iterable: &mut Iterable,
) -> Result<Type, Error> {
    match iterable {
        Iterable::Range(range) => {
            semcheck_range(ctx, range)?;
            Ok(Type::Integer)
        }
        Iterable::ExprTuple(tuple) => {
            let mut prev: Option<(Type, Span)> = None;
            // Make sure that all expressions in the tuple have the same
            // type and that type is acceptable.
            for expr in tuple.iter_mut() {
                let span = expr.span();
                let ty = semcheck!(
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
            Ok(ty)
        }
        Iterable::Ident(_) => {
            todo!()
        }
    }
}

/// If `expr` is not of type boolean, it raises a warning indicating that the
/// expression is being casted to a boolean.
pub(super) fn warning_if_not_boolean(ctx: &mut Context, expr: &Expr) {
    let ty = expr.ty();
    let note = match ty {
        Type::Integer => Some(
            "non-zero integers are considered `true`, while zero is `false`"
                .to_string(),
        ),
        Type::Float => Some(
            "non-zero floats are considered `true`, while zero is `false`"
                .to_string(),
        ),
        Type::String => Some(
             r#"non-empty strings are considered `true`, while the empty string ("") is `false`"#
                .to_string(),
        ),
        _ => None,
    };

    if !matches!(ty, Type::Bool) {
        ctx.warnings.push(Warning::non_boolean_as_boolean(
            ctx.report_builder,
            ctx.src,
            ty,
            expr.span(),
            note,
        ));
    }
}
