use itertools::Itertools;
use std::borrow::Borrow;
use std::iter;
use std::rc::Rc;

use yara_x_parser::ast::*;
use yara_x_parser::types::{Map, Type, TypeValue};
use yara_x_parser::warnings::Warning;

use crate::compiler::{CompileError, Context, Error, ParserError};
use crate::symbols::{Symbol, SymbolLookup, SymbolTable};

macro_rules! semcheck {
    ($ctx:expr, $( $accepted_types:path )|+, $expr:expr) => {
        {
            use yara_x_parser::types::Type;
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
                $compatible_types.iter().any(|ty: &Type| ty == &ty1)
                && $compatible_types.iter().any(|ty: &Type| ty == &ty2)
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
        let type_value = (&*$expr).type_value();
        if let TypeValue::Integer(Some(value)) = type_value {
            if *value < 0 {
                return Err(Error::CompileError(
                    CompileError::unexpected_negative_number(
                        $ctx.report_builder,
                        $ctx.src,
                        span,
                    ),
                ));
            }
        }
        Ok::<_, Error>(ty)
    }};
}

macro_rules! check_integer_in_range {
    ($ctx:ident, $expr:expr, $min:expr, $max:expr) => {{
        let ty = semcheck!($ctx, Type::Integer, $expr)?;
        let span = (&*$expr).span();
        let type_value = (&*$expr).type_value();
        if let TypeValue::Integer(Some(value)) = type_value {
            if !($min..=$max).contains(value) {
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
        }
        Ok::<_, Error>(ty)
    }};
}

macro_rules! gen_semcheck_boolean_op {
    ($name:ident, $op:tt) => {
        fn $name(
            ctx: &mut Context,
            expr: &mut Box<BinaryExpr>,
        ) -> Result<Type, Error> {
            warn_if_not_bool(ctx, &expr.lhs);
            warn_if_not_bool(ctx, &expr.rhs);

            semcheck_operands!(
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

            let type_value = expr.lhs.type_value().$op(expr.rhs.type_value());
            let ty = type_value.ty();

            expr.set_type_value(type_value);

            Ok(ty)
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
            semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                // Integers, floats and strings can be compared.
                Type::Integer | Type::Float | Type::String,
                // Integers can be compared with floats, but string can be
                // compared only with another string.
                &[Type::Integer, Type::Float]
            )?;

            let type_value = expr.lhs.type_value().$op(expr.rhs.type_value());
            let ty = type_value.ty();

            expr.set_type_value(type_value);
            Ok(ty)
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

            semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                Type::Integer,
                &[]
            )?;

            let rhs_type_value = expr.rhs.type_value();

            if let TypeValue::Integer(Some(value)) = rhs_type_value {
                if *value < 0 {
                    return Err(Error::CompileError(
                        CompileError::unexpected_negative_number(
                            ctx.report_builder,
                            ctx.src,
                            span,
                        ),
                    ));
                }
            }

            let type_value = expr.lhs.type_value().$op(rhs_type_value);
            let ty = type_value.ty();

            expr.set_type_value(type_value);
            Ok(ty)
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
            semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                Type::Integer,
                &[]
            )?;

            let type_value = expr.lhs.type_value().$op(expr.rhs.type_value());
            let ty = type_value.ty();

            expr.set_type_value(type_value);
            Ok(ty)
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
            semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                Type::String,
                &[]
            )?;

            let type_value = expr
                .lhs
                .type_value()
                .$op(expr.rhs.type_value(), case_insensitive);

            let ty = type_value.ty();

            expr.set_type_value(type_value);
            Ok(ty)
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
             semcheck_operands!(
                ctx,
                &mut expr.lhs,
                &mut expr.rhs,
                $( $accepted_types )|+,
                &[Type::Integer, Type::Float]
             )?;

             let type_value = expr.lhs.type_value().$op(expr.rhs.type_value());
             let ty = type_value.ty();

             expr.set_type_value(type_value);
             Ok(ty)
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

        Expr::Regexp(_) => Ok(Type::Regexp),
        Expr::Literal(lit) => Ok(lit.ty()),
        Expr::Ident(ident) => semcheck_ident(ctx, ident),

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
            warn_if_not_bool(ctx, &expr.operand);
            // The `not` operator accepts integers, float and strings because
            // those types can be casted to bool.
            semcheck!(
                ctx,
                Type::Bool | Type::Integer | Type::Float | Type::String,
                &mut expr.operand
            )?;
            let type_value = expr.operand.type_value().not();
            expr.set_type_value(type_value);
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
            let type_value = expr.operand.type_value().bitwise_not();
            expr.set_type_value(type_value);
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
            let type_value = expr.operand.type_value().minus();
            expr.set_type_value(type_value);
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
        Expr::Matches(expr) => todo!(),

        Expr::Lookup(expr) => {
            semcheck_expr(ctx, &mut expr.primary)?;

            match expr.primary.type_value() {
                TypeValue::Array(array) => {
                    semcheck!(ctx, Type::Integer, &mut expr.index)?;
                    expr.set_type_value(array.deputy());
                    Ok(expr.ty())
                }
                TypeValue::Map(map) => {
                    // The deputy value is a value that acts as representative
                    // of the values stored in the map. This value only contains
                    // type information, not actual data. For example, if the
                    // value is an integer it will be TypeValue::Integer(None),
                    // if it is an struct, it will contain all the fields in the
                    let (key_ty, deputy_value) = match map.borrow() {
                        Map::IntegerKeys { deputy: Some(value), .. } => {
                            (Type::Integer, value)
                        }
                        Map::StringKeys { deputy: Some(value), .. } => {
                            (Type::String, value)
                        }
                        _ => unreachable!(),
                    };

                    let ty = semcheck_expr(ctx, &mut expr.index)?;

                    // The type of the key/index expression should correspond
                    // with the type of the map's keys.
                    if key_ty != ty {
                        return Err(Error::CompileError(
                            CompileError::wrong_type(
                                ctx.report_builder,
                                ctx.src,
                                format!("`{}`", key_ty),
                                ty.to_string(),
                                expr.index.span(),
                            ),
                        ));
                    }

                    // The type of the Lookup expression (i.e: map[key])
                    // is the type of the map's values.
                    expr.set_type_value(deputy_value.clone());

                    Ok(expr.ty())
                }
                _ => Err(Error::CompileError(CompileError::wrong_type(
                    ctx.report_builder,
                    ctx.src,
                    format!("`{}` or `{}`", Type::Array, Type::Map),
                    expr.primary.ty().to_string(),
                    expr.primary.span(),
                ))),
            }
        }
        Expr::FieldAccess(expr) => {
            // The left side operand of a field access operation (i.e: foo.bar)
            // must be a struct.
            semcheck!(ctx, Type::Struct, &mut expr.lhs)?;

            // Set `current_struct` to the structure returned by the left-hand
            // operand.
            ctx.current_struct =
                Some(expr.lhs.type_value().as_struct().unwrap());

            // Now check the right-hand expression. During the call to
            // semcheck_expr the symbol table of `current_struct` will be used
            // for resolving symbols, instead of using the top-level symbol
            // table.
            let ty = semcheck_expr(ctx, &mut expr.rhs)?;

            // The result of a field access is the result of the right-hand
            // expression (i.e: the field).
            expr.set_type_value(expr.rhs.type_value().clone());

            Ok(ty)
        }

        Expr::FnCall(fn_call) => semcheck_fn_call(ctx, fn_call),

        Expr::Of(of) => semcheck_of(ctx, of),

        Expr::ForIn(for_in) => semcheck_for_in(ctx, for_in),

        Expr::ForOf(for_of) => {
            semcheck_quantifier(ctx, &mut for_of.quantifier)?;
            semcheck!(ctx, Type::Bool, &mut for_of.condition)?;
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
        if let TypeValue::Integer(Some(value)) = expr.type_value() {
            if *value > items_count {
                ctx.warnings.push(Warning::invariant_boolean_expression(
                    ctx.report_builder,
                    ctx.src,
                    false,
                    of.span(),
                    Some(format!(
                        "the expression requires {} matching patterns out of {}",
                        *value, items_count
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
        let raise_warning = match &of.quantifier {
            // `all of <items> at <expr>`: the warning is raised only if there
            // are more than one item. `all of ($a) at 0` doesn't raise a
            // warning.
            Quantifier::All { .. } => items_count > 1,
            // `<expr> of <items> at <expr>: the warning is raised if <expr> is
            // 2 or more.
            Quantifier::Expr(expr) => match expr.type_value() {
                TypeValue::Integer(Some(value)) => *value >= 2,
                _ => false,
            },
            // `<expr>% of <items> at <expr>: the warning is raised if the
            // <expr> percent of the items is 2 or more.
            Quantifier::Percentage(expr) => match expr.type_value() {
                TypeValue::Integer(Some(percentage)) => {
                    items_count as f64 * (*percentage) as f64 / 100.0 >= 2.0
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

fn semcheck_ident(
    ctx: &mut Context,
    ident: &mut Ident,
) -> Result<Type, Error> {
    let current_struct = ctx.current_struct.take();

    let symbol = if let Some(structure) = &current_struct {
        structure.lookup(ident.name)
    } else {
        ctx.symbol_table.lookup(ident.name)
    };

    let type_value = if let Some(symbol) = symbol {
        symbol.type_value().clone()
    } else {
        return Err(Error::CompileError(CompileError::unknown_identifier(
            ctx.report_builder,
            ctx.src,
            ident.name.to_string(),
            ident.span(),
        )));
    };

    let ty = type_value.ty();
    ident.set_type_value(type_value);

    Ok(ty)
}

fn semcheck_for_in(
    ctx: &mut Context,
    for_in: &mut ForIn,
) -> Result<Type, Error> {
    semcheck_quantifier(ctx, &mut for_in.quantifier)?;
    semcheck_iterable(ctx, &mut for_in.iterable)?;

    let expected_vars = match &for_in.iterable {
        Iterable::Range(_) => vec![TypeValue::Integer(None)],
        Iterable::ExprTuple(expressions) => {
            // All expressions in the tuple have the same type, we can use
            // the type of the first item in the tuple as the type of the
            // loop variable. Notice that we are using `clone_without_value`
            // instead of `clone`, because we want a TypeValue with the same
            // type than the first item in the tuple, but we don't want to
            // clone its actual value if known. The actual value for the
            // loop variable is not known until the loop is executed.
            vec![expressions
                .first()
                .unwrap()
                .type_value()
                .clone_without_value()]
        }
        Iterable::Expr(expr) => match expr.type_value() {
            TypeValue::Array(array) => vec![array.deputy()],
            TypeValue::Map(map) => match map.as_ref() {
                Map::IntegerKeys { .. } => {
                    vec![TypeValue::Integer(None), map.deputy()]
                }
                Map::StringKeys { .. } => {
                    vec![TypeValue::String(None), map.deputy()]
                }
            },
            _ => unreachable!(),
        },
    };

    let loop_vars = &for_in.variables;

    if loop_vars.len() != expected_vars.len() {
        let span = loop_vars.first().unwrap().span();
        let span = span.combine(&loop_vars.last().unwrap().span());
        return Err(Error::CompileError(CompileError::assignment_mismatch(
            ctx.report_builder,
            ctx.src,
            loop_vars.len() as u8,
            expected_vars.len() as u8,
            for_in.iterable.span(),
            span,
        )));
    }

    let mut vars = SymbolTable::new();

    // TODO: raise warning when the loop identifier (e.g: "i") hides
    // an existing identifier with the same name.
    for (var, type_value) in iter::zip(loop_vars, expected_vars) {
        vars.insert(var.as_str(), Symbol::new(type_value));
    }

    // Put the loop variables into scope.
    ctx.symbol_table.push(Rc::new(vars));

    semcheck!(ctx, Type::Bool, &mut for_in.condition)?;

    // Leaving the condition's scope. Remove loop variables.
    ctx.symbol_table.pop();

    Ok(Type::Bool)
}

fn semcheck_iterable(
    ctx: &mut Context,
    iterable: &mut Iterable,
) -> Result<(), Error> {
    match iterable {
        Iterable::Range(range) => semcheck_range(ctx, range),
        Iterable::Expr(expr) => {
            semcheck!(ctx, Type::Array | Type::Map, expr)?;
            Ok(())
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
            Ok(())
        }
    }
}

fn semcheck_fn_call(
    ctx: &mut Context,
    fn_call: &mut FnCall,
) -> Result<Type, Error> {
    semcheck!(ctx, Type::Func, &mut fn_call.callable)?;

    let type_value = if let TypeValue::Func(func) =
        fn_call.callable.type_value()
    {
        // Validate the expressions passed as arguments to the function, and
        // collect their types.
        let provided_arg_types: Vec<Type> = fn_call
            .args
            .iter_mut()
            .map(|arg| semcheck_expr(ctx, arg))
            .collect::<Result<_, _>>()?;

        let mut expected_args = Vec::new();
        let mut matching_signature = None;

        // Determine if any of the signatures for the called function matches
        // the provided arguments. Signatures are sorted by function name, so
        // that the error messages are stable, without sorting the order of
        // accepted argument combinations in the message is random.
        for (i, signature) in func.signatures().iter().sorted().enumerate() {
            let expected_arg_types: Vec<Type> =
                signature.args.iter().map(|arg| arg.ty()).collect();

            if provided_arg_types == expected_arg_types {
                fn_call.fn_signature_index = Some(i);
                matching_signature = Some(signature);
                break;
            }

            expected_args.push(expected_arg_types);
        }

        if let Some(matching_signature) = matching_signature {
            matching_signature.result.clone()
        } else {
            // No matching signature was found, that means that the arguments
            // provided were incorrect.
            return Err(Error::CompileError(CompileError::wrong_arguments(
                ctx.report_builder,
                ctx.src,
                (&fn_call.args).span(),
                Some(format!(
                    "accepted argument combinations:\n\n             {}",
                    expected_args
                        .iter()
                        .map(|v| {
                            format!(
                                "({})",
                                v.iter()
                                    .map(|i| i.to_string())
                                    .collect::<Vec<String>>()
                                    .join(", ")
                            )
                        })
                        .collect::<Vec<String>>()
                        .join("\n             ")
                )),
            )));
        }
    } else {
        unreachable!()
    };

    let ty = type_value.ty();
    fn_call.set_type_value(type_value);
    Ok(ty)
}

/// If `expr` is not of type boolean, it raises a warning indicating that the
/// expression is being casted to a boolean.
pub(super) fn warn_if_not_bool(ctx: &mut Context, expr: &Expr) {
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
