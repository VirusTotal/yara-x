/*! Functions for converting an AST into an IR. */

use std::iter;
use std::ops::RangeInclusive;
use std::rc::Rc;
use yara_x_parser::ast::{HasSpan, MatchAnchor, Span};
use yara_x_parser::types::{Map, Type, TypeValue};
use yara_x_parser::{ast, ErrorInfo, Warning};

use crate::compiler::ir::{Expr, FnCall, ForIn, Iterable, Quantifier, Range};
use crate::compiler::{CompileError, Context};
use crate::symbols::{Symbol, SymbolKind, SymbolLookup, SymbolTable};

/// Given the AST for some expression, creates its IR.
pub(in crate::compiler) fn expr_from_ast(
    ctx: &mut Context,
    expr: &ast::Expr,
) -> Result<Expr, CompileError> {
    match expr {
        ast::Expr::Entrypoint { .. } => Ok(Expr::Entrypoint),
        ast::Expr::Filesize { .. } => Ok(Expr::Filesize),

        ast::Expr::True { .. } => {
            Ok(Expr::Const { type_value: TypeValue::Bool(Some(true)) })
        }

        ast::Expr::False { .. } => {
            Ok(Expr::Const { type_value: TypeValue::Bool(Some(false)) })
        }

        ast::Expr::Literal(literal) => {
            Ok(Expr::Const { type_value: literal.type_value.clone() })
        }

        // Boolean operations
        ast::Expr::Not(expr) => not_expr_from_ast(ctx, expr),
        ast::Expr::And(expr) => and_expr_from_ast(ctx, expr),
        ast::Expr::Or(expr) => or_expr_from_ast(ctx, expr),

        // Arithmetic operations
        ast::Expr::Minus(expr) => minus_expr_from_ast(ctx, expr),
        ast::Expr::Add(expr) => add_expr_from_ast(ctx, expr),
        ast::Expr::Sub(expr) => sub_expr_from_ast(ctx, expr),
        ast::Expr::Mul(expr) => mul_expr_from_ast(ctx, expr),
        ast::Expr::Div(expr) => div_expr_from_ast(ctx, expr),
        ast::Expr::Mod(expr) => mod_expr_from_ast(ctx, expr),

        // Shift operations
        ast::Expr::Shl(expr) => shl_expr_from_ast(ctx, expr),
        ast::Expr::Shr(expr) => shr_expr_from_ast(ctx, expr),

        // Bitwise operations
        ast::Expr::BitwiseNot(expr) => bitwise_not_expr_from_ast(ctx, expr),
        ast::Expr::BitwiseAnd(expr) => bitwise_and_expr_from_ast(ctx, expr),
        ast::Expr::BitwiseOr(expr) => bitwise_or_expr_from_ast(ctx, expr),
        ast::Expr::BitwiseXor(expr) => bitwise_xor_expr_from_ast(ctx, expr),

        // Comparison operations
        ast::Expr::Eq(expr) => eq_expr_from_ast(ctx, expr),
        ast::Expr::Ne(expr) => ne_expr_from_ast(ctx, expr),
        ast::Expr::Gt(expr) => gt_expr_from_ast(ctx, expr),
        ast::Expr::Ge(expr) => ge_expr_from_ast(ctx, expr),
        ast::Expr::Lt(expr) => lt_expr_from_ast(ctx, expr),
        ast::Expr::Le(expr) => le_expr_from_ast(ctx, expr),

        // String operations
        ast::Expr::Contains(expr) => contains_expr_from_ast(ctx, expr),
        ast::Expr::IContains(expr) => icontains_expr_from_ast(ctx, expr),
        ast::Expr::StartsWith(expr) => startswith_expr_from_ast(ctx, expr),
        ast::Expr::IStartsWith(expr) => istartswith_expr_from_ast(ctx, expr),
        ast::Expr::EndsWith(expr) => endswith_expr_from_ast(ctx, expr),
        ast::Expr::IEndsWith(expr) => iendswith_expr_from_ast(ctx, expr),
        ast::Expr::IEquals(expr) => iequals_expr_from_ast(ctx, expr),

        ast::Expr::Defined(expr) => defined_expr_from_ast(ctx, expr),

        ast::Expr::FieldAccess(expr) => {
            let lhs = expr_from_ast(ctx, &expr.lhs)?;

            // The left-side operand of a field access operation (i.e: foo.bar)
            // must be a struct.
            check_type(ctx, lhs.ty(), expr.lhs.span(), &[Type::Struct])?;

            // Set `current_struct` to the structure returned by the left-hand
            // operand.
            ctx.current_struct = Some(lhs.type_value().as_struct());

            // Now build the right-side expression. During the call to
            // `build_expr` the symbol table of `current_struct` will be used
            // for resolving symbols, instead of using the top-level symbol
            // table.
            let rhs = expr_from_ast(ctx, &expr.rhs)?;

            // If the right-side expression is constant, the result is also
            // constant.
            if let Expr::Const { type_value, .. } = rhs {
                Ok(Expr::Const { type_value })
            } else {
                Ok(Expr::FieldAccess {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
        }

        ast::Expr::Ident(ident) => {
            let current_struct = ctx.current_struct.take();

            let symbol = if let Some(structure) = &current_struct {
                structure.lookup(ident.name)
            } else {
                ctx.symbol_table.lookup(ident.name)
            };

            if symbol.is_none() {
                return Err(CompileError::unknown_identifier(
                    ctx.report_builder,
                    ctx.src,
                    ident.name.to_string(),
                    ident.span(),
                ));
            }

            let symbol = symbol.unwrap();
            let type_value = symbol.type_value();

            // If the identifier has a known value at compile time then it is
            // a constant.
            if type_value.has_value() {
                Ok(Expr::Const { type_value: type_value.clone() })
            } else {
                Ok(Expr::Ident { symbol })
            }
        }

        ast::Expr::PatternMatch(p) => {
            // If the identifier is just `$` we are inside a loop and we don't
            // know which is the PatternId because `$` refers to a different
            // pattern on each iteration. In those cases the symbol table must
            // contain an entry for `$`, corresponding to the variable that
            // holds the current PatternId for the loop.
            match (p.identifier.name, &p.anchor) {
                // Cases where the identifier is `$`.
                ("$", Some(MatchAnchor::At(at))) => {
                    Ok(Expr::PatternMatchAtVar {
                        symbol: ctx.symbol_table.lookup("$").unwrap(),
                        offset: Box::new(non_negative_integer_from_ast(
                            ctx, &at.expr,
                        )?),
                    })
                }
                ("$", Some(MatchAnchor::In(in_))) => {
                    Ok(Expr::PatternMatchInVar {
                        symbol: ctx.symbol_table.lookup("$").unwrap(),
                        range: range_from_ast(ctx, &in_.range)?,
                    })
                }
                ("$", None) => Ok(Expr::PatternMatchVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                }),
                // Cases where the identifier is not `$`.
                (_, Some(MatchAnchor::At(at))) => Ok(Expr::PatternMatchAt {
                    pattern_id: ctx
                        .get_pattern_from_current_rule(p.identifier.name),
                    offset: Box::new(non_negative_integer_from_ast(
                        ctx, &at.expr,
                    )?),
                }),
                (_, Some(MatchAnchor::In(in_))) => Ok(Expr::PatternMatchIn {
                    pattern_id: ctx
                        .get_pattern_from_current_rule(p.identifier.name),
                    range: range_from_ast(ctx, &in_.range)?,
                }),
                (_, None) => Ok(Expr::PatternMatch {
                    pattern_id: ctx
                        .get_pattern_from_current_rule(p.identifier.name),
                }),
            }
        }

        ast::Expr::ForIn(for_in) => for_in_expr_from_ast(ctx, for_in),
        ast::Expr::FnCall(fn_call) => fn_call_expr_from_ast(ctx, fn_call),

        expr @ _ => {
            unimplemented!("{:?}", expr);
        }
    }
}

macro_rules! gen_unary_op {
    ($name:ident, $variant:ident, $op:tt, $( $accepted_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut Context,
            expr: &ast::UnaryExpr,
        ) -> Result<Expr, CompileError> {
            let span = expr.span();
            let operand = Box::new(expr_from_ast(ctx, &expr.operand)?);

            // The `not` operator accepts integers, floats and strings because
            // those types can be casted to bool.
            check_type(
                ctx,
                operand.ty(),
                expr.operand.span(),
                &[$( $accepted_types ),+],
            )?;

            let check_fn:
                Option<fn(&mut Context, &Expr, Span) -> Result<(), CompileError>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &operand, span)?;
            }

            // If the operand is constant, the result is also constant.
            if let Expr::Const { type_value, .. } = operand.as_ref() {
                Ok(Expr::Const {type_value: type_value.$op()})
            } else {
                Ok(Expr::$variant { operand })
            }
        }
    };
}

macro_rules! gen_binary_op {
    ($name:ident, $variant:ident, $op:tt, $( $accepted_types:path )|+, $( $compatible_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut Context,
            expr: &ast::BinaryExpr,
        ) -> Result<Expr, CompileError> {
            let lhs_span = expr.lhs.span();
            let rhs_span = expr.rhs.span();

            let lhs = Box::new(expr_from_ast(ctx, &expr.lhs)?);
            let rhs = Box::new(expr_from_ast(ctx, &expr.rhs)?);

            check_operands(
                ctx,
                lhs.ty(),
                rhs.ty(),
                lhs_span,
                rhs_span,
                &[$( $accepted_types ),+],
                &[$( $compatible_types ),+],
            )?;

            let check_fn:
                Option<fn(&mut Context, &Expr, &Expr, Span, Span) -> Result<(), CompileError>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &lhs, &rhs, lhs_span, rhs_span)?;
            }

            match (lhs.as_ref(), rhs.as_ref()) {
                (
                    Expr::Const { type_value: lhs, .. },
                    Expr::Const { type_value: rhs, .. },
                ) => Ok(Expr::Const {
                    type_value: lhs.$op(&rhs),
                }),
                _ => Ok(Expr::$variant { lhs, rhs }),
            }
        }
    };
}

macro_rules! gen_string_op {
    ($name:ident, $variant:ident, $op:tt, $case_insensitive:expr) => {
        fn $name(
            ctx: &mut Context,
            expr: &ast::BinaryExpr,
        ) -> Result<Expr, CompileError> {
            let lhs_span = expr.lhs.span();
            let rhs_span = expr.rhs.span();

            let lhs = Box::new(expr_from_ast(ctx, &expr.lhs)?);
            let rhs = Box::new(expr_from_ast(ctx, &expr.rhs)?);

            check_operands(
                ctx,
                lhs.ty(),
                rhs.ty(),
                lhs_span,
                rhs_span,
                &[Type::String],
                &[Type::String],
            )?;

            match (lhs.as_ref(), rhs.as_ref()) {
                (
                    Expr::Const { type_value: lhs, .. },
                    Expr::Const { type_value: rhs, .. },
                ) => Ok(Expr::Const {
                    type_value: lhs.$op(&rhs, $case_insensitive),
                }),
                _ => Ok(Expr::$variant { lhs, rhs }),
            }
        }
    };
}

gen_unary_op!(
    defined_expr_from_ast,
    Defined,
    defined,
    Type::Bool | Type::Integer | Type::Float | Type::String,
    None
);

gen_unary_op!(
    not_expr_from_ast,
    Not,
    not,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // Raise warning if the operand is not bool.
    Some(|ctx, operand, span| {
        warn_if_not_bool(ctx, operand.ty(), span);
        Ok(())
    })
);

gen_binary_op!(
    and_expr_from_ast,
    And,
    and,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // All operand types can be mixed in a boolean operation, as they
    // are casted to boolean anyways.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // Raise warning if some of the operands is not bool.
    Some(|ctx, lhs, rhs, lhs_span, rhs_span| {
        warn_if_not_bool(ctx, lhs.ty(), lhs_span);
        warn_if_not_bool(ctx, rhs.ty(), rhs_span);
        Ok(())
    })
);

gen_binary_op!(
    or_expr_from_ast,
    Or,
    or,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // All operand types can be mixed in a boolean operation, as they
    // are casted to boolean anyways.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // Raise warning if some of the operands is not bool.
    Some(|ctx, lhs, rhs, lhs_span, rhs_span| {
        warn_if_not_bool(ctx, lhs.ty(), lhs_span);
        warn_if_not_bool(ctx, rhs.ty(), rhs_span);
        Ok(())
    })
);

gen_unary_op!(
    minus_expr_from_ast,
    Minus,
    minus,
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    add_expr_from_ast,
    Add,
    add,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    sub_expr_from_ast,
    Sub,
    sub,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    mul_expr_from_ast,
    Mul,
    mul,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    div_expr_from_ast,
    Div,
    div,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    mod_expr_from_ast,
    Mod,
    rem,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    shl_expr_from_ast,
    Shl,
    shl,
    Type::Integer,
    Type::Integer,
    Some(|ctx, _lhs, rhs, _lhs_span, rhs_span| {
        if let TypeValue::Integer(Some(value)) = rhs.type_value() {
            if value < 0 {
                return Err(CompileError::unexpected_negative_number(
                    ctx.report_builder,
                    ctx.src,
                    rhs_span,
                ));
            }
        }
        Ok(())
    })
);

gen_binary_op!(
    shr_expr_from_ast,
    Shr,
    shr,
    Type::Integer,
    Type::Integer,
    Some(|ctx, _lhs, rhs, _lhs_span, rhs_span| {
        if let TypeValue::Integer(Some(value)) = rhs.type_value() {
            if value < 0 {
                return Err(CompileError::unexpected_negative_number(
                    ctx.report_builder,
                    ctx.src,
                    rhs_span,
                ));
            }
        }
        Ok(())
    })
);

gen_unary_op!(
    bitwise_not_expr_from_ast,
    BitwiseNot,
    bitwise_not,
    Type::Integer,
    None
);

gen_binary_op!(
    bitwise_and_expr_from_ast,
    BitwiseAnd,
    bitwise_and,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    bitwise_or_expr_from_ast,
    BitwiseOr,
    bitwise_or,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    bitwise_xor_expr_from_ast,
    BitwiseXor,
    bitwise_xor,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    eq_expr_from_ast,
    Eq,
    eq,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    ne_expr_from_ast,
    Ne,
    ne,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    gt_expr_from_ast,
    Gt,
    gt,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    ge_expr_from_ast,
    Ge,
    ge,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    lt_expr_from_ast,
    Lt,
    lt,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_op!(
    le_expr_from_ast,
    Le,
    le,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_string_op!(contains_expr_from_ast, Contains, contains_str, false);
gen_string_op!(icontains_expr_from_ast, IContains, contains_str, true);
gen_string_op!(startswith_expr_from_ast, StartsWith, starts_with_str, false);
gen_string_op!(istartswith_expr_from_ast, IStartsWith, starts_with_str, true);
gen_string_op!(endswith_expr_from_ast, EndsWith, ends_with_str, false);
gen_string_op!(iendswith_expr_from_ast, IEndsWith, ends_with_str, true);
gen_string_op!(iequals_expr_from_ast, IEquals, equals_str, true);

fn for_in_expr_from_ast(
    ctx: &mut Context,
    for_in: &ast::ForIn,
) -> Result<Expr, CompileError> {
    let quantifier = quantifier_from_ast(ctx, &for_in.quantifier)?;
    let iterable = iterable_from_ast(ctx, &for_in.iterable)?;

    let expected_vars = match &iterable {
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

    // Make sure that the number of variables in the `for .. in` statement
    // corresponds to the number of values returned by the iterator. For
    // example, while most iterators return a single value, maps return two
    // of them: key and value.
    if loop_vars.len() != expected_vars.len() {
        let span = loop_vars.first().unwrap().span();
        let span = span.combine(&loop_vars.last().unwrap().span());
        return Err(CompileError::assignment_mismatch(
            ctx.report_builder,
            ctx.src,
            loop_vars.len() as u8,
            expected_vars.len() as u8,
            for_in.iterable.span(),
            span,
        ));
    }

    let mut vars = SymbolTable::new();

    // TODO: raise warning when the loop identifier (e.g: "i") hides
    // an existing identifier with the same name.
    for (var, type_value) in iter::zip(loop_vars, expected_vars) {
        vars.insert(var.name, Symbol::new(type_value, SymbolKind::Unknown));
    }

    // Put the loop variables into scope.
    ctx.symbol_table.push(Rc::new(vars));

    let condition = expr_from_ast(ctx, &for_in.condition)?;

    // Leaving the condition's scope. Remove loop variables.
    ctx.symbol_table.pop();

    todo!()

    /*
    Ok(Expr::ForIn(Box::new(ForIn {
        span: for_in.span(),
        quantifier,
        iterable,
        condition,
    })))

     */
}

fn iterable_from_ast(
    ctx: &mut Context,
    iter: &ast::Iterable,
) -> Result<Iterable, CompileError> {
    match iter {
        ast::Iterable::Range(range) => {
            Ok(Iterable::Range(range_from_ast(ctx, range)?))
        }
        ast::Iterable::Expr(expr) => {
            let span = expr.span();
            let expr = expr_from_ast(ctx, expr)?;
            // Make sure that the expression has a type that is iterable.
            check_type(ctx, expr.ty(), span, &[Type::Array, Type::Map])?;
            Ok(Iterable::Expr(expr))
        }
        ast::Iterable::ExprTuple(expr_tuple) => {
            let mut e = Vec::with_capacity(expr_tuple.len());
            let mut prev: Option<(Type, Span)> = None;
            for expr in expr_tuple {
                let span = expr.span();
                let expr = expr_from_ast(ctx, expr)?;
                let ty = expr.ty();
                // Items in the tuple must be either integer, float, string
                // or bool.
                check_type(
                    ctx,
                    ty,
                    span,
                    &[Type::Integer, Type::Float, Type::String, Type::Bool],
                )?;
                // All items in the item must have the same type. Compare
                // with the previous item and return as soon as we find a
                // type mismatch.
                if let Some((prev_ty, prev_span)) = prev {
                    if prev_ty != ty {
                        return Err(CompileError::mismatching_types(
                            ctx.report_builder,
                            ctx.src,
                            prev_ty.to_string(),
                            ty.to_string(),
                            prev_span,
                            span,
                        ));
                    }
                }
                prev = Some((ty, span));
                e.push(expr);
            }
            Ok(Iterable::ExprTuple(e))
        }
    }
}

fn range_from_ast(
    ctx: &mut Context,
    range: &ast::Range,
) -> Result<Range, CompileError> {
    let lower_bound =
        Box::new(non_negative_integer_from_ast(ctx, &range.lower_bound)?);

    let upper_bound =
        Box::new(non_negative_integer_from_ast(ctx, &range.upper_bound)?);

    // If both the lower and upper bounds are known at compile time, make sure
    // that lower_bound <= upper_bound. If they are not know (because they are
    // variables, for example) we can't raise an error at compile time but it
    // will be handled at scan time.
    if let (
        TypeValue::Integer(Some(lower_bound)),
        TypeValue::Integer(Some(upper_bound)),
    ) = (lower_bound.type_value(), upper_bound.type_value())
    {
        if lower_bound > upper_bound {
            return Err(CompileError::invalid_range(
                ctx.report_builder,
                ctx.src,
                range.span,
            ));
        }
    }

    Ok(Range { lower_bound, upper_bound })
}

fn non_negative_integer_from_ast(
    ctx: &mut Context,
    expr: &ast::Expr,
) -> Result<Expr, CompileError> {
    let span = expr.span();
    let expr = expr_from_ast(ctx, expr)?;
    let type_value = expr.type_value();

    check_type(ctx, type_value.ty(), span, &[Type::Integer])?;

    if let TypeValue::Integer(Some(value)) = type_value {
        if value < 0 {
            return Err(CompileError::unexpected_negative_number(
                ctx.report_builder,
                ctx.src,
                span,
            ));
        }
    } else {
        unreachable!()
    }

    Ok(expr)
}

fn quantifier_from_ast(
    ctx: &mut Context,
    quantifier: &ast::Quantifier,
) -> Result<Quantifier, CompileError> {
    match quantifier {
        ast::Quantifier::None { .. } => Ok(Quantifier::None),
        ast::Quantifier::All { .. } => Ok(Quantifier::All),
        ast::Quantifier::Any { .. } => Ok(Quantifier::None),
        ast::Quantifier::Percentage(expr) => {
            let span = expr.span();
            let expr = expr_from_ast(ctx, expr)?;
            // The percentage must be between 0 and 100, both inclusive.
            check_integer_in_range(ctx, &expr, span, 0..=100)?;
            Ok(Quantifier::Percentage(expr))
        }
        ast::Quantifier::Expr(expr) => {
            Ok(Quantifier::Expr(non_negative_integer_from_ast(ctx, expr)?))
        }
    }
}

fn fn_call_expr_from_ast(
    ctx: &mut Context,
    fn_call: &ast::FnCall,
) -> Result<Expr, CompileError> {
    let callable = expr_from_ast(ctx, &fn_call.callable)?;
    let func = callable.type_value().as_func();

    let args = fn_call
        .args
        .iter()
        .map(|arg| expr_from_ast(ctx, arg))
        .collect::<Result<Vec<Expr>, CompileError>>()?;

    let arg_types: Vec<Type> = args.iter().map(|arg| arg.ty()).collect();

    let mut expected_args = Vec::new();
    let mut matching_signature = None;

    // Determine if any of the signatures for the called function matches
    // the provided arguments.
    for (i, signature) in func.signatures().iter().enumerate() {
        let expected_arg_types: Vec<Type> =
            signature.args.iter().map(|arg| arg.ty()).collect();

        if arg_types == expected_arg_types {
            matching_signature = Some((i, signature.result.clone()));
            break;
        }

        expected_args.push(expected_arg_types);
    }

    // No matching signature was found, that means that the arguments
    // provided were incorrect.
    if matching_signature.is_none() {
        return Err(CompileError::wrong_arguments(
            ctx.report_builder,
            ctx.src,
            fn_call.args_span,
            Some(format!(
                "accepted argument combinations:\n   │\n   │       {}",
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
                    .join("\n   │       ")
            )),
        ));
    }

    let (signature_index, type_value) = matching_signature.unwrap();

    Ok(Expr::FnCall(Box::new(FnCall {
        callable,
        type_value,
        signature_index,
        args,
    })))
}

fn check_type(
    ctx: &Context,
    ty: Type,
    span: Span,
    accepted_types: &[Type],
) -> Result<(), CompileError> {
    if accepted_types.contains(&ty) {
        Ok(())
    } else {
        Err(CompileError::wrong_type(
            ctx.report_builder,
            ctx.src,
            ErrorInfo::join_with_or(accepted_types, true),
            ty.to_string(),
            span,
        ))
    }
}

fn check_non_negative_integer(
    ctx: &Context,
    expr: &Expr,
    span: Span,
) -> Result<(), CompileError> {
    let type_value = expr.type_value();

    check_type(ctx, type_value.ty(), span, &[Type::Integer])?;

    if let TypeValue::Integer(Some(value)) = type_value {
        if value < 0 {
            return Err(CompileError::unexpected_negative_number(
                ctx.report_builder,
                ctx.src,
                span,
            ));
        }
    } else {
        unreachable!()
    }

    Ok(())
}

fn check_integer_in_range(
    ctx: &Context,
    expr: &Expr,
    span: Span,
    range: RangeInclusive<i64>,
) -> Result<(), CompileError> {
    let type_value = expr.type_value();

    check_type(ctx, type_value.ty(), span, &[Type::Integer])?;

    if let TypeValue::Integer(Some(value)) = type_value {
        if !range.contains(&value) {
            return Err(CompileError::number_out_of_range(
                ctx.report_builder,
                ctx.src,
                *range.start(),
                *range.end(),
                span,
            ));
        }
    } else {
        unreachable!()
    }

    Ok(())
}

fn check_operands(
    ctx: &Context,
    lhs_ty: Type,
    rhs_ty: Type,
    lhs_span: Span,
    rhs_span: Span,
    accepted_types: &[Type],
    compatible_types: &[Type],
) -> Result<(), CompileError> {
    // Both types must be known.
    assert!(!matches!(lhs_ty, Type::Unknown));
    assert!(!matches!(rhs_ty, Type::Unknown));

    check_type(ctx, lhs_ty, lhs_span, accepted_types)?;
    check_type(ctx, rhs_ty, rhs_span, accepted_types)?;

    let types_are_compatible = {
        // If the types are the same, they are compatible.
        (lhs_ty == rhs_ty)
            // If both types are in the list of compatible types,
            // they are compatible too.
            || (
            compatible_types.contains(&lhs_ty)
                && compatible_types.contains(&rhs_ty)
        )
    };

    if !types_are_compatible {
        return Err(CompileError::mismatching_types(
            ctx.report_builder,
            ctx.src,
            lhs_ty.to_string(),
            rhs_ty.to_string(),
            lhs_span,
            rhs_span,
        ));
    }

    Ok(())
}

/// Produce a warning if the expression is not boolean.
fn warn_if_not_bool(ctx: &mut Context, ty: Type, span: Span) {
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
            span,
            note,
        ));
    }
}
