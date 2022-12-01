use bstr::ByteSlice;
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use std::sync::Arc;

use crate::ast::*;
use crate::compiler::{CompileError, Context, Error, ParserError};
use crate::symbols::{Symbol, SymbolLookup, SymbolTable};
use crate::types::{Type, TypeValue, Value};
use crate::warnings::Warning;

use crate::parser::arithmetic_op;
use crate::parser::bitwise_not;
use crate::parser::bitwise_op;
use crate::parser::boolean_not;
use crate::parser::boolean_op;
use crate::parser::cast_to_bool;
use crate::parser::comparison_op;
use crate::parser::minus_op;
use crate::parser::shift_op;
use crate::parser::string_op;

macro_rules! semcheck {
    ($ctx:expr, $( $accepted_types:path )|+, $expr:expr) => {
        {
            use crate::compiler::errors::Error;
            use crate::compiler::semcheck::semcheck_expr;
            let span = $expr.span();
            let type_hint = semcheck_expr($ctx, $expr)?;
            if !matches!(type_hint.ty(), $( $accepted_types )|+) {
                return Err(Error::CompileError(CompileError::wrong_type(
                    $ctx.report_builder,
                    $ctx.src,
                    ParserError::join_with_or(&[ $( $accepted_types ),+ ], true),
                    type_hint.ty().to_string(),
                    span,
                )));
            }
            Ok::<TypeHint, Error>(type_hint)
        }
    };
}

pub(crate) use semcheck;

macro_rules! semcheck_operands {
    ($ctx:ident, $expr1:expr, $expr2:expr, $( $accepted_types:path )|+, $compatible_types:expr) => {{
        let span1 = $expr1.span();
        let span2 = $expr2.span();

        let type_hint1 = semcheck!($ctx, $( $accepted_types )|+, $expr1)?;
        let type_hint2 = semcheck!($ctx, $( $accepted_types )|+, $expr2)?;

        // Both types must be known.
        assert!(!matches!(type_hint1, TypeHint::UnknownType));
        assert!(!matches!(type_hint2, TypeHint::UnknownType));

        let ty1 = type_hint1.ty();
        let ty2 = type_hint2.ty();

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
        let type_hint = semcheck!($ctx, Type::Integer, $expr)?;
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
        let type_hint = semcheck!($ctx, Type::Integer, $expr)?;
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

macro_rules! gen_semcheck_boolean_op {
    ($name:ident, $op:tt) => {
        fn $name(
            ctx: &mut Context,
            expr: &Box<BinaryExpr>,
        ) -> Result<TypeHint, Error> {
            warning_if_not_boolean(ctx, &expr.lhs);
            warning_if_not_boolean(ctx, &expr.rhs);

            let (lhs, rhs) = semcheck_operands!(
                ctx,
                &expr.lhs,
                &expr.rhs,
                // Boolean operations accept integer, float and string operands.
                // If operands are not boolean they are casted to boolean.
                Type::Bool | Type::Integer | Type::Float | Type::String,
                // All operands types can mixed in a boolean operation, as they
                // are casted to boolean.
                &[Type::Bool, Type::Integer, Type::Float, Type::String]
            )?;

            let type_hint = boolean_op!(lhs, $op, rhs);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }
    };
}

gen_semcheck_boolean_op!(semcheck_boolean_and, &&);
gen_semcheck_boolean_op!(semcheck_boolean_or, ||);

macro_rules! gen_semcheck_comparison_op {
    ($name:ident, $op:tt) => {
        fn $name(
            ctx: &mut Context,
            expr: &Box<BinaryExpr>,
        ) -> Result<TypeHint, Error> {
            let (lhs, rhs) = semcheck_operands!(
                ctx,
                &expr.lhs,
                &expr.rhs,
                // Integers, floats and strings can be compared.
                Type::Integer | Type::Float | Type::String,
                // Integers can be compared with floats, but string can be
                // compared only with another string.
                &[Type::Integer, Type::Float]
            )?;

            let type_hint = comparison_op!(lhs, $op, rhs);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }
    };
}

gen_semcheck_comparison_op!(semcheck_comparison_eq, ==);
gen_semcheck_comparison_op!(semcheck_comparison_ne, !=);
gen_semcheck_comparison_op!(semcheck_comparison_gt, >);
gen_semcheck_comparison_op!(semcheck_comparison_lt, <);
gen_semcheck_comparison_op!(semcheck_comparison_ge, >=);
gen_semcheck_comparison_op!(semcheck_comparison_le, <=);

macro_rules! gen_semcheck_shift_op {
    ($name:ident, $op:tt) => {
        fn $name(
            ctx: &mut Context,
            expr: &Box<BinaryExpr>,
        ) -> Result<TypeHint, Error> {
            let span = expr.rhs.span();

            let (lhs, rhs) = semcheck_operands!(
                ctx,
                &expr.lhs,
                &expr.rhs,
                Type::Integer,
                &[]
            )?;

            if let TypeHint::Integer(Some(value)) = rhs {
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

            let type_hint = shift_op!(lhs, $op, rhs);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }
    };
}

gen_semcheck_shift_op!(semcheck_shl, overflowing_shl);
gen_semcheck_shift_op!(semcheck_shr, overflowing_shr);

macro_rules! gen_semcheck_bitwise_op {
    ($name:ident, $op:ident) => {
        fn $name(
            ctx: &mut Context,
            expr: &Box<BinaryExpr>,
        ) -> Result<TypeHint, Error> {
            let (lhs, rhs) = semcheck_operands!(
                ctx,
                &expr.lhs,
                &expr.rhs,
                Type::Integer,
                &[]
            )?;

            let type_hint = bitwise_op!(lhs, $op, rhs);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }
    };
}

gen_semcheck_bitwise_op!(semcheck_bitwise_and, bitand);
gen_semcheck_bitwise_op!(semcheck_bitwise_or, bitor);
gen_semcheck_bitwise_op!(semcheck_bitwise_xor, bitxor);

macro_rules! gen_semcheck_string_op {
    ($name:ident, $op:ident) => {
        fn $name(
            ctx: &mut Context,
            expr: &Box<BinaryExpr>,
            case_insensitive: bool,
        ) -> Result<TypeHint, Error> {
            let (lhs, rhs) = semcheck_operands!(
                ctx,
                &expr.lhs,
                &expr.rhs,
                Type::String,
                &[]
            )?;

            let type_hint = string_op!(lhs, $op, rhs, case_insensitive);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }
    };
}

gen_semcheck_string_op!(semcheck_string_contains, contains_str);
gen_semcheck_string_op!(semcheck_string_startswith, starts_with);
gen_semcheck_string_op!(semcheck_string_endswith, ends_with);
gen_semcheck_string_op!(semcheck_string_equals, eq);

macro_rules! gen_semcheck_arithmetic_op {
    ($name:ident, $op:tt, $checked_op:ident, $( $accepted_types:path )|+) => {
        fn $name(
            ctx: &mut Context,
            expr: &Box<BinaryExpr>,
        ) -> Result<TypeHint, Error> {
            let (lhs, rhs) = semcheck_operands!(
                ctx,
                &expr.lhs,
                &expr.rhs,
                $( $accepted_types )|+,
                &[Type::Integer, Type::Float]
            )?;

            let type_hint = arithmetic_op!(lhs, $op, $checked_op, rhs);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }
    };
}

gen_semcheck_arithmetic_op!(semcheck_arithmetic_add, +, checked_add, Type::Integer | Type::Float);
gen_semcheck_arithmetic_op!(semcheck_arithmetic_sub, -, checked_sub, Type::Integer | Type::Float);
gen_semcheck_arithmetic_op!(semcheck_arithmetic_mul, *, checked_mul, Type::Integer | Type::Float);
gen_semcheck_arithmetic_op!(semcheck_arithmetic_div, /, checked_div, Type::Integer | Type::Float);
gen_semcheck_arithmetic_op!(semcheck_arithmetic_mod, %, checked_rem, Type::Integer);

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
    expr: &Expr,
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
            if let Some(ref range) = p.range {
                semcheck_range(ctx, range)?;
            }
            Ok(TypeHint::Integer(None))
        }

        Expr::PatternOffset(p) | Expr::PatternLength(p) => {
            // In expressions like @a[i] and !a[i] the index i must
            // be an integer >= 1.
            if let Some(ref index) = p.index {
                check_integer_in_range!(ctx, index, 1, i64::MAX)?;
            }
            Ok(TypeHint::Integer(None))
        }

        Expr::PatternMatch(p) => {
            match &p.anchor {
                Some(MatchAnchor::In(ref anchor_in)) => {
                    semcheck_range(ctx, &anchor_in.range)?;
                }
                Some(MatchAnchor::At(anchor_at)) => {
                    check_non_negative_integer!(ctx, &anchor_at.expr)?;
                }
                None => {}
            }
            Ok(TypeHint::Bool(None))
        }

        Expr::Not(expr) => {
            warning_if_not_boolean(ctx, &expr.operand);

            let type_hint = boolean_not!(semcheck!(
                ctx,
                Type::Bool | Type::Integer | Type::Float | Type::String,
                &expr.operand
            )?);

            expr.set_type_hint(type_hint.clone());
            Ok(type_hint)
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
            let type_hint =
                bitwise_not!(semcheck!(ctx, Type::Integer, &expr.operand)?);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }

        Expr::BitwiseAnd(expr) => semcheck_bitwise_and(ctx, expr),
        Expr::BitwiseOr(expr) => semcheck_bitwise_or(ctx, expr),
        Expr::BitwiseXor(expr) => semcheck_bitwise_xor(ctx, expr),

        Expr::Minus(expr) => {
            let type_hint = minus_op!(semcheck!(
                ctx,
                Type::Integer | Type::Float,
                &expr.operand
            )?);

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }

        Expr::Add(expr) => semcheck_arithmetic_add(ctx, expr),
        Expr::Sub(expr) => semcheck_arithmetic_sub(ctx, expr),
        Expr::Mul(expr) => semcheck_arithmetic_mul(ctx, expr),
        Expr::Div(expr) => semcheck_arithmetic_div(ctx, expr),
        Expr::Modulus(expr) => semcheck_arithmetic_mod(ctx, expr),

        Expr::Contains(expr) => semcheck_string_contains(ctx, expr, false),
        Expr::IContains(expr) => semcheck_string_contains(ctx, expr, true),
        Expr::StartsWith(expr) => semcheck_string_startswith(ctx, expr, false),
        Expr::IStartsWith(expr) => semcheck_string_startswith(ctx, expr, true),
        Expr::EndsWith(expr) => semcheck_string_endswith(ctx, expr, false),
        Expr::IEndsWith(expr) => semcheck_string_endswith(ctx, expr, true),
        Expr::IEquals(expr) => semcheck_string_equals(ctx, expr, true),

        Expr::Ident(ident) => {
            let type_hint: TypeHint = {
                let current_struct = ctx.current_struct.take();

                let symbol = if let Some(structure) = &current_struct {
                    structure.lookup(ident.name)
                } else {
                    ctx.symbol_table.lookup(ident.name)
                };

                if let Some(symbol) = symbol {
                    let value = symbol.value();
                    if let Some(Value::Struct(symbol_table)) = value {
                        ctx.current_struct = Some(symbol_table.clone());
                        TypeHint::Struct
                    } else {
                        TypeHint::new(symbol.ty(), value.cloned())
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

            ident.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }

        Expr::LookupIndex(expr) => {
            if let Type::Array(array_item_type) =
                semcheck_expr(ctx, &expr.primary)?.ty()
            {
                semcheck!(ctx, Type::Integer, &expr.index)?;

                let type_hint = TypeHint::new(array_item_type.into(), None);
                expr.set_type_hint(type_hint.clone());
                Ok(type_hint)
            } else {
                todo!()
            }
        }
        Expr::FieldAccess(expr) => {
            // The left side must be a struct.
            semcheck!(ctx, Type::Struct, &expr.lhs)?;

            // Now check the right hand expression. During the call to
            // semcheck_expr the current symbol table is the one corresponding
            // to the struct.
            let type_hint = semcheck_expr(ctx, &expr.rhs)?;

            expr.set_type_hint(type_hint.clone());

            Ok(type_hint)
        }

        Expr::FnCall(_) => {
            todo!()
        }

        Expr::Of(of) => semcheck_of(ctx, of),

        Expr::ForOf(for_of) => {
            semcheck_quantifier(ctx, &for_of.quantifier)?;
            semcheck!(ctx, Type::Bool, &for_of.condition)?;
            Ok(TypeHint::Bool(None))
        }

        Expr::ForIn(for_in) => {
            semcheck_quantifier(ctx, &for_in.quantifier)?;
            let type_hint = semcheck_iterable(ctx, &for_in.iterable)?;

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
                loop_vars
                    .insert(var.as_str(), Symbol::new(type_hint.ty(), None));
            }

            // Put the loop variables into scope.
            ctx.symbol_table.push(Arc::new(loop_vars));

            semcheck!(ctx, Type::Bool, &for_in.condition)?;

            // Leaving the condition's scope. Remove loop variables.
            ctx.symbol_table.pop();

            Ok(TypeHint::Bool(None))
        }
    }
}

fn semcheck_range(ctx: &mut Context, range: &Range) -> Result<(), Error> {
    semcheck!(ctx, Type::Integer, &range.lower_bound)?;
    semcheck!(ctx, Type::Integer, &range.upper_bound)?;
    // TODO: ensure that upper bound is greater than lower bound.
    Ok(())
}

fn semcheck_quantifier(
    ctx: &mut Context,
    quantifier: &Quantifier,
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
    }

    Ok(TypeHint::Integer(None))
}

fn semcheck_of(ctx: &mut Context, of: &Of) -> Result<TypeHint, Error> {
    semcheck_quantifier(ctx, &of.quantifier)?;

    // `x of (<boolean expr>, <boolean expr>, ...)`: make sure that all
    // expressions in the tuple are actually boolean.
    if let OfItems::BoolExprTuple(tuple) = &of.items {
        for expr in tuple.iter() {
            semcheck!(ctx, Type::Bool, expr)?;
        }
    }

    match &of.anchor {
        Some(MatchAnchor::In(anchor_in)) => {
            semcheck_range(ctx, &anchor_in.range)?;
        }
        Some(MatchAnchor::At(anchor_at)) => {
            check_non_negative_integer!(ctx, &anchor_at.expr)?;
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
        if let TypeHint::Integer(Some(i)) = expr.type_hint() {
            if i > items_count {
                ctx.warnings.push(Warning::invariant_boolean_expression(
                    ctx.report_builder,
                    ctx.src,
                    false,
                    of.span(),
                    Some(format!(
                        "the expression requires {} matching patterns out of {}",
                        i, items_count
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
            Quantifier::Expr(ref expr) => match expr.type_hint() {
                TypeHint::Integer(Some(i)) => i >= 2,
                _ => false,
            },
            // `<expr>% of <items> at <expr>: the warning is raised if the
            // <expr> percent of the items is 2 or more.
            Quantifier::Percentage(ref expr) => match expr.type_hint() {
                TypeHint::Integer(Some(percentage)) => {
                    items_count as f64 * percentage as f64 / 100.0 >= 2.0
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

    Ok(TypeHint::Bool(None))
}

fn semcheck_iterable(
    ctx: &mut Context,
    iterable: &Iterable,
) -> Result<TypeHint, Error> {
    match iterable {
        Iterable::Range(range) => {
            semcheck_range(ctx, range)?;
            Ok(TypeHint::Integer(None))
        }
        Iterable::ExprTuple(tuple) => {
            let mut prev: Option<(TypeHint, Span)> = None;
            // Make sure that all expressions in the tuple have the same
            // type and that type is acceptable.
            for expr in tuple.iter() {
                let span = expr.span();
                let type_hint = semcheck!(
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

/// If `expr` is not of type boolean, it raises a warning indicating that the
/// expression is being casted to a boolean.
pub(super) fn warning_if_not_boolean(ctx: &mut Context, expr: &Expr) {
    let ty = expr.type_hint().ty();

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
