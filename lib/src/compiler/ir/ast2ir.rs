/*! Functions for converting an AST into an IR. */

use std::borrow::Borrow;
use std::iter;
use std::ops::RangeInclusive;
use std::rc::Rc;

use bstr::ByteSlice;
use itertools::Itertools;
use yara_x_parser::ast::{HasSpan, Span};
use yara_x_parser::report::ReportBuilder;
use yara_x_parser::{ast, ErrorInfo};

use crate::compiler::ir::hex2hir::hex_pattern_hir_from_ast;
use crate::compiler::ir::{
    Expr, ForIn, ForOf, FuncCall, Iterable, LiteralPattern, Lookup,
    MatchAnchor, Of, OfItems, Pattern, PatternFlagSet, PatternFlags,
    PatternIdx, PatternInRule, Quantifier, Range, RegexpPattern,
};
use crate::compiler::warnings::Warning;
use crate::compiler::{CompileContext, CompileError};
use crate::modules::BUILTIN_MODULES;
use crate::re;
use crate::re::parser::Error;
use crate::symbols::{Symbol, SymbolKind, SymbolLookup, SymbolTable};
use crate::types::{Map, Regexp, Type, TypeValue, Value};

pub(in crate::compiler) fn patterns_from_ast<'src>(
    ctx: &mut CompileContext<'_, 'src, '_>,
    patterns: Option<&Vec<ast::Pattern<'src>>>,
) -> Result<(), Box<CompileError>> {
    for pattern_ast in patterns.into_iter().flatten() {
        let pattern = pattern_from_ast(ctx, pattern_ast)?;
        ctx.current_rule_patterns.push(pattern);
    }
    Ok(())
}

fn pattern_from_ast<'src>(
    ctx: &mut CompileContext,
    pattern: &ast::Pattern<'src>,
) -> Result<PatternInRule<'src>, Box<CompileError>> {
    match pattern {
        ast::Pattern::Text(pattern) => {
            Ok(text_pattern_from_ast(ctx, pattern)?)
        }
        ast::Pattern::Hex(pattern) => Ok(hex_pattern_from_ast(ctx, pattern)?),
        ast::Pattern::Regexp(pattern) => {
            Ok(regexp_pattern_from_ast(ctx, pattern)?)
        }
    }
}

pub(in crate::compiler) fn text_pattern_from_ast<'src>(
    _ctx: &mut CompileContext,
    pattern: &ast::TextPattern<'src>,
) -> Result<PatternInRule<'src>, Box<CompileError>> {
    let mut flags = PatternFlagSet::none();

    if pattern.modifiers.ascii().is_some()
        || pattern.modifiers.wide().is_none()
    {
        flags.set(PatternFlags::Ascii);
    }

    if pattern.modifiers.wide().is_some() {
        flags.set(PatternFlags::Wide);
    }

    if pattern.modifiers.nocase().is_some() {
        flags.set(PatternFlags::Nocase);
    }

    if pattern.modifiers.fullword().is_some() {
        flags.set(PatternFlags::Fullword);
    }

    let xor_range = match pattern.modifiers.xor() {
        Some(ast::PatternModifier::Xor { start, end, .. }) => {
            flags.set(PatternFlags::Xor);
            Some(*start..=*end)
        }
        _ => None,
    };

    let base64_alphabet = match pattern.modifiers.base64() {
        Some(ast::PatternModifier::Base64 { alphabet, .. }) => {
            flags.set(PatternFlags::Base64);
            *alphabet
        }
        _ => None,
    };

    let base64wide_alphabet = match pattern.modifiers.base64wide() {
        Some(ast::PatternModifier::Base64Wide { alphabet, .. }) => {
            flags.set(PatternFlags::Base64Wide);
            *alphabet
        }
        _ => None,
    };

    Ok(PatternInRule {
        identifier: pattern.identifier.name,
        pattern: Pattern::Literal(LiteralPattern {
            flags,
            xor_range,
            base64_alphabet: base64_alphabet.map(String::from),
            base64wide_alphabet: base64wide_alphabet.map(String::from),
            anchored_at: None,
            text: pattern.text.as_ref().into(),
        }),
    })
}

pub(in crate::compiler) fn hex_pattern_from_ast<'src>(
    ctx: &mut CompileContext,
    pattern: &ast::HexPattern<'src>,
) -> Result<PatternInRule<'src>, Box<CompileError>> {
    Ok(PatternInRule {
        identifier: pattern.identifier.name,
        pattern: Pattern::Regexp(RegexpPattern {
            flags: PatternFlagSet::from(PatternFlags::Ascii),
            hir: re::hir::Hir::from(hex_pattern_hir_from_ast(ctx, pattern)),
            anchored_at: None,
        }),
    })
}

pub(in crate::compiler) fn regexp_pattern_from_ast<'src>(
    ctx: &mut CompileContext,
    pattern: &ast::RegexpPattern<'src>,
) -> Result<PatternInRule<'src>, Box<CompileError>> {
    let mut flags = PatternFlagSet::none();

    if pattern.modifiers.ascii().is_some()
        || pattern.modifiers.wide().is_none()
    {
        flags.set(PatternFlags::Ascii);
    }

    if pattern.modifiers.wide().is_some() {
        flags.set(PatternFlags::Wide);
    }

    if pattern.modifiers.fullword().is_some() {
        flags.set(PatternFlags::Fullword);
    }

    // A regexp pattern can use either the `nocase` modifier or the `/i`
    // modifier (e.g: /foobar/i). In both cases it means the same thing.
    if pattern.modifiers.nocase().is_some() || pattern.regexp.case_insensitive
    {
        flags.set(PatternFlags::Nocase);
    }

    // When both the `nocase` modifier and the `/i` modifier are used together,
    // raise a warning because one of them is redundant.
    if pattern.modifiers.nocase().is_some() && pattern.regexp.case_insensitive
    {
        let i_pos = pattern.regexp.literal.rfind('i').unwrap();

        ctx.warnings.add(|| {
            Warning::redundant_case_modifier(
                ctx.report_builder,
                pattern.modifiers.nocase().unwrap().span(),
                pattern.span().subspan(i_pos, i_pos + 1),
            )
        });
    }

    // Notice that regexp patterns can't mix greedy and non-greedy repetitions,
    // like in `/ab.*cd.*?ef/`. All repetitions must have the same greediness.
    // In order to explain why this restriction is necessary consider the
    // regexp /a.*?bbbb/. The atom extracted from this regexp is "bbbb", and
    // once it is found, the rest of the regexp is matched backwards. Now
    // consider the string "abbbbbbbb", there are multiple occurrences of the
    // "bbbb" atom in this string, and every time the atom is found we need to
    // verify if the regexp actually matches. In all cases the regexp matches,
    // but the length of the match is different each time, the first time it
    // finds the match "abbbb", the second time it finds "abbbbb", the third
    // time "abbbbbb", and so on. All these matches occur at the same offset
    // within the string (offset 0), but they have different lengths, which
    // length should we report to the user? Should we report a match at offset
    // 0 with length 6 ("abbbbb")? Or should we report a match at offset 0 with
    // length 9 "abbbbbbbb"? Well, that depends on the greediness of the
    // regexp. In this case the regexp contains a non-greedy repetition
    // (i.e: .*?), therefore the match should be "abbbbb", not "abbbbbbbb". If
    // we replace .*? with .*, then the match should be the longest one,
    // "abbbbbbbb".
    //
    // As long as repetitions in the regexp are all greedy or all non-greedy,
    // we can know the overall greediness of the regexp, and decide whether we
    // should aim for the longest, or the shortest possible match when multiple
    // matches that start at the same offset are found while scanning backwards
    // (right-to-left). However, if the regexp contains a mix of greedy and
    // non-greedy repetitions the decision becomes impossible.
    let hir = re::parser::Parser::new()
        .force_case_insensitive(flags.contains(PatternFlags::Nocase))
        .allow_mixed_greediness(false)
        .relaxed_re_syntax(ctx.relaxed_re_syntax)
        .parse(&pattern.regexp)
        .map_err(|err| {
            re_error_to_compile_error(ctx.report_builder, &pattern.regexp, err)
        })?;

    // TODO: raise warning when .* used, propose using the non-greedy
    // variant .*?

    Ok(PatternInRule {
        identifier: pattern.identifier.name,
        pattern: Pattern::Regexp(RegexpPattern {
            flags,
            hir,
            anchored_at: None,
        }),
    })
}

/// Given the AST for some expression, creates its IR.
pub(in crate::compiler) fn expr_from_ast(
    ctx: &mut CompileContext,
    expr: &ast::Expr,
) -> Result<Expr, Box<CompileError>> {
    match expr {
        ast::Expr::Entrypoint { span } => {
            Err(Box::new(CompileError::entrypoint_unsupported(
                ctx.report_builder,
                *span,
                Some("use `pe.entry_point`, `elf.entry_point` or `macho.entry_point`".to_string()),
            )))
        }
        ast::Expr::Filesize { .. } => Ok(Expr::Filesize),

        ast::Expr::True { .. } => {
            Ok(Expr::Const(TypeValue::const_bool_from(true)))
        }

        ast::Expr::False { .. } => {
            Ok(Expr::Const(TypeValue::const_bool_from(false)))
        }

        ast::Expr::LiteralInteger(literal) => Ok(Expr::Const(
           TypeValue::const_integer_from(literal.value))),

        ast::Expr::LiteralFloat(literal) => Ok(Expr::Const(
            TypeValue::const_float_from(literal.value))),

        ast::Expr::LiteralString(literal) => Ok(Expr::Const(
            TypeValue::const_string_from(literal.value.as_bytes()))),

        ast::Expr::Regexp(regexp) => {
            re::parser::Parser::new()
                .relaxed_re_syntax(ctx.relaxed_re_syntax)
                .parse(regexp.as_ref())
                .map_err(|err| { re_error_to_compile_error(ctx.report_builder, regexp, err)
            })?;

            Ok(Expr::Const(TypeValue::Regexp(Some(Regexp::new(
                    regexp.literal,
                ))),
            ))
        }

        ast::Expr::Defined(expr) => defined_expr_from_ast(ctx, expr),

        // Boolean operations
        ast::Expr::Not(expr) => not_expr_from_ast(ctx, expr),
        ast::Expr::And(operands) => and_expr_from_ast(ctx, operands),
        ast::Expr::Or(operands) => or_expr_from_ast(ctx, operands),

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
        ast::Expr::Matches(expr) => matches_expr_from_ast(ctx, expr),
        ast::Expr::Of(of) => of_expr_from_ast(ctx, of),
        ast::Expr::ForOf(for_of) => for_of_expr_from_ast(ctx, for_of),
        ast::Expr::ForIn(for_in) => for_in_expr_from_ast(ctx, for_in),
        ast::Expr::FuncCall(fn_call) => func_call_from_ast(ctx, fn_call),

        ast::Expr::FieldAccess(expr) => {
            let mut operands = Vec::with_capacity(expr.operands.len());
            // Iterate over all operands except the last one. These operands
            // must be structures. For instance, in `foo.bar.baz`, `foo` and
            // `bar` must be structures, while `baz` can be of any type. This
            // will change in the future when other types can have methods.
            for operand in expr.operands.iter().dropping_back(1) {
                let expr = expr_from_ast(ctx, operand)?;
                check_type(ctx, expr.ty(), operand.span(), &[Type::Struct])?;
                // Set `current_symbol_table` to the symbol table for the type
                // of the expression at the left the field access operator (.).
                // In the expression `foo.bar`, the `current_symbol_table` is
                // set to the symbol table for foo's type, which should have
                // a field or method named `bar`.
                ctx.current_symbol_table =
                    Some(expr.type_value().symbol_table());

                operands.push(expr);
            }

            // Now process the last operand.
            let last_operand =
                expr_from_ast(ctx, expr.operands.last().unwrap())?;

            // If the last operand is constant, the whole expression is
            // constant.
            #[cfg(feature = "constant-folding")]
            if let Expr::Const(type_value) = last_operand {
                // A constant always have a defined value.
                assert!(type_value.is_const());
                return Ok(Expr::Const(type_value));
            }

            operands.push(last_operand);

            Ok(Expr::FieldAccess { operands })
        }

        ast::Expr::Ident(ident) => {
            let current_symbol_table = ctx.current_symbol_table.take();

            let symbol = if let Some(symbol_table) = &current_symbol_table {
                symbol_table.lookup(ident.name)
            } else {
                ctx.symbol_table.lookup(ident.name)
            };

            if symbol.is_none() {
                // If the current symbol table is `None` it means that the
                // identifier is not a field or method of some structure.
                return if current_symbol_table.is_none() {
                    Err(Box::new(CompileError::unknown_identifier(
                        ctx.report_builder,
                        ident.name.to_string(),
                        ident.span(),
                        // Add a note about the missing import statement if
                        // the unknown identifier is a module name.
                        if BUILTIN_MODULES.contains_key(ident.name)
                        {
                            Some(format!(
                                "there is a module named `{}`, but the `import \"{}\"` statement is missing",
                                ident.name,
                                ident.name
                            ))
                        } else {
                            None
                        },
                    )))
                } else {
                    Err(Box::new(CompileError::unknown_field(
                        ctx.report_builder,
                        ident.name.to_string(),
                        ident.span(),
                    )))
                }
            }

            let symbol = symbol.unwrap();
            #[cfg(feature = "constant-folding")]
            {
                let type_value = symbol.type_value();
                if type_value.is_const() {
                    return Ok(Expr::Const(type_value.clone()));
                }
            }

            Ok(Expr::Ident { symbol })
        }

        ast::Expr::PatternMatch(p) => {
            let anchor = anchor_from_ast(ctx, &p.anchor)?;

            // If the identifier is just `$` we are inside a loop and we don't
            // know which is the PatternId because `$` refers to a different
            // pattern on each iteration. In those cases the symbol table must
            // contain an entry for `$`, corresponding to the variable that
            // holds the current PatternId for the loop.
            match p.identifier.name {
                "$" => Ok(Expr::PatternMatchVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                    anchor,
                }),
                _ => {
                    let pattern = ctx.get_pattern_mut(p.identifier.name);

                    if let Some(offset) = anchor.at() {
                        pattern.anchor_at(offset as usize);
                    } else {
                        pattern.make_non_anchorable();
                    }

                    Ok(Expr::PatternMatch {
                        pattern: ctx.get_pattern_index(p.identifier.name),
                        anchor,
                    })
                }
            }
        }

        ast::Expr::PatternCount(p) => {
            // If the identifier is just `#` we are inside a loop and we don't
            // know which is the PatternId because `#` refers to a different
            // pattern on each iteration. In those cases the symbol table must
            // contain an entry for `$`, corresponding to the variable that
            // holds the current PatternId for the loop.
            match (p.name, &p.range) {
                // Cases where the identifier is `#`.
                ("#", Some(range)) => Ok(Expr::PatternCountVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                    range: Some(range_from_ast(ctx, range)?),
                }),
                ("#", None) => Ok(Expr::PatternCountVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                    range: None,
                }),
                // Cases where the identifier is not `#`.
                (_, Some(range)) => {
                    ctx.get_pattern_mut(p.name).make_non_anchorable();
                    Ok(Expr::PatternCount {
                        pattern: ctx.get_pattern_index(p.name),
                        range: Some(range_from_ast(ctx, range)?),
                    })
                }
                (_, None) => {
                    ctx.get_pattern_mut(p.name).make_non_anchorable();
                    Ok(Expr::PatternCount {
                        pattern: ctx.get_pattern_index(p.name),
                        range: None,
                    })
                }
            }
        }

        ast::Expr::PatternOffset(p) => {
            // If the identifier is just `@` we are inside a loop and we don't
            // know which is the PatternId because `@` refers to a different
            // pattern on each iteration. In those cases the symbol table must
            // contain an entry for `$`, corresponding to the variable that
            // holds the current PatternId for the loop.
            match (p.name, &p.index) {
                // Cases where the identifier is `@`.
                ("@", Some(index)) => Ok(Expr::PatternOffsetVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                    index: Some(Box::new(integer_in_range_from_ast(
                        ctx,
                        index,
                        1..=i64::MAX,
                    )?)),
                }),
                ("@", None) => Ok(Expr::PatternOffsetVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                    index: None,
                }),
                // Cases where the identifier is not `@`.
                (_, Some(index)) => {
                    ctx.get_pattern_mut(p.name).make_non_anchorable();
                    Ok(Expr::PatternOffset {
                        pattern: ctx.get_pattern_index(p.name),
                        index: Some(Box::new(integer_in_range_from_ast(
                            ctx,
                            index,
                            1..=i64::MAX,
                        )?)),
                    })
                }
                (_, None) => {
                    ctx.get_pattern_mut(p.name).make_non_anchorable();
                    Ok(Expr::PatternOffset {
                        pattern: ctx.get_pattern_index(p.name),
                        index: None,
                    })
                }
            }
        }

        ast::Expr::PatternLength(p) => {
            // If the identifier is just `!` we are inside a loop and we don't
            // know which is the PatternId because `!` refers to a different
            // pattern on each iteration. In those cases the symbol table must
            // contain an entry for `$`, corresponding to the variable that
            // holds the current PatternId for the loop.
            match (p.name, &p.index) {
                // Cases where the identifier is `!`.
                ("!", Some(index)) => Ok(Expr::PatternLengthVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                    index: Some(Box::new(integer_in_range_from_ast(
                        ctx,
                        index,
                        1..=i64::MAX,
                    )?)),
                }),
                ("!", None) => Ok(Expr::PatternLengthVar {
                    symbol: ctx.symbol_table.lookup("$").unwrap(),
                    index: None,
                }),
                // Cases where the identifier is not `!`.
                (_, Some(index)) => {
                    ctx.get_pattern_mut(p.name).make_non_anchorable();
                    Ok(Expr::PatternLength {
                        pattern: ctx.get_pattern_index(p.name),
                        index: Some(Box::new(integer_in_range_from_ast(
                            ctx,
                            index,
                            1..=i64::MAX,
                        )?)),
                    })
                }
                (_, None) => {
                    ctx.get_pattern_mut(p.name).make_non_anchorable();
                    Ok(Expr::PatternLength {
                        pattern: ctx.get_pattern_index(p.name),
                        index: None,
                    })
                }
            }
        }

        ast::Expr::Lookup(expr) => {
            let primary = Box::new(expr_from_ast(ctx, &expr.primary)?);

            match primary.type_value() {
                TypeValue::Array(array) => {
                    let index = Box::new(non_negative_integer_from_ast(
                        ctx,
                        &expr.index,
                    )?);

                    Ok(Expr::Lookup(Box::new(Lookup {
                        type_value: array.deputy(),
                        primary,
                        index,
                    })))
                }
                TypeValue::Map(map) => {
                    let (key_ty, deputy_value) = match map.borrow() {
                        Map::IntegerKeys { deputy: Some(value), .. } => {
                            (Type::Integer, value)
                        }
                        Map::StringKeys { deputy: Some(value), .. } => {
                            (Type::String, value)
                        }
                        _ => unreachable!(),
                    };

                    let index = Box::new(expr_from_ast(ctx, &expr.index)?);
                    let ty = index.ty();

                    // The type of the key/index expression should correspond
                    // with the type of the map's keys.
                    if key_ty != ty {
                        return Err(Box::new(CompileError::wrong_type(
                                ctx.report_builder,
                                format!("`{}`", key_ty),
                                ty.to_string(),
                                expr.index.span(),
                            ),
                        ));
                    }

                    Ok(Expr::Lookup(Box::new(Lookup {
                        type_value: deputy_value.clone(),
                        primary,
                        index,
                    })))
                }
                type_value => {
                    Err(Box::new(CompileError::wrong_type(
                        ctx.report_builder,
                        format!("`{}` or `{}`", Type::Array, Type::Map),
                        type_value.ty().to_string(),
                        expr.primary.span(),
                    )))
                }
            }
        }
    }
}

pub(in crate::compiler) fn bool_expr_from_ast(
    ctx: &mut CompileContext,
    ast: &ast::Expr,
) -> Result<Expr, Box<CompileError>> {
    let expr = expr_from_ast(ctx, ast)?;
    warn_if_not_bool(ctx, expr.ty(), ast.span());
    Ok(expr)
}

fn of_expr_from_ast(
    ctx: &mut CompileContext,
    of: &ast::Of,
) -> Result<Expr, Box<CompileError>> {
    let quantifier = quantifier_from_ast(ctx, &of.quantifier)?;
    // Create new stack frame with 5 slots:
    //   1 slot for the loop variable, a bool in this case.
    //   4 up to slots used for loop control variables (see: emit::emit_for)
    let stack_frame = ctx.vars.new_frame(5);

    let (items, num_items) = match &of.items {
        // `x of (<boolean expr>, <boolean expr>, ...)`
        ast::OfItems::BoolExprTuple(tuple) => {
            let tuple = tuple
                .iter()
                .map(|e| {
                    let expr = expr_from_ast(ctx, e)?;
                    check_type(ctx, expr.ty(), e.span(), &[Type::Bool])?;
                    Ok(expr)
                })
                .collect::<Result<Vec<Expr>, Box<CompileError>>>()?;

            let num_items = tuple.len();
            (OfItems::BoolExprTuple(tuple), num_items)
        }
        // `x of them`, `x of ($a*, $b)`
        ast::OfItems::PatternSet(pattern_set) => {
            let pattern_indexes = pattern_set_from_ast(ctx, pattern_set)?;
            let num_patterns = pattern_indexes.len();
            (OfItems::PatternSet(pattern_indexes), num_patterns)
        }
    };

    // If the quantifier expression is greater than the number of items,
    // the `of` expression is always false.
    if let Quantifier::Expr(expr) = &quantifier {
        if let TypeValue::Integer(Value::Const(value)) = expr.type_value() {
            if value > num_items.try_into().unwrap() {
                ctx.warnings.add(|| Warning::invariant_boolean_expression(
                    ctx.report_builder,
                    false,
                    of.span(),
                    Some(format!(
                        "the expression requires {} matching patterns out of {}",
                        value, num_items
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
    if matches!(of.anchor, Some(ast::MatchAnchor::At(_))) {
        let raise_warning = match &quantifier {
            // `all of <items> at <expr>`: the warning is raised only if there
            // are more than one item. `all of ($a) at 0` doesn't raise a
            // warning.
            Quantifier::All { .. } => num_items > 1,
            // `<expr> of <items> at <expr>: the warning is raised if <expr> is
            // 2 or more.
            Quantifier::Expr(expr) => match expr.type_value() {
                TypeValue::Integer(Value::Const(value)) => value >= 2,
                _ => false,
            },
            // `<expr>% of <items> at <expr>: the warning is raised if the
            // <expr> percent of the items is 2 or more.
            Quantifier::Percentage(expr) => match expr.type_value() {
                TypeValue::Integer(Value::Const(percentage)) => {
                    num_items as f64 * percentage as f64 / 100.0 >= 2.0
                }
                _ => false,
            },
            Quantifier::None { .. } | Quantifier::Any { .. } => false,
        };

        if raise_warning {
            ctx.warnings.add(|| {
                Warning::potentially_unsatisfiable_expression(
                    ctx.report_builder,
                    of.quantifier.span(),
                    of.anchor.as_ref().unwrap().span(),
                )
            });
        }
    }

    let anchor = anchor_from_ast(ctx, &of.anchor)?;

    ctx.vars.unwind(&stack_frame);

    Ok(Expr::Of(Box::new(Of { quantifier, items, anchor, stack_frame })))
}

fn for_of_expr_from_ast(
    ctx: &mut CompileContext,
    for_of: &ast::ForOf,
) -> Result<Expr, Box<CompileError>> {
    let quantifier = quantifier_from_ast(ctx, &for_of.quantifier)?;
    let pattern_set = pattern_set_from_ast(ctx, &for_of.pattern_set)?;
    // Create new stack frame with 5 slots:
    //   1 slot for the loop variable, a pattern ID in this case
    //   4 up to slots used for loop control variables (see: emit::emit_for)
    let mut stack_frame = ctx.vars.new_frame(5);
    let next_pattern_id = stack_frame.new_var(Type::Integer);
    let mut loop_vars = SymbolTable::new();

    loop_vars.insert(
        "$",
        Symbol::new(
            TypeValue::Integer(Value::Unknown),
            SymbolKind::Var(next_pattern_id),
        ),
    );

    ctx.symbol_table.push(Rc::new(loop_vars));

    let condition = bool_expr_from_ast(ctx, &for_of.condition)?;

    ctx.symbol_table.pop();
    ctx.vars.unwind(&stack_frame);

    Ok(Expr::ForOf(Box::new(ForOf {
        quantifier,
        pattern_set,
        condition,
        stack_frame,
        variable: next_pattern_id,
    })))
}

fn for_in_expr_from_ast(
    ctx: &mut CompileContext,
    for_in: &ast::ForIn,
) -> Result<Expr, Box<CompileError>> {
    let quantifier = quantifier_from_ast(ctx, &for_in.quantifier)?;
    let iterable = iterable_from_ast(ctx, &for_in.iterable)?;

    let expected_vars = match &iterable {
        Iterable::Range(_) => vec![TypeValue::Integer(Value::Unknown)],
        Iterable::ExprTuple(expressions) => {
            // All expressions in the tuple have the same type, we can use
            // the type of the first item in the tuple as the type of the
            // loop variable. Notice that we are using `clone_without_value`
            // instead of `clone`, because we want a TypeValue with the same
            // type as the first item in the tuple, but we don't want to
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
                    vec![TypeValue::Integer(Value::Unknown), map.deputy()]
                }
                Map::StringKeys { .. } => {
                    vec![TypeValue::String(Value::Unknown), map.deputy()]
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
        return Err(Box::new(CompileError::assignment_mismatch(
            ctx.report_builder,
            loop_vars.len() as u8,
            expected_vars.len() as u8,
            for_in.iterable.span(),
            span,
        )));
    }

    // Create stack frame with capacity for the loop variables, plus 4
    // temporary variables used for controlling the loop (see emit_for),
    // plus one additional variable used in loops over arrays and maps
    // (see emit_for_in_array and emit_for_in_map).
    let mut stack_frame = ctx.vars.new_frame(loop_vars.len() as i32 + 5);
    let mut symbols = SymbolTable::new();
    let mut variables = Vec::new();

    // TODO: raise warning when the loop identifier (e.g: "i") hides
    // an existing identifier with the same name.
    for (loop_var, type_value) in iter::zip(loop_vars, expected_vars) {
        let var = stack_frame.new_var(type_value.ty());
        variables.push(var);
        symbols.insert(
            loop_var.name,
            Symbol::new(type_value, SymbolKind::Var(var)),
        );
    }

    // Put the loop variables into scope.
    ctx.symbol_table.push(Rc::new(symbols));

    let condition = bool_expr_from_ast(ctx, &for_in.condition)?;

    // Leaving the condition's scope. Remove loop variables.
    ctx.symbol_table.pop();

    ctx.vars.unwind(&stack_frame);

    Ok(Expr::ForIn(Box::new(ForIn {
        quantifier,
        variables,
        iterable,
        condition,
        stack_frame,
    })))
}

fn iterable_from_ast(
    ctx: &mut CompileContext,
    iter: &ast::Iterable,
) -> Result<Iterable, Box<CompileError>> {
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
                        return Err(Box::new(
                            CompileError::mismatching_types(
                                ctx.report_builder,
                                prev_ty.to_string(),
                                ty.to_string(),
                                prev_span,
                                span,
                            ),
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

fn anchor_from_ast(
    ctx: &mut CompileContext,
    anchor: &Option<ast::MatchAnchor>,
) -> Result<MatchAnchor, Box<CompileError>> {
    match anchor {
        Some(ast::MatchAnchor::At(at_)) => Ok(MatchAnchor::At(Box::new(
            non_negative_integer_from_ast(ctx, &at_.expr)?,
        ))),
        Some(ast::MatchAnchor::In(in_)) => {
            Ok(MatchAnchor::In(range_from_ast(ctx, &in_.range)?))
        }
        None => Ok(MatchAnchor::None),
    }
}

fn range_from_ast(
    ctx: &mut CompileContext,
    range: &ast::Range,
) -> Result<Range, Box<CompileError>> {
    let lower_bound =
        Box::new(non_negative_integer_from_ast(ctx, &range.lower_bound)?);

    let upper_bound =
        Box::new(non_negative_integer_from_ast(ctx, &range.upper_bound)?);

    // If both the lower and upper bounds are known at compile time, make sure
    // that lower_bound <= upper_bound. If they are not know (because they are
    // variables, for example) we can't raise an error at compile time but it
    // will be handled at scan time.
    if let (
        TypeValue::Integer(Value::Const(lower_bound)),
        TypeValue::Integer(Value::Const(upper_bound)),
    ) = (lower_bound.type_value(), upper_bound.type_value())
    {
        if lower_bound > upper_bound {
            return Err(Box::new(CompileError::invalid_range(
                ctx.report_builder,
                range.span,
            )));
        }
    }

    Ok(Range { lower_bound, upper_bound })
}

fn non_negative_integer_from_ast(
    ctx: &mut CompileContext,
    expr: &ast::Expr,
) -> Result<Expr, Box<CompileError>> {
    let span = expr.span();
    let expr = expr_from_ast(ctx, expr)?;
    let type_value = expr.type_value();

    check_type(ctx, type_value.ty(), span, &[Type::Integer])?;

    if let TypeValue::Integer(Value::Const(value)) = type_value {
        if value < 0 {
            return Err(Box::new(CompileError::unexpected_negative_number(
                ctx.report_builder,
                span,
            )));
        }
    }

    Ok(expr)
}

fn integer_in_range_from_ast(
    ctx: &mut CompileContext,
    expr: &ast::Expr,
    range: RangeInclusive<i64>,
) -> Result<Expr, Box<CompileError>> {
    let span = expr.span();
    let expr = expr_from_ast(ctx, expr)?;
    let type_value = expr.type_value();

    check_type(ctx, type_value.ty(), span, &[Type::Integer])?;

    // If the value is known at compile time make sure that it is within
    // the given range.
    if let TypeValue::Integer(Value::Const(value)) = type_value {
        if !range.contains(&value) {
            return Err(Box::new(CompileError::number_out_of_range(
                ctx.report_builder,
                *range.start(),
                *range.end(),
                span,
            )));
        }
    }

    Ok(expr)
}

fn quantifier_from_ast(
    ctx: &mut CompileContext,
    quantifier: &ast::Quantifier,
) -> Result<Quantifier, Box<CompileError>> {
    match quantifier {
        ast::Quantifier::None { .. } => Ok(Quantifier::None),
        ast::Quantifier::All { .. } => Ok(Quantifier::All),
        ast::Quantifier::Any { .. } => Ok(Quantifier::Any),
        ast::Quantifier::Percentage(expr) => {
            // The percentage must be between 0 and 100, both inclusive.
            Ok(Quantifier::Percentage(integer_in_range_from_ast(
                ctx,
                expr,
                0..=100,
            )?))
        }
        ast::Quantifier::Expr(expr) => {
            Ok(Quantifier::Expr(non_negative_integer_from_ast(ctx, expr)?))
        }
    }
}

fn pattern_set_from_ast(
    ctx: &mut CompileContext,
    pattern_set: &ast::PatternSet,
) -> Result<Vec<PatternIdx>, Box<CompileError>> {
    let pattern_indexes = match pattern_set {
        // `x of them`
        ast::PatternSet::Them { span } => {
            let pattern_indexes: Vec<PatternIdx> =
                (0..ctx.current_rule_patterns.len())
                    .map(|i| i.into())
                    .collect();

            if pattern_indexes.is_empty() {
                return Err(Box::new(CompileError::empty_pattern_set(
                    ctx.report_builder,
                    *span,
                    Some("this rule doesn't define any patterns".to_string()),
                )));
            }

            // Make all the patterns in the set non-anchorable.
            for pattern in ctx.current_rule_patterns.iter_mut() {
                pattern.make_non_anchorable();
            }

            pattern_indexes
        }
        // `x of ($a*, $b)`
        ast::PatternSet::Set(ref set) => {
            for item in set {
                if !ctx
                    .current_rule_patterns
                    .iter()
                    .any(|pattern| item.matches(pattern.identifier()))
                {
                    return Err(Box::new(CompileError::empty_pattern_set(
                        ctx.report_builder,
                        item.span(),
                        Some(format!(
                            "`{}` doesn't match any pattern identifier",
                            item.identifier,
                        )),
                    )));
                }
            }
            let mut pattern_indexes = Vec::new();
            for (i, pattern) in
                ctx.current_rule_patterns.iter_mut().enumerate()
            {
                // Iterate over the patterns in the set (e.g: $foo, $foo*) and
                // check if some of them matches the identifier.
                if set.iter().any(|p| p.matches(pattern.identifier())) {
                    pattern_indexes.push(i.into());
                    // All the patterns in the set are made non-anchorable.
                    pattern.make_non_anchorable();
                }
            }
            pattern_indexes
        }
    };

    Ok(pattern_indexes)
}

fn func_call_from_ast(
    ctx: &mut CompileContext,
    func_call: &ast::FuncCall,
) -> Result<Expr, Box<CompileError>> {
    let callable = expr_from_ast(ctx, &func_call.callable)?;
    let type_value = callable.type_value();

    check_type(
        ctx,
        type_value.ty(),
        func_call.callable.span(),
        &[Type::Func],
    )?;

    let args = func_call
        .args
        .iter()
        .map(|arg| expr_from_ast(ctx, arg))
        .collect::<Result<Vec<Expr>, Box<CompileError>>>()?;

    let arg_types: Vec<Type> = args.iter().map(|arg| arg.ty()).collect();

    let mut expected_args = Vec::new();
    let mut matching_signature = None;
    let func = type_value.as_func();

    // Determine if any of the signatures for the called function matches
    // the provided arguments.
    for (i, signature) in func.signatures().iter().enumerate() {
        // If the function is actually a method, the first argument is always
        // the type the method belongs to (i.e: the self pointer). This
        // argument appears in the function's signature, but is not expected
        // to appear among the arguments in the call statement.
        let expected_arg_types: Vec<Type> = if func.method_of().is_some() {
            signature.args.iter().skip(1).map(|arg| arg.ty()).collect()
        } else {
            signature.args.iter().map(|arg| arg.ty()).collect()
        };

        if arg_types == expected_arg_types {
            matching_signature = Some((i, signature.result.clone()));
            break;
        }

        expected_args.push(expected_arg_types);
    }

    // No matching signature was found, that means that the arguments
    // provided were incorrect.
    if matching_signature.is_none() {
        return Err(Box::new(CompileError::wrong_arguments(
            ctx.report_builder,
            func_call.args_span,
            Some(format!(
                "accepted argument combinations:\n\n{}",
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
                    .join("\n")
            )),
        )));
    }

    let (signature_index, type_value) = matching_signature.unwrap();

    Ok(Expr::FuncCall(Box::new(FuncCall {
        callable,
        type_value,
        signature_index,
        args,
    })))
}

fn matches_expr_from_ast(
    ctx: &mut CompileContext,
    expr: &ast::BinaryExpr,
) -> Result<Expr, Box<CompileError>> {
    let span = expr.span();
    let lhs_span = expr.lhs.span();
    let rhs_span = expr.rhs.span();

    let lhs = Box::new(expr_from_ast(ctx, &expr.lhs)?);
    let rhs = Box::new(expr_from_ast(ctx, &expr.rhs)?);

    check_type(ctx, lhs.ty(), lhs_span, &[Type::String])?;
    check_type(ctx, rhs.ty(), rhs_span, &[Type::Regexp])?;

    let expr = Expr::Matches { lhs, rhs };

    if cfg!(feature = "constant-folding") {
        expr.fold(ctx, span)
    } else {
        Ok(expr)
    }
}

fn check_type(
    ctx: &CompileContext,
    ty: Type,
    span: Span,
    accepted_types: &[Type],
) -> Result<(), Box<CompileError>> {
    if accepted_types.contains(&ty) {
        Ok(())
    } else {
        Err(Box::new(CompileError::wrong_type(
            ctx.report_builder,
            ErrorInfo::join_with_or(accepted_types, true),
            ty.to_string(),
            span,
        )))
    }
}

fn check_operands(
    ctx: &CompileContext,
    lhs_ty: Type,
    rhs_ty: Type,
    lhs_span: Span,
    rhs_span: Span,
    accepted_types: &[Type],
    compatible_types: &[Type],
) -> Result<(), Box<CompileError>> {
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
        return Err(Box::new(CompileError::mismatching_types(
            ctx.report_builder,
            lhs_ty.to_string(),
            rhs_ty.to_string(),
            lhs_span,
            rhs_span,
        )));
    }

    Ok(())
}

fn re_error_to_compile_error(
    report_builder: &ReportBuilder,
    regexp: &ast::Regexp,
    err: re::parser::Error,
) -> CompileError {
    match err {
        Error::SyntaxError { msg, span, note } => {
            CompileError::invalid_regexp(
                report_builder,
                msg,
                // the error span is relative to the start of the regexp, not to
                // the start of the source file, here we make it relative to the
                // source file.
                regexp.span.subspan(span.start.offset, span.end.offset),
                note,
            )
        }
        Error::MixedGreediness {
            is_greedy_1,
            is_greedy_2,
            span_1,
            span_2,
        } => CompileError::mixed_greediness(
            report_builder,
            if is_greedy_1 { "greedy" } else { "non-greedy" }.to_string(),
            if is_greedy_2 { "greedy" } else { "non-greedy" }.to_string(),
            regexp.span.subspan(span_1.start.offset, span_1.end.offset),
            regexp.span.subspan(span_2.start.offset, span_2.end.offset),
        ),
    }
}

/// Produce a warning if the expression is not boolean.
pub(in crate::compiler) fn warn_if_not_bool(
    ctx: &mut CompileContext,
    ty: Type,
    span: Span,
) {
    if !matches!(ty, Type::Bool) {
        ctx.warnings.add(|| {
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
            Warning::non_boolean_as_boolean(
                ctx.report_builder,
                ty.to_string(),
                span,
                note,
            )
        });
    }
}

macro_rules! gen_unary_op {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &ast::UnaryExpr,
        ) -> Result<Expr, Box<CompileError>> {
            let span = expr.span();
            let operand = Box::new(expr_from_ast(ctx, &expr.operand)?);

            check_type(
                ctx,
                operand.ty(),
                expr.operand.span(),
                &[$( $accepted_types ),+],
            )?;

            let check_fn:
                Option<fn(&mut CompileContext, &Expr, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &operand, expr.operand.span())?;
            }

            let expr = Expr::$variant { operand };

            if cfg!(feature = "constant-folding") {
                expr.fold(ctx, span)
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_binary_op {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $( $compatible_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &ast::BinaryExpr,
        ) -> Result<Expr, Box<CompileError>> {
            let span = expr.span();
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
                Option<fn(&mut CompileContext, &Expr, &Expr, Span, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &lhs, &rhs, lhs_span, rhs_span)?;
            }

            let expr = Expr::$variant { lhs, rhs };

            if cfg!(feature = "constant-folding") {
                expr.fold(ctx, span)
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_string_op {
    ($name:ident, $variant:ident) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &ast::BinaryExpr,
        ) -> Result<Expr, Box<CompileError>> {
            let span = expr.span();
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

            let expr = Expr::$variant { lhs, rhs };

            if cfg!(feature = "constant-folding") {
                expr.fold(ctx, span)
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_n_ary_operation {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $( $compatible_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &ast::NAryExpr,
        ) -> Result<Expr, Box<CompileError>> {
            let span = expr.span();
            let accepted_types = &[$( $accepted_types ),+];
            let compatible_types = &[$( $compatible_types ),+];

            let operands_hir: Vec<Expr> = expr
                .operands()
                .map(|expr| expr_from_ast(ctx, expr))
                .collect::<Result<Vec<Expr>, Box<CompileError>>>()?;

            let check_fn:
                Option<fn(&mut CompileContext, &Expr, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            // Make sure that all operands have one of the accepted types.
            for (hir, ast) in iter::zip(operands_hir.iter(), expr.operands()) {
                check_type(ctx, hir.ty(), ast.span(), accepted_types)?;
                if let Some(check_fn) = check_fn {
                    check_fn(ctx, hir, ast.span())?;
                }
            }

            // Iterate the operands in pairs (first, second), (second, third),
            // (third, fourth), etc.
            for ((lhs_hir, rhs_ast), (rhs_hir, lhs_ast)) in
                iter::zip(operands_hir.iter(), expr.operands()).tuple_windows()
            {
                let lhs_ty = lhs_hir.ty();
                let rhs_ty = rhs_hir.ty();

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
                    return Err(Box::new(CompileError::mismatching_types(
                            ctx.report_builder,
                            lhs_ty.to_string(),
                            rhs_ty.to_string(),
                            expr.first().span().combine(&lhs_ast.span()),
                            rhs_ast.span(),
                        ),
                    ));
                }
            }

            let expr = Expr::$variant { operands: operands_hir };

            if cfg!(feature = "constant-folding") {
                expr.fold(ctx, span)
            } else {
                Ok(expr)
            }
        }
    };
}

gen_unary_op!(
    defined_expr_from_ast,
    Defined,
    Type::Bool | Type::Integer | Type::Float | Type::String,
    None
);

gen_unary_op!(
    not_expr_from_ast,
    Not,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // Raise warning if the operand is not bool.
    Some(|ctx, operand, span| {
        warn_if_not_bool(ctx, operand.ty(), span);
        Ok(())
    })
);

gen_n_ary_operation!(
    and_expr_from_ast,
    And,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // All operand types can be mixed in a boolean operation, as they
    // are casted to boolean anyways.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    Some(|ctx, operand, span| {
        warn_if_not_bool(ctx, operand.ty(), span);
        Ok(())
    })
);

gen_n_ary_operation!(
    or_expr_from_ast,
    Or,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // All operand types can be mixed in a boolean operation, as they
    // are casted to boolean anyways.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    Some(|ctx, operand, span| {
        warn_if_not_bool(ctx, operand.ty(), span);
        Ok(())
    })
);

gen_unary_op!(minus_expr_from_ast, Minus, Type::Integer | Type::Float, None);

gen_n_ary_operation!(
    add_expr_from_ast,
    Add,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_operation!(
    sub_expr_from_ast,
    Sub,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_operation!(
    mul_expr_from_ast,
    Mul,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_operation!(
    div_expr_from_ast,
    Div,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_operation!(
    mod_expr_from_ast,
    Mod,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    shl_expr_from_ast,
    Shl,
    Type::Integer,
    Type::Integer,
    Some(|ctx, _lhs, rhs, _lhs_span, rhs_span| {
        if let TypeValue::Integer(Value::Const(value)) = rhs.type_value() {
            if value < 0 {
                return Err(Box::new(
                    CompileError::unexpected_negative_number(
                        ctx.report_builder,
                        rhs_span,
                    ),
                ));
            }
        }
        Ok(())
    })
);

gen_binary_op!(
    shr_expr_from_ast,
    Shr,
    Type::Integer,
    Type::Integer,
    Some(|ctx, _lhs, rhs, _lhs_span, rhs_span| {
        if let TypeValue::Integer(Value::Const(value)) = rhs.type_value() {
            if value < 0 {
                return Err(Box::new(
                    CompileError::unexpected_negative_number(
                        ctx.report_builder,
                        rhs_span,
                    ),
                ));
            }
        }
        Ok(())
    })
);

gen_unary_op!(bitwise_not_expr_from_ast, BitwiseNot, Type::Integer, None);

gen_binary_op!(
    bitwise_and_expr_from_ast,
    BitwiseAnd,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    bitwise_or_expr_from_ast,
    BitwiseOr,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    bitwise_xor_expr_from_ast,
    BitwiseXor,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    eq_expr_from_ast,
    Eq,
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
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_string_op!(contains_expr_from_ast, Contains);
gen_string_op!(icontains_expr_from_ast, IContains);
gen_string_op!(startswith_expr_from_ast, StartsWith);
gen_string_op!(istartswith_expr_from_ast, IStartsWith);
gen_string_op!(endswith_expr_from_ast, EndsWith);
gen_string_op!(iendswith_expr_from_ast, IEndsWith);
gen_string_op!(iequals_expr_from_ast, IEquals);
