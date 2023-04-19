/*! This module emits the WASM code for conditions in YARA rules.

The entry point for this module is the [`emit_rule_code`] function, which
emits the WASM a code for a single YARA rule. This function calls other
functions in the module which generate WASM code for specific kinds of
expressions or language constructs.
 */

use std::mem::size_of;
use std::rc::Rc;

use bstr::ByteSlice;
use walrus::ir::ExtendedLoad::ZeroExtend;
use walrus::ir::{BinaryOp, InstrSeqId, LoadKind, MemArg, StoreKind, UnaryOp};
use walrus::ValType::{I32, I64};
use walrus::{InstrSeqBuilder, ValType};
use yara_x_parser::ast::OfItems;
use yara_x_parser::ast::{
    Expr, ForIn, Iterable, MatchAnchor, PatternSet, Quantifier, Range, Rule,
};
use yara_x_parser::ast::{ForOf, Of};
use yara_x_parser::types::{Array, Map, Type, TypeValue};

use crate::compiler::{Context, PatternId, RuleId, Var};
use crate::symbols::{Symbol, SymbolKind, SymbolLookup, SymbolTable};
use crate::wasm;
use crate::wasm::string::RuntimeString;
use crate::wasm::{
    LOOKUP_INDEXES_END, LOOKUP_INDEXES_START, MATCHING_RULES_BITMAP_BASE,
    VARS_STACK_START,
};

/// This macro emits a constant if the [`TypeValue`] indicates that the
/// expression has a constant value (e.i: the value is known at compile time),
/// if not, it executes the code block, emitting whatever the code block says.
/// Notice however that this is done only if the `compile-time-optimization`
/// feature is enabled, if the feature is not enabled the code block will be
/// executed regardless of whether the expression's value is known at compile
/// time or not.
///
/// # Example
///
/// This is how we emit the code for the `add` operation:
///
/// ```text
///emit_const_or_code!(ctx, instr, expr.type_value(), {
///    emit_expr(ctx, instr, &operands.lhs);
///    emit_expr(ctx, instr, &operands.rhs);
///    instr.binop(BinaryOp::I64Add);
///});
/// ```
///
/// In the code above, if the value for `expr` is known at compile time (e.g:
/// the expression is `2+2`), the code emitted would be simply a `i64.const`
/// instruction that pushes that value in the stack. (e.g: `i64.const 4`). If
/// the value is not known at compile time, the code block will be executed,
/// emitting the code for the left and right operands, plus the `i64.add`
/// instruction that sums the results from both operands.
///
macro_rules! emit_const_or_code {
    ($ctx:ident, $instr:ident, $type_value:expr, $code:block) => {{
        if cfg!(feature = "compile-time-optimization") {
            match &*$type_value {
                TypeValue::Bool(Some(value)) => {
                    $instr.i32_const((*value) as i32);
                }
                TypeValue::Integer(Some(value)) => {
                    $instr.i64_const(*value);
                }
                TypeValue::Float(Some(value)) => {
                    $instr.f64_const(*value);
                }
                TypeValue::String(Some(value)) => {
                    // Put the literal string in the pool, or get its ID if it was
                    // already there.
                    let literal_id =
                        $ctx.lit_pool.get_or_intern(value.as_bstr());

                    $instr.i64_const(RuntimeString::Literal(literal_id).as_wasm() as i64);
                }
                _ => $code,
            }
        } else {
            $code
        }
    }};
}

/// This macro emits the code for the left and right operands of some
/// operation, converting integer operands to float if the other operand
/// is a float.
macro_rules! emit_operands {
    ($ctx:ident, $instr:ident, $lhs:expr, $rhs:expr) => {{
        let mut lhs_type = $lhs.ty();
        let mut rhs_type = $rhs.ty();

        emit_expr($ctx, $instr, &$lhs);

        // If the left operand is integer, but the right one is float,
        // convert the left operand to float.
        if lhs_type == Type::Integer && rhs_type == Type::Float {
            $instr.unop(UnaryOp::F64ConvertSI64);
            lhs_type = Type::Float;
        }

        emit_expr($ctx, $instr, &$rhs);

        // If the right operand is integer, but the left one is float,
        // convert the right operand to float.
        if lhs_type == Type::Float && rhs_type == Type::Integer {
            $instr.unop(UnaryOp::F64ConvertSI64);
            rhs_type = Type::Float;
        }

        (lhs_type, rhs_type)
    }};
}

macro_rules! emit_arithmetic_op {
    ($ctx:ident, $instr:ident, $expr:expr, $operands:expr, $int_op:tt, $float_op:tt) => {{
        emit_const_or_code!($ctx, $instr, $expr.type_value(), {
            match emit_operands!($ctx, $instr, $operands.lhs, $operands.rhs) {
                (Type::Integer, Type::Integer) => {
                    // Both operands are integer, the operation is integer.
                    $instr.binop(BinaryOp::$int_op);
                }
                (Type::Float, Type::Float) => {
                    // Both operands are float, the operation is float.
                    $instr.binop(BinaryOp::$float_op);
                }
                _ => unreachable!(),
            };
        });
    }};
}

macro_rules! emit_comparison_op {
    ($ctx:ident, $instr:ident, $expr:expr, $operands:expr, $int_op:tt, $float_op:tt, $str_op:expr) => {{
        emit_const_or_code!($ctx, $instr, $expr.type_value(), {
            match emit_operands!($ctx, $instr, $operands.lhs, $operands.rhs) {
                (Type::Integer, Type::Integer) => {
                    $instr.binop(BinaryOp::$int_op);
                }
                (Type::Float, Type::Float) => {
                    $instr.binop(BinaryOp::$float_op);
                }
                (Type::String, Type::String) => {
                    $instr.call($ctx.function_id($str_op));
                }
                _ => unreachable!(),
            };
        });
    }};
}

macro_rules! emit_shift_op {
    ($ctx:ident, $instr:ident, $expr:expr, $operands:expr, $int_op:tt) => {{
        emit_const_or_code!($ctx, $instr, $expr.type_value(), {
            match emit_operands!($ctx, $instr, $operands.lhs, $operands.rhs) {
                (Type::Integer, Type::Integer) => {
                    // When the left operand is >= 64, shift operations don't
                    // behave in the same way in WebAssembly and YARA. In YARA,
                    // 1 << 64 == 0, but in WebAssembly 1 << 64 == 1.
                    // In general, X << Y behaves as X << (Y mod 64) in
                    // WebAssembly, while in YARA the result is always 0 for
                    // every Y >= 64. The sames applies for X >> Y.
                    //
                    // For that reason shift operations require some additional
                    // code. The code for shift-left goes like this:
                    //
                    //  eval lhs
                    //  eval rhs
                    //  move rhs to tmp while leaving it in the stack (local_tee)
                    //  push result form shift operation
                    //  push 0
                    //  push rhs (from tmp)
                    //  push 64
                    //  is rhs less than 64?
                    //  if true                               ┐
                    //     push result form shift operation   │  select
                    //  else                                  │
                    //     push 0                             ┘
                    //
                    $instr.local_tee($ctx.wasm_symbols.i64_tmp);
                    $instr.binop(BinaryOp::$int_op);
                    $instr.i64_const(0);
                    $instr.local_get($ctx.wasm_symbols.i64_tmp);
                    $instr.i64_const(64);
                    $instr.binop(BinaryOp::I64LtS);
                    $instr.select(Some(I64));
                }
                _ => unreachable!(),
            };
        });
    }};
}

macro_rules! emit_bitwise_op {
    ($ctx:ident, $instr:ident, $expr:expr, $operands:expr, $int_op:tt) => {{
        emit_const_or_code!($ctx, $instr, $expr.type_value(), {
            match emit_operands!($ctx, $instr, $operands.lhs, $operands.rhs) {
                (Type::Integer, Type::Integer) => {
                    $instr.binop(BinaryOp::$int_op)
                }
                _ => unreachable!(),
            };
        });
    }};
}

/// Emits WASM code of a rule.
pub(super) fn emit_rule_code(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    rule_id: RuleId,
    rule: &Rule,
) {
    // Emit WASM code for the rule's condition.
    instr.block(None, |block| {
        catch_undef(ctx, block, |ctx, instr| {
            emit_bool_expr(ctx, instr, &rule.condition);
        });

        // If the condition's result is 0, jump out of the block
        // and don't call the `rule_match` function.
        block.unop(UnaryOp::I32Eqz);
        block.br_if(block.id());

        // RuleId is the argument to `rule_match`.
        block.i32_const(rule_id.0);

        // Emit call instruction for calling `rule_match`.
        block.call(ctx.function_id(wasm::export__rule_match.mangled_name));
    });
}

/// Emits code that checks if the pattern search phase has not been executed
/// yet, and do it in that case.
fn emit_lazy_pattern_search(ctx: &mut Context, instr: &mut InstrSeqBuilder) {
    instr.local_get(ctx.wasm_symbols.pattern_search_done);
    instr.if_else(
        None,
        |_then| {
            // The pattern search phase was already executed. Nothing to
            // do here.
        },
        |_else| {
            // Search for patterns.
            _else.call(
                ctx.function_id(
                    wasm::export__search_for_patterns.mangled_name,
                ),
            );
            // Set pattern_search_done to true.
            _else.i32_const(1);
            _else.local_set(ctx.wasm_symbols.pattern_search_done);
        },
    );
}

/// Emits the code that determines if some pattern is matching.
///
/// This function assumes that the pattern ID is at the top of the stack.
fn emit_pattern_match(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    anchor: Option<&MatchAnchor>,
) {
    match anchor {
        Some(MatchAnchor::At(anchor_at)) => {
            emit_expr(ctx, instr, &anchor_at.expr);
            instr.call(
                ctx.function_id(wasm::export__is_pat_match_at.mangled_name),
            );
        }
        Some(MatchAnchor::In(anchor_in)) => {
            emit_expr(ctx, instr, &anchor_in.range.lower_bound);
            emit_expr(ctx, instr, &anchor_in.range.upper_bound);
            instr.call(
                ctx.function_id(wasm::export__is_pat_match_in.mangled_name),
            );
        }
        None => {
            emit_check_for_pattern_match(ctx, instr);
        }
    }
}

/// Emits WASM code for `expr` into the instruction sequence `instr`.
fn emit_expr(ctx: &mut Context, instr: &mut InstrSeqBuilder, expr: &Expr) {
    match expr {
        Expr::True { .. } => {
            instr.i32_const(1);
        }
        Expr::False { .. } => {
            instr.i32_const(0);
        }
        Expr::Filesize { .. } => {
            instr.global_get(ctx.wasm_symbols.filesize);
        }
        Expr::Entrypoint { .. } => {
            todo!()
        }
        Expr::Regexp(_) => {
            todo!()
        }
        Expr::Literal(lit) => match &lit.type_value {
            TypeValue::Integer(Some(value)) => {
                instr.i64_const(*value);
            }
            TypeValue::Float(Some(value)) => {
                instr.f64_const(*value);
            }
            TypeValue::Bool(Some(value)) => {
                instr.i32_const((*value) as i32);
            }
            TypeValue::String(Some(value)) => {
                // Put the literal string in the pool, or get its ID if it was
                // already there.
                let literal_id = ctx.lit_pool.get_or_intern(value.as_bstr());

                instr.i64_const(RuntimeString::Literal(literal_id).as_wasm());
            }
            _ => unreachable!(),
        },
        Expr::Ident(ident) => {
            emit_const_or_code!(ctx, instr, &ident.type_value, {
                // Search for the identifier in the current structure, if any,
                // or in the global symbol table if `current_struct` is None.
                let symbol = if let Some(current_struct) = &ctx.current_struct
                {
                    current_struct.lookup(ident.name).unwrap()
                } else {
                    ctx.symbol_table.lookup(ident.name).unwrap()
                };

                match symbol.kind {
                    SymbolKind::Unknown => {
                        unreachable!(
                            "symbol kind must be known while emitting code"
                        )
                    }
                    SymbolKind::Rule(rule_id) => {
                        // Emit code that checks if a rule has matched, leaving
                        // zero or one at the top of the stack.
                        emit_check_for_rule_match(ctx, instr, rule_id);
                    }
                    SymbolKind::WasmVar(var) => {
                        // The symbol represents a variable in WASM memory,
                        // emit code for loading its value into the stack.
                        load_var(ctx, instr, var);
                    }
                    SymbolKind::HostVar(var) => {
                        // The symbol represents a host-side variable, so it must
                        // be a structure, map or array.
                        ctx.lookup_start = Some(var);
                    }
                    SymbolKind::Func(func) => {
                        let signature =
                            &func.signatures()[ctx.current_signature.unwrap()];

                        if signature.result_may_be_undef {
                            emit_call_and_handle_undef(
                                ctx,
                                instr,
                                ctx.function_id(
                                    signature.mangled_name.as_str(),
                                ),
                            );
                        } else {
                            instr.call(
                                ctx.function_id(
                                    signature.mangled_name.as_str(),
                                ),
                            );
                        }
                    }
                    SymbolKind::FieldIndex(index) => {
                        ctx.lookup_stack.push_back(index);

                        match ident.ty() {
                            Type::Integer => {
                                emit_lookup_integer(ctx, instr);
                            }
                            Type::Float => {
                                emit_lookup_float(ctx, instr);
                            }
                            Type::Bool => {
                                emit_lookup_bool(ctx, instr);
                            }
                            Type::String => {
                                emit_lookup_string(ctx, instr);
                            }
                            Type::Struct | Type::Array | Type::Map => {
                                // Do nothing. For structs, arrays and maps pushing
                                // the field index in `lookup_stack` is enough. We
                                // don't need to emit a call for retrieving a value.
                            }
                            _ => {
                                // This point should not be reached. The type of
                                // identifiers must be known during code emitting
                                // because they are resolved during the semantic
                                // check, and the AST is updated with type info.
                                unreachable!();
                            }
                        }
                    }
                }
            });
        }
        Expr::PatternMatch(pattern) => {
            // If the patterns has not been searched yet, do it now.
            emit_lazy_pattern_search(ctx, instr);

            // Push the pattern ID in the stack. Identifier "$" is an special
            // case, as this is used inside `for` loops and it represents a
            // different pattern on each iteration. In those cases the pattern
            // ID is obtained from a loop variable.
            if pattern.identifier.name == "$" {
                match ctx.symbol_table.lookup("$").unwrap().kind {
                    SymbolKind::WasmVar(var) => {
                        load_var(ctx, instr, var);
                        // load_var returns a I64, convert it to I32.
                        instr.unop(UnaryOp::I32WrapI64);
                    }
                    _ => unreachable!(),
                }
            }
            // For normal pattern identifiers (e.g: $a, $b, $foo) we find the
            // corresponding pattern in the current rule, and push its ID.
            else {
                instr.i32_const(
                    ctx.get_pattern_from_current_rule(&pattern.identifier).0,
                );
            };

            emit_pattern_match(ctx, instr, pattern.anchor.as_ref());
        }
        Expr::PatternCount(_) => {
            // If the patterns has not been searched yet, do it now.
            emit_lazy_pattern_search(ctx, instr);
            // TODO
        }
        Expr::PatternOffset(_) => {
            // If the patterns has not been searched yet, do it now.
            emit_lazy_pattern_search(ctx, instr);
            // TODO
        }
        Expr::PatternLength(_) => {
            emit_lazy_pattern_search(ctx, instr);
            // TODO
        }
        Expr::Lookup(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                // Emit the code for the index expression, which leaves the
                // index in the stack.
                emit_expr(ctx, instr, &operands.index);
                // Emit code for the primary expression (array or map) that is
                // being indexed.
                //
                // Notice that the index expression must be emitted before the
                // primary expression because the former may need to modify
                // `lookup_stack`, and we don't want to alter `lookup_stack`
                // until `emit_array_indexing` or `emit_map_lookup` is called.
                emit_expr(ctx, instr, &operands.primary);

                // Emit a call instruction to the corresponding function, which
                // depends on the type of the primary expression (array or map)
                // and the type of the index expression.
                match operands.primary.type_value() {
                    TypeValue::Array(array) => {
                        emit_array_indexing(ctx, instr, array, None);
                    }
                    TypeValue::Map(map) => {
                        emit_map_lookup(ctx, instr, map);
                    }
                    _ => unreachable!(),
                };
            })
        }
        Expr::FieldAccess(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_expr(ctx, instr, &operands.lhs);

                ctx.current_struct =
                    Some(operands.lhs.type_value().as_struct());

                emit_expr(ctx, instr, &operands.rhs);

                ctx.current_struct = None;
            })
        }
        Expr::FnCall(fn_call) => {
            for expr in fn_call.args.iter() {
                emit_expr(ctx, instr, expr);
            }

            let previous = ctx
                .current_signature
                .replace(fn_call.fn_signature_index.unwrap());

            emit_expr(ctx, instr, &fn_call.callable);

            ctx.current_signature = previous;
        }
        Expr::Defined(operand) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                // The `defined` expression is emitted as:
                //
                //   try {
                //     evaluate_operand()
                //     true
                //   } catch undefined {
                //     false
                //   }
                //
                catch_undef(ctx, instr, |ctx, instr| {
                    emit_bool_expr(ctx, instr, &operand.operand);
                    // Drop the operand's value as we are not interested in the
                    // value, we are interested only in whether it's defined or
                    // not.
                    instr.drop();
                    // Push a 1 in the stack indicating that the operand is
                    // defined. This point is not reached if the operand calls
                    // `throw_undef`.
                    instr.i32_const(1);
                });
            })
        }
        Expr::Not(operand) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                // The `not` expression is emitted as:
                //
                //   if (evaluate_operand()) {
                //     false
                //   } else {
                //     true
                //   }
                //
                emit_bool_expr(ctx, instr, &operand.operand);
                instr.if_else(
                    I32,
                    |then| {
                        then.i32_const(0);
                    },
                    |else_| {
                        else_.i32_const(1);
                    },
                );
            })
        }
        Expr::And(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                // The `and` expression is emitted as:
                //
                //   try {
                //     lhs = evaluate_left_operand()
                //   } catch undefined {
                //     lhs = false
                //   }
                //
                //   if (lhs) {
                //     try {
                //        evaluate_right_operand()
                //     } catch undefined {
                //        false
                //     }
                //   } else {
                //     false
                //   }
                //
                catch_undef(ctx, instr, |ctx, instr| {
                    emit_bool_expr(ctx, instr, &operands.lhs);
                });

                instr.if_else(
                    I32,
                    |then_| {
                        catch_undef(ctx, then_, |ctx, instr| {
                            emit_bool_expr(ctx, instr, &operands.rhs);
                        });
                    },
                    |else_| {
                        else_.i32_const(0);
                    },
                );
            });
        }
        Expr::Or(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                // The `or` expression is emitted as:
                //
                //   try {
                //     lhs = evaluate_left_operand()
                //   } catch undefined {
                //     lhs = false
                //   }
                //
                //   if (lhs) {
                //     true
                //   } else {
                //     evaluate_right_operand()
                //   }
                //
                catch_undef(ctx, instr, |ctx, instr| {
                    emit_bool_expr(ctx, instr, &operands.lhs);
                });

                instr.if_else(
                    I32,
                    |then_| {
                        then_.i32_const(1);
                    },
                    |else_| {
                        catch_undef(ctx, else_, |ctx, instr| {
                            emit_bool_expr(ctx, instr, &operands.rhs);
                        });
                    },
                );
            });
        }
        Expr::Minus(operand) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                match operand.operand.ty() {
                    Type::Float => {
                        emit_expr(ctx, instr, &operand.operand);
                        instr.unop(UnaryOp::F64Neg);
                    }
                    Type::Integer => {
                        // WebAssembly does not have a i64.neg instruction, it
                        // is implemented as i64.sub(0, x).
                        instr.i64_const(0);
                        emit_expr(ctx, instr, &operand.operand);
                        instr.binop(BinaryOp::I64Sub);
                    }
                    _ => unreachable!(),
                };
            })
        }
        Expr::Modulus(operands) => {
            // emit_arithmetic_op! macro is not used for modulus because this
            // operation doesn't accept float operands.
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                match emit_operands!(ctx, instr, operands.lhs, operands.rhs) {
                    (Type::Integer, Type::Integer) => {
                        // Make sure that the divisor is not zero, if that's
                        // the case the result is undefined.
                        throw_undef_if_zero(ctx, instr);
                        instr.binop(BinaryOp::I64RemS);
                    }
                    _ => unreachable!(),
                };
            });
        }
        Expr::BitwiseNot(operand) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_expr(ctx, instr, &operand.operand);
                // WebAssembly does not have an instruction for bitwise not,
                // it is implemented as i64.xor(x, -1)
                instr.i64_const(-1);
                instr.binop(BinaryOp::I64Xor);
            });
        }
        Expr::Add(operands) => {
            emit_arithmetic_op!(ctx, instr, expr, operands, I64Add, F64Add);
        }
        Expr::Sub(operands) => {
            emit_arithmetic_op!(ctx, instr, expr, operands, I64Sub, F64Sub);
        }
        Expr::Mul(operands) => {
            emit_arithmetic_op!(ctx, instr, expr, operands, I64Mul, F64Mul);
        }
        Expr::Div(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                match emit_operands!(ctx, instr, operands.lhs, operands.rhs) {
                    (Type::Integer, Type::Integer) => {
                        // Make sure that the divisor is not zero, if that's
                        // the case the result is undefined.
                        throw_undef_if_zero(ctx, instr);
                        instr.binop(BinaryOp::I64DivS);
                    }
                    (Type::Float, Type::Float) => {
                        // Both operands are float, the operation is float.
                        instr.binop(BinaryOp::F64Div);
                    }
                    _ => unreachable!(),
                };
            });
        }
        Expr::Shl(operands) => {
            emit_shift_op!(ctx, instr, expr, operands, I64Shl);
        }
        Expr::Shr(operands) => {
            emit_shift_op!(ctx, instr, expr, operands, I64ShrS);
        }
        Expr::BitwiseAnd(operands) => {
            emit_bitwise_op!(ctx, instr, expr, operands, I64And);
        }
        Expr::BitwiseOr(operands) => {
            emit_bitwise_op!(ctx, instr, expr, operands, I64Or);
        }
        Expr::BitwiseXor(operands) => {
            emit_bitwise_op!(ctx, instr, expr, operands, I64Xor);
        }
        Expr::Eq(operands) => {
            emit_comparison_op!(
                ctx,
                instr,
                expr,
                operands,
                I64Eq,
                F64Eq,
                wasm::export__str_eq.mangled_name
            );
        }
        Expr::Ne(operands) => {
            emit_comparison_op!(
                ctx,
                instr,
                expr,
                operands,
                I64Ne,
                F64Ne,
                wasm::export__str_ne.mangled_name
            );
        }
        Expr::Lt(operands) => {
            emit_comparison_op!(
                ctx,
                instr,
                expr,
                operands,
                I64LtS,
                F64Lt,
                wasm::export__str_lt.mangled_name
            );
        }
        Expr::Gt(operands) => {
            emit_comparison_op!(
                ctx,
                instr,
                expr,
                operands,
                I64GtS,
                F64Gt,
                wasm::export__str_gt.mangled_name
            );
        }
        Expr::Le(operands) => {
            emit_comparison_op!(
                ctx,
                instr,
                expr,
                operands,
                I64LeS,
                F64Le,
                wasm::export__str_le.mangled_name
            );
        }
        Expr::Ge(operands) => {
            emit_comparison_op!(
                ctx,
                instr,
                expr,
                operands,
                I64GeS,
                F64Ge,
                wasm::export__str_ge.mangled_name
            );
        }
        Expr::Contains(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(
                    ctx.function_id(wasm::export__str_contains.mangled_name),
                );
            });
        }
        Expr::IContains(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(
                    ctx.function_id(wasm::export__str_icontains.mangled_name),
                );
            });
        }
        Expr::StartsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(
                    ctx.function_id(wasm::export__str_startswith.mangled_name),
                );
            });
        }
        Expr::IStartsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(
                    ctx.function_id(
                        wasm::export__str_istartswith.mangled_name,
                    ),
                );
            });
        }
        Expr::EndsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(
                    ctx.function_id(wasm::export__str_endswith.mangled_name),
                );
            });
        }
        Expr::IEndsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(
                    ctx.function_id(wasm::export__str_iendswith.mangled_name),
                );
            });
        }
        Expr::IEquals(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(
                    ctx.function_id(wasm::export__str_iequals.mangled_name),
                );
            });
        }
        Expr::Matches(_) => {
            // TODO
        }
        Expr::Of(of) => match &of.items {
            OfItems::PatternSet(pattern_set) => {
                emit_of_pattern_set(ctx, instr, of, pattern_set);
            }
            OfItems::BoolExprTuple(expressions) => {
                emit_of_expr_tuple(ctx, instr, of, expressions);
            }
        },
        Expr::ForOf(for_of) => {
            emit_for_of_pattern_set(ctx, instr, for_of);
        }
        Expr::ForIn(for_in) => match &for_in.iterable {
            Iterable::Range(range) => {
                emit_for_in_range(ctx, instr, for_in, range);
            }
            Iterable::ExprTuple(expressions) => {
                emit_for_in_expr_tuple(ctx, instr, for_in, expressions);
            }
            Iterable::Expr(iterable) => {
                emit_for_in_expr(ctx, instr, for_in, iterable);
            }
        },
    }
}

/// Emits the code that checks if rule has matched.
///
/// The emitted code leaves 0 or 1 at the top of the stack.
fn emit_check_for_rule_match(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    rule_id: RuleId,
) {
    // Starting at MATCHING_RULES_BITMAP_BASE there's a
    // bitmap where the N-th bit corresponds to the rule
    // with RuleId = N. If the bit is 1 the rule matched.
    //
    // Notice that the bits in a byte are numbered starting
    // from the least significant bit (LSB). So, the bit
    // corresponding to RuleId = 0, is the LSB of the byte
    // at MATCHING_RULES_BITMAP_BASE.
    //
    // The first thing is loading the byte where the bit
    // resides..
    instr.i32_const(rule_id.0 / 8);
    instr.load(
        ctx.wasm_symbols.main_memory,
        LoadKind::I32_8 { kind: ZeroExtend },
        MemArg {
            align: size_of::<i8>() as u32,
            offset: MATCHING_RULES_BITMAP_BASE as u32,
        },
    );
    // This is the first operator for the I32ShrU operation.
    instr.i32_const(rule_id.0 % 8);
    // Compute byte & (1 << (rule_id % 8)), which clears all
    // bits except the one we are interested in.
    instr.i32_const(1 << (rule_id.0 % 8));
    instr.binop(BinaryOp::I32And);
    // Now shift the byte to the right, leaving the
    // interesting bit as the LSB. So the result is either
    // 1 or 0.
    instr.binop(BinaryOp::I32ShrU);
}

/// Emits the code that checks if a pattern (a.k.a string) has matched.
///
/// This function assumes that the PatternId is at the top of the stack as a
/// I32. The emitted code consumes the PatternId and leaves another I32 with
/// value 0 or 1 at the top of the stack.
fn emit_check_for_pattern_match(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
) {
    // Take the pattern ID at the top of the stack and store it in a temp
    // variable, but leaving a copy in the stack.
    instr.local_tee(ctx.wasm_symbols.i32_tmp);

    // Divide by pattern ID by 8 for getting the byte offset relative to
    // the start of the bitmap.
    instr.i32_const(3);
    instr.binop(BinaryOp::I32ShrU);

    // Add the base of the bitmap for getting the final memory address.
    instr.global_get(ctx.wasm_symbols.matching_patterns_bitmap_base);
    instr.binop(BinaryOp::I32Add);

    // Load the byte that contains the ID-th bit.
    instr.load(
        ctx.wasm_symbols.main_memory,
        LoadKind::I32_8 { kind: ZeroExtend },
        MemArg { align: size_of::<i8>() as u32, offset: 0 },
    );

    // At this point the byte is at the top of the stack. The byte will be
    // the first argument for the I32And instruction below.

    // Put 1 in the stack. This is the first argument to I32Shl.
    instr.i32_const(1);

    // Compute pattern_id % 8 and store the result back to temp variable,
    // but leaving a copy in the stack,
    instr.local_get(ctx.wasm_symbols.i32_tmp);
    instr.i32_const(8);
    instr.binop(BinaryOp::I32RemU);
    instr.local_tee(ctx.wasm_symbols.i32_tmp);

    // Compute (1 << (rule_id % 8))
    instr.binop(BinaryOp::I32Shl);

    // Compute byte & (1 << (rule_id % 8)) which clears all the bits except
    // the one we are interested in.
    instr.binop(BinaryOp::I32And);

    // Now shift the byte to the right, leaving the
    // interesting bit as the LSB. So the result is either
    // 1 or 0.
    instr.local_get(ctx.wasm_symbols.i32_tmp);
    instr.binop(BinaryOp::I32ShrU);
}

/// Emits the code that gets an array item by index.
///
/// This function must be called right after emitting the code that leaves the
/// the index in the stack. The code emitted by this function assumes that the
/// top of the stack is an i64 with the index.
///
/// The `var` argument only has effect when the array contains structs. If this
/// argument is not `None`, it indicates the host-side variable where the
/// resulting structure will be stored.
///
/// # Panics
///
/// If the `var` argument is not `None` for arrays that don't contain structs.
fn emit_array_indexing(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    array: &Rc<Array>,
    dst_var: Option<Var>,
) {
    // Emit the code that fills the `lookup_stack` in WASM memory.
    emit_lookup_common(ctx, instr);

    let func = match array.as_ref() {
        Array::Integers(_) => {
            assert!(dst_var.is_none());
            &wasm::export__array_indexing_integer
        }
        Array::Floats(_) => {
            assert!(dst_var.is_none());
            &wasm::export__array_indexing_float
        }
        Array::Bools(_) => {
            assert!(dst_var.is_none());
            &wasm::export__array_indexing_bool
        }
        Array::Strings(_) => {
            assert!(dst_var.is_none());
            &wasm::export__array_indexing_string
        }
        Array::Structs(_) => {
            // Push the index of the host-side variable where the structure
            // will be stored. If `var` is None pushes -1 which will be
            // ignored by the host-side function that performs the lookup.
            if let Some(var) = dst_var {
                instr.i32_const(var.index);
            } else {
                instr.i32_const(-1);
            }
            &wasm::export__array_indexing_struct
        }
    };

    emit_call_and_handle_undef(ctx, instr, ctx.function_id(func.mangled_name));
}

/// Emits the code that performs map lookup by index.
///
/// This function must be called right after emitting the code that leaves the
/// index in the stack. The code emitted by this function assumes that the top
/// of the stack is an i64 with the index.
///
/// The `dst_var` argument only has effect when the map values are structs.
/// If this argument is not `None`, it indicates the host-side variable where
/// the resulting structure will be stored.
///
/// # Panics
///
/// If the `dst_var` argument is not `None` for maps that don't contain structs.
fn emit_map_lookup_by_index(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    map: &Rc<Map>,
    dst_var: Option<Var>,
) {
    // Emit the code that fills the `lookup_stack` in WASM memory.
    emit_lookup_common(ctx, instr);

    let func = match map.as_ref() {
        Map::IntegerKeys { deputy, .. } => {
            match deputy.as_ref().unwrap().ty() {
                Type::Integer => {
                    assert!(dst_var.is_none());
                    wasm::export__map_lookup_by_index_integer_integer
                        .mangled_name
                }
                Type::String => {
                    assert!(dst_var.is_none());
                    wasm::export__map_lookup_by_index_integer_string
                        .mangled_name
                }
                Type::Float => {
                    assert!(dst_var.is_none());
                    wasm::export__map_lookup_by_index_integer_float
                        .mangled_name
                }
                Type::Bool => {
                    assert!(dst_var.is_none());
                    wasm::export__map_lookup_by_index_integer_bool.mangled_name
                }
                Type::Struct => {
                    // Push the index of the host-side variable where the structure
                    // will be stored. If `var` is None pushes -1 which will be
                    // ignored by the host-side function that performs the lookup.
                    if let Some(var) = dst_var {
                        instr.i32_const(var.index);
                    } else {
                        instr.i32_const(-1);
                    }
                    wasm::export__map_lookup_by_index_integer_struct
                        .mangled_name
                }
                _ => unreachable!(),
            }
        }
        Map::StringKeys { deputy, .. } => {
            match deputy.as_ref().unwrap().ty() {
                Type::Integer => {
                    assert!(dst_var.is_none());
                    wasm::export__map_lookup_by_index_string_integer
                        .mangled_name
                }
                Type::String => {
                    assert!(dst_var.is_none());
                    wasm::export__map_lookup_by_index_string_string
                        .mangled_name
                }
                Type::Float => {
                    assert!(dst_var.is_none());
                    wasm::export__map_lookup_by_index_string_float.mangled_name
                }
                Type::Bool => {
                    wasm::export__map_lookup_by_index_string_bool.mangled_name
                }
                Type::Struct => {
                    // Push the index of the host-side variable where the structure
                    // will be stored. If `var` is None pushes -1 which will be
                    // ignored by the host-side function that performs the lookup.
                    if let Some(var) = dst_var {
                        instr.i32_const(var.index);
                    } else {
                        instr.i32_const(-1);
                    }
                    wasm::export__map_lookup_by_index_string_struct
                        .mangled_name
                }
                _ => unreachable!(),
            }
        }
    };

    instr.call(ctx.function_id(func));
}

fn emit_map_lookup(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    map: &Rc<Map>,
) {
    match map.as_ref() {
        Map::IntegerKeys { deputy, .. } => {
            emit_map_integer_key_lookup(ctx, instr, deputy.as_ref().unwrap())
        }
        Map::StringKeys { deputy, .. } => {
            emit_map_string_key_lookup(ctx, instr, deputy.as_ref().unwrap())
        }
    }
}

fn emit_map_integer_key_lookup(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    map_value: &TypeValue,
) {
    emit_lookup_common(ctx, instr);

    let func = match map_value.ty() {
        Type::Integer => &wasm::export__map_lookup_integer_integer,
        Type::Float => &wasm::export__map_lookup_integer_float,
        Type::Bool => &wasm::export__map_lookup_integer_bool,
        Type::Struct => &wasm::export__map_lookup_integer_struct,
        Type::String => &wasm::export__map_lookup_integer_string,
        _ => unreachable!(),
    };

    emit_call_and_handle_undef(ctx, instr, ctx.function_id(func.mangled_name));
}

fn emit_map_string_key_lookup(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    map_value: &TypeValue,
) {
    emit_lookup_common(ctx, instr);

    // Generate the call depending on the type of the map values.
    let func = match map_value.ty() {
        Type::Integer => &wasm::export__map_lookup_string_integer,
        Type::Float => &wasm::export__map_lookup_string_float,
        Type::Bool => &wasm::export__map_lookup_string_bool,
        Type::Struct => &wasm::export__map_lookup_string_struct,
        Type::String => &wasm::export__map_lookup_string_string,
        _ => unreachable!(),
    };

    emit_call_and_handle_undef(ctx, instr, ctx.function_id(func.mangled_name));
}

fn emit_of_pattern_set(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    of: &Of,
    pattern_set: &PatternSet,
) {
    let pattern_ids: Vec<PatternId> =
        patterns_matching(ctx, pattern_set).collect();

    let num_patterns = pattern_ids.len();
    let mut pattern_ids = pattern_ids.into_iter();
    let next_pattern_id = ctx.new_var(Type::Integer);

    // Make sure the pattern search phase is executed, as the `of` statement
    // depends on patterns.
    emit_lazy_pattern_search(ctx, instr);

    emit_for(
        ctx,
        instr,
        &of.quantifier,
        |ctx, instr, n, _| {
            // Set n = number of patterns.
            set_var(ctx, instr, n, |_, instr| {
                instr.i64_const(num_patterns as i64);
            });
        },
        // Before each iteration.
        |ctx, instr, i| {
            // Get the i-th pattern ID, and store it in `next_pattern_id`.
            set_var(ctx, instr, next_pattern_id, |ctx, instr| {
                load_var(ctx, instr, i);
                emit_switch(ctx, I64, instr, |_, instr| {
                    if let Some(pattern_id) = pattern_ids.next() {
                        instr.i64_const(pattern_id.into());
                        return true;
                    }
                    false
                });
            });
        },
        // Condition
        |ctx, instr| {
            // Push the pattern ID into the stack.
            load_var(ctx, instr, next_pattern_id);
            // load_var returns a I64, convert it to I32.
            instr.unop(UnaryOp::I32WrapI64);

            emit_pattern_match(ctx, instr, of.anchor.as_ref());
        },
        // After each iteration.
        |_, _, _| {},
    );

    // Free loop variables.
    ctx.free_vars(next_pattern_id);
}

fn emit_of_expr_tuple(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    of: &Of,
    expressions: &[Expr],
) {
    // Create variable `next_item`, which will contain the item that will be
    // put in the loop variable in the next iteration.
    let next_item = ctx.new_var(Type::Bool);

    let num_expressions = expressions.len();
    let mut expressions = expressions.iter();

    emit_for(
        ctx,
        instr,
        &of.quantifier,
        |ctx, instr, n, _| {
            // Initialize `n` to number of expressions.
            set_var(ctx, instr, n, |_, instr| {
                instr.i64_const(num_expressions as i64);
            });
        },
        // Before each iteration.
        |ctx, instr, i| {
            // Execute the i-th expression and save its result in `next_item`.
            set_var(ctx, instr, next_item, |ctx, instr| {
                load_var(ctx, instr, i);
                emit_switch(ctx, next_item.ty.into(), instr, |ctx, instr| {
                    if let Some(expr) = expressions.next() {
                        assert_eq!(expr.ty(), Type::Bool);
                        emit_expr(ctx, instr, expr);
                        return true;
                    }
                    false
                });
            });
        },
        // Condition.
        |ctx, instr| {
            load_var(ctx, instr, next_item);
        },
        // After each iteration.
        |_, _, _| {},
    );

    // Free loop variables.
    ctx.free_vars(next_item);
}

fn emit_for_of_pattern_set(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_of: &ForOf,
) {
    let pattern_ids: Vec<PatternId> =
        patterns_matching(ctx, &for_of.pattern_set).collect();

    let num_patterns = pattern_ids.len();
    let mut pattern_ids = pattern_ids.into_iter();
    let next_pattern_id = ctx.new_var(Type::Integer);

    let mut symbol = Symbol::new(TypeValue::Integer(None));
    symbol.kind = SymbolKind::WasmVar(next_pattern_id);

    let mut loop_vars = SymbolTable::new();
    loop_vars.insert("$", symbol);

    ctx.symbol_table.push(Rc::new(loop_vars));

    emit_for(
        ctx,
        instr,
        &for_of.quantifier,
        |ctx, instr, n, _| {
            // Set n = number of patterns.
            set_var(ctx, instr, n, |_, instr| {
                instr.i64_const(num_patterns as i64);
            });
        },
        // Before each iteration.
        |ctx, instr, i| {
            // Get the i-th pattern ID, and store it in `next_pattern_id`.
            set_var(ctx, instr, next_pattern_id, |ctx, instr| {
                load_var(ctx, instr, i);
                emit_switch(ctx, I64, instr, |_, instr| {
                    if let Some(pattern_id) = pattern_ids.next() {
                        instr.i64_const(pattern_id.into());
                        return true;
                    }
                    false
                });
            });
        },
        // Condition
        |ctx, instr| {
            emit_expr(ctx, instr, &for_of.condition);
        },
        // After each iteration.
        |_, _, _| {},
    );

    // Remove the symbol table that contains the loop variable.
    ctx.symbol_table.pop();

    // Free loop variables.
    ctx.free_vars(next_pattern_id);
}

fn emit_for_in_range(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    range: &Range,
) {
    // A `for` loop in a range has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    // Create variable `next_item`, which will contain the item that will be
    // put in the loop variable in the next iteration.
    let next_item = ctx.new_var(Type::Integer);

    // Create a symbol table containing the loop variable.
    let mut symbol = Symbol::new(TypeValue::Integer(None));

    // Associate the symbol with the memory location where `next_item` is
    // stored. Everytime that the loop variable is used in the condition,
    // it will refer to the value stored in `next_item`.
    symbol.kind = SymbolKind::WasmVar(next_item);

    let mut loop_vars = SymbolTable::new();
    loop_vars.insert(for_in.variables.first().unwrap().name, symbol);

    // Push the symbol table with loop variable on top of the existing symbol
    // tables.
    ctx.symbol_table.push(Rc::new(loop_vars));

    emit_for(
        ctx,
        instr,
        &for_in.quantifier,
        |ctx, instr, n, loop_end| {
            // Set n = upper_bound - lower_bound + 1;
            set_var(ctx, instr, n, |ctx, instr| {
                emit_expr(ctx, instr, &range.upper_bound);
                emit_expr(ctx, instr, &range.lower_bound);

                // Store lower_bound in temp variable, without removing
                // it from the stack.
                instr.local_tee(ctx.wasm_symbols.i64_tmp);

                // Compute upper_bound - lower_bound + 1.
                instr.binop(BinaryOp::I64Sub);
                instr.i64_const(1);
                instr.binop(BinaryOp::I64Add);
            });

            // If n <= 0, exit from the loop.
            load_var(ctx, instr, n);
            instr.i64_const(0);
            instr.binop(BinaryOp::I64LeS);
            instr.if_else(
                None,
                |then_| {
                    then_.i32_const(0);
                    then_.br(loop_end);
                },
                |_| {},
            );

            // Store lower_bound in `next_item`.
            set_var(ctx, instr, next_item, |ctx, instr| {
                instr.local_get(ctx.wasm_symbols.i64_tmp);
            });
        },
        // Before each iteration.
        |_, _, _| {},
        // Condition.
        |ctx, instr| emit_expr(ctx, instr, &for_in.condition),
        // After each iteration.
        |ctx, instr, _| {
            incr_var(ctx, instr, next_item);
        },
    );

    // Remove the symbol table that contains the loop variable.
    ctx.symbol_table.pop();

    // Free loop variables.
    ctx.free_vars(next_item);
}

fn emit_for_in_expr(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    iterable: &Expr,
) {
    match iterable.ty() {
        Type::Array => {
            emit_for_in_array(ctx, instr, for_in, iterable);
        }
        Type::Map => {
            emit_for_in_map(ctx, instr, for_in, iterable);
        }
        _ => unreachable!(),
    }
}

fn emit_for_in_array(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    array_expr: &Expr,
) {
    // A `for` loop in an array has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    let array = array_expr.type_value().as_array();

    // The type of the loop variable must be the type of the items in the array,
    // except for arrays of struct, for which we don't need to create a variable.
    let (wasm_side_next_item, loop_var) = match array.as_ref() {
        Array::Integers(_) => (true, TypeValue::Integer(None)),
        Array::Floats(_) => (true, TypeValue::Float(None)),
        Array::Bools(_) => (true, TypeValue::Bool(None)),
        Array::Strings(_) => (true, TypeValue::String(None)),
        Array::Structs(_) => (false, TypeValue::Unknown),
    };

    // Create variable `next_item`, which will contain the item that will be
    // put in the loop variable in the next iteration.
    let next_item = ctx.new_var(loop_var.ty());

    // Create a symbol table containing the loop variable.
    let mut symbol = Symbol::new(loop_var);
    let mut loop_vars = SymbolTable::new();

    // Associate the symbol with the memory location where `next_item` is
    // stored. Everytime that the loop variable is used in the condition,
    // it will refer to the value stored in `next_item`.
    if wasm_side_next_item {
        symbol.kind = SymbolKind::WasmVar(next_item);
    } else {
        symbol.kind = SymbolKind::HostVar(next_item);
    }

    loop_vars.insert(for_in.variables.first().unwrap().name, symbol);

    // Push the symbol table with loop variable on top of the existing symbol
    // tables.
    ctx.symbol_table.push(Rc::new(loop_vars));

    // Emit the expression that lookup the array.
    emit_expr(ctx, instr, array_expr);

    let array_var = ctx.new_var(Type::Array);

    emit_lookup_value(ctx, instr, array_var);

    emit_for(
        ctx,
        instr,
        &for_in.quantifier,
        |ctx, instr, n, loop_end| {
            // Initialize `n` to the array's length.
            set_var(ctx, instr, n, |ctx, instr| {
                instr.i32_const(array_var.index);
                instr.call(
                    ctx.function_id(wasm::export__array_len.mangled_name),
                );
            });

            // If n <= 0, exit from the loop.
            load_var(ctx, instr, n);
            instr.i64_const(0);
            instr.binop(BinaryOp::I64LeS);
            instr.if_else(
                None,
                |then_| {
                    then_.i32_const(0);
                    then_.br(loop_end);
                },
                |_| {},
            );
        },
        // Before each iteration.
        |ctx, instr, i| {
            // The next lookup operation starts at the local variable
            // `array_var`.
            ctx.lookup_start = Some(array_var);

            if wasm_side_next_item {
                // Get the i-th item in the array and store it in the
                // WASM-side local variable `next_item`.
                set_var(ctx, instr, next_item, |ctx, instr| {
                    load_var(ctx, instr, i);
                    emit_array_indexing(ctx, instr, &array, None);
                });
            } else {
                // Get the i-th item in the array and store it in the
                // host-side local variable `next_item`.
                load_var(ctx, instr, i);
                emit_array_indexing(ctx, instr, &array, Some(next_item));
            }
        },
        |ctx, instr| {
            emit_expr(ctx, instr, &for_in.condition);
        },
        // After each iteration.
        |_, _, _| {},
    );

    ctx.symbol_table.pop();
    ctx.free_vars(next_item);
}

fn emit_for_in_map(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    map_expr: &Expr,
) {
    // A `for` loop in an map has exactly two variables.
    assert_eq!(for_in.variables.len(), 2);

    let map = map_expr.type_value().as_map();

    let (key, val) = match map.as_ref() {
        Map::IntegerKeys { deputy, .. } => (
            TypeValue::Integer(None),                       // key
            deputy.as_ref().unwrap().clone_without_value(), // value
        ),
        Map::StringKeys { deputy, .. } => (
            TypeValue::String(None),                        // key
            deputy.as_ref().unwrap().clone_without_value(), // value
        ),
    };

    // Create variable `next_key`, which will contain the key that will be
    // put in the loop variable in the next iteration.
    let next_key = ctx.new_var(key.ty());

    // Create variable `next_val`, which will contain the value that will be
    // put in the loop variable in the next iteration.
    let next_val = ctx.new_var(val.ty());

    // When values in the map are structs, `next_val` is a host-side variable.
    // For every other type it is a WASM-side variable.
    let wasm_side_next_val = !matches!(val.ty(), Type::Struct);

    // Create a symbol table containing the loop variables.
    let mut symbol_key = Symbol::new(key);
    let mut symbol_val = Symbol::new(val);

    symbol_key.kind = SymbolKind::WasmVar(next_key);
    symbol_val.kind = match next_val.ty {
        Type::Integer | Type::Float | Type::Bool | Type::String => {
            SymbolKind::WasmVar(next_val)
        }
        Type::Struct | Type::Array => SymbolKind::HostVar(next_val),
        _ => unreachable!(),
    };

    let mut loop_vars = SymbolTable::new();

    loop_vars.insert(for_in.variables[0].name, symbol_key);
    loop_vars.insert(for_in.variables[1].name, symbol_val);

    // Push the symbol table with loop variable on top of the existing symbol
    // tables.
    ctx.symbol_table.push(Rc::new(loop_vars));

    // Emit the expression that lookup the map.
    emit_expr(ctx, instr, map_expr);

    let map_var = ctx.new_var(Type::Map);

    emit_lookup_value(ctx, instr, map_var);

    emit_for(
        ctx,
        instr,
        &for_in.quantifier,
        |ctx, instr, n, loop_end| {
            // Initialize `n` to the maps's length.
            set_var(ctx, instr, n, |ctx, instr| {
                instr.i32_const(map_var.index);
                instr
                    .call(ctx.function_id(wasm::export__map_len.mangled_name));
            });

            // If n <= 0, exit from the loop.
            load_var(ctx, instr, n);
            instr.i64_const(0);
            instr.binop(BinaryOp::I64LeS);
            instr.if_else(
                None,
                |then_| {
                    then_.i32_const(0);
                    then_.br(loop_end);
                },
                |_| {},
            );
        },
        // Before each iteration.
        |ctx, instr, i| {
            // The next lookup operation starts at the local variable
            // `map_var`.
            ctx.lookup_start = Some(map_var);

            // If `next_val` is a WASM-side variable, its value will be returned
            // by the lookup function, and the WASM code must put it into the
            // WASM-side variable. If not, it's a host-side variable that
            // will be set directly by the lookup function.
            if wasm_side_next_val {
                set_vars(ctx, instr, &[next_key, next_val], |ctx, instr| {
                    load_var(ctx, instr, i);
                    emit_map_lookup_by_index(ctx, instr, &map, None);
                });
            } else {
                set_var(ctx, instr, next_key, |ctx, instr| {
                    load_var(ctx, instr, i);
                    emit_map_lookup_by_index(ctx, instr, &map, Some(next_val));
                });
            }
        },
        // Condition.
        |ctx, instr| {
            emit_expr(ctx, instr, &for_in.condition);
        },
        // After each iteration.
        |_, _, _| {},
    );

    ctx.symbol_table.pop();
    ctx.free_vars(next_key);
}

fn emit_for_in_expr_tuple(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    expressions: &[Expr],
) {
    // A `for` in a tuple of expressions has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    // Create variable `next_item`, which will contain the item that will be
    // put in the loop variable in the next iteration.
    let next_item = ctx.new_var(expressions.first().unwrap().ty());

    // Create a symbol table containing the loop variable.
    let mut symbol = Symbol::new(
        expressions.first().unwrap().type_value().clone_without_value(),
    );

    symbol.kind = SymbolKind::WasmVar(next_item);

    let mut loop_vars = SymbolTable::new();
    loop_vars.insert(for_in.variables.first().unwrap().name, symbol);

    // Push the symbol table with loop variable on top of the existing symbol
    // tables.
    ctx.symbol_table.push(Rc::new(loop_vars));

    let num_expressions = expressions.len();
    let mut expressions = expressions.iter();

    emit_for(
        ctx,
        instr,
        &for_in.quantifier,
        |ctx, instr, n, _| {
            // Initialize `n` to number of expressions.
            set_var(ctx, instr, n, |_, instr| {
                instr.i64_const(num_expressions as i64);
            });
        },
        // Before each iteration.
        |ctx, instr, i| {
            // Execute the i-th expression and save its result in `next_item`.
            set_var(ctx, instr, next_item, |ctx, instr| {
                load_var(ctx, instr, i);
                emit_switch(ctx, next_item.ty.into(), instr, |ctx, instr| {
                    if let Some(expr) = expressions.next() {
                        emit_expr(ctx, instr, expr);
                        return true;
                    }
                    false
                });
            });
        },
        // Condition.
        |ctx, instr| {
            emit_expr(ctx, instr, &for_in.condition);
        },
        // After each iteration.
        |_, _, _| {},
    );

    // Remove the symbol table that contains the loop variable.
    ctx.symbol_table.pop();

    // Free loop variables.
    ctx.free_vars(next_item);
}

/// Emits a `for` loop.
///
/// This function allows creating different types of `for` loops by receiving
/// other functions that emit the loop initialization code, the code that gets
/// executed just before and after each iteration, and the for condition.
///
/// `loop_init` is the function that emits the initialization code, which is
/// executed only once, before the loop itself. This code should initialize
/// the variable `n` with the total number of items in the object that is
/// being iterated. This code should not leave anything on the stack.
///
/// `before_cond` emits the code that gets executed on every iteration just
/// before the loop's condition. The code produced by `before_cond` must set
/// the loop variable(s) used by the condition to the value(s) corresponding
/// to the current iteration. This code should not leave anything on the stack.
///
/// `cond` emits the loop's condition, it should leave an I32 on the stack with
/// value 0 or 1.
///
/// `after_cond` emits the code that gets executed on every iteration after
/// the loop's condition. This code should not leave anything on the stack.
fn emit_for<I, B, C, A>(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    quantifier: &Quantifier,
    loop_init: I,
    before_cond: B,
    condition: C,
    after_cond: A,
) where
    I: FnOnce(&mut Context, &mut InstrSeqBuilder, Var, InstrSeqId),
    B: FnOnce(&mut Context, &mut InstrSeqBuilder, Var),
    C: FnOnce(&mut Context, &mut InstrSeqBuilder),
    A: FnOnce(&mut Context, &mut InstrSeqBuilder, Var),
{
    // Create variable `n`, which will contain the maximum number of iterations.
    let n = ctx.new_var(Type::Integer);

    // Create variable `i`, which will contain the current iteration number.
    // The value of `i` is in the range 0..n-1.
    let i = ctx.new_var(Type::Integer);

    // Function that increments `i` and checks if `i` < `n` after each
    // iteration, repeating the loop while the condition is true.
    let incr_i_and_repeat =
        |ctx: &mut Context,
         instr: &mut InstrSeqBuilder,
         n: Var,
         i: Var,
         loop_start: InstrSeqId| {
            // Emit code that checks if loop should finish.
            after_cond(ctx, instr, n);

            // Increment `i`.
            incr_var(ctx, instr, i);

            // Compare `i` to `n`.
            load_var(ctx, instr, i);
            load_var(ctx, instr, n);
            instr.binop(BinaryOp::I64LtS);

            // Keep iterating while i < n.
            instr.br_if(loop_start);
        };

    instr.block(I32, |instr| {
        let loop_end = instr.id();

        loop_init(ctx, instr, n, loop_end);

        // Initialize `i` to zero.
        set_var(ctx, instr, i, |_, instr| {
            instr.i64_const(0);
        });

        let (max_count, count) = match quantifier {
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                // `max_count` is the number of loop conditions that must return
                // `true` for the loop to be `true`.
                let max_count = ctx.new_var(Type::Integer);
                // `count` is the number of loop conditions that actually
                // returned `true`. This is initially zero.
                let count = ctx.new_var(Type::Integer);

                set_var(ctx, instr, max_count, |ctx, instr| {
                    if matches!(quantifier, Quantifier::Percentage(_)) {
                        // Quantifier is a percentage, its final value will be
                        // n * quantifier / 100

                        // n * quantifier
                        load_var(ctx, instr, n);
                        instr.unop(UnaryOp::F64ConvertSI64);
                        emit_expr(ctx, instr, expr);
                        instr.unop(UnaryOp::F64ConvertSI64);
                        instr.binop(BinaryOp::F64Mul);

                        // / 100
                        instr.f64_const(100.0);
                        instr.binop(BinaryOp::F64Div);
                        instr.unop(UnaryOp::F64Ceil);
                        instr.unop(UnaryOp::I64TruncSF64);
                    } else {
                        // Quantifier is not a percentage, use it as is.
                        emit_expr(ctx, instr, expr);
                    }
                });

                // Initialize `count` to 0.
                set_var(ctx, instr, count, |_, instr| {
                    instr.i64_const(0);
                });

                (max_count, count)
            }
            _ => (
                Var { ty: Type::Integer, index: 0 },
                Var { ty: Type::Integer, index: 0 },
            ),
        };

        instr.loop_(I32, |block| {
            let loop_start = block.id();

            // Emit code that advances to next item.
            before_cond(ctx, block, i);

            // Emit code for the loop's condition. Use `catch_undef` for
            // capturing any undefined exception produced by the condition
            // because we don't want to abort the loop in such cases. When the
            // condition is undefined it's handled as a false.
            catch_undef(ctx, block, |ctx, block| {
                condition(ctx, block);
            });

            // At the top of the stack we have the i32 with the result from
            // the loop condition. Decide what to do depending on the
            // quantifier.
            match quantifier {
                Quantifier::None { .. } => {
                    block.if_else(
                        I32,
                        |then_| {
                            // If the condition returned true, break the loop with
                            // result false.
                            then_.i32_const(0);
                            then_.br(loop_end);
                        },
                        |else_| {
                            incr_i_and_repeat(ctx, else_, n, i, loop_start);

                            // If this point is reached is because all the
                            // the range was iterated without the condition
                            // returning true, this means that the whole "for"
                            // statement is true.
                            else_.i32_const(1);
                            else_.br(loop_end);
                        },
                    );
                }
                Quantifier::All { .. } => {
                    block.if_else(
                        I32,
                        |then_| {
                            incr_i_and_repeat(ctx, then_, n, i, loop_start);

                            // If this point is reached is because all the
                            // the range was iterated without the condition
                            // returning false, this means that the whole "for"
                            // statement is true.
                            then_.i32_const(1);
                            then_.br(loop_end);
                        },
                        |else_| {
                            // If the condition returned false, break the loop with
                            // result false.
                            else_.i32_const(0);
                            else_.br(loop_end);
                        },
                    );
                }
                Quantifier::Any { .. } => {
                    block.if_else(
                        I32,
                        |then_| {
                            // If the condition returned true, break the loop with
                            // result true.
                            then_.i32_const(1);
                            then_.br(loop_end);
                        },
                        |else_| {
                            incr_i_and_repeat(ctx, else_, n, i, loop_start);

                            // If this point is reached is because all the
                            // the range was iterated without the condition
                            // returning true, this means that the whole "for"
                            // statement is false.
                            else_.i32_const(0);
                            else_.br(loop_end);
                        },
                    );
                }
                Quantifier::Percentage(_) | Quantifier::Expr(_) => {
                    block.if_else(
                        None,
                        |then_| {
                            // The condition was true, increment count.
                            incr_var(ctx, then_, count);

                            // Is counter >= quantifier?.
                            load_var(ctx, then_, count);
                            load_var(ctx, then_, max_count);
                            then_.binop(BinaryOp::I64GeS);

                            then_.if_else(
                                None,
                                // count >= max_count
                                |then_| {
                                    // Is max_count == 0?
                                    load_var(ctx, then_, max_count);
                                    then_.unop(UnaryOp::I64Eqz);
                                    then_.if_else(
                                        None,
                                        // max_count == 0, this should treated be
                                        // as a `none` quantifier. At this point
                                        // count >= 1, so break the loop with
                                        // result false.
                                        |then_| {
                                            then_.i32_const(0);
                                            then_.br(loop_end);
                                        },
                                        // max_count != 0 and count >= max_count
                                        // break the loop with result true.
                                        |else_| {
                                            else_.i32_const(1);
                                            else_.br(loop_end);
                                        },
                                    );
                                },
                                |_| {},
                            );
                        },
                        |_| {},
                    );

                    incr_i_and_repeat(ctx, block, n, i, loop_start);

                    // If this point is reached we have iterated over the whole
                    // range 0..n. If `max_count` is zero this means that all
                    // iterations returned false and therefore the loop must
                    // return true. If `max_count` is non-zero it means that
                    // `counter` didn't reached `max_count` and the loop must
                    // return false.
                    load_var(ctx, block, max_count);
                    block.unop(UnaryOp::I64Eqz);
                    block.if_else(
                        I32,
                        // max_count == 0
                        |then_| {
                            then_.i32_const(1);
                        },
                        // max_count != 0
                        |else_| {
                            else_.i32_const(0);
                        },
                    );
                }
            }
        });

        if matches!(
            quantifier,
            Quantifier::Percentage(_) | Quantifier::Expr(_)
        ) {
            ctx.free_vars(max_count);
        };
    });

    ctx.free_vars(n);
}

/// Produces a switch statement by calling a `branch_generator` function
/// multiple times.
///
/// On each call to `branch_generator` it emits the code for one of the
/// branches and returns `true`. When `branch_generator` returns `false`
/// it won't be called anymore and no more branches will be produced.
///
/// Given an iterator that returns `N` expressions ([`Expr`]), generates a
/// switch statement that takes an `i64` value from the stack (in the range
/// `0..N-1`) and executes the corresponding expression.
///
/// For `branch_generator` function that returns 3 expressions the generated
/// code looks like this:
///
/// ```text
/// i32.wrap_i64                        ;; convert the i64 at the top of the
///                                     ;; to i32.
/// local.set $tmp                      ;; store the i32 value in $tmp
/// block (result i64)                  ;; block @1
///   block                             ;; block @2
///     block                           ;; block @3
///       block                         ;; block @4
///         block                       ;; block @5
///           local.get $tmp            ;; put $tmp at the top of the stack
///           
///           ;; Look for the i32 at the top of the stack, and depending on its
///           ;; value jumps out of some block...
///           br_table
///                3 (;@2;)   ;; selector == 0 -> jump out of block @2
///                2 (;@3;)   ;; selector == 1 -> jump out of block @3
///                1 (;@4;)   ;; selector == 2 -> jump out of block @4
///                0 (;@5;)   ;; default       -> jump out of block @5
///         
///         end                         ;; block @5
///         unreachable                 ;; if this point is reached is because
///                                     ;; the switch selector is out of range
///       end                           ;; block @4
///       block (result i64)
///         ;; < code expr 2 goes here >
///       end
///       br 2 (;@1;)                   ;; exits block @1
///     end                             ;; block @3  
///     block (result i64)
///       ;; < code expr 1 goes here >
///     end
///     br 1 (;@1;)                     ;; exits block @1        
///   end                               ;; block @2
///   block (result i64)                
///     ;; < code expr 0 goes here >
///   end                                 
///   br 0 (;@1;)                       ;; exits block @1   
/// end                                 ;; block @1
///                                     ;; at this point the i64 returned by the
///                                     ;; selected expression is at the top of
///                                     ;; the stack.
/// ```
fn emit_switch<F>(
    ctx: &mut Context,
    ty: ValType,
    instr: &mut InstrSeqBuilder,
    branch_generator: F,
) where
    F: FnMut(&mut Context, &mut InstrSeqBuilder) -> bool,
{
    // Convert the i64 at the top of the stack to an i32, which is the type
    // expected by the `bt_table` instruction.
    instr.unop(UnaryOp::I32WrapI64);

    // Store the i32 switch selector in a temp variable. The selector is the i32
    // value at the top of the stack that tells which expression should be
    // executed.
    instr.local_set(ctx.wasm_symbols.i32_tmp);

    let block_ids = Vec::new();

    instr.block(ty, |block| {
        emit_switch_internal(ctx, ty, block, branch_generator, block_ids);
    });
}

fn emit_switch_internal<F>(
    ctx: &mut Context,
    ty: ValType,
    instr: &mut InstrSeqBuilder,
    mut branch_generator: F,
    mut block_ids: Vec<InstrSeqId>,
) where
    F: FnMut(&mut Context, &mut InstrSeqBuilder) -> bool,
{
    block_ids.push(instr.id());

    // Create a dangling instructions sequence, this sequence will be inserting
    // later in the final code, but for the time being is floating around.
    let mut expr = instr.dangling_instr_seq(ty);

    // Call the branch generator, that will emit code into the dangling
    // instruction sequence.
    if branch_generator(ctx, &mut expr) {
        // The branch generator function returned true, which means that it
        // emitted code for a branch.
        let expr_id = expr.id();
        let outermost_block = block_ids.first().cloned();
        instr.block(None, |block| {
            emit_switch_internal(ctx, ty, block, branch_generator, block_ids);
        });
        instr.instr(walrus::ir::Block { seq: expr_id });
        instr.br(outermost_block.unwrap());
    } else {
        // The branch generator function returned false, no more branches will
        // be emitted. Let's emit the `br_table` which jumps to the appropriate
        // branch depending on the switch selector.
        instr.block(None, |block| {
            block.local_get(ctx.wasm_symbols.i32_tmp);
            block.br_table(block_ids[1..].into(), block.id());
        });
    }
}

/// Sets into a variable the value produced by a code block.
///
/// For multiple variables use [`set_vars`].
fn set_var<B>(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    var: Var,
    block: B,
) where
    B: FnOnce(&mut Context, &mut InstrSeqBuilder),
{
    // First push the offset where the variable resided in memory. This will
    // be used by the `store` instruction.
    instr.i32_const(var.index * size_of::<i64>() as i32);
    // Block that produces the value that will be stored in the variable.
    block(ctx, instr);

    let (store_kind, alignment) = match var.ty {
        Type::Bool => (StoreKind::I32 { atomic: false }, size_of::<i32>()),
        Type::Float => (StoreKind::F64, size_of::<f64>()),
        Type::Integer | Type::String | Type::Struct => {
            (StoreKind::I64 { atomic: false }, size_of::<i64>())
        }
        _ => unreachable!(),
    };

    // The store instruction will remove two items from the stack, the value and
    // the offset where it will be stored.
    instr.store(
        ctx.wasm_symbols.main_memory,
        store_kind,
        MemArg { align: alignment as u32, offset: 0 },
    );
}

/// Sets into variables the values produced by a code block.
///
/// The code block must leave in the stack as many values as the number of vars
/// and their types must match. The first variable will contain the first value
/// that was pushed into the stack.
///
/// For a single variable use [`set_var`].
fn set_vars<B>(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    vars: &[Var],
    block: B,
) where
    B: FnOnce(&mut Context, &mut InstrSeqBuilder),
{
    // Execute the block that produces the values.
    block(ctx, instr);

    // Iterate variables in reverse order as the last variable is the one
    // at the top of the stack.
    for var in vars.iter().rev() {
        match var.ty {
            Type::Bool => {
                // Pop the value and store it into temp variable.
                instr.local_set(ctx.wasm_symbols.i32_tmp);
                // Push the offset where the variable resides in memory.
                // The offset is always multiple of 64-bits, as each variable
                // occupies a 64-bits slot. This is true even for bool values
                // that are represented as a 32-bits integer.
                instr.i32_const(var.index * size_of::<i64>() as i32);
                // Push the value.
                instr.local_get(ctx.wasm_symbols.i32_tmp);
                // Store the value in memory.
                instr.store(
                    ctx.wasm_symbols.main_memory,
                    StoreKind::I32 { atomic: false },
                    MemArg { align: size_of::<i32>() as u32, offset: 0 },
                );
            }
            Type::Integer | Type::String => {
                instr.local_set(ctx.wasm_symbols.i64_tmp);
                instr.i32_const(var.index * size_of::<i64>() as i32);
                instr.local_get(ctx.wasm_symbols.i64_tmp);
                instr.store(
                    ctx.wasm_symbols.main_memory,
                    StoreKind::I64 { atomic: false },
                    MemArg { align: size_of::<i64>() as u32, offset: 0 },
                );
            }
            Type::Float => {
                instr.local_set(ctx.wasm_symbols.f64_tmp);
                instr.i32_const(var.index * size_of::<i64>() as i32);
                instr.local_get(ctx.wasm_symbols.f64_tmp);
                instr.store(
                    ctx.wasm_symbols.main_memory,
                    StoreKind::F64,
                    MemArg { align: size_of::<f64>() as u32, offset: 0 },
                );
            }
            _ => unreachable!(),
        }
    }
}

/// Loads the value of variable into the stack.
fn load_var(ctx: &Context, instr: &mut InstrSeqBuilder, var: Var) {
    // The slots where variables are stored start at offset VARS_STACK_START
    // within main memory, and are 64-bits long. Lets compute the variable's
    // offset with respect to VARS_STACK_START.
    instr.i32_const(var.index * size_of::<i64>() as i32);

    let (load_kind, alignment) = match var.ty {
        Type::Bool => (LoadKind::I32 { atomic: false }, size_of::<i32>()),
        Type::Float => (LoadKind::F64, size_of::<i64>()),
        Type::Integer | Type::String | Type::Struct => {
            (LoadKind::I64 { atomic: false }, size_of::<i64>())
        }
        _ => unreachable!(),
    };

    instr.load(
        ctx.wasm_symbols.main_memory,
        load_kind,
        MemArg { align: alignment as u32, offset: VARS_STACK_START as u32 },
    );
}

/// Increments a variable.
fn incr_var(ctx: &mut Context, instr: &mut InstrSeqBuilder, var: Var) {
    // incr_var only works with integer variables.
    assert_eq!(var.ty, Type::Integer);
    set_var(ctx, instr, var, |ctx, instr| {
        load_var(ctx, instr, var);
        instr.i64_const(1);
        instr.binop(BinaryOp::I64Add);
    });
}

/// Emits WASM code for boolean expression `expr` into the instruction
/// sequence `instr`. If `expr` doesn't return a boolean its result is casted
/// to a boolean as follows:
///
/// * Integer and float values are converted to `true` if they are non-zero,
///   and to `false` if they are zero.
/// * String values are `true` if they are non-empty, or `false` if they are
///   empty (e.g: "").
///
fn emit_bool_expr(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    expr: &Expr,
) {
    emit_expr(ctx, instr, expr);

    match expr.ty() {
        Type::Bool => {
            // `expr` already returned a bool, nothing more to do.
        }
        Type::Integer => {
            instr.i64_const(0);
            instr.binop(BinaryOp::I64Ne);
        }
        Type::Float => {
            instr.f64_const(0.0);
            instr.binop(BinaryOp::F64Ne);
        }
        Type::String => {
            instr.call(ctx.function_id(wasm::export__str_len.mangled_name));
            instr.i64_const(0);
            instr.binop(BinaryOp::I64Ne);
        }
        ty => unreachable!("type `{:?}` can't be casted to boolean", ty),
    }
}

/// Calls a function that may return an undefined value.
///
/// Some functions in YARA can return undefined values, for example the
/// built-in function `uint8(offset)` returns an undefined result when `offset`
/// is outside the data boundaries. The same occurs with many function
/// implemented by YARA modules.
///
/// These functions return actually a tuple `(value, is_undef)`, where
/// `is_undef` is an `i32` that will be `0` for valid values and `1` for
/// undefined values. When `is_undef` is `1` the value is ignored.
///
/// This emits code that calls the specified function, checks if its result
/// is undefined, and throws an exception if that's the case (see:
/// [`throw_undef`])
fn emit_call_and_handle_undef(
    ctx: &Context,
    instr: &mut InstrSeqBuilder,
    fn_id: walrus::FunctionId,
) {
    // The result from this call is a tuple (value, is_undef), where
    // `is_undef` is 1 if the result is undefined. If not, `is_undef` is
    // zero and `value` contains the actual result.
    instr.call(fn_id);

    // At this point `is_undef` is at the top of the stack, lets check if
    // it is zero. This remove `is_undef` from the stack, leaving `value`
    // at the top.
    instr.if_else(
        None,
        |then_| {
            // `is_undef` is non-zero, the result is undefined, let's raise
            // an exception.
            throw_undef(ctx, then_);
        },
        |_| {
            // Intentionally empty. An `if` method would be handy, but it
            // does not exists. This however emits WebAssembly code without
            // the `else` branch.
        },
    );
}

fn emit_lookup_common(ctx: &mut Context, instr: &mut InstrSeqBuilder) {
    let num_lookup_indexes = ctx.lookup_stack.len();
    let main_memory = ctx.wasm_symbols.main_memory;

    for (i, field_index) in ctx.lookup_stack.drain(0..).enumerate() {
        let offset = (i * size_of::<i32>()) as i32;

        assert!(
            // Memory offset (relative to LOOKUP_INDEXES_START) must be in the
            // range 0..LOOKUP_INDEXES_END - LOOKUP_INDEXES_START.
            (0..LOOKUP_INDEXES_END - LOOKUP_INDEXES_START).contains(&offset)
        );

        instr.i32_const(offset);
        instr.i32_const(field_index);
        instr.store(
            main_memory,
            StoreKind::I32 { atomic: false },
            MemArg {
                align: size_of::<i32>() as u32,
                offset: LOOKUP_INDEXES_START as u32,
            },
        );
    }

    instr.i32_const(num_lookup_indexes as i32);

    if let Some(start) = ctx.lookup_start.take() {
        instr.i32_const(start.index);
    } else {
        instr.i32_const(-1);
    }
}

#[inline]
fn emit_lookup_integer(ctx: &mut Context, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_integer.mangled_name),
    );
}

#[inline]
fn emit_lookup_float(ctx: &mut Context, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_float.mangled_name),
    );
}

#[inline]
fn emit_lookup_bool(ctx: &mut Context, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_bool.mangled_name),
    );
}

#[inline]
fn emit_lookup_string(ctx: &mut Context, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_string.mangled_name),
    );
}

#[inline]
fn emit_lookup_value(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    dst_var: Var,
) {
    emit_lookup_common(ctx, instr);
    instr.i32_const(dst_var.index);
    instr.call(ctx.function_id(wasm::export__lookup_value.mangled_name));
}

/// Emits code for catching exceptions caused by undefined values.
///
/// This function emits WebAssembly code that behaves similarly to an exception
/// handler. The code inside the catch block must return an `i32`, which is left
/// at the top of the stack. However, at any point inside this block you can use
/// [`throw_undef`] for throwing an exception when an undefined value is detected
/// In that case the execution flow will be interrupted at the point where
/// [`throw_undef`] was found, and the control transferred to the instruction
/// that follows after the `catch_undef` block, leaving a zero value of type
/// `i32` at the top of the stack.
///
/// In other words, [`catch_undef`] protects a block that returns an `i32` from
/// exceptions caused by undefined values, replacing the block's result with a
/// zero in case such exception occurs.
///
/// [`catch_undef`] blocks can be nested, and in such cases the control will
/// transferred to the end of the innermost block.
///
/// # Example
///
/// ```text
/// catch_undef(ctx, instr,
///    |block| {
///       throw_undef(ctx, block);   // The exception is raised here ...
///       block.i32_const(1);        // ... and this is not executed.
///    },
/// );
/// // ... at this point we have a zero value of type i32 at the top of the
/// // stack.
/// ```
///
fn catch_undef(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    expr: impl FnOnce(&mut Context, &mut InstrSeqBuilder),
) {
    // Create a new block containing `expr`. When an exception is raised from
    // within `expr`, the control flow will jump out of this block via a `br`
    // instruction.
    instr.block(I32, |block| {
        // Push the type and ID of the current block in the handlers stack.
        ctx.exception_handler_stack.push((I32, block.id()));
        expr(ctx, block);
    });

    // Pop exception handler from the stack.
    ctx.exception_handler_stack.pop();
}

/// Throws an exception when an undefined value is found.
///
/// For more information see [`catch_undef`].
fn throw_undef(ctx: &Context, instr: &mut InstrSeqBuilder) {
    let innermost_handler = *ctx
        .exception_handler_stack
        .last()
        .expect("calling `raise` from outside `try` block");

    // Put in the stack the result for the code block that we are about
    // to exit from. In WebAssembly each block has a return type, and the
    // top of the stack must be of that type when leaving that block, both
    // because the end of the block was reached or, as in this case,
    // because a `br` instruction jumped out the block. For example:
    //
    // ;; outer block returns an i32
    // (block $outer (result i32)
    //
    //   ;; inner block returns an i64
    //   (block $inner (result i64)
    //      i64.const 1      ;; this would be the result from $inner block in
    //                       ;; normal conditions, but we are about to use br
    //                       ;; for jumping out of the block.
    //      i32.const 0xBAD  ;; put an i32 in the stack, even if $inner block
    //                       ;; returns an i64 ...
    //      br $outer        ;; ... because this jumps to the end of $outer
    //                       ;; block, and $outer returns an i32.
    //    )
    //
    //    ;; the instructions below would be executed in normal conditions
    //    ;; but the `br` instruction prevents it forced an early exit.
    //
    //    i64.const 1     ;; pushes 1 in to the stack
    //    i64.eq          ;; compare the with the result from $inner block
    //
    //    ;; the result from `eq` is an i32 at the top of the stack, that
    //    ;; will be the result of $outer in normal conditions, but instead
    // .  ;; it will return 0xBAD.
    //  )
    //
    // Notice how we need to put an i32 in the stack before executing
    // `br $outer`, because that is going to be the result for the $outer
    // block.
    //
    match innermost_handler.0 {
        I32 => instr.i32_const(0),
        I64 => instr.i64_const(0),
        _ => unreachable!(),
    };

    // Jump to the exception handler.
    instr.br(innermost_handler.1);
}

/// Similar to [`throw_undef`], but throws the exception if the top of the
/// stack is zero. If the top of the stack is non-zero, calling this function
/// is a no-op.
fn throw_undef_if_zero(ctx: &Context, instr: &mut InstrSeqBuilder) {
    // Save the top of the stack into temp variable, but leave a copy in the
    // stack.
    instr.local_tee(ctx.wasm_symbols.i64_tmp);
    // Is top of the stack zero? The comparison removes the value from the
    // stack.
    instr.unop(UnaryOp::I64Eqz);
    instr.if_else(
        I64,
        |then| {
            // Is zero, throw exception
            throw_undef(ctx, then);
        },
        |else_| {
            // Non-zero, put back the value into the stack.
            else_.local_get(ctx.wasm_symbols.i64_tmp);
        },
    );
}

/// Returns the patterns (a.k.a: strings) in the current rule that match a
/// pattern set.
fn patterns_matching<'a>(
    ctx: &'a mut Context,
    pattern_set: &'a PatternSet,
) -> Box<dyn Iterator<Item = PatternId> + 'a> {
    match pattern_set {
        PatternSet::Them => {
            Box::new(ctx.current_rule.patterns.iter().map(|p| p.1))
        }
        PatternSet::Set(set_patterns) => Box::new(
            ctx.current_rule.patterns.iter().filter_map(move |rule_pattern| {
                // Get the pattern identifier (e.g: $, $a, $foo)
                let ident = ctx.ident_pool.get(rule_pattern.0).unwrap();
                // Iterate over the patterns in the set (e.g: $foo, $foo*) and
                // check if some of them matches the identifier.
                for set_pattern in set_patterns {
                    if set_pattern.matches(ident) {
                        return Some(rule_pattern.1);
                    }
                }
                None
            }),
        ),
    }
}
