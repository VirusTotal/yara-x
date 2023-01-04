use core::slice;
use std::mem::size_of;
use std::rc::Rc;

use bstr::ByteSlice;
use walrus::ir::ExtendedLoad::ZeroExtend;
use walrus::ir::{BinaryOp, InstrSeqId, LoadKind, MemArg, StoreKind, UnaryOp};
use walrus::ValType::{I32, I64};
use walrus::{InstrSeqBuilder, ValType};

use crate::ast::{
    Expr, ForIn, Iterable, MatchAnchor, Quantifier, Range, Rule,
};
use crate::compiler::{Context, RuleId, Var};
use crate::symbols::{Symbol, SymbolKind, SymbolLookup, SymbolTable};
use crate::types::{Array, Map, Type, TypeValue};
use crate::wasm::{
    RuntimeString, LOOKUP_INDEXES_END, LOOKUP_INDEXES_START,
    MATCHING_RULES_BITMAP_BASE, VARS_STACK_START,
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
/// This how we emit the code for the `add` operation:
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
    ($ctx:ident, $instr:ident, $expr:expr, $operands:expr, $int_op:tt, $float_op:tt, $str_op:tt) => {{
        emit_const_or_code!($ctx, $instr, $expr.type_value(), {
            match emit_operands!($ctx, $instr, $operands.lhs, $operands.rhs) {
                (Type::Integer, Type::Integer) => {
                    $instr.binop(BinaryOp::$int_op);
                }
                (Type::Float, Type::Float) => {
                    $instr.binop(BinaryOp::$float_op);
                }
                (Type::String, Type::String) => {
                    $instr.call($ctx.wasm_symbols.$str_op);
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
    // Emit WebAssembly code for the rule's condition.
    instr.block(None, |block| {
        catch_undef(ctx, block, |ctx, instr| {
            emit_bool_expr(ctx, instr, &rule.condition);
        });

        // If the condition's result is 0, jump out of the block
        // and don't call the `rule_result` function.
        block.unop(UnaryOp::I32Eqz);
        block.br_if(block.id());

        // RuleId is the argument to `rule_match`.
        block.i32_const(rule_id);

        // Emit call instruction for calling `rule_match`.
        block.call(ctx.wasm_symbols.rule_match);
    });
}

/// Emits WASM code for `expr` into the instruction sequence `instr`.
pub(super) fn emit_expr(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    expr: &Expr,
) {
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

                instr.i64_const(
                    RuntimeString::Literal(literal_id).as_wasm() as i64
                );
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
                        instr.i32_const(rule_id / 8);
                        instr.load(
                            ctx.wasm_symbols.main_memory,
                            LoadKind::I32_8 { kind: ZeroExtend },
                            MemArg {
                                align: size_of::<i8>() as u32,
                                offset: MATCHING_RULES_BITMAP_BASE as u32,
                            },
                        );
                        // This is the first operator for the I32ShrU operation.
                        instr.i32_const(rule_id % 8);
                        // Compute byte & (1 << (rule_id % 8)), which clears all
                        // bits except the one we are interested in.
                        instr.i32_const(1 << (rule_id % 8));
                        instr.binop(BinaryOp::I32And);
                        // Now shift the byte to the right, leaving the
                        // interesting bit as the LSB. So the result is either
                        // 1 or 0.
                        instr.binop(BinaryOp::I32ShrU);
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
                    SymbolKind::FieldIndex(index) => {
                        match ident.ty() {
                            Type::Integer => {
                                emit_lookup_integer(ctx, instr, index);
                            }
                            Type::Float => {
                                emit_lookup_float(ctx, instr, index);
                            }
                            Type::Bool => {
                                emit_lookup_bool(ctx, instr, index);
                            }
                            Type::String => {
                                emit_lookup_string(ctx, instr, index);
                            }
                            Type::Struct => {
                                ctx.lookup_stack.push_back(index);
                            }
                            Type::Array => {
                                ctx.lookup_stack.push_back(index);
                            }
                            Type::Map => {
                                ctx.lookup_stack.push_back(index);
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
            let pattern_id =
                ctx.get_pattern_from_current_rule(&pattern.identifier);

            match &pattern.anchor {
                Some(MatchAnchor::At(anchor_at)) => {
                    instr.i32_const(pattern_id);
                    emit_expr(ctx, instr, &anchor_at.expr);
                    instr.call(ctx.wasm_symbols.is_pat_match_at);
                }
                Some(MatchAnchor::In(anchor_in)) => {
                    instr.i32_const(pattern_id);
                    emit_expr(ctx, instr, &anchor_in.range.lower_bound);
                    emit_expr(ctx, instr, &anchor_in.range.upper_bound);
                    instr.call(ctx.wasm_symbols.is_pat_match_in);
                }
                None => {
                    instr.i32_const(pattern_id);
                    instr.call(ctx.wasm_symbols.is_pat_match);
                }
            }
        }
        Expr::PatternCount(_) => {
            // TODO
        }
        Expr::PatternOffset(_) => {
            // TODO
        }
        Expr::PatternLength(_) => {
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
                // until `emit_array_lookup` or `emit_map_lookup` is called.
                emit_expr(ctx, instr, &operands.primary);

                // Emit a call instruction to the corresponding function, which
                // depends on the type of the primary expression (array or map)
                // and the type of the index expression.
                match operands.primary.type_value() {
                    TypeValue::Array(array) => {
                        emit_array_lookup(ctx, instr, array, None);
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
                    Some(operands.lhs.type_value().as_struct().unwrap());

                emit_expr(ctx, instr, &operands.rhs);

                ctx.current_struct = None;
            })
        }
        Expr::FnCall(_) => {
            // TODO
        }
        Expr::Not(operand) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                // The NOT expression is emitted as:
                //
                //   if (evaluate_operand()) {
                //     0
                //   } else {
                //     1
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
                // The AND expression is emitted as:
                //
                //   try {
                //     lhs = evaluate_left_operand()
                //   } catch undefined {
                //     lhs = false
                //   }
                //
                //   if (lhs) {
                //     try {
                //        return evaluate_right_operand()
                //     } catch undefined {
                //        return false
                //     }
                //   } else {
                //     return false
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
                // The OR expression is emitted as:
                //
                //   try {
                //     lhs = evaluate_left_operand()
                //   } catch undefined {
                //     lhs = false
                //   }
                //
                //   if (lhs) {
                //     return true
                //   } else {
                //     return evaluate_right_operand()
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
                ctx, instr, expr, operands, I64Eq, F64Eq, str_eq
            );
        }
        Expr::Ne(operands) => {
            emit_comparison_op!(
                ctx, instr, expr, operands, I64Ne, F64Ne, str_ne
            );
        }
        Expr::Lt(operands) => {
            emit_comparison_op!(
                ctx, instr, expr, operands, I64LtS, F64Lt, str_lt
            );
        }
        Expr::Gt(operands) => {
            emit_comparison_op!(
                ctx, instr, expr, operands, I64GtS, F64Gt, str_gt
            );
        }
        Expr::Le(operands) => {
            emit_comparison_op!(
                ctx, instr, expr, operands, I64LeS, F64Le, str_le
            );
        }
        Expr::Ge(operands) => {
            emit_comparison_op!(
                ctx, instr, expr, operands, I64GeS, F64Ge, str_ge
            );
        }
        Expr::Contains(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.wasm_symbols.str_contains);
            });
        }
        Expr::IContains(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.wasm_symbols.str_icontains);
            });
        }
        Expr::StartsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.wasm_symbols.str_startswith);
            });
        }
        Expr::IStartsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.wasm_symbols.str_istartswith);
            });
        }
        Expr::EndsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.wasm_symbols.str_endswith);
            });
        }
        Expr::IEndsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.wasm_symbols.str_iendswith);
            });
        }
        Expr::IEquals(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.wasm_symbols.str_iequals);
            });
        }
        Expr::Matches(_) => {
            // TODO
        }
        Expr::Of(_) => {
            // TODO
        }
        Expr::ForOf(_) => {
            // TODO
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

fn emit_array_lookup(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    array: &Rc<Array>,
    var: Option<Var>,
) {
    // Emit the code that fills the `lookup_stack` in WASM memory.
    emit_lookup_common(ctx, instr);

    if let Some(var) = var {
        instr.i32_const(var.index);
    } else {
        instr.i32_const(-1);
    }

    match array.as_ref() {
        Array::Integers(_) => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.array_lookup_integer,
            );
        }
        Array::Floats(_) => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.array_lookup_float,
            );
        }
        Array::Bools(_) => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.array_lookup_bool,
            );
        }
        Array::Structs(_) => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.array_lookup_struct,
            );
        }
        Array::Strings(_) => {
            emit_call_and_handle_undef_str(
                ctx,
                instr,
                ctx.wasm_symbols.array_lookup_string,
            );
        }
    }
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

    match map_value.ty() {
        Type::Integer => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_integer_integer,
            );
        }
        Type::Float => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_integer_float,
            );
        }
        Type::Bool => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_integer_bool,
            );
        }
        Type::Struct => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_integer_struct,
            );
        }
        Type::String => {
            emit_call_and_handle_undef_str(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_integer_string,
            );
        }
        _ => unreachable!(),
    }
}

fn emit_map_string_key_lookup(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    map_value: &TypeValue,
) {
    emit_lookup_common(ctx, instr);

    // Generate the call depending on the type of the map values.
    match map_value.ty() {
        Type::Integer => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_string_integer,
            );
        }
        Type::Float => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_string_float,
            );
        }
        Type::Bool => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_string_bool,
            );
        }
        Type::Struct => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_string_struct,
            );
        }
        Type::String => {
            emit_call_and_handle_undef_str(
                ctx,
                instr,
                ctx.wasm_symbols.map_lookup_string_string,
            );
        }
        _ => unreachable!(),
    }
}

/// Emits a `for` loop.
///
/// This function allows creating different types of `for` loops by receiving
/// other functions that emit the loop initialization code, the code that gets
/// executed just before and after each iteration.
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
/// `after_cond` emits the code that gets executed on every iteration after
/// the loop's condition. This code should not leave anything on the stack.
pub(super) fn emit_for<I, B, A>(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    loop_init: I,
    before_cond: B,
    after_cond: A,
) where
    I: FnOnce(&mut Context, &mut InstrSeqBuilder, Var, InstrSeqId),
    B: FnOnce(&mut Context, &mut InstrSeqBuilder, Var),
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

        let (quantifier, counter) = match &for_in.quantifier {
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                // `quantifier` is the number of loop conditions that must return
                // `true` for the loop to be `true`.
                let quantifier = ctx.new_var(Type::Integer);
                // `counter` is the number of loop conditions that actually
                // returned `true`. This is initially zero.
                let counter = ctx.new_var(Type::Integer);

                set_var(ctx, instr, quantifier, |ctx, instr| {
                    if matches!(&for_in.quantifier, Quantifier::Percentage(_))
                    {
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

                // Initialize `counter` to 0.
                set_var(ctx, instr, counter, |_, instr| {
                    instr.i64_const(0);
                });

                (quantifier, counter)
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

            // Emit code for the loop's condition.
            emit_expr(ctx, block, &for_in.condition);

            // At the top of the stack we have the i32 with the result from
            // the loop condition. Decide what to do depending on the
            // quantifier.
            match &for_in.quantifier {
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
                            // The condition was true, increment counter.
                            incr_var(ctx, then_, counter);

                            // Is counter >= quantifier?.
                            load_var(ctx, then_, counter);
                            load_var(ctx, then_, quantifier);
                            then_.binop(BinaryOp::I64GeS);

                            then_.if_else(
                                None,
                                // counter >= quantifier
                                |then_| {
                                    // Is quantifier == 0?
                                    load_var(ctx, then_, quantifier);
                                    then_.unop(UnaryOp::I64Eqz);
                                    then_.if_else(
                                        None,
                                        // quantifier == 0, this should treated
                                        // as a `none` quantifier. At this point
                                        // counter >= 1, so break the loop with
                                        // result false.
                                        |then_| {
                                            then_.i32_const(0);
                                            then_.br(loop_end);
                                        },
                                        // quantifier != 0 and counter >= quantifier
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
                    // range 0..n. If quantifier is zero this means that all
                    // iterations returned false and therefore the loop must
                    // return true. If quantifier is non-zero it means that
                    // `counter` didn't reached `quantifier` and the loop must
                    // return false.
                    load_var(ctx, block, quantifier);
                    block.unop(UnaryOp::I64Eqz);
                    block.if_else(
                        I32,
                        // quantifier == 0
                        |then_| {
                            then_.i32_const(1);
                        },
                        // quantifier != 0
                        |else_| {
                            else_.i32_const(0);
                        },
                    );
                }
            }
        });

        if matches!(
            &for_in.quantifier,
            Quantifier::Percentage(_) | Quantifier::Expr(_)
        ) {
            ctx.free_vars(quantifier);
        };
    });

    ctx.free_vars(n);
}

pub(super) fn emit_for_in_range(
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
    loop_vars.insert(for_in.variables.first().unwrap().as_str(), symbol);

    // Push the symbol table with loop variable on top of the existing symbol
    // tables.
    ctx.symbol_table.push(Rc::new(loop_vars));

    emit_for(
        ctx,
        instr,
        for_in,
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

pub(super) fn emit_for_in_expr(
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

pub(super) fn emit_for_in_array(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    array_expr: &Expr,
) {
    // A `for` loop in an array has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    let array = array_expr.type_value().as_array().unwrap();

    // The type of the loop variable must be the type of the items in the array,
    // except for arrays of struct, for which we don't need to create a variable.
    let (is_wasm_var, loop_var) = match array.as_ref() {
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
    if is_wasm_var {
        symbol.kind = SymbolKind::WasmVar(next_item);
    } else {
        symbol.kind = SymbolKind::HostVar(next_item);
    }

    loop_vars.insert(for_in.variables.first().unwrap().as_str(), symbol);

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
        for_in,
        |ctx, instr, n, loop_end| {
            // Initialize `n` to the array's length.
            set_var(ctx, instr, n, |ctx, instr| {
                instr.i32_const(array_var.index);
                instr.call(ctx.wasm_symbols.array_len);
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

            if is_wasm_var {
                // Get the i-th item in the array and store it in the
                // WASM-side local variable `next_item`.
                set_var(ctx, instr, next_item, |ctx, instr| {
                    load_var(ctx, instr, i);
                    emit_array_lookup(ctx, instr, &array, None);
                });
            } else {
                // Get the i-th item in the array and store it in the
                // host-side local variable `next_item`.
                load_var(ctx, instr, i);
                emit_array_lookup(ctx, instr, &array, Some(next_item));
            }
        },
        // After each iteration.
        |_, _, _| {},
    );

    ctx.symbol_table.pop();
    ctx.free_vars(next_item);
}

pub(super) fn emit_for_in_map(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    map_expr: &Expr,
) {
    // A `for` loop in an map has exactly two variables.
    assert_eq!(for_in.variables.len(), 2);

    let map = map_expr.type_value().as_map().unwrap();

    let (key, val) = match map.as_ref() {
        Map::IntegerKeys { deputy, .. } => (
            TypeValue::Integer(None),
            deputy.as_ref().unwrap().clone_without_value(),
        ),
        Map::StringKeys { deputy, .. } => (
            TypeValue::String(None),
            deputy.as_ref().unwrap().clone_without_value(),
        ),
    };

    // Create variable `next_key`, which will contain the key that will be
    // put in the loop variable in the next iteration.
    let next_key = ctx.new_var(key.ty());

    // Create variable `next_val`, which will contain the value that will be
    // put in the loop variable in the next iteration.
    let next_val = ctx.new_var(val.ty());

    // Create a symbol table containing the loop variable.
    let mut symbol_key = Symbol::new(key);
    let mut symbol_val = Symbol::new(val);

    symbol_key.kind = SymbolKind::WasmVar(next_key);
    symbol_val.kind = match next_key.ty {
        Type::Integer | Type::Float | Type::Bool | Type::String => {
            SymbolKind::WasmVar(next_val)
        }
        Type::Struct | Type::Array => SymbolKind::HostVar(next_val),
        _ => unreachable!(),
    };

    let mut loop_vars = SymbolTable::new();

    loop_vars.insert(for_in.variables[0].as_str(), symbol_key);
    loop_vars.insert(for_in.variables[1].as_str(), symbol_val);

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
        for_in,
        |ctx, instr, n, loop_end| {
            // Initialize `n` to the maps's length.
            set_var(ctx, instr, n, |ctx, instr| {
                instr.i32_const(map_var.index);
                instr.call(ctx.wasm_symbols.map_len);
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
        |ctx, instr, i| todo!(),
        // After each iteration.
        |_, _, _| todo!(),
    );

    ctx.symbol_table.pop();
    ctx.free_vars(next_key);
}

/// Given an iterator that returns `N` expressions ([`Expr`]), generates a
/// switch statement that takes an `i64` value from the stack (in the range
/// `0..N-1`) and executes the corresponding expression.
///
/// For an iterator that returns 3 expressions the generated code looks like
/// this:
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
///       ;; < code expr 2 goes here >
///       br 2 (;@1;)                   ;; exits block @1
///     end                             ;; block @3  
///     ;; < code expr 1 goes here >
///     br 1 (;@1;)                     ;; exits block @1        
///   end                               ;; block @2
///   ;; < code expr 0 goes here >
///   br 0 (;@1;)                       ;; exits block @1   
/// end                                 ;; block @1
///                                     ;; at this point the i64 returned by the
///                                     ;; selected expression is at the top of
///                                     ;; the stack.
/// ```
fn emit_switch(
    ctx: &mut Context,
    ty: ValType,
    instr: &mut InstrSeqBuilder,
    expressions: &[Expr],
) {
    // Convert the i64 at the top of the stack to an i32, which is the type
    // expected by the `bt_table` instruction.
    instr.unop(UnaryOp::I32WrapI64);

    // Store the i32 switch selector in a temp variable. The selector is the i32
    // value at the top of the stack that tells which expression should be
    // executed.
    instr.local_set(ctx.wasm_symbols.i32_tmp);

    let block_ids = Vec::new();

    instr.block(ty, |block| {
        emit_switch_internal(ctx, block, expressions.iter(), block_ids);
    });
}

fn emit_switch_internal(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    mut expressions: slice::Iter<Expr>,
    mut block_ids: Vec<InstrSeqId>,
) {
    block_ids.push(instr.id());

    if let Some(expr) = expressions.next() {
        let outermost_block = block_ids.first().cloned();
        instr.block(None, |block| {
            emit_switch_internal(ctx, block, expressions, block_ids);
        });
        emit_expr(ctx, instr, expr);
        instr.br(outermost_block.unwrap());
    } else {
        instr.block(None, |block| {
            block.local_get(ctx.wasm_symbols.i32_tmp);
            block.br_table(block_ids[1..].into(), block.id());
        });
        instr.unreachable();
    };
}

pub(super) fn emit_for_in_expr_tuple(
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
    loop_vars.insert(for_in.variables.first().unwrap().as_str(), symbol);

    // Push the symbol table with loop variable on top of the existing symbol
    // tables.
    ctx.symbol_table.push(Rc::new(loop_vars));

    emit_for(
        ctx,
        instr,
        for_in,
        |ctx, instr, n, _| {
            // Initialize `n` to number of expressions.
            set_var(ctx, instr, n, |_, instr| {
                instr.i64_const(expressions.len() as i64);
            });
        },
        // Before each iteration.
        |ctx, instr, i| {
            // Execute the i-th expression and save its result in `next_item`.
            set_var(ctx, instr, next_item, |ctx, instr| {
                load_var(ctx, instr, i);
                emit_switch(ctx, next_item.ty.into(), instr, expressions);
            });
        },
        // After each iteration.
        |_, _, _| {},
    );

    // Remove the symbol table that contains the loop variable.
    ctx.symbol_table.pop();

    // Free loop variables.
    ctx.free_vars(next_item);
}

/// Sets a variable to the value produced by a code block.
pub(super) fn set_var<B>(
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

    let store_kind = match var.ty {
        Type::Bool => StoreKind::I32 { atomic: false },
        Type::Integer => StoreKind::I64 { atomic: false },
        Type::Float => StoreKind::F64,
        Type::String => StoreKind::I64 { atomic: false },
        _ => unreachable!(),
    };

    // The store instruction will remove two items from the stack, the value and
    // the offset where it will be stored.
    instr.store(
        ctx.wasm_symbols.main_memory,
        store_kind,
        MemArg { align: size_of::<i64>() as u32, offset: 0 },
    );
}

/// Loads the value of variable into the stack.
pub(super) fn load_var(ctx: &Context, instr: &mut InstrSeqBuilder, var: Var) {
    instr.i32_const(var.index * size_of::<i64>() as i32);

    let load_kind = match var.ty {
        Type::Bool => LoadKind::I32 { atomic: false },
        Type::Integer => LoadKind::I64 { atomic: false },
        Type::Float => LoadKind::F64,
        Type::String => LoadKind::I64 { atomic: false },
        _ => unreachable!(),
    };

    instr.load(
        ctx.wasm_symbols.main_memory,
        load_kind,
        MemArg {
            align: size_of::<i64>() as u32,
            offset: VARS_STACK_START as u32,
        },
    );
}

/// Increments a variable.
pub(super) fn incr_var(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    var: Var,
) {
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
pub(super) fn emit_bool_expr(
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
            instr.call(ctx.wasm_symbols.str_len);
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
pub(super) fn emit_call_and_handle_undef(
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

/// Calls a function that may return an undefined string.
///
/// This function is similar to [`emit_call_and_handle_undef`], but strings
/// are represented differently from other values and therefore they require
/// a different treatment.
///
/// Strings are represented by an `i64` (see [`RuntimeStringWasm`] for more
/// details), and they are undefined when the value is zero.
pub(super) fn emit_call_and_handle_undef_str(
    ctx: &Context,
    instr: &mut InstrSeqBuilder,
    fn_id: walrus::FunctionId,
) {
    // Call the function that returns a string. The string is represented
    // by an i64, and is undefined when its value is zero.
    instr.call(fn_id);
    // If the value was zero throws an exception.
    throw_undef_if_zero(ctx, instr);
}

pub(super) fn emit_lookup_common(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
) {
    if let Some(start) = ctx.lookup_start.take() {
        instr.i32_const(start.index);
        instr.global_set(ctx.wasm_symbols.lookup_start);
    } else {
        instr.i32_const(-1);
        instr.global_set(ctx.wasm_symbols.lookup_start);
    }

    instr.i32_const(ctx.lookup_stack.len() as i32);
    instr.global_set(ctx.wasm_symbols.lookup_stack_top);

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
}

#[inline]
pub(super) fn emit_lookup_integer(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(ctx, instr, ctx.wasm_symbols.lookup_integer);
}

#[inline]
pub(super) fn emit_lookup_float(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(ctx, instr, ctx.wasm_symbols.lookup_float);
}

#[inline]
pub(super) fn emit_lookup_bool(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(ctx, instr, ctx.wasm_symbols.lookup_bool);
}

#[inline]
pub(super) fn emit_lookup_string(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef_str(ctx, instr, ctx.wasm_symbols.lookup_string);
}

#[inline]
pub(super) fn emit_lookup_value(
    ctx: &mut Context,
    instr: &mut InstrSeqBuilder,
    var: Var,
) {
    emit_lookup_common(ctx, instr);
    instr.i32_const(var.index);
    instr.call(ctx.wasm_symbols.lookup_value);
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
pub(super) fn catch_undef(
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
pub(super) fn throw_undef(ctx: &Context, instr: &mut InstrSeqBuilder) {
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
pub(super) fn throw_undef_if_zero(ctx: &Context, instr: &mut InstrSeqBuilder) {
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
