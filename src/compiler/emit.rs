use std::cell::RefCell;
use std::mem::size_of;
use std::rc::Rc;

use bstr::ByteSlice;
use walrus::ir::{BinaryOp, InstrSeqId, LoadKind, MemArg, StoreKind, UnaryOp};
use walrus::InstrSeqBuilder;
use walrus::ValType::{I32, I64};

use crate::ast::{Expr, ForIn, Iterable, MatchAnchor, Quantifier, Range};
use crate::compiler::Context;
use crate::symbols::{Symbol, SymbolLookup, SymbolTable};
use crate::types::{Array, Map, Type, TypeValue};
use crate::wasm;
use crate::wasm::{RuntimeString, RuntimeStringWasm};

/// This macro emits a constant if the type hint indicates that the expression
/// has a constant value (e.i: the value is known at compile time), if not,
/// it executes the code block, emitting whatever the code block says. Notice
/// however that this is done only if the `compile-time-optimization` feature
/// is enabled, if the feature is not enabled the code block will be executed
/// regardless of whether the expression's value is known at compile time or
/// not.
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
                        $ctx.borrow_mut().lit_pool.get_or_intern(value.as_bstr());

                    push_string($instr, RuntimeString::Literal(literal_id).as_wasm());
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
                    $instr.call($ctx.borrow().wasm_symbols.$str_op);
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
                    $instr.local_tee($ctx.borrow().wasm_symbols.i64_tmp);
                    $instr.binop(BinaryOp::$int_op);
                    $instr.i64_const(0);
                    $instr.local_get($ctx.borrow().wasm_symbols.i64_tmp);
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

/// Emits WebAssembly code for `expr` into the instruction sequence `instr`.
pub(super) fn emit_expr(
    ctx: &RefCell<Context>,
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
            instr.global_get(ctx.borrow().wasm_symbols.filesize);
        }
        Expr::Entrypoint { .. } => {
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
                let literal_id =
                    ctx.borrow_mut().lit_pool.get_or_intern(value.as_bstr());

                push_string(
                    instr,
                    RuntimeString::Literal(literal_id).as_wasm(),
                );
            }
            _ => unreachable!(),
        },
        Expr::Ident(ident) => {
            emit_const_or_code!(ctx, instr, &ident.type_value, {
                let current_struct = ctx.borrow_mut().current_struct.take();

                // Search for the identifier in the current structure, if any,
                // or in the global symbol table if `current_struct` is None.
                let symbol = if let Some(ref current_struct) = current_struct {
                    current_struct.lookup(ident.name).unwrap()
                } else {
                    ctx.borrow().symbol_table.lookup(ident.name).unwrap()
                };

                if let Some(mem_location) = symbol.mem_offset() {
                    // The symbol is known to be at some memory location, emit
                    // code for loading its value from memory and put it into
                    // the stack.
                    instr.i32_const(mem_location);
                    emit_load(ctx, instr);
                } else {
                    let index = symbol.field_index().unwrap();

                    // Emit code for looking up the identifier in the current
                    // symbol table.
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
                            // If the identifier refers to some struct, store
                            // it in `current_struct`.
                            if let TypeValue::Struct(structure) =
                                symbol.type_value()
                            {
                                ctx.borrow_mut().current_struct =
                                    Some(structure.clone());
                            } else {
                                unreachable!()
                            }

                            ctx.borrow_mut().lookup_stack.push_back(index);
                        }
                        Type::Array => {
                            ctx.borrow_mut().lookup_stack.push_back(index);
                        }
                        Type::Map => {
                            ctx.borrow_mut().lookup_stack.push_back(index);
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
            });
        }
        Expr::PatternMatch(pattern) => {
            let pattern_id = ctx
                .borrow()
                .get_pattern_from_current_rule(&pattern.identifier);

            match &pattern.anchor {
                Some(MatchAnchor::At(anchor_at)) => {
                    instr.i32_const(pattern_id);
                    emit_expr(ctx, instr, &anchor_at.expr);
                    instr.call(ctx.borrow().wasm_symbols.is_pat_match_at);
                }
                Some(MatchAnchor::In(anchor_in)) => {
                    instr.i32_const(pattern_id);
                    emit_expr(ctx, instr, &anchor_in.range.lower_bound);
                    emit_expr(ctx, instr, &anchor_in.range.upper_bound);
                    instr.call(ctx.borrow().wasm_symbols.is_pat_match_in);
                }
                None => {
                    instr.i32_const(pattern_id);
                    instr.call(ctx.borrow().wasm_symbols.is_pat_match);
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
                // Emit code for the value (array or map) that is being indexed.
                // This will set the value of `current_array` or `current_map`
                // in the scan context, but doesn't leave anything in the
                // stack.
                //
                // Notice that the index expression must be evaluated first
                // because it may contain another indexing operation that will
                // change the value of `current_array` or `current_map`. If
                // the primary expression is evaluated first, the value left
                // in `current_array/current_dict` would be overwritten while
                // emitting the index expression.
                emit_expr(ctx, instr, &operands.primary);

                // Emit a call instruction to the corresponding function, which
                // depends on the type of the primary expression (array or map)
                // and the type of the index expression.
                match operands.primary.type_value() {
                    TypeValue::Array(array) => {
                        emit_array_lookup(ctx, instr, array);
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
                emit_expr(ctx, instr, &operands.rhs);
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
                catch_undef(ctx, instr, |instr| {
                    emit_bool_expr(ctx, instr, &operands.lhs);
                });

                instr.if_else(
                    I32,
                    |then_| {
                        catch_undef(ctx, then_, |instr| {
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
                catch_undef(ctx, instr, |instr| {
                    emit_bool_expr(ctx, instr, &operands.lhs);
                });

                instr.if_else(
                    I32,
                    |then_| {
                        then_.i32_const(1);
                    },
                    |else_| {
                        catch_undef(ctx, else_, |instr| {
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
                        if_non_zero(ctx, instr, |instr| {
                            // Both operands are integer, the operation is integer.
                            instr.binop(BinaryOp::I64RemS);
                        });
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
                        if_non_zero(ctx, instr, |instr| {
                            // Both operands are integer, the operation is integer.
                            instr.binop(BinaryOp::I64DivS);
                        });
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
                instr.call(ctx.borrow().wasm_symbols.str_contains);
            });
        }
        Expr::IContains(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_icontains);
            });
        }
        Expr::StartsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_startswith);
            });
        }
        Expr::IStartsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_istartswith);
            });
        }
        Expr::EndsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_endswith);
            });
        }
        Expr::IEndsWith(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_iendswith);
            });
        }
        Expr::IEquals(operands) => {
            emit_const_or_code!(ctx, instr, expr.type_value(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_iequals);
            });
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
            Iterable::Expr(expr) => {
                emit_for_in_expr(ctx, instr, for_in, expr);
            }
        },
    }
}

fn emit_array_lookup(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    array: &Rc<Array>,
) {
    emit_lookup_common(ctx, instr);

    match array.as_ref() {
        Array::Integers(_) => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.array_lookup_integer,
            );
        }
        Array::Floats(_) => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.array_lookup_float,
            );
        }
        Array::Bools(_) => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.array_lookup_bool,
            );
        }
        Array::Structs(array) => {
            ctx.borrow_mut().current_struct =
                Some(array.first().unwrap().clone());

            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.array_lookup_struct,
            );
        }
        Array::Strings(_) => {
            emit_call_and_handle_undef_str(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.array_lookup_string,
            );
        }

        _ => unreachable!(),
    }
}

fn emit_map_lookup(
    ctx: &RefCell<Context>,
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
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    map_value: &TypeValue,
) {
    // If values in the map are structs, update `current_struct` accordingly.
    if let TypeValue::Struct(s) = map_value {
        ctx.borrow_mut().current_struct = Some(s.clone())
    }

    emit_lookup_common(ctx, instr);

    match map_value.ty() {
        Type::Integer => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_integer_integer,
            );
        }
        Type::Float => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_integer_float,
            );
        }
        Type::Bool => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_integer_bool,
            );
        }
        Type::Struct => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_integer_struct,
            );
        }
        Type::String => {
            emit_call_and_handle_undef_str(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_integer_string,
            );
        }
        _ => unreachable!(),
    }
}

fn emit_map_string_key_lookup(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    map_value: &TypeValue,
) {
    // If values in the map are structs, update `current_struct` accordingly.
    if let TypeValue::Struct(s) = map_value {
        ctx.borrow_mut().current_struct = Some(s.clone())
    }

    emit_lookup_common(ctx, instr);

    // Generate the call depending on the type of the map values.
    match map_value.ty() {
        Type::Integer => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_string_integer,
            );
        }
        Type::Float => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_string_float,
            );
        }
        Type::Bool => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_string_bool,
            );
        }
        Type::Struct => {
            emit_call_and_handle_undef(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_string_struct,
            );
        }
        Type::String => {
            emit_call_and_handle_undef_str(
                ctx,
                instr,
                ctx.borrow().wasm_symbols.map_lookup_string_string,
            );
        }
        _ => unreachable!(),
    }
}

/// Emits a `for` loop.
///
/// This function allows creating different types of `for` loops by receiving
/// other functions that emit the loop initialization code, the code that
/// produces the next item, and the code that checks if the loop has finished.
///
/// `loop_init` is the function that emits the initialization code, which is
/// executed only once, before the loop itself. This code should not leave
/// anything on the stack.
///
/// `next_item` emits the code that gets executed on every iteration just
/// before the loop's condition. The code produced by `next_item` must set the
/// loop variable(s) used by the condition to the value(s) corresponding to
/// the current iteration. This code should not leave anything on the stack.
///
/// `loop_cond` emits the code that decides whether the loop should continue
/// or not. This code should leave a i32 with values 0 or 1 in the stack, 1
/// means the the loop should continue and 0 that it should finish.
pub(super) fn emit_for<I, N, C>(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    n_ptr: i32,
    loop_init: I,
    next_item: N,
    loop_cond: C,
) where
    I: FnOnce(&mut InstrSeqBuilder, InstrSeqId),
    N: FnOnce(&mut InstrSeqBuilder),
    C: FnOnce(&mut InstrSeqBuilder),
{
    instr.block(I32, |instr| {
        let loop_end = instr.id();

        loop_init(instr, loop_end);

        let (quantifier, counter) = match &for_in.quantifier {
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                // `quantifier` is the number of loop conditions that must return
                // `true` for the loop to be `true`.
                let quantifier = ctx.borrow_mut().new_var();
                // `counter` is the number of loop conditions that actually
                // returned `true`. This is initially zero.
                let counter = ctx.borrow_mut().new_var();

                // Push memory offset where `quantifier` will be stored.
                instr.i32_const(quantifier);

                if matches!(&for_in.quantifier, Quantifier::Percentage(_)) {
                    // Compute n * quantifier / 100;

                    // n * quantifier
                    instr.i32_const(n_ptr);
                    emit_load(ctx, instr);
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
                    // Push value of `quantifier`.
                    emit_expr(ctx, instr, expr);
                }

                // Store `quantifier` in memory.
                emit_store(ctx, instr);

                // Push memory offset where `counter` will be stored.
                instr.i32_const(counter);
                // Initialize `counter` to 0.
                instr.i64_const(0);
                // Store `counter` in memory.
                emit_store(ctx, instr);

                (quantifier, counter)
            }
            _ => (0, 0),
        };

        instr.loop_(I32, |block| {
            let loop_start = block.id();

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
                            // Emit code that advances to next item.
                            next_item(else_);
                            // Emit code that checks if loop should finish.
                            loop_cond(else_);
                            // Keep iterating while true.
                            else_.br_if(loop_start);
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
                            // Emit code that advances to next item.
                            next_item(then_);
                            // Emit code that checks if loop should finish.
                            loop_cond(then_);
                            // Keep iterating while true.
                            then_.br_if(loop_start);
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
                            // Emit code that advances to next item.
                            next_item(else_);
                            // Emit code that checks if loop should finish.
                            loop_cond(else_);
                            // Keep iterating while true.
                            else_.br_if(loop_start);
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
                            // If the condition was true increment counter.

                            // Offset where the counter will be stored.
                            then_.i32_const(counter);
                            // Offset from where the counter will be loaded
                            then_.i32_const(counter);
                            // Load counter
                            emit_load(ctx, then_);
                            // Increment the counter by 1.
                            then_.i64_const(1);
                            then_.binop(BinaryOp::I64Add);
                            // Store counter in memory.
                            emit_store(ctx, then_);

                            // Compare counter to quantifier.
                            then_.i32_const(counter);
                            emit_load(ctx, then_);
                            then_.i32_const(quantifier);
                            emit_load(ctx, then_);
                            then_.binop(BinaryOp::I64Eq);

                            // If the counter is equal to the quantifier
                            // break the loop with result true
                            then_.if_else(
                                None,
                                |then_| {
                                    then_.i32_const(1);
                                    then_.br(loop_end);
                                },
                                |_| {},
                            );
                        },
                        |_| {},
                    );

                    // Emit code that advances to next item.
                    next_item(block);
                    // Emit code that checks if loop should finish.
                    loop_cond(block);
                    // Keep iterating while true.
                    block.br_if(loop_start);
                    // If this point is reached we have iterated over the whole
                    // range 0..n without `counter` reaching `quantifier`. The `for`
                    // loop must return false.
                    block.i32_const(0);
                }
            }
        });
    });
}

pub(super) fn emit_for_in_range(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    range: &Range,
) {
    // A `for` loop in a range has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    // Create variable `n`, which will contain the maximum number of iterations.
    let n_ptr = ctx.borrow_mut().new_var();

    // Create variable `i`, which will contain the current iteration number.
    // The value of `i` is in the range 0..n-1.
    let i_ptr = ctx.borrow_mut().new_var();

    // Create variable `next_item`, which will contain the item that will be
    // put in the loop variable in the next iteration.
    let next_item = ctx.borrow_mut().new_var();

    emit_for(
        ctx,
        instr,
        for_in,
        n_ptr,
        |instr, loop_end| {
            // Initialize `i` to zero.
            instr.i32_const(i_ptr);
            instr.i64_const(0);
            emit_store(ctx, instr);

            // (1) Push memory offset where `n` will be stored in the next
            // emit_store(ctx, block);
            instr.i32_const(n_ptr);

            emit_expr(ctx, instr, &range.upper_bound);
            emit_expr(ctx, instr, &range.lower_bound);

            // Store lower_bound in temp variable, without removing it from the stack.
            instr.local_tee(ctx.borrow().wasm_symbols.i64_tmp);

            // Compute upper_bound - lower_bound + 1.
            instr.binop(BinaryOp::I64Sub);
            instr.i64_const(1);
            instr.binop(BinaryOp::I64Add);

            // Set n = upper_bound - lower_bound + 1. Offset of `n` was pushed in (1).
            emit_store(ctx, instr);

            // If n <= 0, exit from the loop.
            instr.i32_const(n_ptr);
            emit_load(ctx, instr);
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
            instr.i32_const(next_item);
            instr.local_get(ctx.borrow().wasm_symbols.i64_tmp);
            emit_store(ctx, instr);

            let mut symbol = Symbol::new(TypeValue::Integer(None));

            symbol.set_mem_offset(next_item);

            let mut loop_vars = SymbolTable::new();

            loop_vars
                .insert(for_in.variables.first().unwrap().as_str(), symbol);

            // Put the loop variables into scope.
            ctx.borrow_mut().symbol_table.push(Rc::new(loop_vars));
        },
        // Next item.
        |instr| {
            instr.i32_const(next_item);
            instr.i32_const(next_item);
            emit_load(ctx, instr);
            instr.i64_const(1);
            instr.binop(BinaryOp::I64Add);
            emit_store(ctx, instr);
        },
        // Loop condition.
        |instr| {
            // Offset where `i` will be stored
            instr.i32_const(i_ptr);
            // Offset from where `i` will be loaded
            instr.i32_const(i_ptr);
            // Load `i` from memory.
            emit_load(ctx, instr);
            // Increment it
            instr.i64_const(1);
            instr.binop(BinaryOp::I64Add);
            // Store it back to memory.
            emit_store(ctx, instr);

            // Compare `i` to `n`.
            instr.i32_const(i_ptr);
            emit_load(ctx, instr);
            instr.i32_const(n_ptr);
            emit_load(ctx, instr);
            instr.binop(BinaryOp::I64LtS);
        },
    );

    ctx.borrow_mut().symbol_table.pop();
    ctx.borrow_mut().free_vars(n_ptr);
}

pub(super) fn emit_for_in_expr(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    expr: &Expr,
) {
    match expr.ty() {
        Type::Array => {
            emit_for_in_array(ctx, instr, for_in, expr);
        }
        Type::Map => {
            emit_for_in_map(ctx, instr, for_in, expr);
        }
        _ => unreachable!(),
    }
}

pub(super) fn emit_for_in_array(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    expr: &Expr,
) {
    emit_expr(ctx, instr, expr);

    // A `for` loop in an array has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    // Create variable `n`, which will contain the maximum number of iterations.
    let n_ptr = ctx.borrow_mut().new_var();

    // Create variable `i`, which will contain the current iteration number.
    // The value of `i` is in the range 0..n-1.
    let i_ptr = ctx.borrow_mut().new_var();

    // Create variable `next_item`, which will contain the item that will be
    // put in the loop variable in the next iteration.
    let next_item = ctx.borrow_mut().new_var();

    emit_for(
        ctx,
        instr,
        for_in,
        n_ptr,
        |instr, loop_end| {
            // Initialize `i` to zero.
            instr.i32_const(i_ptr);
            instr.i64_const(0);
            emit_store(ctx, instr);
        },
        // Next item.
        |instr| {
            // Offset from where `i` will be loaded
            instr.i32_const(i_ptr);
            // Load `i` from memory.
            emit_load(ctx, instr);

            emit_array_lookup(
                ctx,
                instr,
                &expr.type_value().as_array().unwrap(),
            );
        },
        // Loop condition.
        |instr| {},
    );

    ctx.borrow_mut().symbol_table.pop();
    ctx.borrow_mut().free_vars(n_ptr);
}

pub(super) fn emit_for_in_map(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    expr: &Expr,
) {
    emit_expr(ctx, instr, expr);
}

pub(super) fn emit_for_in_expr_tuple(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    for_in: &ForIn,
    expressions: &Vec<Expr>,
) {
    for expr in expressions {
        emit_expr(ctx, instr, expr);
    }
}

#[inline]
pub(super) fn emit_store(ctx: &RefCell<Context>, instr: &mut InstrSeqBuilder) {
    instr.store(
        ctx.borrow().wasm_symbols.main_memory,
        StoreKind::I64 { atomic: false },
        MemArg { align: size_of::<i64>() as u32, offset: 0 },
    );
}

#[inline]
pub(super) fn emit_load(ctx: &RefCell<Context>, instr: &mut InstrSeqBuilder) {
    instr.load(
        ctx.borrow().wasm_symbols.main_memory,
        LoadKind::I64 { atomic: false },
        MemArg {
            align: size_of::<i64>() as u32,
            offset: wasm::LOOP_VARS_START as u32,
        },
    );
}

/// Emits WebAssembly code for boolean expression `expr` into the instruction
/// sequence `instr`. If `expr` doesn't return a boolean its result is casted
/// to a boolean as follows:
///
/// * Integer and float values are converted to `true` if they are non-zero,
///   `false` if they are zero.
/// * String values are `true` if they are non-empty, or `false` if they are
///   empty (e.g: "").
///
pub(super) fn emit_bool_expr(
    ctx: &RefCell<Context>,
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
            instr.call(ctx.borrow().wasm_symbols.str_len);
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
    ctx: &RefCell<Context>,
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
/// Strings in general are represented by a tuple `(i64, i64)` (see
/// [`RuntimeStringWasm`] for more details), and they are undefined when the
/// second item in the tuple is zero.
pub(super) fn emit_call_and_handle_undef_str(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    fn_id: walrus::FunctionId,
) {
    // Call the function that returns a string. The string is represented
    // by a tuple (i64, i64), and is undefined when the second item is zero.
    // Tuple items are pushed in the stack from left to right, so the the
    // second item is the one at the top of the stack.
    instr.call(fn_id);

    // Store the value at the top of the stack in a temp variable, but
    // leave it in the stack.
    instr.local_tee(ctx.borrow().wasm_symbols.i64_tmp);

    // Is the value zero?
    instr.unop(UnaryOp::I64Eqz);
    instr.if_else(
        I64,
        |then_| {
            // It's zero, throw exception.
            throw_undef(ctx, then_);
        },
        |else_| {
            // It's non-zero, return the value to the top of the stack.
            else_.local_get(ctx.borrow().wasm_symbols.i64_tmp);
        },
    );
}

pub(super) fn emit_lookup_common(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
) {
    let mut ctx_mut = ctx.borrow_mut();

    instr.i32_const(ctx_mut.lookup_stack.len() as i32);
    instr.global_set(ctx_mut.wasm_symbols.lookup_stack_top);

    let main_memory = ctx_mut.wasm_symbols.main_memory;

    for (i, field_index) in ctx_mut.lookup_stack.drain(0..).enumerate() {
        let mem_offset = (i * size_of::<i32>()) as i32;
        assert!(
            wasm::LOOKUP_INDEXES_START + mem_offset < wasm::LOOKUP_INDEXES_END,
        );
        instr.i32_const(mem_offset);
        instr.i32_const(field_index);
        instr.store(
            main_memory,
            StoreKind::I32 { atomic: false },
            MemArg {
                align: size_of::<i32>() as u32,
                offset: wasm::LOOKUP_INDEXES_START as u32,
            },
        );
    }
}

#[inline]
pub(super) fn emit_lookup_integer(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.borrow_mut().lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.borrow().wasm_symbols.lookup_integer,
    );
}

#[inline]
pub(super) fn emit_lookup_float(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.borrow_mut().lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.borrow().wasm_symbols.lookup_float,
    );
}

#[inline]
pub(super) fn emit_lookup_bool(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.borrow_mut().lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.borrow().wasm_symbols.lookup_bool,
    );
}

#[inline]
pub(super) fn emit_lookup_string(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    field_index: i32,
) {
    ctx.borrow_mut().lookup_stack.push_back(field_index);
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef_str(
        ctx,
        instr,
        ctx.borrow().wasm_symbols.lookup_string,
    );
}

/// Emits code that checks if the top of the stack is non-zero and executes
/// `expr` in that case. If it is zero throws an exception that signals that
/// the result is undefined.
pub(super) fn if_non_zero(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    expr: impl FnOnce(&mut InstrSeqBuilder),
) {
    // Save the top of the stack into temp variable, but leave a copy in the
    // stack.
    instr.local_tee(ctx.borrow().wasm_symbols.i64_tmp);
    // Is top of the stack zero?
    instr.unop(UnaryOp::I64Eqz);
    instr.if_else(
        I64,
        |then| {
            // Is zero, throw exception
            throw_undef(ctx, then);
        },
        |else_| {
            // Non-zero, put back the value into the stack.
            else_.local_get(ctx.borrow().wasm_symbols.i64_tmp);
        },
    );

    expr(instr);
}

#[inline]
pub(super) fn push_string(
    instr: &mut InstrSeqBuilder,
    string: RuntimeStringWasm,
) {
    instr.i64_const(string.0 as i64);
    instr.i64_const(string.1 as i64);
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
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    expr: impl FnOnce(&mut InstrSeqBuilder),
) {
    // Create a new block containing `expr`. When an exception is raised from
    // within `expr`, the control flow will jump out of this block via a `br`
    // instruction.
    instr.block(I32, |block| {
        // Push the type and ID of the current block in the handlers stack.
        ctx.borrow_mut().exception_handler_stack.push((I32, block.id()));
        expr(block);
    });

    // Pop exception handler from the stack.
    ctx.borrow_mut().exception_handler_stack.pop();
}

/// Throws an exception when an undefined value is found.
///
/// For more information see [`catch_undef`].
pub(super) fn throw_undef(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
) {
    let ctx = ctx.borrow();

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
