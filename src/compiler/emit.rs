use crate::ast::MatchAnchor;
use crate::ast::{Expr, TypeHint};
use crate::compiler::Context;
use crate::Type;
use bstr::ByteSlice;
use std::cell::RefCell;
use walrus::ir::{BinaryOp, UnaryOp};
use walrus::InstrSeqBuilder;
use walrus::ValType::{I32, I64};

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
/// ```
///emit_const_or_code!(instr, expr.type_hint(), {
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
    ($instr:ident, $type_hint:expr, $code:block) => {{
        if cfg!(feature = "compile-time-optimization") {
            match $type_hint {
                TypeHint::Bool(Some(b)) => {
                    $instr.i32_const(b as i32);
                }
                TypeHint::Integer(Some(i)) => {
                    $instr.i64_const(i);
                }
                TypeHint::Float(Some(f)) => {
                    $instr.f64_const(f);
                }
                TypeHint::String(_) => {
                    todo!()
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
        let mut lhs_type = $lhs.type_hint().ty();
        let mut rhs_type = $rhs.type_hint().ty();

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
        emit_const_or_code!($instr, $expr.type_hint(), {
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
        emit_const_or_code!($instr, $expr.type_hint(), {
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
        emit_const_or_code!($instr, $expr.type_hint(), {
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
        emit_const_or_code!($instr, $expr.type_hint(), {
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
            // TODO
        }
        Expr::Entrypoint { .. } => {
            // TODO
        }
        Expr::LiteralInt(lit) => {
            instr.i64_const(lit.value);
        }
        Expr::LiteralFlt(lit) => {
            instr.f64_const(lit.value);
        }
        Expr::LiteralStr(lit) => {
            // Put the literal string in the pool, or get its ID if it was
            // already there.
            let string_id =
                ctx.borrow_mut().lit_pool.get_or_intern(lit.value.as_bstr());

            // Invoke the function that converts the ID into an externref.
            instr.i64_const(string_id.id() as i64);
            instr.call(ctx.borrow().wasm_symbols.literal_to_ref);
        }
        Expr::Ident(ident) => {
            let type_hint = ident.type_hint();
            emit_const_or_code!(instr, type_hint, {
                match type_hint {
                    TypeHint::Bool(_) => {
                        todo!();
                    }
                    TypeHint::Integer(_) => {
                        todo!();
                    }
                    TypeHint::Float(_) => {
                        todo!();
                    }
                    TypeHint::String(_) => {
                        todo!();
                    }
                    TypeHint::Struct => {
                        todo!();
                    }
                    _ => {
                        // At this point the type of the identifier should be
                        // known, as the type hint should be updated during
                        // the semantic check.
                        unreachable!();
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
        Expr::LookupIndex(_) => {
            // TODO
        }
        Expr::FieldAccess(_) => {
            todo!();
        }
        Expr::FnCall(_) => {
            // TODO
        }
        Expr::Not(operand) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                // The NOT expression is emitted as:
                //
                //   if (expr) {
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
            emit_const_or_code!(instr, expr.type_hint(), {
                // The AND expression is emitted as:
                //
                //   if (lhs) {
                //     rhs
                //   } else {
                //     false
                //   }
                //
                emit_bool_expr(ctx, instr, &operands.lhs);
                instr.if_else(
                    I32,
                    |then| {
                        emit_bool_expr(ctx, then, &operands.rhs);
                    },
                    |else_| {
                        else_.i32_const(0);
                    },
                );
            });
        }
        Expr::Or(operands) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                // The OR expression is emitted as:
                //
                //   if (lhs) {
                //     true
                //   } else {
                //     rhs
                //   }
                //
                emit_bool_expr(ctx, instr, &operands.lhs);
                instr.if_else(
                    I32,
                    |then| {
                        then.i32_const(1);
                    },
                    |else_| {
                        emit_bool_expr(ctx, else_, &operands.rhs);
                    },
                );
            });
        }
        Expr::Minus(operand) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                match operand.operand.type_hint().ty() {
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
            emit_const_or_code!(instr, expr.type_hint(), {
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
            emit_const_or_code!(instr, expr.type_hint(), {
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
            emit_const_or_code!(instr, expr.type_hint(), {
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
        Expr::Neq(operands) => {
            emit_comparison_op!(
                ctx, instr, expr, operands, I64Ne, F64Ne, str_neq
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
            emit_const_or_code!(instr, expr.type_hint(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_contains);
            });
        }
        Expr::IContains(operands) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_icontains);
            });
        }
        Expr::StartsWith(operands) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_startswith);
            });
        }
        Expr::IStartsWith(operands) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_istartswith);
            });
        }
        Expr::EndsWith(operands) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_endswith);
            });
        }
        Expr::IEndsWith(operands) => {
            emit_const_or_code!(instr, expr.type_hint(), {
                emit_operands!(ctx, instr, operands.lhs, operands.rhs);
                instr.call(ctx.borrow().wasm_symbols.str_iendswith);
            });
        }
        Expr::IEquals(operands) => {
            emit_const_or_code!(instr, expr.type_hint(), {
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
        Expr::ForIn(_) => {
            // TODO
        }
    }
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

    match expr.type_hint().ty() {
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
            // TODO
            // todo!();
        }
        ty => unreachable!("type `{}` can't be casted to boolean", ty),
    }
}

/// Emits code for catching exceptions caused by undefined values.
///
/// This function emits WebAssembly code that behaves similarly to an exception
/// handler. The code generated by `expr` must leave a result of type `ty` at
/// the top of the stack. However, `expr` can make use of [`raise`] for
/// raising an exception when an undefined value is detected during the
/// evaluation of `expr`. In that case the execution flow will be interrupted
/// at the point where [`raise`] was found, and the control transferred
/// to the exception handler. The exception handler, which is defined by the
/// `handler` argument, can contain as much as logic as required, but must
/// leave a value of type `ty` in the stack. This will be the value that will
/// replace the one that `expr` should have being returned, but didn't because
/// it was interrupted by [`raise`].
///
/// As in the usual exception handling mechanism, [`try_except`] can be nested,
/// and in such cases the exception will be captured by the innermost handler.
///
/// # Example
///
/// ```
/// use walrus::ValType::I32;
/// try_except(
///    ctx,
///    block,
///    I32,
///    |try_block| {
///       raise(ctx, try_block);   // The exception is raised here ...
///       try_block.i32_const(1); // ... and this is not executed.
///    },
///    |except_block| {
///       // The control is transferred here when the exception occurs ...
///       except_block.i32_const(0); //  ... the final result is false.
///    },
///);
/// ```
///
pub(super) fn try_except(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    ty: walrus::ValType,
    expr: impl FnOnce(&mut InstrSeqBuilder),
    handler: impl FnOnce(&mut InstrSeqBuilder),
) {
    // Create a new block containing `expr`. When an exception is raised from
    // within `expr`, the control flow will jump out of this block via a `br`
    // instruction.
    instr.block(ty, |block| {
        // Push the type and ID of the current block in the handlers stack.
        ctx.borrow_mut().exception_handler_stack.push((ty, block.id()));
        expr(block);
    });

    // Pop exception handler from the stack.
    ctx.borrow_mut().exception_handler_stack.pop();

    // Emit the exception handling logic only if `raise` was actually used
    // in `expr.
    if ctx.borrow().raise_emitted {
        ctx.borrow_mut().raise_emitted = false;

        // Store the result of `expr` for later use.
        match ty {
            I32 => {
                instr.local_set(ctx.borrow().wasm_symbols.i32_tmp);
            }
            I64 => {
                instr.local_set(ctx.borrow().wasm_symbols.i64_tmp);
            }
            _ => unreachable!(),
        }

        // Check if an exception occurred by checking if exception_flag
        // is set to 1.
        instr.local_get(ctx.borrow().wasm_symbols.exception_flag);
        instr.unop(UnaryOp::I32Eqz);

        instr.if_else(
            ty,
            |then| {
                // No exception, return the result of `expr` that was
                // previously saved.
                match ty {
                    I32 => {
                        then.local_get(ctx.borrow().wasm_symbols.i32_tmp);
                    }
                    I64 => {
                        then.local_get(ctx.borrow().wasm_symbols.i64_tmp);
                    }
                    _ => unreachable!(),
                };
            },
            |else_| {
                // Clear exception_flag.
                else_.i32_const(0);
                else_.local_set(ctx.borrow().wasm_symbols.exception_flag);
                handler(else_);
            },
        );
    }
}

/// Raises an exception.
///
/// For more information see [`try_except`].
pub(super) fn raise(ctx: &RefCell<Context>, instr: &mut InstrSeqBuilder) {
    let mut ctx = ctx.borrow_mut();
    ctx.raise_emitted = true;

    let innermost_handler = *ctx
        .exception_handler_stack
        .last()
        .expect("calling `raise` from outside `try` block");

    // Set exception_flag to one.
    instr.i32_const(1);
    instr.local_set(ctx.wasm_symbols.exception_flag);

    // Put in the stack a dummy result for the code block that we are about
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
        I32 => instr.i32_const(0xBADF00D),
        I64 => instr.i64_const(0xBADF00D),
        _ => unreachable!(),
    };

    // Jump to the exception handler.
    instr.br(innermost_handler.1);
}

/// Calls a function that may return an undefined value.
///
/// Some functions in YARA can return undefined values, for example the
/// built-in function `uint8(offset)` returns an undefined result when
/// `offset` is outside the data boundaries. The same occurs with many
/// function implemented by YARA modules.
///
/// These functions return actually a tuple (value, is_undef), where
/// is_undef is an i32 that will be for valid values and 1 for undefined
/// values. When is_undef is 1 the value is ignored.
///
/// This emits code that calls the specified function and checks if its
/// result is undefined. In such cases raises an exception.
pub(super) fn call(
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
            raise(ctx, then_);
        },
        |_| {
            // Intentionally empty. An `if` method would be handy, but it
            // does not exists. This however emits WebAssembly code without
            // the `else` branch.
        },
    );
}

// Emits code that checks if the top of the stack is non-zero and executes
// `expr` in that case. If it is zero raises an exception that signals that
// the result is undefined.
pub(super) fn if_non_zero(
    ctx: &RefCell<Context>,
    instr: &mut InstrSeqBuilder,
    expr: impl FnOnce(&mut InstrSeqBuilder),
) {
    // Save the right operand in tmp variable, but leave a copy
    // in the stack.
    instr.local_tee(ctx.borrow().wasm_symbols.i64_tmp);
    // Is the right operand zero?
    instr.unop(UnaryOp::I64Eqz);
    instr.if_else(
        I64,
        |then| {
            // Is zero, raise exception
            raise(ctx, then);
        },
        |else_| {
            // Non-zero, put back the operand in the stack.
            else_.local_get(ctx.borrow().wasm_symbols.i64_tmp);
        },
    );

    expr(instr);
}
