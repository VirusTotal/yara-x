use crate::ast::MatchAnchor;
use crate::ast::{Expr, TypeHint};
use crate::compiler::Context;
use crate::Type;
use walrus::ir::{BinaryOp, UnaryOp};
use walrus::InstrSeqBuilder;
use walrus::ValType::I32;

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
            $instr.unop(UnaryOp::F32ConvertSI64);
            lhs_type = Type::Float;
        }

        emit_expr($ctx, $instr, &$rhs);

        // If the right operand is integer, but the left one is float,
        // convert the right operand to float.
        if lhs_type == Type::Float && rhs_type == Type::Integer {
            $instr.unop(UnaryOp::F32ConvertSI64);
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
                    $instr.binop(BinaryOp::$int_op)
                }
                (Type::Float, Type::Float) => {
                    // Both operands are float, the operation is float.
                    $instr.binop(BinaryOp::$float_op)
                }
                _ => unreachable!(),
            };
        });
    }};
}

macro_rules! emit_comparison_op {
    ($ctx:ident, $instr:ident, $expr:expr, $operands:expr, $int_op:tt, $float_op:tt) => {{
        emit_const_or_code!($instr, $expr.type_hint(), {
            match emit_operands!($ctx, $instr, $operands.lhs, $operands.rhs) {
                (Type::Integer, Type::Integer) => {
                    $instr.binop(BinaryOp::$int_op)
                }
                (Type::Float, Type::Float) => {
                    $instr.binop(BinaryOp::$float_op)
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

/// Emits the WebAssembly code for `expr` into the instruction sequence
/// `instr`
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
        Expr::LiteralStr(_) => {
            // TODO
        }
        Expr::Ident(ident) => {
            emit_const_or_code!(instr, ident.type_hint(), {});
        }
        Expr::PatternMatch(pattern) => {
            let pattern_id =
                ctx.get_pattern_from_current_rule(&pattern.identifier);
            match &pattern.anchor {
                Some(MatchAnchor::At(anchor_at)) => {
                    instr.i32_const(pattern_id);
                    emit_expr(ctx, instr, &anchor_at.expr);
                    instr.call(ctx.wasm_imports.is_pat_match_at);
                }
                Some(MatchAnchor::In(anchor_in)) => {
                    instr.i32_const(pattern_id);
                    emit_expr(ctx, instr, &anchor_in.range.lower_bound);
                    emit_expr(ctx, instr, &anchor_in.range.upper_bound);
                    instr.call(ctx.wasm_imports.is_pat_match_in);
                }
                None => {
                    instr.i32_const(pattern_id);
                    instr.call(ctx.wasm_imports.is_pat_match);
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
            // TODO
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
                emit_expr(ctx, instr, &operand.operand);
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
                emit_expr(ctx, instr, &operands.lhs);
                instr.if_else(
                    I32,
                    |then| {
                        emit_expr(ctx, then, &operands.rhs);
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
                emit_expr(ctx, instr, &operands.lhs);
                instr.if_else(
                    I32,
                    |then| {
                        then.i32_const(1);
                    },
                    |else_| {
                        emit_expr(ctx, else_, &operands.rhs);
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
                        instr.binop(BinaryOp::I64RemS)
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
            emit_arithmetic_op!(ctx, instr, expr, operands, I64DivS, F64Div);
        }
        Expr::Shl(operands) => {
            emit_bitwise_op!(ctx, instr, expr, operands, I64Shl);
        }
        Expr::Shr(operands) => {
            emit_bitwise_op!(ctx, instr, expr, operands, I64ShrS);
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
            emit_comparison_op!(ctx, instr, expr, operands, I64Eq, F64Eq);
        }
        Expr::Neq(operands) => {
            emit_comparison_op!(ctx, instr, expr, operands, I64Ne, F64Ne);
        }
        Expr::Lt(operands) => {
            emit_comparison_op!(ctx, instr, expr, operands, I64LtS, F64Lt);
        }
        Expr::Gt(operands) => {
            emit_comparison_op!(ctx, instr, expr, operands, I64GtS, F64Gt);
        }
        Expr::Le(operands) => {
            emit_comparison_op!(ctx, instr, expr, operands, I64LeS, F64Le);
        }
        Expr::Ge(operands) => {
            emit_comparison_op!(ctx, instr, expr, operands, I64GeS, F64Ge);
        }
        Expr::Contains(_) => {
            // TODO
        }
        Expr::IContains(_) => {
            // TODO
        }
        Expr::StartsWith(_) => {
            // TODO
        }
        Expr::IStartsWith(_) => {
            // TODO
        }
        Expr::EndsWith(_) => {
            // TODO
        }
        Expr::IEndsWith(_) => {
            // TODO
        }
        Expr::IEquals(_) => {
            // TODO
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
