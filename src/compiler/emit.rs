use crate::ast::{Expr, TypeHint};
use crate::compiler::Context;
use walrus::InstrSeqBuilder;
use walrus::ValType::I32;

/// Emits the WebAssembly code for `expr` into the instruction sequence
/// `instr`.
pub(super) fn emit_expr(
    ctx: &Context,
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
        Expr::LiteralInt(_) => {
            // TODO
        }
        Expr::LiteralFlt(_) => {
            // TODO
        }
        Expr::LiteralStr(_) => {
            // TODO
        }
        Expr::Ident(_) => {
            // TODO
        }
        Expr::PatternMatch(p) => {
            for (ident_id, pattern_id) in &ctx.current_rule.patterns {
                if ctx.resolve_ident(*ident_id) == p.identifier.as_str() {
                    break;
                }
            }
            // TODO
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
        Expr::Not(_) => {
            // TODO
        }
        Expr::And(operands) => {
            if let TypeHint::Bool(Some(b)) = expr.type_hint() {
                // The value if the AND expression is already known, so we can
                // emit its value.
                instr.i32_const(b as i32);
            } else {
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
            }
        }
        Expr::Or(operands) => {
            if let TypeHint::Bool(Some(b)) = expr.type_hint() {
                instr.i32_const(b as i32);
            } else {
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
            }
        }
        Expr::Minus(_) => {
            // TODO
        }
        Expr::Add(_) => {
            // TODO
        }
        Expr::Sub(_) => {
            // TODO
        }
        Expr::Mul(_) => {
            // TODO
        }
        Expr::Div(_) => {
            // TODO
        }
        Expr::Modulus(_) => {
            // TODO
        }
        Expr::BitwiseNot(_) => {
            // TODO
        }
        Expr::Shl(_) => {
            // TODO
        }
        Expr::Shr(_) => {
            // TODO
        }
        Expr::BitwiseAnd(_) => {
            // TODO
        }
        Expr::BitwiseOr(_) => {
            // TODO
        }
        Expr::BitwiseXor(_) => {
            // TODO
        }
        Expr::Eq(_) => {
            // TODO
        }
        Expr::Neq(_) => {
            // TODO
        }
        Expr::Lt(_) => {
            // TODO
        }
        Expr::Gt(_) => {
            // TODO
        }
        Expr::Le(_) => {
            // TODO
        }
        Expr::Ge(_) => {
            // TODO
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
