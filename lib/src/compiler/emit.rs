/*! This module emits the WASM code for conditions in YARA rules.

The entry point for this module is the [`emit_rule_condition`] function, which
emits the WASM a code for a single YARA rule. This function calls other
functions in the module which generate WASM code for specific kinds of
expressions or language constructs.
 */

use std::collections::VecDeque;
use std::mem::size_of;
use std::ops::RangeInclusive;
use std::rc::Rc;

use bstr::ByteSlice;
use itertools::{Itertools, Position};
use rustc_hash::FxHashMap;
use walrus::ir::ExtendedLoad::ZeroExtend;
use walrus::ir::{
    BinaryOp, InstrSeqId, InstrSeqType, LoadKind, MemArg, StoreKind, UnaryOp,
};
use walrus::ValType::{I32, I64};
use walrus::{FunctionId, InstrSeqBuilder, ValType};

use crate::compiler::ir::{
    Expr, ExprId, ForIn, ForOf, Iterable, MatchAnchor, PatternIdx, Quantifier,
    IR,
};
use crate::compiler::{
    FieldAccess, ForVars, LiteralId, OfExprTuple, OfPatternSet, PatternId,
    RegexpId, RuleId, RuleInfo, Var,
};
use crate::scanner::RuntimeObjectHandle;
use crate::string_pool::{BStringPool, StringPool};
use crate::symbols::Symbol;
use crate::types::Value::Const;
use crate::types::{Array, Map, Type, TypeValue};
use crate::utils::cast;
use crate::wasm;
use crate::wasm::builder::WasmModuleBuilder;
use crate::wasm::string::RuntimeString;
use crate::wasm::{
    WasmSymbols, LOOKUP_INDEXES_END, LOOKUP_INDEXES_START,
    MATCHING_RULES_BITMAP_BASE, VARS_STACK_START,
};

/// This macro emits the code for the left and right operands of some
/// operation, converting integer operands to float if the other operand
/// is a float.
macro_rules! emit_operands {
    ($ctx:ident, $ir:ident, $lhs:expr, $rhs:expr, $instr:ident) => {{
        let lhs = $lhs;
        let rhs = $rhs;

        emit_expr($ctx, $ir, lhs, $instr);

        let mut lhs_type = $ir.get(lhs).ty();
        let mut rhs_type = $ir.get(rhs).ty();

        // If the left operand is integer, but the right one is float,
        // convert the left operand to float.
        if lhs_type == Type::Integer && rhs_type == Type::Float {
            $instr.unop(UnaryOp::F64ConvertSI64);
            lhs_type = Type::Float;
        }

        // If the left operand is bool, promote it from i32 to i64.
        if lhs_type == Type::Bool {
            $instr.unop(UnaryOp::I64ExtendUI32);
        }

        emit_expr($ctx, $ir, rhs, $instr);

        // If the right operand is integer, but the left one is float,
        // convert the right operand to float.
        if lhs_type == Type::Float && rhs_type == Type::Integer {
            $instr.unop(UnaryOp::F64ConvertSI64);
            rhs_type = Type::Float;
        }

        // If the right operand is bool, promote it from i32 to i64.
        if rhs_type == Type::Bool {
            $instr.unop(UnaryOp::I64ExtendUI32);
        }

        (lhs_type, rhs_type)
    }};
}

macro_rules! emit_arithmetic_op {
    ($ctx:ident, $ir:ident, $operands:expr, $is_float:expr, $int_op:tt, $float_op:tt, $instr:ident) => {{
        let mut operands = $operands.iter();
        let first_operand = operands.next().unwrap();

        emit_expr($ctx, $ir, *first_operand, $instr);

        if $is_float && matches!($ir.get(*first_operand).ty(), Type::Integer) {
            $instr.unop(UnaryOp::F64ConvertSI64);
        }

        while let Some(operand) = operands.next() {
            emit_expr($ctx, $ir, *operand, $instr);
            if $is_float {
                if matches!($ir.get(*operand).ty(), Type::Integer) {
                    $instr.unop(UnaryOp::F64ConvertSI64);
                }
                $instr.binop(BinaryOp::$float_op);
            } else {
                $instr.binop(BinaryOp::$int_op);
            }
        }
    }};
}

macro_rules! emit_comparison_op {
    ($ctx:ident, $ir:ident, $lhs:expr, $rhs:expr, $int_op:tt, $float_op:tt, $str_op:expr, $instr:ident) => {{
        match emit_operands!($ctx, $ir, $lhs, $rhs, $instr) {
            (Type::Integer, Type::Integer)
            | (Type::Bool, Type::Bool)
            | (Type::Bool, Type::Integer)
            | (Type::Integer, Type::Bool) => {
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
    }};
}

macro_rules! emit_shift_op {
    ($ctx:ident, $ir:ident, $lhs:expr, $rhs:expr, $int_op:tt, $instr:ident) => {{
        match emit_operands!($ctx, $ir, $lhs, $rhs, $instr) {
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
                //  move rhs to tmp_b
                //  move lhs to tmp_a
                //  push rhs
                //  push 64
                //  is rhs less than 64?
                //  if true
                //     push lhs
                //     push rhs
                //  else
                //     push 0
                //
                $instr.local_set($ctx.wasm_symbols.i64_tmp_b);
                $instr.local_set($ctx.wasm_symbols.i64_tmp_a);
                $instr.local_get($ctx.wasm_symbols.i64_tmp_b);
                $instr.i64_const(64);
                $instr.binop(BinaryOp::I64LtS);
                $instr.if_else(
                    I64,
                    |then_| {
                        then_.local_get($ctx.wasm_symbols.i64_tmp_a);
                        then_.local_get($ctx.wasm_symbols.i64_tmp_b);
                        then_.binop(BinaryOp::$int_op);
                    },
                    |else_| {
                        else_.i64_const(0);
                    },
                )
            }
            _ => unreachable!(),
        };
    }};
}

macro_rules! emit_bitwise_op {
    ($ctx:ident, $ir:ident, $lhs:expr, $rhs:expr, $int_op:tt, $instr:ident) => {{
        match emit_operands!($ctx, $ir, $lhs, $rhs, $instr) {
            (Type::Integer, Type::Integer) => $instr.binop(BinaryOp::$int_op),
            _ => unreachable!(),
        };
    }};
}

type ExceptionHandler = Box<dyn Fn(&mut EmitContext, &mut InstrSeqBuilder)>;

/// Structure that contains information used while emitting the code that
/// corresponds to the condition of a YARA rule.
pub(crate) struct EmitContext<'a> {
    /// Information about the rule whose condition is being emitted.
    pub current_rule: &'a RuleInfo,

    /// Table with all the symbols (functions, variables) used by WASM.
    pub wasm_symbols: &'a WasmSymbols,

    /// Map where keys are fully qualified and mangled function names, and
    /// values are the function's ID in the WASM module.
    pub wasm_exports: &'a FxHashMap<String, FunctionId>,

    /// Pool with regular expressions used in rule conditions.
    pub regexp_pool: &'a mut StringPool<RegexpId>,

    /// Pool with literal strings used in the rules.
    pub lit_pool: &'a mut BStringPool<LiteralId>,

    /// Stack of installed exception handlers for catching undefined values.
    /// When an exception occurs the execution flow will jump out of the block
    /// identified by `InstrSeqId`.
    pub exception_handler_stack: Vec<(InstrSeqId, ExceptionHandler)>,

    /// Controls whether [emit_lazy_call_to_search_for_patterns] needs to emit
    /// code or not.
    pub emit_search_for_pattern_stack: Vec<bool>,

    /// The lookup_list contains a sequence of field IDs that will be used
    /// in the next field lookup operation. Each field ID is accompanied by a
    /// boolean that is true if the field belongs to the root structure. Only
    /// the first item in the list can have this boolean set to true, because
    /// the remaining items are describing fields in nested structures. For
    /// instance, if `lookup_list` contains the pairs (3,true), (0,false),
    /// and (1,false), it means that lookup operation will search for field
    /// number 3 in the root structure, then field 0 in the previous one (which
    /// must be of type struct) and finally field 1 in the previous one (which
    /// must be also of type struct).
    ///
    /// See [`emit::emit_lookup_common`] for details.
    pub(crate) lookup_list: Vec<(i32, bool)>,
}

impl EmitContext<'_> {
    /// Given a function mangled name returns its id.
    ///
    /// # Panics
    ///
    /// If a no function with the given name exists.
    pub fn function_id(&self, fn_mangled_name: &str) -> FunctionId {
        *self.wasm_exports.get(fn_mangled_name).unwrap_or_else(|| {
            panic!("can't find function `{fn_mangled_name}`")
        })
    }

    /// Given the index of a pattern in the current rule, returns its
    /// [`PatternId`].
    ///
    /// The index of a pattern is the position of the pattern in the `strings`
    /// section of the rule.
    pub fn pattern_id(&self, index: PatternIdx) -> PatternId {
        self.current_rule.patterns[index.as_usize()].pattern_id
    }
}

/// Emits WASM code of a rule.
pub(crate) fn emit_rule_condition(
    ctx: &mut EmitContext,
    ir: &IR,
    rule_id: RuleId,
    condition: ExprId,
    builder: &mut WasmModuleBuilder,
) {
    let mut instr = builder.start_rule(rule_id, ctx.current_rule.is_global);

    ctx.emit_search_for_pattern_stack.push(true);

    // Emit WASM code for the rule's condition.
    catch_undef(
        ctx,
        I32,
        &mut instr,
        |ctx, instr| {
            emit_bool_expr(ctx, ir, condition, instr);
        },
        |_, instr| {
            instr.i32_const(0);
        },
    );

    ctx.emit_search_for_pattern_stack.pop();
    assert!(ctx.emit_search_for_pattern_stack.is_empty());
    builder.finish_rule();
}

/// Emits WASM code for `expr` into the instruction sequence `instr`.
fn emit_expr(
    ctx: &mut EmitContext,
    ir: &IR,
    expr: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    match ir.get(expr) {
        Expr::Const(type_value) => match type_value {
            TypeValue::Integer { value: Const(value), .. } => {
                instr.i64_const(*value);
            }
            TypeValue::Float { value: Const(value) } => {
                instr.f64_const(*value);
            }
            TypeValue::Bool { value: Const(value) } => {
                instr.i32_const((*value).into());
            }
            TypeValue::String { value: Const(value), .. } => {
                // Put the literal string in the pool, or get its ID if it was
                // already there.
                let literal_id = ctx.lit_pool.get_or_intern(value.as_bstr());

                instr
                    .i64_const(RuntimeString::Literal(literal_id).into_wasm());
            }
            TypeValue::Regexp(Some(regexp)) => {
                let re_id = ctx.regexp_pool.get_or_intern(regexp.as_str());

                instr.i32_const(re_id.into());
            }
            t => unreachable!("{:?}", t),
        },

        Expr::Filesize => {
            let tmp = ctx.wasm_symbols.i64_tmp_a;
            // Get the value of filesize from global variable.
            instr.global_get(ctx.wasm_symbols.filesize);
            // Make a copy in tmp, while leaving the value in the stack.
            instr.local_tee(tmp);
            // Compare filesize with 0.
            instr.i64_const(0);
            instr.binop(BinaryOp::I64LtS);
            // Is filesize < 0?
            instr.if_else(
                I64,
                // If yes, filesize is undefined
                |then_| throw_undef(ctx, then_),
                // Otherwise return its value
                |else_| {
                    else_.local_get(tmp);
                },
            );
        }

        Expr::Symbol(symbol) => {
            match symbol.as_ref() {
                Symbol::Rule { rule_id, .. } => {
                    // Emit code that checks if a rule has matched, leaving
                    // zero or one at the top of the stack.
                    emit_check_for_rule_match(ctx, *rule_id, instr);
                }
                Symbol::Var { var, .. } => {
                    // The symbol represents a variable in WASM memory,
                    // emit code for loading its value into the stack.
                    if !matches!(var.ty(), Type::Func) {
                        load_var(ctx, instr, *var);
                    }
                }
                Symbol::Field { index, is_root, type_value, .. } => {
                    let index: i32 = (*index).try_into().unwrap();

                    match type_value {
                        TypeValue::Integer { .. } => {
                            ctx.lookup_list.push((index, *is_root));
                            emit_lookup_integer(ctx, instr);
                            assert!(ctx.lookup_list.is_empty());
                        }
                        TypeValue::Float { .. } => {
                            ctx.lookup_list.push((index, *is_root));
                            emit_lookup_float(ctx, instr);
                            assert!(ctx.lookup_list.is_empty());
                        }
                        TypeValue::Bool { .. } => {
                            ctx.lookup_list.push((index, *is_root));
                            emit_lookup_bool(ctx, instr);
                            assert!(ctx.lookup_list.is_empty());
                        }
                        TypeValue::String { .. } => {
                            ctx.lookup_list.push((index, *is_root));
                            emit_lookup_string(ctx, instr);
                            assert!(ctx.lookup_list.is_empty());
                        }
                        TypeValue::Struct(_)
                        | TypeValue::Array(_)
                        | TypeValue::Map(_) => {
                            ctx.lookup_list.push((index, *is_root));
                            emit_lookup_object(ctx, instr);
                            assert!(ctx.lookup_list.is_empty());
                        }
                        TypeValue::Func(func) => {
                            // Take the first field in the lookup list and see
                            // if it belongs to the root structure. If that is
                            // the case, and this function is a method, we need
                            // to lookup the object and leave it in the stack
                            // as the first argument to the method.
                            //
                            // When the function is not a method we don't need
                            // to push any object into the stack. When the first
                            // field in the lookup list doesn't belong to the
                            // root structure, we know that the stack already
                            // contains the object.
                            if let Some((_, true)) = ctx.lookup_list.first() {
                                if func.is_method() {
                                    emit_lookup_object(ctx, instr);
                                }
                            }
                            ctx.lookup_list.clear();
                        }
                        TypeValue::Regexp(_) => {
                            // The value of an identifier can't be a regular
                            // expression.
                            unreachable!();
                        }
                        TypeValue::Unknown => {
                            // This point should not be reached. The type of
                            // identifiers must be known during code emitting
                            // because they are resolved during the semantic
                            // check, and the AST is updated with type info.
                            unreachable!();
                        }
                    }
                }
                Symbol::Func(_) => {
                    unreachable!()
                }
            }
        }

        Expr::PatternMatch { .. } | Expr::PatternMatchVar { .. } => {
            emit_pattern_match(ctx, ir, expr, instr);
        }

        Expr::PatternCount { .. } | Expr::PatternCountVar { .. } => {
            emit_pattern_count(ctx, ir, expr, instr);
        }

        Expr::PatternOffset { .. } | Expr::PatternOffsetVar { .. } => {
            emit_pattern_offset(ctx, ir, expr, instr);
        }

        Expr::PatternLength { .. } | Expr::PatternLengthVar { .. } => {
            emit_pattern_length(ctx, ir, expr, instr);
        }

        Expr::FieldAccess(field_access) => {
            emit_field_access(ctx, ir, field_access, instr);
        }

        Expr::Defined { operand } => {
            emit_defined(ctx, ir, *operand, instr);
        }

        Expr::Not { operand } => {
            emit_not(ctx, ir, *operand, instr);
        }

        Expr::And { operands } => {
            ctx.emit_search_for_pattern_stack.push(true);
            emit_and(ctx, ir, operands.as_slice(), instr);
            ctx.emit_search_for_pattern_stack.pop();
        }

        Expr::Or { operands } => {
            ctx.emit_search_for_pattern_stack.push(true);
            emit_or(ctx, ir, operands.as_slice(), instr);
            ctx.emit_search_for_pattern_stack.pop();
        }

        Expr::Minus { operand, is_float } => {
            if *is_float {
                emit_expr(ctx, ir, *operand, instr);
                instr.unop(UnaryOp::F64Neg);
            } else {
                // WebAssembly does not have a i64.neg instruction, it
                // is implemented as i64.sub(0, x).
                instr.i64_const(0);
                emit_expr(ctx, ir, *operand, instr);
                instr.binop(BinaryOp::I64Sub);
            }
        }
        Expr::BitwiseNot { operand } => {
            emit_expr(ctx, ir, *operand, instr);
            // WebAssembly does not have an instruction for bitwise not,
            // it is implemented as i64.xor(x, -1)
            instr.i64_const(-1);
            instr.binop(BinaryOp::I64Xor);
        }
        Expr::Add { operands, is_float } => {
            emit_arithmetic_op!(
                ctx, ir, operands, *is_float, I64Add, F64Add, instr
            );
        }
        Expr::Sub { operands, is_float } => {
            emit_arithmetic_op!(
                ctx, ir, operands, *is_float, I64Sub, F64Sub, instr
            );
        }
        Expr::Mul { operands, is_float } => {
            emit_arithmetic_op!(
                ctx, ir, operands, *is_float, I64Mul, F64Mul, instr
            );
        }
        Expr::Div { operands, .. } => {
            emit_div(ctx, ir, operands.as_slice(), instr)
        }
        Expr::Mod { operands } => {
            emit_mod(ctx, ir, operands.as_slice(), instr)
        }
        Expr::Shl { lhs, rhs } => {
            emit_shift_op!(ctx, ir, *lhs, *rhs, I64Shl, instr);
        }
        Expr::Shr { lhs, rhs } => {
            emit_shift_op!(ctx, ir, *lhs, *rhs, I64ShrS, instr);
        }
        Expr::BitwiseAnd { lhs, rhs } => {
            emit_bitwise_op!(ctx, ir, *lhs, *rhs, I64And, instr);
        }
        Expr::BitwiseOr { lhs, rhs } => {
            emit_bitwise_op!(ctx, ir, *lhs, *rhs, I64Or, instr);
        }
        Expr::BitwiseXor { lhs, rhs } => {
            emit_bitwise_op!(ctx, ir, *lhs, *rhs, I64Xor, instr);
        }
        Expr::Eq { lhs, rhs } => {
            emit_comparison_op!(
                ctx,
                ir,
                *lhs,
                *rhs,
                I64Eq,
                F64Eq,
                wasm::export__str_eq.mangled_name,
                instr
            );
        }
        Expr::Ne { lhs, rhs } => {
            emit_comparison_op!(
                ctx,
                ir,
                *lhs,
                *rhs,
                I64Ne,
                F64Ne,
                wasm::export__str_ne.mangled_name,
                instr
            );
        }
        Expr::Lt { lhs, rhs } => {
            emit_comparison_op!(
                ctx,
                ir,
                *lhs,
                *rhs,
                I64LtS,
                F64Lt,
                wasm::export__str_lt.mangled_name,
                instr
            );
        }
        Expr::Gt { lhs, rhs } => {
            emit_comparison_op!(
                ctx,
                ir,
                *lhs,
                *rhs,
                I64GtS,
                F64Gt,
                wasm::export__str_gt.mangled_name,
                instr
            );
        }
        Expr::Le { lhs, rhs } => {
            emit_comparison_op!(
                ctx,
                ir,
                *lhs,
                *rhs,
                I64LeS,
                F64Le,
                wasm::export__str_le.mangled_name,
                instr
            );
        }
        Expr::Ge { lhs, rhs } => {
            emit_comparison_op!(
                ctx,
                ir,
                *lhs,
                *rhs,
                I64GeS,
                F64Ge,
                wasm::export__str_ge.mangled_name,
                instr
            );
        }
        Expr::Contains { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr.call(
                ctx.function_id(wasm::export__str_contains.mangled_name),
            );
        }
        Expr::IContains { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr.call(
                ctx.function_id(wasm::export__str_icontains.mangled_name),
            );
        }
        Expr::StartsWith { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr.call(
                ctx.function_id(wasm::export__str_startswith.mangled_name),
            );
        }
        Expr::IStartsWith { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr.call(
                ctx.function_id(wasm::export__str_istartswith.mangled_name),
            );
        }
        Expr::EndsWith { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr.call(
                ctx.function_id(wasm::export__str_endswith.mangled_name),
            );
        }
        Expr::IEndsWith { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr.call(
                ctx.function_id(wasm::export__str_iendswith.mangled_name),
            );
        }
        Expr::IEquals { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr
                .call(ctx.function_id(wasm::export__str_iequals.mangled_name));
        }

        Expr::Matches { lhs, rhs } => {
            emit_operands!(ctx, ir, *lhs, *rhs, instr);
            instr
                .call(ctx.function_id(wasm::export__str_matches.mangled_name));
        }

        Expr::Lookup(lookup) => {
            // Emit code for the primary expression (array or map) that is
            // being indexed.
            emit_expr(ctx, ir, lookup.primary, instr);
            // Emit the code for the index expression, which leaves the
            // index in the stack.
            emit_expr(ctx, ir, lookup.index, instr);
            // Emit a call instruction to the corresponding function, which
            // depends on the type of the primary expression (array or map)
            // and the type of the index expression.
            match ir.get(lookup.primary).type_value() {
                TypeValue::Array(array) => {
                    emit_array_indexing(ctx, instr, &array);
                }
                TypeValue::Map(map) => {
                    emit_map_lookup(ctx, instr, map);
                }
                _ => unreachable!(),
            };
        }

        Expr::OfPatternSet(of_pattern_set) => {
            emit_of_pattern_set(ctx, ir, of_pattern_set, instr);
        }

        Expr::OfExprTuple(of_expr_tuple) => {
            emit_of_expr_tuple(ctx, ir, of_expr_tuple, instr)
        }

        Expr::ForOf(for_of) => {
            emit_for_of_pattern_set(ctx, ir, for_of, instr);
        }

        Expr::ForIn(for_in) => match &for_in.iterable {
            Iterable::Range(_) => {
                emit_for_in_range(ctx, ir, for_in, instr);
            }
            Iterable::ExprTuple(_) => {
                emit_for_in_expr_tuple(ctx, ir, for_in, instr);
            }
            Iterable::Expr(_) => {
                emit_for_in_expr(ctx, ir, for_in, instr);
            }
        },

        Expr::FuncCall(func_call) => {
            // If this is method call, the target object (self or this in some
            // programming languages) is the first argument.
            if let Some(obj) = func_call.object {
                emit_expr(ctx, ir, obj, instr);
            }

            for expr in func_call.args.iter() {
                emit_expr(ctx, ir, *expr, instr);
            }

            if func_call.signature().result_may_be_undef() {
                emit_call_and_handle_undef(
                    ctx,
                    instr,
                    ctx.function_id(func_call.mangled_name()),
                );
            } else {
                instr.call(ctx.function_id(func_call.mangled_name()));
            }
        }

        Expr::With(with) => {
            emit_with(ctx, ir, with.declarations.as_slice(), with.body, instr);
        }
    }
}

/// Emits the code for `defined` operations.
fn emit_defined(
    ctx: &mut EmitContext,
    ir: &IR,
    operand: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    // The `defined` expression is emitted as:
    //
    //   try {
    //     evaluate_operand()
    //     true
    //   } catch undefined {
    //     false
    //   }
    //
    catch_undef(
        ctx,
        I32,
        instr,
        |ctx, instr| {
            emit_bool_expr(ctx, ir, operand, instr);
            // Drop the operand's value as we are not interested in the
            // value, we are interested only in whether it's defined or
            // not.
            instr.drop();
            // Push a 1 in the stack indicating that the operand is
            // defined. This point is not reached if the operand calls
            // `throw_undef`.
            instr.i32_const(1);
        },
        |_, instr| {
            instr.i32_const(0);
        },
    );
}

/// Emits the code for `not` operations.
fn emit_not(
    ctx: &mut EmitContext,
    ir: &IR,
    operand: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    // The `not` expression is emitted as:
    //
    //   if (evaluate_operand()) {
    //     false
    //   } else {
    //     true
    //   }
    //
    emit_bool_expr(ctx, ir, operand, instr);
    instr.if_else(
        I32,
        |then| {
            then.i32_const(0);
        },
        |else_| {
            else_.i32_const(1);
        },
    );
}

/// Emits the code for `and` operations.
fn emit_and(
    ctx: &mut EmitContext,
    ir: &IR,
    operands: &[ExprId],
    instr: &mut InstrSeqBuilder,
) {
    // The `and` expression is emitted as:
    //
    //  try {
    //    result = first_operand()
    //    if !result {
    //      push false
    //      exit from try
    //    }
    //    result = second_operand()
    //    if !result {
    //      push false
    //      exit from try
    //    }
    //    ...
    //    push last_operand()
    //  }
    //  catch undefined {
    //    push false
    //  }
    catch_undef(
        ctx,
        I32,
        instr,
        |ctx, instr| {
            let block_id = instr.id();
            for (position, operand) in operands.iter().with_position() {
                emit_bool_expr(ctx, ir, *operand, instr);
                // For all operands except the last one, check the result
                // and exit early from the block if it is false.
                if matches!(position, Position::First | Position::Middle) {
                    instr.if_else(
                        None,
                        |_| {},
                        |else_| {
                            else_.i32_const(0);
                            else_.br(block_id);
                        },
                    );
                }
            }
        },
        |_, instr| {
            instr.i32_const(0); // push false
        },
    );
}

/// Emits the code for `or` operations.
fn emit_or(
    ctx: &mut EmitContext,
    ir: &IR,
    operands: &[ExprId],
    instr: &mut InstrSeqBuilder,
) {
    // The `or` expression is emitted as:
    //
    // block {
    //   try {
    //     result = first_operand()
    //   } catch undefined {
    //     result = false
    //   }
    //   if result {
    //     push true
    //     exit from block
    //   }
    //   try {
    //     result = second_operand()
    //   } catch undefined {
    //     result = false
    //   }
    //   if result {
    //     push true
    //     exit from block
    //   }
    //   ...
    //   try {
    //     result = last_operand()
    //   } catch undefined {
    //     result = false
    //   }
    //   result
    // }
    instr.block(
        I32, // the block returns a bool
        |block| {
            let block_id = block.id();
            for (position, operand) in operands.iter().with_position() {
                catch_undef(
                    ctx,
                    I32,
                    block,
                    |ctx, instr| {
                        emit_bool_expr(ctx, ir, *operand, instr);
                    },
                    |_, instr| {
                        instr.i32_const(0);
                    },
                );
                // For all operands except the last one, check the result
                // and exit early from the block if it is true.
                if matches!(position, Position::First | Position::Middle) {
                    block.if_else(
                        None,
                        |then_| {
                            then_.i32_const(1);
                            then_.br(block_id);
                        },
                        |_| {},
                    );
                }
            }
        },
    );
}

/// Emits the code for `div` operations.
fn emit_div(
    ctx: &mut EmitContext,
    ir: &IR,
    operands: &[ExprId],
    instr: &mut InstrSeqBuilder,
) {
    let mut operands = operands.iter();
    let first_operand = operands.next().unwrap();
    let mut is_float = matches!(ir.get(*first_operand).ty(), Type::Float);

    emit_expr(ctx, ir, *first_operand, instr);

    for operand in operands {
        let operand_ty = ir.get(*operand).ty();

        // The previous operand is not float but this one is float,
        // we must convert the previous operand to float.
        if !is_float && matches!(operand_ty, Type::Float) {
            instr.unop(UnaryOp::F64ConvertSI64);
            is_float = true;
        }

        emit_expr(ctx, ir, *operand, instr);

        if is_float && matches!(operand_ty, Type::Integer) {
            instr.unop(UnaryOp::F64ConvertSI64);
        }

        if is_float {
            instr.binop(BinaryOp::F64Div);
        } else {
            // In integer division make sure that the divisor is not
            // zero, if that's the case the result is undefined.
            throw_undef_if_zero(ctx, instr);
            instr.binop(BinaryOp::I64DivS);
        }
    }
}

/// Emits the code for `mod` operations.
fn emit_mod(
    ctx: &mut EmitContext,
    ir: &IR,
    operands: &[ExprId],
    instr: &mut InstrSeqBuilder,
) {
    let mut operands = operands.iter();
    let first_operand = operands.next().unwrap();

    emit_expr(ctx, ir, *first_operand, instr);

    for operand in operands {
        emit_expr(ctx, ir, *operand, instr);
        throw_undef_if_zero(ctx, instr);
        instr.binop(BinaryOp::I64RemS);
    }
}

fn emit_field_access(
    ctx: &mut EmitContext,
    ir: &IR,
    field_access: &FieldAccess,
    instr: &mut InstrSeqBuilder,
) {
    // Iterate over the operands, excluding the last one. While the operands
    // are field identifiers they are simply added to `lookup_list`, and
    // during the last call to `emit_expr` a single field lookup operation
    // will be emitted, encompassing all the lookups in a single call to
    // Rust code.
    for operand in field_access.operands.iter().dropping_back(1) {
        if let Expr::Symbol(symbol) = ir.get(*operand) {
            if let Symbol::Field { index, is_root, .. } = symbol.as_ref() {
                ctx.lookup_list.push((*index as i32, *is_root));
                continue;
            }
        }
        emit_expr(ctx, ir, *operand, instr);
    }

    emit_expr(ctx, ir, *field_access.operands.last().unwrap(), instr);
}

/// Emits code that ensures the pattern search phase is executed if it hasn't
/// been performed yet, invoking `search_for_patterns` when necessary.
///
/// The `search_for_patterns` function is invoked lazily during the evaluation
/// of rule conditions. When a pattern identifier (e.g., `$a`) is first used
/// in a condition, `search_for_patterns` is called, and the global variable
/// `pattern_search_done` is set to `true`. This prevents redundant calls to
/// `search_for_patterns` during subsequent evaluations.
///
/// The WASM code that checks `pattern_search_done` and triggers
/// `search_for_patterns` does not need to be emitted for every pattern
/// identifier in a condition. For example, consider the following condition:
///
/// ```text
/// $a and $b and $c
/// ```
///
/// When `$a` is encountered, the emitted code includes the check and the call
/// to `search_for_patterns`. However, for `$b` and `$c`, this code is no longer
/// needed because evaluating `$a` will already ensure the search is performed
/// if required.
///
/// A single boolean flag to track whether the call has been emitted is not
/// sufficient due to short-circuit evaluation semantics. For example:
///
/// ```text
/// (my_bool and $a) and $b
/// ```
///
/// In this case, `$a` appears first during code emission, so the call to
/// `search_for_patterns` must be emitted there. However, `$b` may still require
/// the same code because `$a` might be skipped entirely at runtime if
/// `my_bool` evaluates to `false`. Thus, we cannot rely solely on a single
/// emitted flag.
///
/// To handle this, a stack of boolean values is maintained. The top of the
/// stack indicates whether it is necessary to emit the call to
/// `search_for_patterns`. Once the call is emitted, the top value is set to
/// `false`. To correctly account for short-circuiting behavior, a new `true`
/// value is pushed onto the stack whenever an `AND` or `OR` expression is
/// encountered.
fn emit_lazy_call_to_search_for_patterns(
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
) {
    if *ctx.emit_search_for_pattern_stack.last().unwrap() {
        instr.global_get(ctx.wasm_symbols.pattern_search_done);
        instr.if_else(
            None,
            |_then| {
                // The pattern search phase was already executed. Nothing to
                // do here.
            },
            |_else| {
                _else
                    // Call `search_for_patterns`. This function will set
                    // `pattern_search_done` to true before exiting.
                    .call(ctx.function_id(
                        wasm::export__search_for_patterns.mangled_name,
                    ));
            },
        );
        let top = ctx.emit_search_for_pattern_stack.last_mut().unwrap();
        *top = false;
    }
}

fn emit_pattern_match(
    ctx: &mut EmitContext,
    ir: &IR,
    expr: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    emit_lazy_call_to_search_for_patterns(ctx, instr);

    let anchor = match ir.get(expr) {
        // When the pattern ID is known, simply push the ID into the stack.
        Expr::PatternMatch { pattern, anchor } => {
            instr.i32_const(ctx.pattern_id(*pattern).into());
            anchor
        }
        // When the pattern ID is not known, the ID is taken from a variable.
        Expr::PatternMatchVar { symbol, anchor } => {
            if let Symbol::Var { var, .. } = symbol.as_ref() {
                load_var(ctx, instr, *var);
                // load_var returns an I64, convert it to I32 because
                // PatternId is an I32.
                instr.unop(UnaryOp::I32WrapI64);
            } else {
                unreachable!()
            }
            anchor
        }
        _ => unreachable!(),
    };

    // At this point the pattern ID is already in the stack, emit the code that
    // checks if there's a match.
    match anchor {
        MatchAnchor::None => {
            instr.call(ctx.wasm_symbols.check_for_pattern_match);
        }
        MatchAnchor::At(offset) => {
            emit_expr(ctx, ir, *offset, instr);
            instr.call(
                ctx.function_id(wasm::export__is_pat_match_at.mangled_name),
            );
        }
        MatchAnchor::In(range) => {
            emit_expr(ctx, ir, range.lower_bound, instr);
            emit_expr(ctx, ir, range.upper_bound, instr);
            instr.call(
                ctx.function_id(wasm::export__is_pat_match_in.mangled_name),
            );
        }
    }
}

/// Emits the code that returns the number of matches for a pattern.
fn emit_pattern_count(
    ctx: &mut EmitContext,
    ir: &IR,
    expr: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    emit_lazy_call_to_search_for_patterns(ctx, instr);

    let range = match ir.get(expr) {
        // Cases where the pattern ID is known, simply push the ID into the
        // stack.
        Expr::PatternCount { pattern, range } => {
            instr.i32_const(ctx.pattern_id(*pattern).into());
            range
        }
        Expr::PatternCountVar { symbol, range } => {
            match symbol.as_ref() {
                Symbol::Var { var, .. } => {
                    load_var(ctx, instr, *var);
                    // load_var returns an I64, convert it to I32.
                    instr.unop(UnaryOp::I32WrapI64);
                }
                _ => unreachable!(),
            }
            range
        }
        _ => unreachable!(),
    };

    match range {
        Some(range) => {
            emit_expr(ctx, ir, range.lower_bound, instr);
            emit_expr(ctx, ir, range.upper_bound, instr);
            instr.call(
                ctx.function_id(wasm::export__pat_matches_in.mangled_name),
            );
        }
        None => {
            instr
                .call(ctx.function_id(wasm::export__pat_matches.mangled_name));
        }
    }
}

/// Emits the code that returns the offset of matches for a pattern.
fn emit_pattern_offset(
    ctx: &mut EmitContext,
    ir: &IR,
    expr: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    emit_lazy_call_to_search_for_patterns(ctx, instr);

    let index = match ir.get(expr) {
        // Cases where the pattern ID is known, simply push the ID into the
        // stack.
        Expr::PatternOffset { pattern, index } => {
            instr.i32_const(ctx.pattern_id(*pattern).into());
            index
        }
        Expr::PatternOffsetVar { symbol, index } => {
            match symbol.as_ref() {
                Symbol::Var { var, .. } => {
                    load_var(ctx, instr, *var);
                    // load_var returns an I64, convert it to I32.
                    instr.unop(UnaryOp::I32WrapI64);
                }
                _ => unreachable!(),
            }
            index
        }
        _ => unreachable!(),
    };

    match index {
        // The index was specified, like in `@a[2]`
        Some(index) => {
            emit_expr(ctx, ir, *index, instr);
        }
        // The index was not specified, like in `!a`, which is
        // equivalent to `@a[1]`.
        None => {
            instr.i64_const(1);
        }
    }

    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__pat_offset.mangled_name),
    )
}

/// Emits the code that returns the length of matches for a pattern.
fn emit_pattern_length(
    ctx: &mut EmitContext,
    ir: &IR,
    expr: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    emit_lazy_call_to_search_for_patterns(ctx, instr);

    let index = match ir.get(expr) {
        // Cases where the pattern ID is known, simply push the ID into the
        // stack.
        Expr::PatternLength { pattern, index } => {
            instr.i32_const(ctx.pattern_id(*pattern).into());
            index
        }
        Expr::PatternLengthVar { symbol, index } => {
            match symbol.as_ref() {
                Symbol::Var { var, .. } => {
                    load_var(ctx, instr, *var);
                    // load_var returns an I64, convert it to I32.
                    instr.unop(UnaryOp::I32WrapI64);
                }
                _ => unreachable!(),
            }
            index
        }
        _ => unreachable!(),
    };

    match index {
        // The index was specified, like in `!a[2]`
        Some(index) => {
            emit_expr(ctx, ir, *index, instr);
        }
        // The index was not specified, like in `!a`, which is
        // equivalent to `!a[1]`.
        None => {
            instr.i64_const(1);
        }
    }

    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__pat_length.mangled_name),
    )
}

/// Emits the code that checks if rule has matched.
///
/// The emitted code leaves 0 or 1 at the top of the stack.
fn emit_check_for_rule_match(
    ctx: &mut EmitContext,
    rule_id: RuleId,
    instr: &mut InstrSeqBuilder,
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
    // resides.
    instr.i32_const(rule_id.0 / 8);
    instr.load(
        ctx.wasm_symbols.main_memory,
        LoadKind::I32_8 { kind: ZeroExtend },
        MemArg {
            align: size_of::<i8>() as u32,
            offset: MATCHING_RULES_BITMAP_BASE as u32,
        },
    );

    // Compute byte & (1 << (rule_id % 8)), which clears all
    // bits except the one we are interested in.
    instr.i32_const(1 << (rule_id.0 % 8));
    instr.binop(BinaryOp::I32And);
    // Now shift the byte to the right, leaving the
    // interesting bit as the LSB. So the result is either
    // 1 or 0.
    instr.i32_const(rule_id.0 % 8);
    instr.binop(BinaryOp::I32ShrU);
}

/// Emits the code that gets an array item by index.
///
/// This function must be called right after emitting the code that leaves the
/// index in the stack. The code emitted by this function assumes that the top
/// of the stack is an i64 with the index.
fn emit_array_indexing(
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    array: &Rc<Array>,
) {
    let func = match array.as_ref() {
        Array::Integers(_) => &wasm::export__array_indexing_integer,
        Array::Floats(_) => &wasm::export__array_indexing_float,
        Array::Bools(_) => &wasm::export__array_indexing_bool,
        Array::Strings(_) => &wasm::export__array_indexing_string,
        Array::Structs(_) => &wasm::export__array_indexing_struct,
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
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    map: &Rc<Map>,
) {
    let func = match map.as_ref() {
        Map::IntegerKeys { deputy, .. } => {
            match deputy.as_ref().unwrap().ty() {
                Type::Integer => {
                    wasm::export__map_lookup_by_index_integer_integer
                        .mangled_name
                }
                Type::String => {
                    wasm::export__map_lookup_by_index_integer_string
                        .mangled_name
                }
                Type::Float => {
                    wasm::export__map_lookup_by_index_integer_float
                        .mangled_name
                }
                Type::Bool => {
                    wasm::export__map_lookup_by_index_integer_bool.mangled_name
                }
                Type::Struct => {
                    wasm::export__map_lookup_by_index_integer_struct
                        .mangled_name
                }
                _ => unreachable!(),
            }
        }
        Map::StringKeys { deputy, .. } => {
            match deputy.as_ref().unwrap().ty() {
                Type::Integer => {
                    wasm::export__map_lookup_by_index_string_integer
                        .mangled_name
                }
                Type::String => {
                    wasm::export__map_lookup_by_index_string_string
                        .mangled_name
                }
                Type::Float => {
                    wasm::export__map_lookup_by_index_string_float.mangled_name
                }
                Type::Bool => {
                    wasm::export__map_lookup_by_index_string_bool.mangled_name
                }
                Type::Struct => {
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
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    map: Rc<Map>,
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
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    map_value: &TypeValue,
) {
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
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    map_value: &TypeValue,
) {
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

fn consecutive_ranges(
    iter: impl Iterator<Item = PatternId>,
) -> impl Iterator<Item = RangeInclusive<PatternId>> {
    iter.peekable().batching(|it| {
        let start = it.next()?;
        let mut end = start;
        while let Some(&next) = it.peek() {
            if next.0 == end.0 + 1 {
                end = next;
                it.next();
            } else {
                break;
            }
        }
        Some(start..=end)
    })
}

fn emit_of_pattern_set(
    ctx: &mut EmitContext,
    ir: &IR,
    of: &OfPatternSet,
    instr: &mut InstrSeqBuilder,
) {
    // Make sure the pattern search phase is executed, as the `of` statement
    // depends on patterns.
    emit_lazy_call_to_search_for_patterns(ctx, instr);

    // Convert the pattern indexes to pattern IDs.
    let pattern_ids = of
        .items
        .iter()
        .map(|pattern_idx: &PatternIdx| ctx.pattern_id(*pattern_idx))
        .sorted();

    // Separate the pattern IDs in contiguous ranges. For instance, if we have
    // the IDs: 0,1,2,3,8,9,12,15,16, the ranges are 0..=3, 8..=9, 12..=12, and
    // 15..=16.
    let mut ranges = consecutive_ranges(pattern_ids).collect::<Vec<_>>();

    // Cases like `any of them`, `all of them` and `x of them` are special, as
    // they can be evaluated by calling a special function that receives a range
    // of pattern IDs and the minimum number of patterns in that range that must
    // match. All remaining cases must be evaluated by emitting a loop.
    match (&of.quantifier, &of.items, &of.anchor) {
        // `any of them`
        (Quantifier::Any, _, MatchAnchor::None) => {
            instr.block(I32, |instr| {
                let block = instr.id();
                for (position, range) in ranges.iter().with_position() {
                    let start: i32 = (*range.start()).into();
                    let end: i32 = (*range.end()).into();
                    // If the range contains a single PatternId, invoke
                    // `check_for_pattern_match` instead of `pat_range_match`.
                    if end == start {
                        instr.i32_const(start);
                        instr.call(ctx.wasm_symbols.check_for_pattern_match);
                    } else {
                        instr.i32_const(start);
                        instr.i32_const(end);
                        instr.i64_const(1);
                        instr.call(ctx.function_id(
                            wasm::export__pat_range_match.mangled_name,
                        ));
                    }
                    // For every call, except the last one, check the result
                    // and exit early from the block if any of the patterns
                    // were found.
                    if matches!(position, Position::First | Position::Middle) {
                        instr.if_else(
                            None,
                            |then_| {
                                then_.i32_const(1);
                                then_.br(block);
                            },
                            |_else| {},
                        );
                    }
                }
            });
        }
        // `any of them`
        (Quantifier::All, _, MatchAnchor::None) => {
            instr.block(I32, |instr| {
                let block = instr.id();
                for (position, range) in ranges.iter().with_position() {
                    let start: i32 = (*range.start()).into();
                    let end: i32 = (*range.end()).into();
                    if end == start {
                        instr.i32_const(start);
                        instr.call(ctx.wasm_symbols.check_for_pattern_match);
                    } else {
                        instr.i32_const(start);
                        instr.i32_const(end);
                        instr.i64_const(end as i64 - start as i64 + 1);
                        instr.call(ctx.function_id(
                            wasm::export__pat_range_match.mangled_name,
                        ));
                    }
                    // For every call, except the last one, check the result
                    // and exit early from the block if some of the patterns
                    // was not found.
                    if !matches!(position, Position::Only | Position::Last) {
                        instr.if_else(
                            None,
                            |_| {},
                            |else_| {
                                else_.i32_const(0);
                                else_.br(block);
                            },
                        );
                    }
                }
            });
        }
        // `n of them` but all the pattern IDs are contiguous (there's a
        // single range)
        (Quantifier::Expr(quantifier), _, MatchAnchor::None)
            if ranges.len() == 1 =>
        {
            let range = ranges.pop().unwrap();
            let start: i32 = (*range.start()).into();
            let end: i32 = (*range.end()).into();
            instr.i32_const(start);
            instr.i32_const(end);
            emit_expr(ctx, ir, *quantifier, instr);
            instr.call(
                ctx.function_id(wasm::export__pat_range_match.mangled_name),
            );
        }
        // All the remaining cases are evaluated using a loop.
        _ => emit_of_pattern_set_with_loop(ctx, ir, of, instr),
    }
}

fn emit_of_pattern_set_with_loop(
    ctx: &mut EmitContext,
    ir: &IR,
    of: &OfPatternSet,
    instr: &mut InstrSeqBuilder,
) {
    debug_assert!(!of.items.is_empty());

    let num_patterns = of.items.len();
    let mut patterns = of.items.iter();
    let next_pattern_id = of.next_pattern_var;

    emit_for(
        ctx,
        ir,
        &of.for_vars,
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
                emit_switch(ctx, I64, instr, |ctx, instr| {
                    if let Some(pattern) = patterns.next() {
                        instr.i64_const(ctx.pattern_id(*pattern).into());
                        return true;
                    }
                    false
                });
            });
        },
        // Body
        |ctx, instr| {
            // Push the pattern ID into the stack.
            load_var(ctx, instr, next_pattern_id);
            // load_var returns an I64, convert it to I32.
            instr.unop(UnaryOp::I32WrapI64);

            match &of.anchor {
                MatchAnchor::None => {
                    instr.call(ctx.wasm_symbols.check_for_pattern_match);
                }
                MatchAnchor::At(offset) => {
                    emit_expr(ctx, ir, *offset, instr);
                    instr.call(ctx.function_id(
                        wasm::export__is_pat_match_at.mangled_name,
                    ));
                }
                MatchAnchor::In(range) => {
                    emit_expr(ctx, ir, range.lower_bound, instr);
                    emit_expr(ctx, ir, range.upper_bound, instr);
                    instr.call(ctx.function_id(
                        wasm::export__is_pat_match_in.mangled_name,
                    ));
                }
            }
        },
        // After each iteration.
        |_, _, _| {},
        instr,
    );
}

fn emit_of_expr_tuple(
    ctx: &mut EmitContext,
    ir: &IR,
    of: &OfExprTuple,
    instr: &mut InstrSeqBuilder,
) {
    let num_expressions = of.items.len();
    let mut expressions = of.items.iter();
    let next_item = of.next_expr_var;

    emit_for(
        ctx,
        ir,
        &of.for_vars,
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
                emit_switch(
                    ctx,
                    next_item.ty().into(),
                    instr,
                    |ctx, instr| {
                        if let Some(expr) = expressions.next() {
                            emit_bool_expr(ctx, ir, *expr, instr);
                            return true;
                        }
                        false
                    },
                );
            });
        },
        // Body.
        |ctx, instr| {
            load_var(ctx, instr, next_item);
        },
        // After each iteration.
        |_, _, _| {},
        instr,
    );
}

fn emit_for_of_pattern_set(
    ctx: &mut EmitContext,
    ir: &IR,
    for_of: &ForOf,
    instr: &mut InstrSeqBuilder,
) {
    let num_patterns = for_of.pattern_set.len();
    let mut patterns = for_of.pattern_set.iter();
    let next_pattern_id = for_of.variable;

    emit_for(
        ctx,
        ir,
        &for_of.for_vars,
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
                emit_switch(ctx, I64, instr, |ctx, instr| {
                    if let Some(pattern) = patterns.next() {
                        instr.i64_const(ctx.pattern_id(*pattern).into());
                        return true;
                    }
                    false
                });
            });
        },
        // Body.
        |ctx, instr| {
            emit_bool_expr(ctx, ir, for_of.body, instr);
        },
        // After each iteration.
        |_, _, _| {},
        instr,
    );
}

fn emit_for_in_range(
    ctx: &mut EmitContext,
    ir: &IR,
    for_in: &ForIn,
    instr: &mut InstrSeqBuilder,
) {
    let range = cast!(&for_in.iterable, Iterable::Range);

    // A `for` loop in a range has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    // The only variable contains the loop's next item.
    let next_item = for_in.variables[0];

    emit_for(
        ctx,
        ir,
        &for_in.for_vars,
        &for_in.quantifier,
        // Loop initialization
        |ctx, instr, n, loop_end| {
            // Set n = upper_bound - lower_bound + 1;
            set_var(ctx, instr, n, |ctx, instr| {
                // Catch undefined values in upper_bound and lower_bound
                // expressions. In such cases n = 0.
                catch_undef(
                    ctx,
                    I64,
                    instr,
                    |ctx, instr| {
                        emit_expr(ctx, ir, range.upper_bound, instr);
                        emit_expr(ctx, ir, range.lower_bound, instr);

                        // Store lower_bound in temp variable, without removing
                        // it from the stack.
                        instr.local_tee(ctx.wasm_symbols.i64_tmp_a);

                        // Compute upper_bound - lower_bound + 1.
                        instr.binop(BinaryOp::I64Sub);
                        instr.i64_const(1);
                        instr.binop(BinaryOp::I64Add);
                    },
                    |_, instr| {
                        instr.i64_const(0);
                    },
                )
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
                instr.local_get(ctx.wasm_symbols.i64_tmp_a);
            });
        },
        // Before each iteration.
        |_, _, _| {},
        // Body.
        |ctx, instr| {
            emit_bool_expr(ctx, ir, for_in.body, instr);
        },
        // After each iteration.
        |ctx, instr, _| {
            incr_var(ctx, instr, next_item);
        },
        instr,
    );
}

fn emit_for_in_expr(
    ctx: &mut EmitContext,
    ir: &IR,
    for_in: &ForIn,
    instr: &mut InstrSeqBuilder,
) {
    let expr = cast!(for_in.iterable, Iterable::Expr);

    match ir.get(expr).ty() {
        Type::Array => {
            emit_for_in_array(ctx, ir, for_in, instr);
        }
        Type::Map => {
            emit_for_in_map(ctx, ir, for_in, instr);
        }
        _ => unreachable!(),
    }
}

fn emit_for_in_array(
    ctx: &mut EmitContext,
    ir: &IR,
    for_in: &ForIn,
    instr: &mut InstrSeqBuilder,
) {
    // A `for` loop in an array has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    let expr = cast!(for_in.iterable, Iterable::Expr);
    let array = ir.get(expr).type_value().as_array();

    // The only variable contains the loop's next item.
    let next_item = for_in.variables[0];

    // The variable `array_var` will hold a reference to the array being
    // iterated.
    let array_var = for_in.iterable_var;

    // Emit the expression that returns the array and stores a reference to
    // it in `array_var`.
    set_var(ctx, instr, array_var, |ctx, instr| {
        emit_expr(ctx, ir, expr, instr);
    });

    emit_for(
        ctx,
        ir,
        &for_in.for_vars,
        &for_in.quantifier,
        |ctx, instr, n, loop_end| {
            // Initialize `n` to the array's length.
            set_var(ctx, instr, n, |ctx, instr| {
                load_var(ctx, instr, array_var);
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
            // Get the i-th item in the array and store it in the
            // local variable `next_item`.
            set_var(ctx, instr, next_item, |ctx, instr| {
                load_var(ctx, instr, array_var);
                load_var(ctx, instr, i);
                emit_array_indexing(ctx, instr, &array);
            });
        },
        |ctx, instr| {
            emit_bool_expr(ctx, ir, for_in.body, instr);
        },
        // After each iteration.
        |_, _, _| {},
        instr,
    );
}

fn emit_for_in_map(
    ctx: &mut EmitContext,
    ir: &IR,
    for_in: &ForIn,
    instr: &mut InstrSeqBuilder,
) {
    // A `for` loop in a map has exactly two variables, one for the key
    // and the other for the value.
    assert_eq!(for_in.variables.len(), 2);

    let expr = cast!(for_in.iterable, Iterable::Expr);
    let map = ir.get(expr).type_value().as_map();

    let next_key = for_in.variables[0];
    let next_val = for_in.variables[1];

    // The variable `map_var` will hold a reference to the array being
    // iterated.
    let map_var = for_in.iterable_var;

    // Emit the expression that returns the map and stores a reference to
    // it in `map_var`.
    set_var(ctx, instr, map_var, |ctx, instr| {
        emit_expr(ctx, ir, expr, instr);
    });

    emit_for(
        ctx,
        ir,
        &for_in.for_vars,
        &for_in.quantifier,
        |ctx, instr, n, loop_end| {
            // Initialize `n` to the map's length.
            set_var(ctx, instr, n, |ctx, instr| {
                load_var(ctx, instr, map_var);
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
            set_vars(ctx, instr, &[next_key, next_val], |ctx, instr| {
                load_var(ctx, instr, map_var);
                load_var(ctx, instr, i);
                emit_map_lookup_by_index(ctx, instr, &map);
            });
        },
        // Body.
        |ctx, instr| {
            emit_bool_expr(ctx, ir, for_in.body, instr);
        },
        // After each iteration.
        |_, _, _| {},
        instr,
    );
}

fn emit_for_in_expr_tuple(
    ctx: &mut EmitContext,
    ir: &IR,
    for_in: &ForIn,
    instr: &mut InstrSeqBuilder,
) {
    // A `for` in a tuple of expressions has exactly one variable.
    assert_eq!(for_in.variables.len(), 1);

    let expressions = cast!(&for_in.iterable, Iterable::ExprTuple);

    // The only variable contains the loop's next item.
    let next_item = for_in.variables[0];

    let num_expressions = expressions.len();
    let mut expressions = expressions.iter();

    emit_for(
        ctx,
        ir,
        &for_in.for_vars,
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
            // If the expression calls `throw_undef`, we capture the exception
            // and flag the `next_item` variable as undefined.
            catch_undef(
                ctx,
                None,
                instr,
                |ctx, instr| {
                    set_var(ctx, instr, next_item, |ctx, instr| {
                        load_var(ctx, instr, i);
                        emit_switch(
                            ctx,
                            next_item.ty().into(),
                            instr,
                            |ctx, instr| match expressions.next() {
                                Some(expr) => {
                                    emit_expr(ctx, ir, *expr, instr);
                                    true
                                }
                                None => false,
                            },
                        );
                    });
                },
                move |ctx, instr| {
                    set_var_undef(ctx, instr, next_item, true);
                },
            );
        },
        // Body.
        |ctx, instr| {
            emit_bool_expr(ctx, ir, for_in.body, instr);
        },
        // After each iteration.
        |_, _, _| {},
        instr,
    );
}

/// Emits a `for` loop.
///
/// This function allows creating different types of `for` loops by receiving
/// other functions that emit the loop initialization code, the code that gets
/// executed just before and after each iteration, and the `for` body.
///
/// `loop_init` is the function that emits the initialization code, which is
/// executed only once, before the loop itself. This code should initialize
/// the variable `n` with the total number of items in the object that is
/// being iterated. This code should not leave anything on the stack.
///
/// `before_cond` emits the code that gets executed on every iteration just
/// before the loop's body. The code produced by `before_cond` must set the
/// loop variable(s) used by the body to the value(s) corresponding to the
/// current iteration. This code should not leave anything on the stack.
///
/// `body` emits the loop's body, it should leave an I32 on the stack with
/// value 0 or 1.
///
/// `after_cond` emits the code that gets executed on every iteration after
/// the loop's body. This code should not leave anything on the stack.
#[allow(clippy::too_many_arguments)]
fn emit_for<I, B, C, A>(
    ctx: &mut EmitContext,
    ir: &IR,
    for_vars: &ForVars,
    quantifier: &Quantifier,
    loop_init: I,
    before_cond: B,
    body: C,
    after_cond: A,
    instr: &mut InstrSeqBuilder,
) where
    I: FnOnce(&mut EmitContext, &mut InstrSeqBuilder, Var, InstrSeqId),
    B: FnOnce(&mut EmitContext, &mut InstrSeqBuilder, Var),
    C: FnOnce(&mut EmitContext, &mut InstrSeqBuilder),
    A: FnOnce(&mut EmitContext, &mut InstrSeqBuilder, Var),
{
    // Variable `n` contains the maximum number of iterations.
    let n = for_vars.n;

    // Variable `i` contains the current iteration number.
    // The value of `i` is in the range 0..n-1.
    let i = for_vars.i;

    // Function that increments `i` and checks if `i` < `n` after each
    // iteration, repeating the loop while the body returns true.
    let incr_i_and_repeat =
        |ctx: &mut EmitContext,
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

        let p = match quantifier {
            Quantifier::Percentage(expr) => Some((expr, true)),
            Quantifier::Expr(expr) => Some((expr, false)),
            _ => None,
        };

        let (max_count, count) = match p {
            Some((quantifier, is_percentage)) => {
                // `max_count` is the number of loop iterations that must return
                // `true` for the loop to be `true`.
                let max_count = for_vars.max_count;
                // `count` is the number of loop iterations that actually
                // returned `true`. This is initially zero.
                let count = for_vars.count;

                set_var(ctx, instr, max_count, |ctx, instr| {
                    if is_percentage {
                        // Quantifier is a percentage, its final value will be
                        // n * quantifier / 100

                        // n * quantifier
                        load_var(ctx, instr, n);
                        instr.unop(UnaryOp::F64ConvertSI64);
                        emit_expr(ctx, ir, *quantifier, instr);
                        instr.unop(UnaryOp::F64ConvertSI64);
                        instr.binop(BinaryOp::F64Mul);

                        // / 100
                        instr.f64_const(100.0);
                        instr.binop(BinaryOp::F64Div);
                        instr.unop(UnaryOp::F64Ceil);
                        instr.unop(UnaryOp::I64TruncSF64);
                    } else {
                        // Quantifier is not a percentage, use it as is.
                        emit_expr(ctx, ir, *quantifier, instr);
                    }
                });

                // Initialize `count` to 0.
                set_var(ctx, instr, count, |_, instr| {
                    instr.i64_const(0);
                });

                (max_count, count)
            }
            _ => (
                // Not really used, but we must return something.
                Var::default(),
                Var::default(),
            ),
        };

        instr.loop_(I32, |block| {
            let loop_start = block.id();

            // Emit code that advances to next item.
            before_cond(ctx, block, i);

            // Emit code for the loop's body. Use `catch_undef` for
            // capturing any undefined exception produced by the body because
            // we don't want to abort the loop in such cases. When the body's
            // result is undefined it's handled as a false.
            catch_undef(
                ctx,
                I32,
                block,
                |ctx, block| {
                    body(ctx, block);
                },
                |_, instr| {
                    instr.i32_const(0);
                },
            );

            // At the top of the stack we have the i32 with the result from
            // the loop body. Decide what to do depending on the quantifier.
            match quantifier {
                Quantifier::None => {
                    block.if_else(
                        I32,
                        |then_| {
                            // If the body returned true, break the loop with
                            // result false.
                            then_.i32_const(0);
                            then_.br(loop_end);
                        },
                        |else_| {
                            incr_i_and_repeat(ctx, else_, n, i, loop_start);
                            // If this point is reached is because all the
                            // range was iterated without the body returning
                            // true, this means that the whole "for" statement
                            // is true.
                            else_.i32_const(1);
                            else_.br(loop_end);
                        },
                    );
                }
                Quantifier::All => {
                    block.if_else(
                        I32,
                        |then_| {
                            incr_i_and_repeat(ctx, then_, n, i, loop_start);
                            // If this point is reached is because all the
                            // range was iterated without the body returning
                            // false, this means that the whole "for"
                            // statement is true.
                            then_.i32_const(1);
                            then_.br(loop_end);
                        },
                        |else_| {
                            // If the body returned false, break the loop
                            // with result false.
                            else_.i32_const(0);
                            else_.br(loop_end);
                        },
                    );
                }
                Quantifier::Any => {
                    block.if_else(
                        I32,
                        |then_| {
                            // If the body returned true, break the loop with
                            // result true.
                            then_.i32_const(1);
                            then_.br(loop_end);
                        },
                        |else_| {
                            incr_i_and_repeat(ctx, else_, n, i, loop_start);
                            // If this point is reached is because all the
                            // range was iterated without the body returning
                            // true, this means that the whole "for"
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
                            // The body was true, increment count.
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
                    // `counter` didn't reach `max_count` and the loop must
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
    });
}

/// Emits the code for a `with` statement.
///
/// Each `with` statement has a corresponding <identifier> = <expression> pair.
/// Each pair is stored in the `identifiers` and `expressions` fields of the
/// `with` statement.
/// For each pair, the code emitted by this function sets the variable
/// corresponding to the identifier to the value of the emitted expression.
/// Those variables are later used in the body of the `with` statement.
fn emit_with(
    ctx: &mut EmitContext,
    ir: &IR,
    declarations: &[(Var, ExprId)],
    body: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    // Emit the code that sets the variables in the `with` statement.
    for (id, expr) in declarations.iter().cloned() {
        catch_undef(
            ctx,
            None,
            instr,
            |ctx, instr| {
                set_var(ctx, instr, id, |ctx, instr| {
                    emit_expr(ctx, ir, expr, instr);
                });
            },
            move |ctx, instr| {
                set_var_undef(ctx, instr, id, true);
            },
        );
    }

    // Emit the code that evaluates the body of the `with` statement.
    emit_expr(ctx, ir, body, instr)
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
///           ;; Look for the i32 at the top of the stack, and depending on its
///           ;; value jumps out of some block...
///           br_table
///                1 (;@4;)   ;; selector == 0 -> jump out of block @4
///                2 (;@3;)   ;; selector == 1 -> jump out of block @3
///                4 (;@2;)   ;; selector == 2 -> jump out of block @2
///                0 (;@5;)   ;; default       -> jump out of block @5
///
///         end                         ;; block @5
///         unreachable                 ;; if this point is reached is because
///                                     ;; the switch selector is out of range
///       end                           ;; block @4
///       block (result i64)
///         ;; < code expr 0 goes here >
///       end
///       br 2 (;@1;)                   ;; exits block @1
///     end                             ;; block @3
///     block (result i64)
///       ;; < code expr 1 goes here >
///     end
///     br 1 (;@1;)                     ;; exits block @1
///   end                               ;; block @2
///   block (result i64)
///     ;; < code expr 2 goes here >
///   end
/// end                                 ;; block @1
///                                     ;; at this point the i64 returned by the
///                                     ;; selected expression is at the top of
///                                     ;; the stack.
/// ```
fn emit_switch<F>(
    ctx: &mut EmitContext,
    ty: ValType,
    instr: &mut InstrSeqBuilder,
    mut branch_generator: F,
) where
    F: FnMut(&mut EmitContext, &mut InstrSeqBuilder) -> bool,
{
    // Convert the i64 at the top of the stack to an i32, which is the type
    // expected by the `bt_table` instruction.
    instr.unop(UnaryOp::I32WrapI64);

    // Store the i32 switch selector in a temp variable. The selector is the i32
    // value at the top of the stack that tells which expression should be
    // executed.
    instr.local_set(ctx.wasm_symbols.i32_tmp);

    let mut branch_blocks = VecDeque::new();
    let mut branch_expr = instr.dangling_instr_seq(ty);

    while branch_generator(ctx, &mut branch_expr) {
        branch_blocks.push_back(walrus::ir::Block { seq: branch_expr.id() });
        branch_expr = instr.dangling_instr_seq(ty);
    }

    // The switch statement returns a value of type `ty`.
    let outermost_block = instr.dangling_instr_seq(ty);
    let outermost_block_id = outermost_block.id();

    let switch_block = instr.dangling_instr_seq(None);
    let switch_block_id = switch_block.id();

    // These are the block IDs for the `br_table` instruction.
    let mut block_ids = Vec::with_capacity(branch_blocks.len());

    let mut block_id = switch_block_id;

    block_ids.push(block_id);

    let last_branch = branch_blocks.pop_back().unwrap();

    // Iterate over the branches of the switch statement except the last one.
    // The last branch is handled slightly differently because its code is put
    // directly in the outermost block.
    while let Some(expr_block) = branch_blocks.pop_front() {
        let mut branch = instr.dangling_instr_seq(None);
        // This is the block that contains all the previous branches
        branch.instr(walrus::ir::Block { seq: block_id });
        // This is the block for the current branch.
        branch.instr(expr_block);
        // The instruction that goes out of the switch statement
        // after each branch (think of `break` statements in a C switch).
        branch.br(outermost_block_id);
        block_id = branch.id();
        block_ids.push(block_id);
    }

    instr
        .instr_seq(switch_block_id)
        .block(None, |block| {
            block.local_get(ctx.wasm_symbols.i32_tmp);
            block.br_table(block_ids.into(), block.id());
        })
        .unreachable();

    instr
        .instr_seq(outermost_block_id)
        .instr(walrus::ir::Block { seq: block_id })
        .instr(last_branch);

    instr.instr(walrus::ir::Block { seq: outermost_block_id });
}

/// Sets into a variable the value produced by a code block.
///
/// For multiple variables use [`set_vars`].
fn set_var<B>(
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    var: Var,
    block: B,
) where
    B: FnOnce(&mut EmitContext, &mut InstrSeqBuilder),
{
    let (store_kind, alignment) = match var.ty() {
        Type::Bool => (StoreKind::I32 { atomic: false }, size_of::<i32>()),
        Type::Float => (StoreKind::F64, size_of::<f64>()),
        Type::Integer
        | Type::String
        | Type::Struct
        | Type::Array
        | Type::Map
        | Type::Func => (StoreKind::I64 { atomic: false }, size_of::<i64>()),
        _ => unreachable!(),
    };

    // First push the offset where the variable resides in memory. This will
    // be used by the `store` instruction.
    instr.i32_const(var.index() * Var::mem_size());

    // Block that produces the value that will be stored in the variable.
    block(ctx, instr);

    // The store instruction will remove two items from the stack, the value and
    // the offset where it will be stored.
    instr.store(
        ctx.wasm_symbols.main_memory,
        store_kind,
        MemArg { align: alignment as u32, offset: VARS_STACK_START as u32 },
    );

    // Flag the variable as not undefined.
    set_var_undef(ctx, instr, var, false);
}

/// Sets into variables the values produced by a code block.
///
/// The code block must leave in the stack as many values as the number of vars
/// and their types must match. The first variable will contain the first value
/// that was pushed into the stack.
///
/// For a single variable use [`set_var`].
fn set_vars<B>(
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    vars: &[Var],
    block: B,
) where
    B: FnOnce(&mut EmitContext, &mut InstrSeqBuilder),
{
    // Execute the block that produces the values.
    block(ctx, instr);

    // Iterate variables in reverse order as the last variable is the one
    // at the top of the stack.
    for var in vars.iter().rev() {
        match var.ty() {
            Type::Bool => {
                // Pop the value and store it into temp variable.
                instr.local_set(ctx.wasm_symbols.i32_tmp);
                // Push the offset where the variable resides in memory.
                // The offset is always multiple of 64-bits, as each variable
                // occupies a 64-bits slot. This is true even for bool values
                // that are represented as a 32-bits integer.
                instr.i32_const(var.index() * Var::mem_size());
                // Push the value.
                instr.local_get(ctx.wasm_symbols.i32_tmp);
                // Store the value in memory.
                instr.store(
                    ctx.wasm_symbols.main_memory,
                    StoreKind::I32 { atomic: false },
                    MemArg {
                        align: size_of::<i32>() as u32,
                        offset: VARS_STACK_START as u32,
                    },
                );
            }
            Type::Integer
            | Type::String
            | Type::Struct
            | Type::Array
            | Type::Map
            | Type::Func => {
                instr.local_set(ctx.wasm_symbols.i64_tmp_a);
                instr.i32_const(var.index() * Var::mem_size());
                instr.local_get(ctx.wasm_symbols.i64_tmp_a);
                instr.store(
                    ctx.wasm_symbols.main_memory,
                    StoreKind::I64 { atomic: false },
                    MemArg {
                        align: size_of::<i64>() as u32,
                        offset: VARS_STACK_START as u32,
                    },
                );
            }
            Type::Float => {
                instr.local_set(ctx.wasm_symbols.f64_tmp);
                instr.i32_const(var.index() * Var::mem_size());
                instr.local_get(ctx.wasm_symbols.f64_tmp);
                instr.store(
                    ctx.wasm_symbols.main_memory,
                    StoreKind::F64,
                    MemArg {
                        align: size_of::<f64>() as u32,
                        offset: VARS_STACK_START as u32,
                    },
                );
            }
            _ => unreachable!(),
        }
        set_var_undef(ctx, instr, *var, false);
    }
}

/// Loads the value of variable into the stack.
fn load_var(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder, var: Var) {
    // First check if the undefined flag is set for the requested variable
    // and throw the undefined exception in that case.
    instr.i32_const(var.index().saturating_div(64));
    instr.load(
        ctx.wasm_symbols.main_memory,
        LoadKind::I64 { atomic: false },
        MemArg { align: 8, offset: 0 },
    );
    instr.i64_const(1 << var.index().wrapping_rem(64));
    instr.binop(BinaryOp::I64And);
    instr.unop(UnaryOp::I64Eqz);
    instr.if_else(None, |_then| {}, |_else| throw_undef(ctx, _else));

    // The slots where variables are stored start at offset VARS_STACK_START
    // within main memory, and are 64-bits long. Let's compute the variable's
    // offset with respect to VARS_STACK_START.
    instr.i32_const(var.index() * Var::mem_size());

    let (load_kind, alignment) = match var.ty() {
        Type::Bool => (LoadKind::I32 { atomic: false }, size_of::<i32>()),
        Type::Float => (LoadKind::F64, size_of::<i64>()),
        Type::Integer
        | Type::String
        | Type::Struct
        | Type::Array
        | Type::Map
        | Type::Func => (LoadKind::I64 { atomic: false }, size_of::<i64>()),
        _ => unreachable!(),
    };

    instr.load(
        ctx.wasm_symbols.main_memory,
        load_kind,
        MemArg { align: alignment as u32, offset: VARS_STACK_START as u32 },
    );
}

fn set_var_undef(
    ctx: &mut EmitContext,
    instr: &mut InstrSeqBuilder,
    var: Var,
    is_undef: bool,
) {
    // Push the address of the i64 where the flag is located. Push it
    // twice, one is for the load instruction and the other one is for
    // the store instruction.
    instr.i32_const(var.index().saturating_div(64));
    instr.i32_const(var.index().saturating_div(64));
    instr.load(
        ctx.wasm_symbols.main_memory,
        LoadKind::I64 { atomic: false },
        MemArg { align: 8, offset: 0 },
    );

    let bit = 1i64 << var.index().wrapping_rem(64);

    if is_undef {
        instr.i64_const(bit);
        instr.binop(BinaryOp::I64Or);
    } else {
        instr.i64_const(!bit);
        instr.binop(BinaryOp::I64And);
    }

    instr.store(
        ctx.wasm_symbols.main_memory,
        StoreKind::I64 { atomic: false },
        MemArg { align: 8, offset: 0 },
    );
}

/// Increments a variable.
fn incr_var(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder, var: Var) {
    // incr_var only works with integer variables.
    assert_eq!(var.ty(), Type::Integer);
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
    ctx: &mut EmitContext,
    ir: &IR,
    expr: ExprId,
    instr: &mut InstrSeqBuilder,
) {
    emit_expr(ctx, ir, expr, instr);

    match ir.get(expr).ty() {
        Type::Bool => {
            // `expr` already returned a bool, nothing more to do.
        }
        Type::Integer => {
            // cast the integer to a bool.
            instr.i64_const(0);
            instr.binop(BinaryOp::I64Ne);
        }
        Type::Float => {
            // cast the float to a bool.
            instr.f64_const(0.0);
            instr.binop(BinaryOp::F64Ne);
        }
        Type::String => {
            // cast the string to a bool.
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
    ctx: &mut EmitContext,
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
            // does not exist. This however emits WebAssembly code without
            // the `else` branch.
        },
    );
}

/// Emits the code that prepares the arguments for any of the lookup functions
/// like [`wasm::lookup_integer`], [`wasm::lookup_string`], etc.
///
/// This function takes all the values in `ctx.lookup_list` and put them in
/// WASM memory starting at offset [`LOOKUP_INDEXES_START`], then it pushes the
/// number of values in the WASM stack. These values are the indexes of fields
/// within some structure. For example, suppose we have the following structure:
///
/// ```text
/// Struct {
///     some_integer_field: Integer,
///     some_struct_field: Struct {
///        inner_field_1: String,
///        inner_field_2: String,
///        inner_field_3: String,
///     }
/// }
/// ```
///
/// Field indexes are relative to the structure where they are contained, and
/// start at 0, so the index for `some_integer_field` is 0, while the index for
/// `some_struct_field` is 1. If we want to locate `inner_field_3` starting at
/// the outer struct, we must lookup `some_struct_field` first (index 1) and
/// then lookup `inner_field_3` (index 2), so `ctx.lookup_list` will contain
/// the values `0` and `3`. These two values are copied to WASM memory and then
/// the number of values (2) will be pushed into the WASM stack. These way the
/// lookup function can know how many values to read from WASM memory.
fn emit_lookup_common(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    let num_lookup_indexes = ctx.lookup_list.len();
    let main_memory = ctx.wasm_symbols.main_memory;

    let root = ctx.lookup_list.first().unwrap().1;

    // At the top of the stack we have the object handler for
    // the structure containing the field identified by `index`
    // except when the field belongs to the root structure, in
    // which case we must push a null reference
    if root {
        instr.i64_const(RuntimeObjectHandle::NULL.into());
    }

    for (i, (field_index, _)) in ctx.lookup_list.drain(0..).enumerate() {
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
}

#[inline]
fn emit_lookup_integer(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_integer.mangled_name),
    );
}

#[inline]
fn emit_lookup_float(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_float.mangled_name),
    );
}

#[inline]
fn emit_lookup_bool(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_bool.mangled_name),
    );
}

#[inline]
fn emit_lookup_string(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    emit_call_and_handle_undef(
        ctx,
        instr,
        ctx.function_id(wasm::export__lookup_string.mangled_name),
    );
}

#[inline]
fn emit_lookup_object(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    emit_lookup_common(ctx, instr);
    instr.call(ctx.function_id(wasm::export__lookup_object.mangled_name));
}

/// Emits code for catching exceptions caused by undefined values.
///
/// This function emits WebAssembly code that behaves similarly to an exception
/// handler. The code in `expr` must return a value of type `ty` which is left
/// at the top of the stack. However, at any point inside this block you can
/// use [`throw_undef`] for throwing an exception when an undefined value is
/// detected. In that case the execution flow will be interrupted at the point
/// where [`throw_undef`] was found, the code in `catch` is executed, leaving
/// its result in the stack, and the control transferred to the instruction
/// that follows after the `catch_undef` block. Notice that `expr` and `catch`
/// must return values of the same type. In a normal execution the result from
/// the `catch_undef` block is the result from `expr`, but when an exception
/// occurs the value is provided by the `catch` block.
///
/// [`catch_undef`] blocks can be nested, and in such cases the control will
/// be transferred to the end of the innermost block.
///
/// # Example
///
/// ```text
/// catch_undef(ctx, instr,
///    |ctx, block| {
///       throw_undef(ctx, block);   // The exception is raised here ...
///       block.i32_const(1);        // ... and this is not executed.
///    },
///    |catch| {
///       catch.i32_const(0);        // If an exception is raised, the result
///                                  // from `catch_undef` will be 0.
///    }
/// );
/// // ... at this point we have a zero value of type i32 at the top of the
/// // stack.
/// ```
///
fn catch_undef(
    ctx: &mut EmitContext,
    ty: impl Into<InstrSeqType>,
    instr: &mut InstrSeqBuilder,
    expr: impl FnOnce(&mut EmitContext, &mut InstrSeqBuilder),
    catch: impl Fn(&mut EmitContext, &mut InstrSeqBuilder) + 'static,
) {
    // Create a new block containing `expr`. When an exception is raised from
    // within `expr`, the control flow will jump out of this block via a `br`
    // instruction.
    instr.block(ty, |block| {
        // Push the type and ID of the current block in the handlers stack.
        ctx.exception_handler_stack.push((block.id(), Box::new(catch)));
        expr(ctx, block);
    });

    // Pop exception handler from the stack.
    ctx.exception_handler_stack.pop();
}

/// Throws an exception when an undefined value is found.
///
/// For more information see [`catch_undef`].
fn throw_undef(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    let innermost_handler = ctx
        .exception_handler_stack
        .pop()
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
    innermost_handler.1(ctx, instr);

    // Jump to the exception handler.
    instr.br(innermost_handler.0);

    ctx.exception_handler_stack.push(innermost_handler);
}

/// Similar to [`throw_undef`], but throws the exception if the top of the
/// stack is zero. If the top of the stack is non-zero, calling this function
/// is a no-op.
fn throw_undef_if_zero(ctx: &mut EmitContext, instr: &mut InstrSeqBuilder) {
    // Save the top of the stack into temp variable, but leave a copy in the
    // stack.
    let tmp = ctx.wasm_symbols.i64_tmp_a;
    instr.local_tee(tmp);
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
            else_.local_get(tmp);
        },
    );
}
