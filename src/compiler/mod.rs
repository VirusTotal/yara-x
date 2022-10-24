/*! Compiles YARA source code into binary form.

YARA rules must be compiled before they can be used for scanning data. This
module implements the YARA compiler.
*/
use bstr::{BString, ByteSlice};
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;

use crate::parser::Error as ParserError;
use crate::parser::{
    arithmetic_op, bitwise_not, bitwise_op, boolean_not, boolean_op,
    comparison_op, minus_op, shift_op, string_op,
};
use crate::parser::{
    Expr, HasSpan, Iterable, MatchAnchor, Parser, Quantifier, SourceCode,
};
use crate::report::ReportBuilder;
use crate::{SymbolTable, Type, Value};

#[doc(inline)]
pub use crate::compiler::errors::*;

mod errors;

#[cfg(test)]
mod tests;

/// A YARA compiler.
pub struct Compiler<'sym> {
    colorize_errors: bool,
    report_builder: ReportBuilder,
    sym_tbl: SymbolTable<'sym>,
}

impl<'sym> Compiler<'sym> {
    /// Creates a new YARA compiler.
    pub fn new() -> Self {
        Self {
            colorize_errors: false,
            report_builder: ReportBuilder::new(),
            sym_tbl: SymbolTable::new(),
        }
    }

    /// Specifies whether the compiler should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn colorize_errors(self, b: bool) -> Self {
        Self {
            colorize_errors: b,
            report_builder: self.report_builder,
            sym_tbl: self.sym_tbl,
        }
    }

    /// Adds a YARA source code to be compiled.
    ///
    /// This function can be called multiple times.
    pub fn add(&self, src: &str) -> Result<(), Error> {
        let mut ast = Parser::new()
            .colorize_errors(self.colorize_errors)
            .set_report_builder(&self.report_builder)
            .build_ast(src, None)?;

        let src = SourceCode { text: src, origin: None };

        for ns in ast.namespaces.values_mut() {
            for rule in ns.rules.values_mut() {
                self.expr_semantic_check(&src, &mut rule.condition)?;
            }
        }

        Ok(())
    }
}

macro_rules! check_type {
    ($self:ident, $src:ident, $( $pattern:path )|+, $expr:expr) => {
        {
            use crate::compiler::errors::Error;
            let span = $expr.span();
            let (ty, val) = $self.expr_semantic_check($src, $expr)?;
            if !matches!(ty, $( $pattern )|+) {
                return Err(Error::CompileError(CompileError::wrong_type(
                    &$self.report_builder,
                    $src,
                    ParserError::join_with_or(&[ $( $pattern.to_string() ),+ ], true),
                    ty.to_string(),
                    span,
                )));
            }
            Ok::<(Type, Value), Error>((ty, val))
        }
    };
}

macro_rules! check_operands {
        ($self:ident, $src:ident, $( $pattern:path )|+, $expr1:expr, $expr2:expr) => {
        {
            let (ty1, value1) = check_type!($self, $src, $( $pattern )|+, $expr1)?;
            let (ty2, value2) = check_type!($self, $src, $( $pattern )|+, $expr2)?;

            // Both types must be known.
            assert!(!matches!(ty1, Type::Unknown));
            assert!(!matches!(ty2, Type::Unknown));

            let mismatching_types = match ty1 {
                // Float and Integer are compatible types, operators can
                // have different operand types where one is Integer and
                // the other is Float.
                Type::Integer | Type::Float => {
                    !matches!(ty2, Type::Integer | Type::Float)
                }
                // In all other cases types must be equal to be considered
                // compatible.
                _ => ty1 != ty2,
            };

            if mismatching_types {
                return Err(Error::CompileError(CompileError::mismatching_types(
                    &$self.report_builder,
                    $src,
                    ty1.to_string(),
                    ty2.to_string(),
                    $expr1.span(),
                    $expr2.span(),
                )));
            }

            Ok::<_, Error>(((ty1, value1), (ty2, value2)))
        }
    };
}

macro_rules! check_non_negative_integer {
    ($self:ident, $src:ident, $expr:expr) => {{
        if let Value::Integer(value) = $expr {
            if value < 0 {
                return Err(Error::CompileError(
                    CompileError::unexpected_negative_number(
                        &$self.report_builder,
                        $src,
                        $expr.span(),
                    ),
                ));
            }
        } else {
            unreachable!();
        };
        Ok::<(), Error>(())
    }};
}

macro_rules! check_boolean_op {
    ($self:ident, $src:ident, $expr:ident, $op:tt) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $self,
            $src,
            Type::Bool,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) = boolean_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_comparison_op {
    ($self:ident, $src:ident, $expr:ident, $op:tt) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $self,
            $src,
            Type::Integer | Type::Float | Type::String,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) = comparison_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_shift_op {
    ($self:ident, $src:ident, $expr:ident, $op:ident) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $self,
            $src,
            Type::Integer,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        if let Value::Integer(value) = rhs_value {
            if value < 0 {
                return Err(Error::CompileError(
                    CompileError::unexpected_negative_number(
                        &$self.report_builder,
                        $src,
                        $expr.rhs.span(),
                    ),
                ));
            }
        } else {
            unreachable!();
        };

        ($expr.ty, $expr.value) = shift_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_bitwise_op {
    ($self:ident, $src:ident, $expr:ident, $op:ident) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $self,
            $src,
            Type::Integer,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) = bitwise_op!(lhs_value, $op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_arithmetic_op {
    ($self:ident, $src:ident, $expr:ident, $op:tt, $checked_op:ident) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $self,
            $src,
            Type::Integer | Type::Float,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) =
            arithmetic_op!(lhs_value, $op, $checked_op, rhs_value);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

macro_rules! check_string_op {
    ($self:ident, $src:ident, $expr:ident, $op:ident, $case_insensitive:expr) => {{
        let ((_, lhs_value), (_, rhs_value)) = check_operands!(
            $self,
            $src,
            Type::String,
            &mut $expr.lhs,
            &mut $expr.rhs
        )?;

        ($expr.ty, $expr.value) =
            string_op!(lhs_value, $op, rhs_value, $case_insensitive);

        Ok(($expr.ty.clone(), $expr.value.clone()))
    }};
}

impl<'sym> Compiler<'sym> {
    /// Makes sure that an expression is semantically valid.
    ///
    /// This functions traverses the AST and makes sure that the expression
    /// and all its sub-expressions are semantically correct. This function
    /// checks that...
    ///
    /// * Operands have the correct types, for example, boolean operations
    ///   can't have operands of type string.
    /// * Array indexes are non-negative integers.
    /// * Operands in bitwise operations are non-negative integers.
    /// * Range bounds are non-negative integers and upper bound is greater
    ///   than lower bound.
    ///
    /// This function returns the expression's type and value, if known at
    /// compile time.
    ///
    pub(crate) fn expr_semantic_check(
        &self,
        src: &SourceCode,
        expr: &'sym mut Expr,
    ) -> Result<(Type, Value<'sym>), Error> {
        match expr {
            Expr::True { .. }
            | Expr::False { .. }
            | Expr::Filesize { .. }
            | Expr::Entrypoint { .. }
            | Expr::LiteralFlt(_)
            | Expr::LiteralInt(_)
            | Expr::LiteralStr(_) => Ok(expr.type_value()),

            Expr::PatternCount(p) => {
                // check range bounds
                todo!()
            }

            Expr::PatternOffset(p) | Expr::PatternLength(p) => {
                // check that index is integer and >= 1
                todo!()
            }

            Expr::PatternMatch(p) => {
                match &mut p.anchor {
                    Some(MatchAnchor::In(anchor_in)) => {
                        todo!()
                    }
                    Some(MatchAnchor::At(anchor_at)) => {
                        todo!()
                    }
                    None => {}
                }
                Ok((Type::Bool, Value::Unknown))
            }

            Expr::Not(expr) => {
                let (_, value) =
                    check_type!(self, src, Type::Bool, &mut expr.operand)?;

                (expr.ty, expr.value) = boolean_not!(value);

                Ok((expr.ty.clone(), expr.value.clone()))
            }

            Expr::And(expr) => {
                check_boolean_op!(self, src, expr, &&)
            }

            Expr::Or(expr) => {
                check_boolean_op!(self, src, expr, ||)
            }

            Expr::Eq(expr) => {
                check_comparison_op!(self, src, expr, ==)
            }

            Expr::Neq(expr) => {
                check_comparison_op!(self, src, expr, !=)
            }

            Expr::Lt(expr) => {
                check_comparison_op!(self, src, expr, <)
            }

            Expr::Le(expr) => {
                check_comparison_op!(self, src, expr, <=)
            }

            Expr::Gt(expr) => {
                check_comparison_op!(self, src, expr, >)
            }

            Expr::Ge(expr) => {
                check_comparison_op!(self, src, expr, >=)
            }

            Expr::Shl(expr) => {
                check_shift_op!(self, src, expr, overflowing_shl)
            }

            Expr::Shr(expr) => {
                check_shift_op!(self, src, expr, overflowing_shr)
            }

            Expr::BitwiseNot(expr) => {
                let (_, value) =
                    check_type!(self, src, Type::Integer, &mut expr.operand)?;

                (expr.ty, expr.value) = bitwise_not!(value);

                Ok((expr.ty.clone(), expr.value.clone()))
            }

            Expr::BitwiseAnd(expr) => {
                check_bitwise_op!(self, src, expr, bitand)
            }

            Expr::BitwiseOr(expr) => {
                check_bitwise_op!(self, src, expr, bitor)
            }

            Expr::BitwiseXor(expr) => {
                check_bitwise_op!(self, src, expr, bitxor)
            }

            Expr::Minus(expr) => {
                let (ty, value) = check_type!(
                    self,
                    src,
                    Type::Integer | Type::Float,
                    &mut expr.operand
                )?;

                (expr.ty, expr.value) = minus_op!(value);

                Ok((expr.ty.clone(), expr.value.clone()))
            }

            Expr::Add(expr) => {
                check_arithmetic_op!(self, src, expr, +, checked_add)
            }

            Expr::Sub(expr) => {
                check_arithmetic_op!(self, src, expr, -, checked_sub)
            }

            Expr::Mul(expr) => {
                check_arithmetic_op!(self, src, expr, *, checked_mul)
            }

            Expr::Div(expr) => {
                check_arithmetic_op!(self, src, expr, /, checked_div)
            }

            Expr::Modulus(expr) => {
                check_arithmetic_op!(self, src, expr, %, checked_rem)
            }

            Expr::Contains(expr) => {
                check_string_op!(self, src, expr, contains_str, false)
            }

            Expr::IContains(expr) => {
                check_string_op!(self, src, expr, contains_str, true)
            }

            Expr::StartsWith(expr) => {
                check_string_op!(self, src, expr, starts_with, false)
            }

            Expr::IStartsWith(expr) => {
                check_string_op!(self, src, expr, starts_with, true)
            }

            Expr::EndsWith(expr) => {
                check_string_op!(self, src, expr, ends_with, false)
            }

            Expr::IEndsWith(expr) => {
                check_string_op!(self, src, expr, ends_with, true)
            }

            Expr::IEquals(expr) => {
                todo!()
            }

            Expr::Ident(_) => {
                todo!()
            }
            Expr::LookupIndex(_) => {
                todo!()
            }
            Expr::FieldAccess(_) => {
                todo!()
            }
            Expr::FnCall(_) => {
                todo!()
            }

            Expr::Of(of) => {
                match &mut of.anchor {
                    Some(MatchAnchor::In(anchor_in)) => {
                        todo!()
                    }
                    Some(MatchAnchor::At(anchor_at)) => {
                        todo!()
                    }
                    None => {}
                }
                Ok((Type::Bool, Value::Unknown))
            }

            Expr::ForOf(for_of) => {
                self.quantifier_check_type(src, &mut for_of.quantifier)?;
                check_type!(self, src, Type::Bool, &mut for_of.condition)?;
                Ok((Type::Bool, Value::Unknown))
            }

            Expr::ForIn(for_in) => {
                self.quantifier_check_type(src, &mut for_in.quantifier)?;
                self.iterable_check_type(src, &mut for_in.iterable)?;
                check_type!(self, src, Type::Bool, &mut for_in.condition)?;
                Ok((Type::Bool, Value::Unknown))
            }
        }
    }

    fn quantifier_check_type(
        &self,
        src: &SourceCode,
        quantifier: &mut Quantifier,
    ) -> Result<Type, Error> {
        match quantifier {
            Quantifier::Expr(expr) | Quantifier::Percentage(expr) => {
                todo!()
            }
            _ => {}
        };
        Ok(Type::Integer)
    }

    fn iterable_check_type(
        &self,
        src: &SourceCode,
        iterable: &mut Iterable,
    ) -> Result<Type, Error> {
        match iterable {
            Iterable::Range(range) => {
                todo!()
            }
            Iterable::ExprTuple(tuple) => {
                /*let mut expr_types = vec![];
                for expr in tuple.iter_mut() {
                    let ty = check_type!(self, src, Type::Integer, expr)?;
                    expr_types.push((expr, ty));
                }*/

                todo!()
            }
            Iterable::Ident(_) => {
                todo!()
            }
        }
    }
}
