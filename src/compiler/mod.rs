/*! Compiles YARA source code into binary form.

YARA rules must be compiled before they can be used for scanning data. This
module implements the YARA compiler.
*/

#[doc(inline)]
pub use crate::compiler::errors::*;

use crate::parser::Error as ParserError;
use crate::parser::{
    Expr, HasSpan, Iterable, MatchAnchor, Parser, Quantifier, SourceCode, Span,
};
use crate::report::ReportBuilder;
use crate::ValueType;

mod errors;

/// A YARA compiler.
pub struct Compiler {
    colorize_errors: bool,
    report_builder: ReportBuilder,
}

impl Compiler {
    /// Creates a new YARA compiler.
    pub fn new() -> Self {
        Self { colorize_errors: false, report_builder: ReportBuilder::new() }
    }

    /// Specifies whether the compiler should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn colorize_errors(self, b: bool) -> Self {
        Self { colorize_errors: b, report_builder: self.report_builder }
    }

    /// Adds a YARA source code to be compiled.
    ///
    /// This function can be called multiple times.
    pub fn add(&self, src: &str) -> Result<(), Error> {
        let ast = Parser::new()
            .colorize_errors(self.colorize_errors)
            .set_report_builder(&self.report_builder)
            .build_ast(src, None)?;

        let src = SourceCode { text: src, origin: None };

        for ns in ast.namespaces.values() {
            for rule in ns.rules.values() {
                self.expr_semantic_check(&src, &rule.condition)?;
            }
        }

        todo!()
    }
}

macro_rules! check_type {
    ($self:ident, $src:ident, $( $pattern:path )|+, $expr:expr) => {
        {
            use crate::compiler::errors::Error;
            let ty = $self.expr_semantic_check($src, $expr)?;
            if !matches!(ty, $( $pattern )|+) {
                return Err(Error::CompileError(CompileError::wrong_type(
                    &$self.report_builder,
                    $src,
                    ParserError::join_with_or(&[ $( $pattern.to_string() ),+ ], true),
                    ty.to_string(),
                    $expr.span(),
                )));
            }
            Ok::<ValueType, Error>(ty)
        }
    };
}

/// Ensures that the type of one or more expressions is one of from a set of
/// accepted types. If there are more than one expressions also makes sure that
/// all of them have compatible types.
///
/// `expr` must be some identifier of type [`Expr`], and the last argument is
/// a sequence of one or more values of `ExprKind` separated by pipes.
///
/// # Examples
///
/// ```ignore
/// // Check a single expression, the expression should be of type bool.
/// check_types!(report_builder, src, ExprKind::Bool, expr);
///
/// // Check multiple expressions, they can be of type integer or float,
/// // and both must have the same type.
/// check_types!(report_builder, src, ExprKind::Integer|ExprKind::Float, expr1, expr2);
/// ```
macro_rules! check_types {
    ($self:ident, $src:ident, $( $pattern:path )|+, $( $expr:expr),+ ) => {
        {
            let mut prev_ty: Option<(ValueType, Span)> = None;
            for expression in [ $( $expr ),+ ] {
                let ty = check_type!($self, $src, $( $pattern )|+, expression)?;
                // The expression type is among the specified ones, let's see
                // if it matches with the previous expression.
                if let Some((prev_ty, prev_ty_span)) = prev_ty {
                    let mismatching_types = match ty {
                        // Float and Integer are compatible types, operators can
                        // have different operand types where one is Integer and
                        // the other is Float.
                        ValueType::Integer | ValueType::Float => {
                            !matches!(prev_ty, ValueType::Integer | ValueType::Float)
                        }
                        // In all other cases types must be equal to be considered
                        // compatible.
                        _ => ty != prev_ty,
                    };
                    if mismatching_types {
                        return Err(Error::CompileError(CompileError::mismatching_types(
                            &$self.report_builder,
                            $src,
                            prev_ty.to_string(),
                            ty.to_string(),
                            prev_ty_span,
                            expression.span(),
                        )));
                    }
                }
                prev_ty = Some((ty, expression.span()));
            }
        }
    };
}

impl Compiler {
    pub(crate) fn expr_semantic_check(
        &self,
        src: &SourceCode,
        expr: &Expr,
    ) -> Result<ValueType, Error> {
        match expr {
            Expr::True { .. } | Expr::False { .. } => Ok(ValueType::Bool),

            Expr::PatternMatch(p) => {
                match &p.anchor {
                    Some(MatchAnchor::In(anchor_in)) => {
                        check_types!(
                            self,
                            src,
                            ValueType::Integer,
                            &anchor_in.range.lower_bound,
                            &anchor_in.range.upper_bound
                        );
                    }
                    Some(MatchAnchor::At(anchor_at)) => {
                        check_type!(
                            self,
                            src,
                            ValueType::Integer,
                            &anchor_at.expr
                        )?;
                    }
                    None => {}
                }
                Ok(ValueType::Bool)
            }
            Expr::LiteralInt(_)
            | Expr::Filesize { .. }
            | Expr::Entrypoint { .. }
            | Expr::PatternCount(_)
            | Expr::PatternOffset(_)
            | Expr::PatternLength(_) => Ok(ValueType::Integer),

            Expr::LiteralFlt(_) => Ok(ValueType::Float),
            Expr::LiteralStr(_) => Ok(ValueType::String),

            Expr::Not(expr) => {
                check_type!(self, src, ValueType::Bool, &expr.operand)?;
                Ok(ValueType::Bool)
            }

            Expr::And(expr) | Expr::Or(expr) => {
                check_types!(self, src, ValueType::Bool, &expr.lhs, &expr.rhs);
                Ok(ValueType::Bool)
            }

            Expr::Eq(expr)
            | Expr::Neq(expr)
            | Expr::Lt(expr)
            | Expr::Le(expr)
            | Expr::Gt(expr)
            | Expr::Ge(expr) => {
                check_types!(
                    self,
                    src,
                    ValueType::Integer | ValueType::Float | ValueType::String,
                    &expr.lhs,
                    &expr.rhs
                );
                Ok(ValueType::Bool)
            }

            Expr::BitwiseNot(expr) => {
                check_type!(self, src, ValueType::Integer, &expr.operand)?;
                Ok(ValueType::Integer)
            }

            Expr::Modulus(expr)
            | Expr::Shr(expr)
            | Expr::Shl(expr)
            | Expr::BitwiseAnd(expr)
            | Expr::BitwiseOr(expr)
            | Expr::BitwiseXor(expr) => {
                check_types!(
                    self,
                    src,
                    ValueType::Integer,
                    &expr.lhs,
                    &expr.rhs
                );
                Ok(ValueType::Integer)
            }

            // The minus expression returns the type of its operand, it
            // could be ExprType::Integer or ExprType::Float.
            Expr::Minus(expr) => check_type!(
                self,
                src,
                ValueType::Integer | ValueType::Float,
                &expr.operand
            ),

            // Arithmetic operations return an integer if both operands are
            // integers. If any of the operands is a float the result is
            // also a float.
            Expr::Add(expr)
            | Expr::Sub(expr)
            | Expr::Div(expr)
            | Expr::Mul(expr) => {
                let lhs_ty = check_type!(
                    self,
                    src,
                    ValueType::Integer | ValueType::Float,
                    &expr.lhs
                )?;
                let rhs_ty = check_type!(
                    self,
                    src,
                    ValueType::Integer | ValueType::Float,
                    &expr.rhs
                )?;
                match (lhs_ty, rhs_ty) {
                    // If both operands are integers the result of the
                    // operation is also integer.
                    (ValueType::Integer, ValueType::Integer) => {
                        Ok(ValueType::Integer)
                    }
                    // If one of the operands is float the result is float.
                    _ => Ok(ValueType::Float),
                }
            }

            Expr::Contains(expr)
            | Expr::IContains(expr)
            | Expr::StartsWith(expr)
            | Expr::IStartsWith(expr)
            | Expr::EndsWith(expr)
            | Expr::IEndsWith(expr)
            | Expr::IEquals(expr) => {
                check_types!(
                    self,
                    src,
                    ValueType::String,
                    &expr.lhs,
                    &expr.rhs
                );
                Ok(ValueType::Bool)
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
                match &of.anchor {
                    Some(MatchAnchor::In(anchor_in)) => {
                        check_types!(
                            self,
                            src,
                            ValueType::Integer,
                            &anchor_in.range.lower_bound,
                            &anchor_in.range.upper_bound
                        );
                    }
                    Some(MatchAnchor::At(anchor_at)) => {
                        check_types!(
                            self,
                            src,
                            ValueType::Integer,
                            &anchor_at.expr
                        );
                    }
                    None => {}
                }
                Ok(ValueType::Bool)
            }

            Expr::ForOf(for_of) => {
                self.quantifier_check_type(src, &for_of.quantifier)?;
                check_type!(self, src, ValueType::Bool, &for_of.condition)?;
                Ok(ValueType::Bool)
            }

            Expr::ForIn(for_in) => {
                self.quantifier_check_type(src, &for_in.quantifier)?;
                self.iterable_check_type(src, &for_in.iterable)?;
                check_type!(self, src, ValueType::Bool, &for_in.condition)?;

                Ok(ValueType::Bool)
            }
        }
    }

    fn quantifier_check_type(
        &self,
        src: &SourceCode,
        quantifier: &Quantifier,
    ) -> Result<ValueType, Error> {
        match quantifier {
            Quantifier::Expr(expr) | Quantifier::Percentage(expr) => {
                check_types!(self, src, ValueType::Integer, expr);
            }
            _ => {}
        };
        Ok(ValueType::Integer)
    }

    fn iterable_check_type(
        &self,
        src: &SourceCode,
        iterable: &Iterable,
    ) -> Result<ValueType, Error> {
        match iterable {
            Iterable::Range(range) => {
                check_types!(
                    self,
                    src,
                    ValueType::Integer,
                    &range.upper_bound,
                    &range.lower_bound
                );
                Ok(ValueType::Integer)
            }
            Iterable::ExprTuple(tuple) => {
                let mut expr_types = vec![];
                for expr in tuple {
                    expr_types.push((
                        expr,
                        check_type!(self, src, ValueType::Integer, &expr)?,
                    ));
                }

                todo!()
            }
            Iterable::Ident(_) => {
                todo!()
            }
        }
    }
}
