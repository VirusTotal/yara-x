use crate::ast::*;

/// Events yielded by [`DFSIter`].
#[derive(Debug)]
pub enum DFSEvent<'src> {
    Enter(&'src Expr<'src>),
    Leave(&'src Expr<'src>),
}

/// An iterator that performs a depth-first search traversal of the AST.
///
/// This iterator yields an [`DFSEvent::Enter`] when entering an AST node and a
/// [`DFSEvent::Leave`] when leaving it. For leaf nodes, the `Enter` and `Leave`
/// events are emitted consecutively.
pub struct DFSIter<'src> {
    stack: Vec<DFSEvent<'src>>,
}

impl<'src> DFSIter<'src> {
    /// Creates a new [`DFSIter`] that traverses the tree starting at the
    /// given expression.
    pub fn new(expr: &'src Expr<'src>) -> Self {
        Self { stack: vec![DFSEvent::Enter(expr)] }
    }
}

impl<'src> Iterator for DFSIter<'src> {
    type Item = DFSEvent<'src>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.stack.pop()?;

        if let DFSEvent::Enter(expr) = next {
            self.stack.push(DFSEvent::Leave(expr));
            dfs_common(expr, &mut self.stack);
        }

        Some(next)
    }
}

fn dfs_common<'a>(expr: &'a Expr, stack: &mut Vec<DFSEvent<'a>>) {
    match expr {
        Expr::True { .. }
        | Expr::False { .. }
        | Expr::Filesize { .. }
        | Expr::Entrypoint { .. }
        | Expr::LiteralString(_)
        | Expr::LiteralInteger(_)
        | Expr::LiteralFloat(_)
        | Expr::Regexp(_)
        | Expr::Ident(_)
        | Expr::PatternCount(_)
        | Expr::PatternOffset(_)
        | Expr::PatternLength(_) => {}

        Expr::PatternMatch(expr) => {
            if let Some(anchor) = &expr.anchor {
                match anchor {
                    MatchAnchor::At(at) => {
                        stack.push(DFSEvent::Enter(&at.expr));
                    }
                    MatchAnchor::In(in_expr) => {
                        stack
                            .push(DFSEvent::Enter(&in_expr.range.lower_bound));
                        stack
                            .push(DFSEvent::Enter(&in_expr.range.upper_bound));
                    }
                }
            }
        }

        Expr::Lookup(expr) => {
            stack.push(DFSEvent::Enter(&expr.primary));
            stack.push(DFSEvent::Enter(&expr.index));
        }

        Expr::FieldAccess(expr) => {
            for operand in expr.operands.iter().rev() {
                stack.push(DFSEvent::Enter(operand));
            }
        }

        Expr::FuncCall(expr) => {
            if let Some(obj) = &expr.object {
                stack.push(DFSEvent::Enter(obj));
            }
            for arg in expr.args.iter().rev() {
                stack.push(DFSEvent::Enter(arg));
            }
        }

        Expr::Defined(expr)
        | Expr::Not(expr)
        | Expr::Minus(expr)
        | Expr::BitwiseNot(expr) => {
            stack.push(DFSEvent::Enter(&expr.operand));
        }

        Expr::And(expr) | Expr::Or(expr) => {
            for operand in expr.operands.iter().rev() {
                stack.push(DFSEvent::Enter(operand));
            }
        }

        Expr::Add(expr)
        | Expr::Sub(expr)
        | Expr::Mul(expr)
        | Expr::Div(expr)
        | Expr::Mod(expr) => {
            for operand in expr.operands.iter().rev() {
                stack.push(DFSEvent::Enter(operand));
            }
        }

        Expr::Shl(expr)
        | Expr::Shr(expr)
        | Expr::BitwiseAnd(expr)
        | Expr::BitwiseOr(expr)
        | Expr::BitwiseXor(expr)
        | Expr::Eq(expr)
        | Expr::Ne(expr)
        | Expr::Lt(expr)
        | Expr::Gt(expr)
        | Expr::Le(expr)
        | Expr::Ge(expr)
        | Expr::Contains(expr)
        | Expr::IContains(expr)
        | Expr::StartsWith(expr)
        | Expr::IStartsWith(expr)
        | Expr::EndsWith(expr)
        | Expr::IEndsWith(expr)
        | Expr::IEquals(expr)
        | Expr::Matches(expr) => {
            stack.push(DFSEvent::Enter(&expr.rhs));
            stack.push(DFSEvent::Enter(&expr.lhs));
        }

        Expr::Of(expr) => {
            if let Some(anchor) = &expr.anchor {
                match anchor {
                    MatchAnchor::At(at) => {
                        stack.push(DFSEvent::Enter(&at.expr));
                    }
                    MatchAnchor::In(in_expr) => {
                        stack
                            .push(DFSEvent::Enter(&in_expr.range.upper_bound));
                        stack
                            .push(DFSEvent::Enter(&in_expr.range.lower_bound));
                    }
                }
            }
            if let OfItems::BoolExprTuple(tuple) = &expr.items {
                for item in tuple.iter().rev() {
                    stack.push(DFSEvent::Enter(item));
                }
            }
        }

        Expr::ForOf(expr) => {
            stack.push(DFSEvent::Enter(&expr.body));
        }

        Expr::ForIn(expr) => {
            stack.push(DFSEvent::Enter(&expr.body));
            match &expr.iterable {
                Iterable::Range(range) => {
                    stack.push(DFSEvent::Enter(&range.upper_bound));
                    stack.push(DFSEvent::Enter(&range.lower_bound));
                }
                Iterable::ExprTuple(tuple) => {
                    for item in tuple.iter().rev() {
                        stack.push(DFSEvent::Enter(item));
                    }
                }
                Iterable::Expr(expr) => {
                    stack.push(DFSEvent::Enter(expr));
                }
            }
        }
        Expr::With(expr) => {
            stack.push(DFSEvent::Enter(&expr.body));
            for declaration in expr.declarations.iter().rev() {
                stack.push(DFSEvent::Enter(&declaration.expression));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ast::dfs::{DFSEvent, DFSIter};
    use crate::ast::{Expr, AST};
    use crate::Parser;

    #[test]
    fn dfs() {
        let parser = Parser::new(
            r#"
            rule test {
                condition:
                    (true and false) or (1 + 2 > 5)
            }
            "#
            .as_bytes(),
        );

        let ast = AST::from(parser);
        let mut dfs = DFSIter::new(&ast.rules().next().unwrap().condition);

        // enter: (true and false) or (1 + 2 > 5)
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::Or(_)))));
        // enter: true and false
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::And(_)))));
        // enter: true
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::True { .. }))
        ));
        // leave: true
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::True { .. }))
        ));
        // enter: false
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::False { .. }))
        ));
        // leave: false
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::False { .. }))
        ));
        // leave: true and false
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::And(_)))));
        // enter: 1 + 2 > 5
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::Gt(_)))));
        // enter: 1 + 2
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::Add(_)))));
        // enter: 1
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::LiteralInteger(_)))
        ));
        // leave: 1
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::LiteralInteger(_)))
        ));
        // enter: 2
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::LiteralInteger(_)))
        ));
        // leave: 2
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::LiteralInteger(_)))
        ));
        // leave: 1 + 2
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::Add(_)))));
        // enter: 5
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::LiteralInteger(_)))
        ));
        // leave: 5
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::LiteralInteger(_)))
        ));
        // leave: 1 + 2 > 5
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::Gt(_)))));
        // leave: (true and false) or (1 + 2 > 5)
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::Or(_)))));

        assert!(dfs.next().is_none());
    }
}
