use crate::ast::*;

/// Events yielded by [`DFSIter`].
#[derive(Debug)]
pub enum DFSEvent<T> {
    Enter(T),
    Leave(T),
}

/// Describes the context in which an expression is being visited during a
/// depth-first search traversal of the AST.
///
/// The context provides information about the relationship between the
/// expression being visited and its parent.
pub enum DFSContext<'src> {
    /// The visited expression is the one that was used for starting the
    /// traversal.
    Root,
    /// The visited expression is the body of a `for`, or `with` expression.
    /// The associated [`Expr`] is the `for` or `with` expression itself.
    Body(&'src Expr<'src>),
    /// The visited expression is the quantifier of a `for` or `of` expression.
    /// The associated [`Expr`] is the `for` or `of` expression itself.
    Quantifier(&'src Expr<'src>),
    /// The visited expression is an operand of a unary or binary expression.
    /// The associated [`Expr`] is the unary or binary expression itself.
    Operand(&'src Expr<'src>),
    /// The visited expression is part of the declarations in a `with`
    /// statement.
    WithDeclaration(&'src Expr<'src>),
    /// The visited expression is the lower or upper bound of a range.
    /// The associated [`Expr`] is the expression that contains the range.
    /// For example, in `#a in (0..10)`, the expressions `0` and `10` are
    /// visited with this context.
    Range(&'src Expr<'src>),
    /// The visited expression is an anchor that specifies where a pattern
    /// should be found. The associated [`Expr`] is the expression that
    /// contains the anchor. For example, in `$a at 10`, the expression `10`
    /// is visited with this context.
    Anchor(&'src Expr<'src>),
    /// The visited expression is one of the items in a `for..in` or `of`
    /// expression. The associated [`Expr`] is the `for..in` or `of`
    /// expression itself.
    Items(&'src Expr<'src>),
    /// The visited expression is being used as an index. The associated
    /// [`Expr`] is the expression that contains the index. For example, in
    /// `@a[i]`, the expression `i` is visited with this context.
    Index(&'src Expr<'src>),
    /// The visited expression is an argument in a function call. The
    /// associated [`Expr`] is the [`Expr::FuncCall`] itself.
    FuncArg(&'src Expr<'src>),
    /// The visited expression is the object on which a method is being
    /// called. The associated [`Expr`] is the [`Expr::FuncCall`] itself.
    FuncSelf(&'src Expr<'src>),
}

/// An iterator that performs a depth-first search traversal of the AST.
///
/// This iterator yields an [`DFSEvent::Enter`] when entering an AST node and a
/// [`DFSEvent::Leave`] when leaving it. For leaf nodes, the `Enter` and `Leave`
/// events are emitted consecutively.
pub struct DFSIter<'src> {
    stack: Vec<DFSEvent<(&'src Expr<'src>, DFSContext<'src>)>>,
}

impl<'src> DFSIter<'src> {
    /// Creates a new [`DFSIter`] that traverses the tree starting at the
    /// given expression.
    pub fn new(expr: &'src Expr<'src>) -> Self {
        Self { stack: vec![DFSEvent::Enter((expr, DFSContext::Root))] }
    }

    /// Returns an iterator that yields the contexts corresponding to the
    /// expressions currently being visited.
    ///
    /// When traversing an expression tree, this method returns an iterator
    /// that walks the stack of expressions being visited, from the expression
    /// currently being visited to the root of the traversal, and provides
    /// the context in which each of them is being visited.
    ///
    /// The returned iterator yields [`DFSContext`] items. The first item is
    /// the context of the expression that is currently being visited, and the
    /// last one is always [`DFSContext::Root`].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use yara_x_parser::Parser;
    /// # use yara_x_parser::ast::{AST, DFSIter, DFSEvent, DFSContext, Expr};
    /// let mut parser = Parser::new(r#"
    /// rule test {
    ///   condition:
    ///     (1 + 2) > 3
    /// }
    /// "#.as_bytes());
    ///
    /// let ast = AST::from(parser);
    /// let mut iter = DFSIter::new(&ast.rules().next().unwrap().condition);
    ///
    /// // iter enters `(1 + 2) > 3`
    /// iter.next();
    /// // iter enters `1 + 2`
    /// iter.next();
    /// // iter enters `1`
    /// iter.next();
    ///
    /// // The iterator is currently in at `1` expression, let's iterate
    /// // the contexts...
    /// let mut contexts = iter.contexts();
    ///
    /// // The first context indicates that `1` is an operand of the `Add`
    /// // expression.
    /// assert!(matches!(
    ///     contexts.next(),
    ///     Some(DFSContext::Operand(Expr::Add(_)))
    /// ));
    ///
    /// // The second context indicates that the `Add` expression is an operand
    /// // of the `Gt` expression.
    /// assert!(matches!(
    ///     contexts.next(),
    ///     Some(DFSContext::Operand(Expr::Gt(_)))
    /// ));
    ///
    /// // The last context indicates that the `Gt` expression is the root one.
    /// assert!(matches!(
    ///     contexts.next(),
    ///     Some(DFSContext::Root)
    /// ));
    ///
    /// assert!(contexts.next().is_none());
    /// ```
    pub fn contexts(&self) -> impl Iterator<Item = &DFSContext<'src>> {
        self.stack.iter().rev().filter_map(|event| match event {
            DFSEvent::Enter(_) => None,
            DFSEvent::Leave((_, ctx)) => Some(ctx),
        })
    }
}

impl<'src> Iterator for DFSIter<'src> {
    type Item = DFSEvent<&'src Expr<'src>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stack.pop()? {
            DFSEvent::Enter((expr, context)) => {
                self.stack.push(DFSEvent::Leave((expr, context)));
                dfs_enter(expr, &mut self.stack);
                Some(DFSEvent::Enter(expr))
            }
            DFSEvent::Leave((expr, _)) => Some(DFSEvent::Leave(expr)),
        }
    }
}

fn dfs_enter<'a>(
    expr: &'a Expr,
    stack: &mut Vec<DFSEvent<(&'a Expr<'a>, DFSContext<'a>)>>,
) {
    match expr {
        Expr::True { .. }
        | Expr::False { .. }
        | Expr::Filesize { .. }
        | Expr::Entrypoint { .. }
        | Expr::LiteralString(_)
        | Expr::LiteralInteger(_)
        | Expr::LiteralFloat(_)
        | Expr::Regexp(_)
        | Expr::Ident(_) => {}

        Expr::PatternCount(p) => {
            if let Some(r) = &p.range {
                stack.push(DFSEvent::Enter((
                    &r.upper_bound,
                    DFSContext::Range(expr),
                )));
                stack.push(DFSEvent::Enter((
                    &r.lower_bound,
                    DFSContext::Range(expr),
                )));
            }
        }

        Expr::PatternOffset(p) | Expr::PatternLength(p) => {
            if let Some(index) = &p.index {
                stack.push(DFSEvent::Enter((index, DFSContext::Index(expr))));
            }
        }

        Expr::PatternMatch(m) => {
            if let Some(anchor) = &m.anchor {
                match anchor {
                    MatchAnchor::At(at) => {
                        stack.push(DFSEvent::Enter((
                            &at.expr,
                            DFSContext::Anchor(expr),
                        )));
                    }
                    MatchAnchor::In(in_expr) => {
                        stack.push(DFSEvent::Enter((
                            &in_expr.range.upper_bound,
                            DFSContext::Anchor(expr),
                        )));
                        stack.push(DFSEvent::Enter((
                            &in_expr.range.lower_bound,
                            DFSContext::Anchor(expr),
                        )));
                    }
                }
            }
        }

        Expr::Lookup(lookup) => {
            stack.push(DFSEvent::Enter((
                &lookup.index,
                DFSContext::Index(expr),
            )));
            stack.push(DFSEvent::Enter((
                &lookup.primary,
                DFSContext::Operand(expr),
            )));
        }

        Expr::FieldAccess(e) => {
            for operand in e.operands.iter().rev() {
                stack.push(DFSEvent::Enter((
                    operand,
                    DFSContext::Operand(expr),
                )));
            }
        }

        Expr::FuncCall(func) => {
            for arg in func.args.iter().rev() {
                stack.push(DFSEvent::Enter((arg, DFSContext::FuncArg(expr))));
            }
            if let Some(obj) = &func.object {
                stack.push(DFSEvent::Enter((obj, DFSContext::FuncSelf(expr))));
            }
        }

        Expr::Defined(e)
        | Expr::Not(e)
        | Expr::Minus(e)
        | Expr::BitwiseNot(e) => {
            stack.push(DFSEvent::Enter((
                &e.operand,
                DFSContext::Operand(expr),
            )));
        }

        Expr::And(e) | Expr::Or(e) => {
            for operand in e.operands.iter().rev() {
                stack.push(DFSEvent::Enter((
                    operand,
                    DFSContext::Operand(expr),
                )));
            }
        }

        Expr::Add(e)
        | Expr::Sub(e)
        | Expr::Mul(e)
        | Expr::Div(e)
        | Expr::Mod(e) => {
            for operand in e.operands.iter().rev() {
                stack.push(DFSEvent::Enter((
                    operand,
                    DFSContext::Operand(expr),
                )));
            }
        }

        Expr::Shl(e)
        | Expr::Shr(e)
        | Expr::BitwiseAnd(e)
        | Expr::BitwiseOr(e)
        | Expr::BitwiseXor(e)
        | Expr::Eq(e)
        | Expr::Ne(e)
        | Expr::Lt(e)
        | Expr::Gt(e)
        | Expr::Le(e)
        | Expr::Ge(e)
        | Expr::Contains(e)
        | Expr::IContains(e)
        | Expr::StartsWith(e)
        | Expr::IStartsWith(e)
        | Expr::EndsWith(e)
        | Expr::IEndsWith(e)
        | Expr::IEquals(e)
        | Expr::Matches(e) => {
            stack.push(DFSEvent::Enter((&e.rhs, DFSContext::Operand(expr))));
            stack.push(DFSEvent::Enter((&e.lhs, DFSContext::Operand(expr))));
        }

        Expr::Of(of) => {
            if let Some(anchor) = &of.anchor {
                match anchor {
                    MatchAnchor::At(at) => {
                        stack.push(DFSEvent::Enter((
                            &at.expr,
                            DFSContext::Anchor(expr),
                        )));
                    }
                    MatchAnchor::In(in_expr) => {
                        stack.push(DFSEvent::Enter((
                            &in_expr.range.upper_bound,
                            DFSContext::Anchor(expr),
                        )));
                        stack.push(DFSEvent::Enter((
                            &in_expr.range.lower_bound,
                            DFSContext::Anchor(expr),
                        )));
                    }
                }
            }
            if let OfItems::BoolExprTuple(tuple) = &of.items {
                for item in tuple.iter().rev() {
                    stack.push(DFSEvent::Enter((
                        item,
                        DFSContext::Items(expr),
                    )));
                }
            }
            match &of.quantifier {
                Quantifier::Percentage(quantifier)
                | Quantifier::Expr(quantifier) => {
                    stack.push(DFSEvent::Enter((
                        quantifier,
                        DFSContext::Quantifier(expr),
                    )));
                }
                _ => {}
            }
        }

        Expr::ForOf(for_of) => {
            stack
                .push(DFSEvent::Enter((&for_of.body, DFSContext::Body(expr))));
            match &for_of.quantifier {
                Quantifier::Percentage(quantifier)
                | Quantifier::Expr(quantifier) => {
                    stack.push(DFSEvent::Enter((
                        quantifier,
                        DFSContext::Quantifier(expr),
                    )));
                }
                _ => {}
            }
        }

        Expr::ForIn(for_in) => {
            stack
                .push(DFSEvent::Enter((&for_in.body, DFSContext::Body(expr))));
            match &for_in.iterable {
                Iterable::Range(range) => {
                    stack.push(DFSEvent::Enter((
                        &range.upper_bound,
                        DFSContext::Items(expr),
                    )));
                    stack.push(DFSEvent::Enter((
                        &range.lower_bound,
                        DFSContext::Items(expr),
                    )));
                }
                Iterable::ExprTuple(tuple) => {
                    for item in tuple.iter().rev() {
                        stack.push(DFSEvent::Enter((
                            item,
                            DFSContext::Items(expr),
                        )));
                    }
                }
                Iterable::Expr(iterable_expr) => {
                    stack.push(DFSEvent::Enter((
                        iterable_expr,
                        DFSContext::Items(expr),
                    )));
                }
            }
            match &for_in.quantifier {
                Quantifier::Percentage(quantifier)
                | Quantifier::Expr(quantifier) => {
                    stack.push(DFSEvent::Enter((
                        quantifier,
                        DFSContext::Quantifier(expr),
                    )));
                }
                _ => {}
            }
        }
        Expr::With(with) => {
            stack.push(DFSEvent::Enter((&with.body, DFSContext::Body(expr))));
            for declaration in with.declarations.iter().rev() {
                stack.push(DFSEvent::Enter((
                    &declaration.expression,
                    DFSContext::WithDeclaration(expr),
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ast::dfs::{DFSContext, DFSEvent, DFSIter};
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

    #[test]
    fn dfs_contexts() {
        let parser = Parser::new(
            r#"
            rule test {
                strings:
                    $a = "foo"
                condition:
                    for 1 of ($a) : (
                        with i = 1 : (
                            i == 1
                        )
                    )
            }
            "#
            .as_bytes(),
        );

        let ast = AST::from(parser);
        let mut dfs = DFSIter::new(&ast.rules().next().unwrap().condition);
        assert!(dfs.contexts().next().is_none());

        // enter `for 1 of ($a) : (...)`
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::ForOf(_)))));

        let mut contexts = dfs.contexts();
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(matches!(contexts.next(), None));
        drop(contexts);

        // enter `1`
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::LiteralInteger(_)))
        ));

        let mut contexts = dfs.contexts();
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Quantifier(Expr::ForOf(_)))
        ));
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(matches!(contexts.next(), None));
        drop(contexts);

        // leave `1`
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::LiteralInteger(_)))
        ));

        let mut contexts = dfs.contexts();
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(matches!(contexts.next(), None));
        drop(contexts);

        // enter `with i = 1 : ( i == 1 )`
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::With(_)))));

        let mut contexts = dfs.contexts();
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Body(Expr::ForOf(_)))
        ));
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(matches!(contexts.next(), None));
        drop(contexts);

        // enter `1`
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::LiteralInteger(_)))
        ));
        // leave `1`
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::LiteralInteger(_)))
        ));

        // enter `i == 1`
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::Eq(_)))));

        let mut contexts = dfs.contexts();
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Body(Expr::With(_)))
        ));
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Body(Expr::ForOf(_)))
        ));
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(matches!(contexts.next(), None));
        drop(contexts);

        // enter `i`
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::Ident(_)))));

        let mut contexts = dfs.contexts();
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Operand(Expr::Eq(_)))
        ));
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Body(Expr::With(_)))
        ));
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Body(Expr::ForOf(_)))
        ));
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(matches!(contexts.next(), None));
        drop(contexts);

        // leave `i`
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::Ident(_)))));

        // enter `1`
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Enter(Expr::LiteralInteger(_)))
        ));
        // leave `1`
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::LiteralInteger(_)))
        ));

        // leave `i == 1`
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::Eq(_)))));
        // leave `with i = 1 : ( i == 1 )`
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::With(_)))));
        // leave `for 1 of ($a) : (...)`
        assert!(matches!(dfs.next(), Some(DFSEvent::Leave(Expr::ForOf(_)))));

        assert!(dfs.next().is_none());
    }
}
