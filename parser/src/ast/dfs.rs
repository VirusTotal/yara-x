//! A module for traversing an expression's AST using a depth-first search
//! (DFS) algorithm.
//!
//! This module provides [`DFSIter`], an iterator that walks an expression's
//! Abstract Syntax Tree (AST) and emits [`DFSEvent`]s for each node in the
//! tree. There are two types of events: `Enter` and `Leave`. An `Enter` event
//! is emitted when a node is visited for the first time, before visiting its
//! children. A `Leave` event is emitted after all the node's children have
//! been visited.
//!
//! For each visited node, the iterator also provides a [`DFSContext`] that
//! describes the relationship between the visited node and its parent.
//!
//! # Example
//!
//! The following example shows how to use [`DFSIter`] to collect all the
//! pattern identifiers used in a YARA rule's condition.
//!
//! ```rust
//! use yara_x_parser::Parser;
//! use yara_x_parser::ast::*;
//! use yara_x_parser::ast::dfs::{DFSIter, DFSEvent};
//!
//! // Parse a YARA rule from a string.
//! let mut rules = r#"
//! rule test {
//!   strings:
//!     $a = "some string"
//!     $b = "another string"
//!   condition:
//!     ($a at 100) and $b
//! }
//! "#;
//!
//! // The AST object is the root of the AST.
//! let ast = AST::from(rules);
//!
//! // Get the condition of the first rule.
//! let condition = &ast.rules().next().unwrap().condition;
//!
//! // Create a new iterator that will traverse the condition's AST.
//! let mut iter = DFSIter::new(condition);
//!
//! // A vector that will store the identifiers found in the condition.
//! let mut identifiers = Vec::new();
//!
//! // Iterate over the events produced by the iterator.
//! while let Some(event) = iter.next() {
//!     if let DFSEvent::Enter(expr) = event {
//!         if let Expr::PatternMatch(pattern_match) = expr {
//!             identifiers.push(pattern_match.identifier.name);
//!         }
//!     }
//! }
//!
//! assert_eq!(identifiers, vec!["$a", "$b"]);
//! ```
//!
//! The example below does the same as the one above, but it also demonstrates
//! how to use [`DFSIter::prune`] for preventing the iterator from visiting
//! certain nodes. In this case we are not interested in the expression used
//! in the `at` operator, so we prune the traversal after finding a
//! `PatternMatch` expression with an `at` anchor.
//!
//! ```rust
//! # use yara_x_parser::Parser;
//! # use yara_x_parser::ast::*;
//! # use yara_x_parser::ast::dfs::{DFSIter, DFSEvent};
//! #
//! # let rules = r#"
//! # rule test {
//! #   strings:
//! #     $a = "some string"
//! #     $b = "another string"
//! #   condition:
//! #     ($a at 100) and $b
//! # }
//! # "#;
//! #
//! # let ast = AST::from(rules);
//! # let condition = &ast.rules().next().unwrap().condition;
//! #
//! let mut iter = DFSIter::new(condition);
//! let mut identifiers = Vec::new();
//!
//! while let Some(event) = iter.next() {
//!     if let DFSEvent::Enter(expr) = event {
//!         match expr {
//!             Expr::PatternMatch(pattern_match) => {
//!                 identifiers.push(pattern_match.identifier.name);
//!                 // The `at` anchor has an expression that we are not interested
//!                 // in, so we can prune the traversal to avoid visiting it.
//!                 if pattern_match.anchor.is_some() {
//!                     iter.prune();
//!                 }
//!             }
//!             // We are only interested in `PatternMatch` expressions, for any
//!             // other expression we do nothing. The iterator will continue
//!             // the traversal normally.
//!             _ => {}
//!         }
//!     }
//! }
//!
//! assert_eq!(identifiers, vec!["$a", "$b"]);
//! ```
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
    recently_left_context: Option<DFSContext<'src>>,
}

impl<'src> DFSIter<'src> {
    /// Creates a new [`DFSIter`] that traverses the tree starting at the
    /// given expression.
    pub fn new(expr: &'src Expr<'src>) -> Self {
        Self {
            stack: vec![DFSEvent::Enter((expr, DFSContext::Root))],
            recently_left_context: None,
        }
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
    /// # use yara_x_parser::ast::{AST, Expr};
    /// # use yara_x_parser::ast::dfs::{DFSIter, DFSEvent, DFSContext};
    /// let rules = r#"
    /// rule test {
    ///   condition:
    ///     (1 + 2) > 3
    /// }
    /// "#;
    ///
    /// let ast = AST::from(rules);
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
    pub fn contexts(
        &self,
    ) -> impl DoubleEndedIterator<Item = &DFSContext<'src>> {
        itertools::chain(
            self.recently_left_context.iter(),
            self.stack.iter().rev().filter_map(|event| match event {
                DFSEvent::Enter(_) => None,
                DFSEvent::Leave((_, ctx)) => Some(ctx),
            }),
        )
    }

    /// Prunes the search tree, preventing the traversal from visiting the
    /// children of the current node.
    ///
    /// The effect of this function depends on the current position in the tree
    /// For example, if `prune` is called immediately after an [`DFSEvent::Enter`],
    /// the current node is the one that was just entered. In this scenario,
    /// pruning ensures that none of this node's children are visited, and the
    /// next event will be the corresponding [`DFSEvent::Leave`] for the node
    /// that was entered.
    ///
    /// Conversely, if `prune` is called right after an [`DFSEvent::Leave`], the
    /// current node is the parent of the node that was just left. In this
    /// case, pruning prevents any remaining children of the current node
    /// (i.e., the siblings of the node that was just left) from being visited.
    /// The next event will then be the [`DFSEvent::Leave`] for the parent of
    /// the node that was exited.
    pub fn prune(&mut self) {
        // Remove all DFSEvent::Enter from the stack until finding a
        // DFSEvent::Leave.
        while let Some(DFSEvent::Enter(_)) = self.stack.last() {
            self.stack.pop();
        }
    }
}

impl<'src> Iterator for DFSIter<'src> {
    type Item = DFSEvent<&'src Expr<'src>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stack.pop()? {
            DFSEvent::Enter((expr, context)) => {
                self.recently_left_context = None;
                self.stack.push(DFSEvent::Leave((expr, context)));
                dfs_enter(expr, &mut self.stack);
                Some(DFSEvent::Enter(expr))
            }
            DFSEvent::Leave((expr, context)) => {
                self.recently_left_context = Some(context);
                Some(DFSEvent::Leave(expr))
            }
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

    #[test]
    fn dfs() {
        let source = br#"
            rule test {
                condition:
                    (true and false) or (1 + 2 > 5)
            }
            "#;

        let ast = AST::from(source.as_slice());
        let mut dfs = DFSIter::new(&ast.rules().next().unwrap().condition);

        // enter: (true and false) or (1 + 2 > 5)
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::Or(_)))));
        // enter: true and false
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::And(_)))));

        // Prune the tree, children of the current node won't be visited.
        dfs.prune();

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

        // Prune the tree. Siblings of 1 won't be traversed.
        dfs.prune();

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
        let source = r#"
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
            "#;

        let ast = AST::from(source);
        let mut dfs = DFSIter::new(&ast.rules().next().unwrap().condition);
        assert!(dfs.contexts().next().is_none());

        // enter `for 1 of ($a) : (...)`
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::ForOf(_)))));

        let mut contexts = dfs.contexts();
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(contexts.next().is_none());
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
        assert!(contexts.next().is_none());
        drop(contexts);

        // leave `1`
        assert!(matches!(
            dfs.next(),
            Some(DFSEvent::Leave(Expr::LiteralInteger(_)))
        ));

        let mut contexts = dfs.contexts();
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Quantifier(Expr::ForOf(_)))
        ));
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(contexts.next().is_none());
        drop(contexts);

        // enter `with i = 1 : ( i == 1 )`
        assert!(matches!(dfs.next(), Some(DFSEvent::Enter(Expr::With(_)))));

        let mut contexts = dfs.contexts();
        assert!(matches!(
            contexts.next(),
            Some(DFSContext::Body(Expr::ForOf(_)))
        ));
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(contexts.next().is_none());
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
        assert!(contexts.next().is_none());
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
        assert!(contexts.next().is_none());
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

        let mut contexts = dfs.contexts();
        assert!(matches!(contexts.next(), Some(DFSContext::Root)));
        assert!(contexts.next().is_none());
    }
}
