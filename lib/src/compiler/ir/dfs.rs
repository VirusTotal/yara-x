use crate::compiler::ir::{Expr, ExprId, Iterable, MatchAnchor, Quantifier};

/// Events yielded by [`DFSIter`].
pub(crate) enum Event<T> {
    Enter(T),
    Leave(T),
}

/// An iterator that conducts a Depth First Search (DFS) traversal of the IR
/// tree.
///
/// This iterator yields [`Event::Enter`] when entering an IR node, and
/// [`Event::Leave`] upon exiting an IR node. For example, given the following
/// tree structure:
///
/// ```text
///       a
///      / \
///     b   c
///        / \
///       d   e
/// ```
///
/// The sequence of events would be:
///
/// ```text
/// Enter(a)
/// Enter(b)
/// Leave(b)
/// Enter(c)
/// Enter(d)
/// Leave(d)
/// Enter(e)
/// Leave(e)
/// Leave(c)
/// Leave(a)
/// ```
///
pub(crate) struct DFSIter<'a> {
    nodes: &'a [Expr],
    stack: Vec<Event<ExprId>>,
}

impl<'a> DFSIter<'a> {
    /// Creates a new [`DFSIter`] that traverses the tree starting at a given
    /// node.
    pub fn new(start: ExprId, nodes: &'a [Expr]) -> Self {
        Self { nodes, stack: vec![Event::Enter(start)] }
    }

    /// Prunes the search tree, preventing the traversal from visiting the
    /// children of the current node.
    ///
    /// The effect of this function depends on the current position in the tree
    /// For example, if `prune` is called immediately after an [`Event::Enter`],
    /// the current node is the one that was just entered. In this scenario,
    /// pruning ensures that none of this node's children are visited, and the
    /// next event will be the corresponding [`Event::Leave`] for the node that
    /// was entered.
    ///
    /// Conversely, if `prune` is called right after an [`Event::Leave`], the
    /// current node is the parent of the node that was just left. In this
    /// case, pruning prevents any remaining children of the current node
    /// (i.e., the siblings of the node that was just left) from being visited.
    /// The next event will then be the [`Event::Leave`] for the parent of the
    /// node that was exited.
    pub fn prune(&mut self) {
        // Remove all Event::Enter from the stack until finding an Event::Leave.
        while let Some(Event::Enter(_)) = self.stack.last() {
            self.stack.pop();
        }
    }
}

impl<'a> Iterator for DFSIter<'a> {
    type Item = Event<(ExprId, &'a Expr)>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.stack.pop()?;

        if let Event::Enter(expr) = next {
            self.stack.push(Event::Leave(expr));
            dfs_common(&self.nodes[expr], &mut self.stack);
        }

        let next = match next {
            Event::Enter(expr) => Event::Enter((expr, &self.nodes[expr])),
            Event::Leave(expr) => Event::Leave((expr, &self.nodes[expr])),
        };

        Some(next)
    }
}

pub(super) fn dfs_common(expr: &Expr, stack: &mut Vec<Event<ExprId>>) {
    let push_quantifier =
        |quantifier: &Quantifier, stack: &mut Vec<_>| match quantifier {
            Quantifier::None => {}
            Quantifier::All => {}
            Quantifier::Any => {}
            Quantifier::Percentage(_) => {}
            Quantifier::Expr(expr) => stack.push(Event::Enter(*expr)),
        };

    let push_anchor = |anchor: &MatchAnchor, stack: &mut Vec<_>| match anchor {
        MatchAnchor::None => {}
        MatchAnchor::At(expr) => {
            stack.push(Event::Enter(*expr));
        }
        MatchAnchor::In(range) => {
            stack.push(Event::Enter(range.upper_bound));
            stack.push(Event::Enter(range.lower_bound));
        }
    };

    match expr {
        Expr::Const(_) => {}
        Expr::Filesize => {}
        Expr::Symbol(_) => {}

        Expr::Not { operand }
        | Expr::Defined { operand }
        | Expr::Minus { operand, .. }
        | Expr::BitwiseNot { operand } => {
            stack.push(Event::Enter(*operand));
        }

        Expr::And { operands }
        | Expr::Or { operands }
        | Expr::Add { operands, .. }
        | Expr::Sub { operands, .. }
        | Expr::Mul { operands, .. }
        | Expr::Div { operands, .. }
        | Expr::Mod { operands, .. } => {
            for operand in operands.iter().rev() {
                stack.push(Event::Enter(*operand))
            }
        }

        Expr::Eq { lhs, rhs }
        | Expr::Ne { lhs, rhs }
        | Expr::Ge { lhs, rhs }
        | Expr::Gt { lhs, rhs }
        | Expr::Le { lhs, rhs }
        | Expr::Lt { lhs, rhs }
        | Expr::Shl { lhs, rhs }
        | Expr::Shr { lhs, rhs }
        | Expr::BitwiseAnd { lhs, rhs }
        | Expr::BitwiseOr { lhs, rhs }
        | Expr::BitwiseXor { lhs, rhs }
        | Expr::Contains { lhs, rhs }
        | Expr::IContains { lhs, rhs }
        | Expr::StartsWith { lhs, rhs }
        | Expr::IStartsWith { lhs, rhs }
        | Expr::EndsWith { lhs, rhs }
        | Expr::IEndsWith { lhs, rhs }
        | Expr::IEquals { lhs, rhs }
        | Expr::Matches { lhs, rhs } => {
            stack.push(Event::Enter(*rhs));
            stack.push(Event::Enter(*lhs));
        }

        Expr::PatternMatch { anchor, .. }
        | Expr::PatternMatchVar { anchor, .. } => {
            push_anchor(anchor, stack);
        }

        Expr::PatternCount { range, .. }
        | Expr::PatternCountVar { range, .. } => {
            if let Some(range) = range {
                stack.push(Event::Enter(range.upper_bound));
                stack.push(Event::Enter(range.lower_bound));
            }
        }

        Expr::PatternOffset { index, .. }
        | Expr::PatternOffsetVar { index, .. }
        | Expr::PatternLength { index, .. }
        | Expr::PatternLengthVar { index, .. } => {
            if let Some(index) = index {
                stack.push(Event::Enter(*index));
            }
        }

        Expr::FieldAccess(field_access) => {
            for operand in field_access.operands.iter().rev() {
                stack.push(Event::Enter(*operand))
            }
        }

        Expr::FuncCall(func_call) => {
            for arg in func_call.args.iter().rev() {
                stack.push(Event::Enter(*arg))
            }
            if let Some(obj) = func_call.object {
                stack.push(Event::Enter(obj));
            }
        }

        Expr::OfExprTuple(of_expr_tuple) => {
            push_anchor(&of_expr_tuple.anchor, stack);
            for expr in of_expr_tuple.items.iter() {
                stack.push(Event::Enter(*expr));
            }
            push_quantifier(&of_expr_tuple.quantifier, stack);
        }

        Expr::OfPatternSet(of_pattern_set) => {
            push_anchor(&of_pattern_set.anchor, stack);
            push_quantifier(&of_pattern_set.quantifier, stack);
        }

        Expr::ForOf(for_of) => {
            stack.push(Event::Enter(for_of.condition));
            push_quantifier(&for_of.quantifier, stack);
        }

        Expr::ForIn(for_in) => {
            stack.push(Event::Enter(for_in.condition));
            match &for_in.iterable {
                Iterable::Range(range) => {
                    stack.push(Event::Enter(range.upper_bound));
                    stack.push(Event::Enter(range.lower_bound));
                }
                Iterable::ExprTuple(expr_tuple) => {
                    for expr in expr_tuple.iter().rev() {
                        stack.push(Event::Enter(*expr))
                    }
                }
                Iterable::Expr(expr) => stack.push(Event::Enter(*expr)),
            }
            push_quantifier(&for_in.quantifier, stack);
        }

        Expr::Lookup(lookup) => {
            stack.push(Event::Enter(lookup.index));
            stack.push(Event::Enter(lookup.primary));
        }

        Expr::With(with) => {
            stack.push(Event::Enter(with.condition));
            for (_id, expr) in with.declarations.iter().rev() {
                stack.push(Event::Enter(*expr))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::ir::dfs::Event;
    use crate::compiler::ir::{Expr, ExprId, IR};
    use crate::types::TypeValue;

    #[test]
    fn dfs() {
        let mut ir = IR::new();

        let const_1 = ir.constant(TypeValue::const_integer_from(1));
        let const_2 = ir.constant(TypeValue::const_integer_from(2));
        let const_3 = ir.constant(TypeValue::const_integer_from(2));
        let add = ir.add(vec![const_2, const_3]).unwrap();
        let root = ir.add(vec![const_1, add]).unwrap();

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((ExprId(4), &Expr::Add { .. })))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((ExprId(0), &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((ExprId(0), &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((ExprId(3), &Expr::Add { .. })))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((ExprId(1), &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((ExprId(1), &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((ExprId(2), &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((ExprId(2), &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((ExprId(3), &Expr::Add { .. })))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((ExprId(4), &Expr::Add { .. })))
        ));
        assert!(dfs.next().is_none());

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((ExprId(4), &Expr::Add { .. })))
        ));
        dfs.prune();
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((ExprId(4), &Expr::Add { .. })))
        ));
        assert!(dfs.next().is_none());

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Add { .. })))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Add { .. })))
        ));
        dfs.prune();
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Add { .. })))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Add { .. })))
        ));
        assert!(dfs.next().is_none());

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Add { .. })))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Const(_))))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Const(_))))
        ));
        dfs.prune();
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Add { .. })))
        ));
        assert!(dfs.next().is_none());
    }

    #[test]
    fn dfs_mut() {
        let mut ir = IR::new();

        let const_1 = ir.constant(TypeValue::const_integer_from(1));
        let const_2 = ir.constant(TypeValue::const_integer_from(2));
        let const_3 = ir.constant(TypeValue::const_integer_from(2));
        let add = ir.add(vec![const_2, const_3]).unwrap();
        let root = ir.add(vec![const_1, add]).unwrap();

        assert!(matches!(ir.get(add), Expr::Add { is_float: false, .. }));

        ir.dfs_mut(root, |evt| match evt {
            Event::Enter((_, expr)) => {
                if let Expr::Add { is_float, .. } = expr {
                    *is_float = true;
                }
            }
            Event::Leave(_) => {}
        });

        assert!(matches!(ir.get(add), Expr::Add { is_float: true, .. }));
    }
}
