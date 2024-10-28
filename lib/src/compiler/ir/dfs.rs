use crate::compiler::ir::{Expr, ExprId, Iterable, MatchAnchor, Quantifier};

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
/// Lever(d)
/// Enter(e)
/// Leave(e)
/// Leave(c)
/// Leave(a)
/// ```
///
pub(crate) struct DepthFirstSearch<'a> {
    nodes: &'a [Expr],
    stack: Vec<Event<ExprId>>,
}

impl<'a> DepthFirstSearch<'a> {
    /// Creates a new [`DepthFirstSearch`] that traverses the tree starting
    /// at the given node.
    pub fn new(start: ExprId, nodes: &'a [Expr]) -> Self {
        Self { nodes, stack: vec![Event::Enter(start)] }
    }

    /// Prunes the search tree, preventing the traversal from visiting the
    /// children of the current node.
    ///
    /// The effect of this function depends on the current position in the
    /// tree. For example, if `prune` is called immediately after an
    /// [`StackEvent::Enter`], the current node is the one that was just entered.
    /// In this scenario, pruning ensures that none of this node's children
    /// are visited, and the next event will be the corresponding
    /// [`StackEvent::Leave`] for the node that was entered.
    ///
    /// Conversely, if `prune` is called right after an [`StackEvent::Leave`], the
    /// current node is the parent of the node that was just exited. In this
    /// case, pruning prevents any remaining children of the current node
    /// (i.e., the siblings of the node that was just left) from being visited.
    /// The next event will then be the [`StackEvent::Leave`] for the parent of the
    /// node that was exited.
    #[allow(dead_code)] // TODO: remove when this is used.
    pub fn prune(&mut self) {
        // Remove all Event::Enter from the stack until finding an Event::Leave.
        while let Some(Event::Enter(_)) = self.stack.last() {
            self.stack.pop();
        }
    }
}

impl<'a> Iterator for DepthFirstSearch<'a> {
    type Item = Event<(ExprId, &'a Expr)>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.stack.pop()?;

        let push_quantifier =
            |quantifier: &Quantifier, stack: &mut Vec<_>| match quantifier {
                Quantifier::None => {}
                Quantifier::All => {}
                Quantifier::Any => {}
                Quantifier::Percentage(_) => {}
                Quantifier::Expr(expr) => stack.push(Event::Enter(*expr)),
            };

        let push_anchor =
            |anchor: &MatchAnchor, stack: &mut Vec<_>| match anchor {
                MatchAnchor::None => {}
                MatchAnchor::At(expr) => {
                    stack.push(Event::Enter(*expr));
                }
                MatchAnchor::In(range) => {
                    stack.push(Event::Enter(range.upper_bound));
                    stack.push(Event::Enter(range.lower_bound));
                }
            };

        if let Event::Enter(expr) = next {
            self.stack.push(Event::Leave(expr));
            match &self.nodes[expr] {
                Expr::Const(_) => {}
                Expr::Filesize => {}
                Expr::Ident { .. } => {}

                Expr::Not { operand }
                | Expr::Defined { operand }
                | Expr::Minus { operand, .. }
                | Expr::BitwiseNot { operand } => {
                    self.stack.push(Event::Enter(*operand));
                }

                Expr::And { operands }
                | Expr::Or { operands }
                | Expr::Add { operands, .. }
                | Expr::Sub { operands, .. }
                | Expr::Mul { operands, .. }
                | Expr::Div { operands, .. }
                | Expr::Mod { operands, .. } => {
                    for operand in operands.iter().rev() {
                        self.stack.push(Event::Enter(*operand))
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
                    self.stack.push(Event::Enter(*rhs));
                    self.stack.push(Event::Enter(*lhs));
                }

                Expr::PatternMatch { anchor, .. }
                | Expr::PatternMatchVar { anchor, .. } => {
                    push_anchor(anchor, &mut self.stack);
                }

                Expr::PatternCount { range, .. }
                | Expr::PatternCountVar { range, .. } => {
                    if let Some(range) = range {
                        self.stack.push(Event::Enter(range.upper_bound));
                        self.stack.push(Event::Enter(range.lower_bound));
                    }
                }

                Expr::PatternOffset { index, .. }
                | Expr::PatternOffsetVar { index, .. }
                | Expr::PatternLength { index, .. }
                | Expr::PatternLengthVar { index, .. } => {
                    if let Some(index) = index {
                        self.stack.push(Event::Enter(*index));
                    }
                }

                Expr::FieldAccess(field_access) => {
                    for operand in field_access.operands.iter().rev() {
                        self.stack.push(Event::Enter(*operand))
                    }
                }

                Expr::FuncCall(fn_call) => {
                    for arg in fn_call.args.iter().rev() {
                        self.stack.push(Event::Enter(*arg))
                    }
                    self.stack.push(Event::Enter(fn_call.callable));
                }

                Expr::Of(of) => {
                    push_anchor(&of.anchor, &mut self.stack);
                    push_quantifier(&of.quantifier, &mut self.stack);
                }

                Expr::ForOf(for_of) => {
                    self.stack.push(Event::Enter(for_of.condition));
                    push_quantifier(&for_of.quantifier, &mut self.stack);
                }

                Expr::ForIn(for_in) => {
                    self.stack.push(Event::Enter(for_in.condition));
                    match &for_in.iterable {
                        Iterable::Range(range) => {
                            self.stack.push(Event::Enter(range.upper_bound));
                            self.stack.push(Event::Enter(range.lower_bound));
                        }
                        Iterable::ExprTuple(expr_tuple) => {
                            for expr in expr_tuple.iter().rev() {
                                self.stack.push(Event::Enter(*expr))
                            }
                        }
                        Iterable::Expr(expr) => {
                            self.stack.push(Event::Enter(*expr))
                        }
                    }
                    push_quantifier(&for_in.quantifier, &mut self.stack);
                }

                Expr::Lookup(lookup) => {
                    self.stack.push(Event::Enter(lookup.index));
                    self.stack.push(Event::Enter(lookup.primary));
                }

                Expr::With { declarations, condition } => {
                    self.stack.push(Event::Enter(*condition));
                    for (_id, expr) in declarations.iter().rev() {
                        self.stack.push(Event::Enter(*expr))
                    }
                }
            }
        }

        let next = match next {
            Event::Enter(expr) => Event::Enter((expr, &self.nodes[expr])),
            Event::Leave(expr) => Event::Leave((expr, &self.nodes[expr])),
        };

        Some(next)
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
}
