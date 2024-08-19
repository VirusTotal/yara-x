use crate::compiler::ir::{Expr, MatchAnchor};

#[allow(dead_code)]
pub enum Event<'a> {
    Enter(&'a Expr),
    Leave(&'a Expr),
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
pub struct DepthFirstSearch<'a> {
    stack: Vec<Event<'a>>,
}

impl<'a> DepthFirstSearch<'a> {
    /// Creates a new [`DepthFirstSearch`] that traverses the given expression.
    pub fn new(expr: &'a Expr) -> Self {
        Self { stack: vec![Event::Enter(expr)] }
    }

    /// Prunes the search tree, preventing the traversal from visiting the
    /// children of the current node.
    ///
    /// The effect of this function depends on the current position in the
    /// tree. For example, if `prune` is called immediately after an
    /// [`Event::Enter`], the current node is the one that was just entered.
    /// In this scenario, pruning ensures that none of this node's children
    /// are visited, and the next event will be the corresponding
    /// [`Event::Leave`] for the node that was entered.
    ///
    /// Conversely, if `prune` is called right after an [`Event::Leave`], the
    /// current node is the parent of the node that was just exited. In this
    /// case, pruning prevents any remaining children of the current node
    /// (i.e., the siblings of the node that was just left) from being visited.
    /// The next event will then be the [`Event::Leave`] for the parent of the
    /// node that was exited.
    pub fn prune(&mut self) {
        // Remove all Event::Enter from the stack until an Event::Leave.
        while let Some(Event::Enter(_)) = self.stack.last() {
            self.stack.pop();
        }
    }
}

impl<'a> Iterator for DepthFirstSearch<'a> {
    type Item = Event<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.stack.pop()?;

        if let Event::Enter(expr) = next {
            self.stack.push(Event::Leave(expr));
            match expr {
                Expr::Const(_) => {}
                Expr::Filesize => {}
                Expr::Ident { .. } => {}

                Expr::Not { operand }
                | Expr::Defined { operand }
                | Expr::Minus { operand }
                | Expr::BitwiseNot { operand } => {
                    self.stack.push(Event::Enter(operand));
                }

                Expr::And { operands }
                | Expr::Or { operands }
                | Expr::Add { operands }
                | Expr::Sub { operands }
                | Expr::Mul { operands }
                | Expr::Div { operands }
                | Expr::Mod { operands }
                | Expr::FieldAccess { operands } => {
                    for operand in operands.iter().rev() {
                        self.stack.push(Event::Enter(operand))
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
                    self.stack.push(Event::Enter(rhs));
                    self.stack.push(Event::Enter(lhs));
                }

                Expr::PatternMatch { anchor, .. }
                | Expr::PatternMatchVar { anchor, .. } => match anchor {
                    MatchAnchor::None => {}
                    MatchAnchor::At(expr) => {
                        self.stack.push(Event::Enter(expr));
                    }
                    MatchAnchor::In(range) => {
                        self.stack.push(Event::Enter(&range.upper_bound));
                        self.stack.push(Event::Enter(&range.lower_bound));
                    }
                },

                Expr::PatternCount { range, .. }
                | Expr::PatternCountVar { range, .. } => {
                    if let Some(range) = range {
                        self.stack.push(Event::Enter(&range.upper_bound));
                        self.stack.push(Event::Enter(&range.lower_bound));
                    }
                }

                Expr::PatternOffset { index, .. }
                | Expr::PatternOffsetVar { index, .. }
                | Expr::PatternLength { index, .. }
                | Expr::PatternLengthVar { index, .. } => {
                    if let Some(index) = index {
                        self.stack.push(Event::Enter(index));
                    }
                }

                Expr::FuncCall(fn_call) => {
                    for arg in fn_call.args.iter().rev() {
                        self.stack.push(Event::Enter(arg))
                    }
                    self.stack.push(Event::Enter(&fn_call.callable));
                }

                Expr::Of(_) => {}
                Expr::ForOf(_) => {}
                Expr::ForIn(_) => {}
                Expr::Lookup(_) => {}
            }
        }

        Some(next)
    }
}

#[cfg(test)]
mod test {
    use crate::compiler::ir::dfs::Event;
    use crate::compiler::ir::Expr;
    use crate::types::TypeValue;

    #[test]
    fn dfs() {
        let expr = Expr::add(vec![
            Expr::Const(TypeValue::const_integer_from(1)),
            Expr::add(vec![
                Expr::Const(TypeValue::const_integer_from(2)),
                Expr::Const(TypeValue::const_integer_from(3)),
            ]),
        ]);

        let mut dfs = expr.depth_first_search();

        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Add { .. }))));
        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Add { .. }))));
        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Add { .. }))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Add { .. }))));
        assert!(dfs.next().is_none());

        let mut dfs = expr.depth_first_search();

        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Add { .. }))));
        dfs.prune();
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Add { .. }))));
        assert!(dfs.next().is_none());

        let mut dfs = expr.depth_first_search();

        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Add { .. }))));
        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Add { .. }))));
        dfs.prune();
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Add { .. }))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Add { .. }))));
        assert!(dfs.next().is_none());

        let mut dfs = expr.depth_first_search();

        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Add { .. }))));
        assert!(matches!(dfs.next(), Some(Event::Enter(&Expr::Const(_)))));
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Const(_)))));
        dfs.prune();
        assert!(matches!(dfs.next(), Some(Event::Leave(&Expr::Add { .. }))));
        assert!(dfs.next().is_none());
    }
}
