use crate::compiler::IR;
use crate::compiler::ir::{Expr, ExprId, Iterable, MatchAnchor, Quantifier};

/// Events yielded by [`DFSIter`].
pub(crate) enum Event<T> {
    Enter(T),
    Leave(T),
}

/// Indicates the context in which an event occurred.
///
/// In some cases, while traversing the IR tree we need additional information
/// about the expression that we are currently visiting. For instance, in
/// expressions that have a body, like `for` loops or the `with` statement, we
/// may need to know whether we are visiting the body, or some other part of
/// the statement.
#[derive(Copy, Clone)]
pub(crate) enum EventContext {
    /// No context provided.
    None,
    /// The current expression is the body of its parent expression.
    Body,
    /// The current expression is a children of a field access expression.
    FieldAccess,
    /// The current expression is one of the expressions that initializes a
    /// variable in a `with` statement. For instance, the `<expr>` in:
    /// ```text
    /// with some_var = <expr> : ( .. )
    /// ```
    WithDeclaration,
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
    ir: &'a IR,
    stack: Vec<Event<(ExprId, EventContext)>>,
}

impl<'a> DFSIter<'a> {
    /// Creates a new [`DFSIter`] that traverses the tree starting at a given
    /// node.
    pub fn new(start: ExprId, ir: &'a IR) -> Self {
        Self { ir, stack: vec![Event::Enter((start, EventContext::None))] }
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
    type Item = Event<(ExprId, &'a Expr, EventContext)>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.stack.pop()?;

        if let Event::Enter((expr, ctx)) = next {
            self.stack.push(Event::Leave((expr, ctx)));
            dfs_common(self.ir.get(expr), ctx, &mut self.stack);
        }

        let next = match next {
            Event::Enter((expr, ctx)) => {
                Event::Enter((expr, self.ir.get(expr), ctx))
            }
            Event::Leave((expr, ctx)) => {
                Event::Leave((expr, self.ir.get(expr), ctx))
            }
        };

        Some(next)
    }
}

/// In addition to the functionality offered by [`DFSIter`], this type has a
/// [scopes][1] method that allows you to iterate over the scopes the current
/// node belongs to.
///
/// With scope, we mean the context in which a variable is accessible or
/// valid. In YARA there are only two types of expressions that create new
/// scopes: `for` loops and `with` statements. Both of these statements can
/// declare new variables that are accessible only within their bodies.
///
/// When traversing the IR tree, it's often necessary to determine the currently
/// valid contexts for a given expression. For example, for understanding which
/// variables are accessible at a specific point in the code.
///
/// [1]: DFSWithScopeIter::scopes
pub(crate) struct DFSWithScopeIter<'a> {
    ir: &'a IR,
    dfs: DFSIter<'a>,
    scopes: Vec<ExprId>,
    pending_pop: bool,
}

impl<'a> DFSWithScopeIter<'a> {
    pub fn new(start: ExprId, ir: &'a IR) -> Self {
        DFSWithScopeIter {
            ir,
            dfs: ir.dfs_iter(start),
            scopes: Vec::new(),
            pending_pop: false,
        }
    }

    /// Returns an iterator that yields the [`ExprId`] associated to the
    /// expressions that created the scopes that are valid in the current
    /// position within the IR tree.
    ///
    /// For instance, if we are currently at some expression that is inside
    /// the body of a `for` loop, this iterator will yield the [`ExprId`]
    /// corresponding to the `for` statement.
    ///
    /// Let's see a more complex example, consider the following YARA
    /// expression, where we are positioned at `<for body expr>`:
    ///
    /// ```text
    /// with a = <init expr> : (
    ///    for any i in (0..10) : (
    ///         <for body expr>
    ///    )
    /// )
    /// ```
    ///
    /// This iterator will return the [`ExprId`] corresponding to the `with`
    /// statement first and then the [`ExprId`] corresponding to the `for`
    /// statement. The iterator processes the scopes starting from the outermost
    /// scope and progresses inward.
    ///
    /// If we are positioned at `<init expr>`, the iterator returns the
    /// [`ExprId`] that corresponds to the `with` statement.
    pub fn scopes(&self) -> impl DoubleEndedIterator<Item = ExprId> + '_ {
        self.scopes.iter().cloned()
    }

    /// Similar to [`DFSWithScopeIter::scopes`], but only returns the `for`
    /// statements, ignoring the `with` statements.
    pub fn for_scopes(&self) -> impl Iterator<Item = ExprId> + '_ {
        self.scopes.iter().filter_map(|expr_id| match self.ir.get(*expr_id) {
            Expr::ForIn(_) => Some(*expr_id),
            _ => None,
        })
    }
}

impl Iterator for DFSWithScopeIter<'_> {
    type Item = Event<(ExprId, EventContext)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_pop {
            self.scopes.pop();
            self.pending_pop = false;
        }
        let next = match self.dfs.next()? {
            Event::Enter((expr_id, _, ctx)) => {
                if matches!(
                    ctx,
                    EventContext::Body | EventContext::WithDeclaration
                ) {
                    // If the current expression is the body of some other
                    // expression, the current expression must have a parent.
                    self.scopes.push(self.ir.get_parent(expr_id).unwrap());
                }
                Event::Enter((expr_id, ctx))
            }
            Event::Leave((expr_id, _, ctx)) => {
                if matches!(
                    ctx,
                    EventContext::Body | EventContext::WithDeclaration
                ) {
                    // Don't remove the scope at top of the stack right away.
                    // If the user calls `scopes()` while processing the Leave
                    // event, we want the current context to be there. We just
                    // signal that the top of the stack must be popped the next
                    // time.
                    self.pending_pop = true;
                }
                Event::Leave((expr_id, ctx))
            }
        };
        Some(next)
    }
}

pub(super) fn dfs_common(
    expr: &Expr,
    ctx: EventContext,
    stack: &mut Vec<Event<(ExprId, EventContext)>>,
) {
    // Only `EventContext::FieldAccess` propagates down target object chains
    // (`FieldAccess` first operand, `Lookup::primary`, `FuncCall::object`).
    // Other contexts like `Body` and `WithDeclaration` apply strictly to the
    // immediate child node.
    let inherited_ctx = if matches!(ctx, EventContext::FieldAccess) {
        EventContext::FieldAccess
    } else {
        EventContext::None
    };

    let push_quantifier =
        |quantifier: &Quantifier, stack: &mut Vec<_>| match quantifier {
            Quantifier::None => {}
            Quantifier::All => {}
            Quantifier::Any => {}
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                stack.push(Event::Enter((*expr, EventContext::None)))
            }
        };

    let push_anchor = |anchor: &MatchAnchor, stack: &mut Vec<_>| match anchor {
        MatchAnchor::None => {}
        MatchAnchor::At(expr) => {
            stack.push(Event::Enter((*expr, EventContext::None)));
        }
        MatchAnchor::In(range) => {
            stack.push(Event::Enter((range.upper_bound, EventContext::None)));
            stack.push(Event::Enter((range.lower_bound, EventContext::None)));
        }
    };

    match expr {
        Expr::Const(_) => {}
        Expr::Filesize => {}
        Expr::Symbol(_) => {}

        Expr::Not { operand }
        | Expr::Defined { operand }
        | Expr::Minus { operand, .. }
        | Expr::BitwiseNot { operand, .. } => {
            stack.push(Event::Enter((*operand, EventContext::None)));
        }

        Expr::And { operands }
        | Expr::Or { operands }
        | Expr::Add { operands, .. }
        | Expr::Sub { operands, .. }
        | Expr::Mul { operands, .. }
        | Expr::Div { operands, .. }
        | Expr::Mod { operands, .. } => {
            for operand in operands.iter().rev() {
                stack.push(Event::Enter((*operand, EventContext::None)))
            }
        }

        Expr::Eq { lhs, rhs }
        | Expr::Ne { lhs, rhs }
        | Expr::Ge { lhs, rhs }
        | Expr::Gt { lhs, rhs }
        | Expr::Le { lhs, rhs }
        | Expr::Lt { lhs, rhs }
        | Expr::Shl { lhs, rhs, .. }
        | Expr::Shr { lhs, rhs, .. }
        | Expr::BitwiseAnd { lhs, rhs, .. }
        | Expr::BitwiseOr { lhs, rhs, .. }
        | Expr::BitwiseXor { lhs, rhs, .. }
        | Expr::Contains { lhs, rhs }
        | Expr::IContains { lhs, rhs }
        | Expr::StartsWith { lhs, rhs }
        | Expr::IStartsWith { lhs, rhs }
        | Expr::EndsWith { lhs, rhs }
        | Expr::IEndsWith { lhs, rhs }
        | Expr::IEquals { lhs, rhs }
        | Expr::Matches { lhs, rhs } => {
            stack.push(Event::Enter((*rhs, EventContext::None)));
            stack.push(Event::Enter((*lhs, EventContext::None)));
        }

        Expr::MatchesMany { lhs, .. }
        | Expr::EqMany { lhs, .. }
        | Expr::IEqualsMany { lhs, .. }
        | Expr::ContainsMany { lhs, .. }
        | Expr::IContainsMany { lhs, .. }
        | Expr::StartsWithMany { lhs, .. }
        | Expr::IStartsWithMany { lhs, .. }
        | Expr::EndsWithMany { lhs, .. }
        | Expr::IEndsWithMany { lhs, .. } => {
            stack.push(Event::Enter((*lhs, EventContext::None)));
        }

        Expr::PatternMatch { anchor, .. }
        | Expr::PatternMatchVar { anchor, .. } => {
            push_anchor(anchor, stack);
        }

        Expr::PatternCount { range, .. }
        | Expr::PatternCountVar { range, .. } => {
            if let Some(range) = range {
                stack.push(Event::Enter((
                    range.upper_bound,
                    EventContext::None,
                )));
                stack.push(Event::Enter((
                    range.lower_bound,
                    EventContext::None,
                )));
            }
        }

        Expr::PatternOffset { index, .. }
        | Expr::PatternOffsetVar { index, .. }
        | Expr::PatternLength { index, .. }
        | Expr::PatternLengthVar { index, .. } => {
            if let Some(index) = index {
                stack.push(Event::Enter((*index, EventContext::None)));
            }
        }

        Expr::FieldAccess(field_access) => {
            // All operands except the first one depend on the result produced
            // by their preceding sibling, so they get `EventContext::FieldAccess`.
            // The first operand only gets `EventContext::FieldAccess` if this
            // `FieldAccess` itself was entered in a `FieldAccess` context.
            for operand in field_access.operands.iter().skip(1).rev() {
                stack
                    .push(Event::Enter((*operand, EventContext::FieldAccess)));
            }
            if let Some(first) = field_access.operands.first() {
                stack.push(Event::Enter((*first, inherited_ctx)));
            }
        }

        Expr::FuncCall(func_call) => {
            for arg in func_call.args.iter().rev() {
                stack.push(Event::Enter((*arg, EventContext::None)));
            }
            if let Some(obj) = func_call.object {
                stack.push(Event::Enter((obj, inherited_ctx)));
            }
        }

        Expr::OfExprTuple(of_expr_tuple) => {
            push_anchor(&of_expr_tuple.anchor, stack);
            for expr in of_expr_tuple.items.iter() {
                stack.push(Event::Enter((*expr, EventContext::None)));
            }
            push_quantifier(&of_expr_tuple.quantifier, stack);
        }

        Expr::OfPatternSet(of_pattern_set) => {
            push_anchor(&of_pattern_set.anchor, stack);
            push_quantifier(&of_pattern_set.quantifier, stack);
        }

        Expr::ForOf(for_of) => {
            stack.push(Event::Enter((for_of.body, EventContext::Body)));
            push_quantifier(&for_of.quantifier, stack);
        }

        Expr::ForIn(for_in) => {
            stack.push(Event::Enter((for_in.body, EventContext::Body)));
            match &for_in.iterable {
                Iterable::Range(range) => {
                    stack.push(Event::Enter((
                        range.upper_bound,
                        EventContext::None,
                    )));
                    stack.push(Event::Enter((
                        range.lower_bound,
                        EventContext::None,
                    )));
                }
                Iterable::ExprTuple(expr_tuple) => {
                    for expr in expr_tuple.iter().rev() {
                        stack.push(Event::Enter((*expr, EventContext::None)))
                    }
                }
                Iterable::Expr(expr) => {
                    stack.push(Event::Enter((*expr, EventContext::None)))
                }
            }
            push_quantifier(&for_in.quantifier, stack);
        }

        Expr::Lookup(lookup) => {
            stack.push(Event::Enter((lookup.index, EventContext::None)));
            stack.push(Event::Enter((lookup.primary, inherited_ctx)));
        }

        Expr::With(with) => {
            stack.push(Event::Enter((with.body, EventContext::Body)));
            for (_id, expr) in with.declarations.iter().rev() {
                stack
                    .push(Event::Enter((*expr, EventContext::WithDeclaration)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::context::VarStack;
    use crate::compiler::ir::dfs::{Event, EventContext};
    use crate::compiler::ir::{Expr, ExprId, IR};
    use crate::types::{Type, TypeValue};

    #[test]
    fn dfs() {
        let mut ir = IR::new();

        let const_1 = ir.constant(TypeValue::const_signed_integer_from(1));
        let const_2 = ir.constant(TypeValue::const_signed_integer_from(2));
        let const_3 = ir.constant(TypeValue::const_signed_integer_from(2));
        let add = ir.add(vec![const_2, const_3]).unwrap();
        let root = ir.add(vec![const_1, add]).unwrap();

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((
                ExprId(4),
                &Expr::Add { .. },
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((
                ExprId(0),
                &Expr::Const(_),
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((
                ExprId(0),
                &Expr::Const(_),
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((
                ExprId(3),
                &Expr::Add { .. },
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((
                ExprId(1),
                &Expr::Const(_),
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((
                ExprId(1),
                &Expr::Const(_),
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((
                ExprId(2),
                &Expr::Const(_),
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((
                ExprId(2),
                &Expr::Const(_),
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((
                ExprId(3),
                &Expr::Add { .. },
                EventContext::None
            )))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((
                ExprId(4),
                &Expr::Add { .. },
                EventContext::None
            )))
        ));
        assert!(dfs.next().is_none());

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((
                ExprId(4),
                &Expr::Add { .. },
                EventContext::None
            )))
        ));
        dfs.prune();
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((
                ExprId(4),
                &Expr::Add { .. },
                EventContext::None
            )))
        ));
        assert!(dfs.next().is_none());

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Add { .. }, EventContext::None)))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Const(_), EventContext::None)))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Const(_), EventContext::None)))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Add { .. }, EventContext::None)))
        ));
        dfs.prune();
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Add { .. }, EventContext::None)))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Add { .. }, EventContext::None)))
        ));
        assert!(dfs.next().is_none());

        let mut dfs = ir.dfs_iter(root);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Add { .. }, EventContext::None)))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((_, &Expr::Const(_), EventContext::None)))
        ));
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Const(_), EventContext::None)))
        ));
        dfs.prune();
        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((_, &Expr::Add { .. }, EventContext::None)))
        ));
        assert!(dfs.next().is_none());
    }

    #[test]
    fn dfs_mut() {
        let mut ir = IR::new();

        let const_1 = ir.constant(TypeValue::const_signed_integer_from(1));
        let const_2 = ir.constant(TypeValue::const_signed_integer_from(2));
        let const_3 = ir.constant(TypeValue::const_signed_integer_from(2));
        let add = ir.add(vec![const_2, const_3]).unwrap();
        let root = ir.add(vec![const_1, add]).unwrap();

        assert!(matches!(ir.get(add), Expr::Add { is_float: false, .. }));

        ir.dfs_mut(root, |evt| match evt {
            Event::Enter((_, expr, _)) => {
                if let Expr::Add { is_float, .. } = expr {
                    *is_float = true;
                }
            }
            Event::Leave(_) => {}
        });

        assert!(matches!(ir.get(add), Expr::Add { is_float: true, .. }));
    }

    #[test]
    fn dfs_with_scope() {
        let mut ir = IR::new();

        let mut var_stack = VarStack::new();
        let mut var_frame = var_stack.new_frame(1).unwrap();

        let const_1 = ir.constant(TypeValue::const_signed_integer_from(2));
        let with_body = ir.constant(TypeValue::const_bool_from(true));

        let with = ir.with(
            vec![(var_frame.new_var(Type::Integer), const_1)],
            with_body,
        );

        let mut dfs = ir.dfs_with_scope(with);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((expr_id, EventContext::None))) if expr_id == with
        ));

        assert_eq!(dfs.scopes().collect::<Vec<_>>(), vec![]);

        assert!(matches!(
            dfs.next(),
             Some(Event::Enter((expr_id, EventContext::WithDeclaration))) if expr_id == const_1
        ));

        assert_eq!(dfs.scopes().collect::<Vec<_>>(), vec![with]);

        assert!(matches!(
            dfs.next(),
             Some(Event::Leave((expr_id, EventContext::WithDeclaration))) if expr_id == const_1
        ));

        assert_eq!(dfs.scopes().collect::<Vec<_>>(), vec![with]);

        assert!(matches!(
            dfs.next(),
            Some(Event::Enter((expr_id, EventContext::Body))) if expr_id == with_body
        ));

        assert_eq!(dfs.scopes().collect::<Vec<_>>(), vec![with]);

        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((expr_id, EventContext::Body))) if expr_id == with_body
        ));

        assert_eq!(dfs.scopes().collect::<Vec<_>>(), vec![with]);

        assert!(matches!(
            dfs.next(),
            Some(Event::Leave((expr_id, EventContext::None))) if expr_id == with
        ));

        assert_eq!(dfs.scopes().collect::<Vec<_>>(), vec![]);
    }

    #[test]
    fn dfs_quantifier_percentage() {
        use crate::compiler::ir::{ForVars, MatchAnchor, Quantifier};

        let mut ir = IR::new();
        let mut var_stack = VarStack::new();
        let mut var_frame = var_stack.new_frame(5).unwrap();

        let pct = ir.constant(TypeValue::const_signed_integer_from(50));
        let item = ir.constant(TypeValue::const_bool_from(true));
        let for_vars = ForVars {
            n: var_frame.new_var(Type::Integer),
            i: var_frame.new_var(Type::Integer),
            max_count: var_frame.new_var(Type::Integer),
            count: var_frame.new_var(Type::Integer),
            item: var_frame.new_var(Type::Bool),
        };
        let of = ir.of_expr_tuple(
            Quantifier::Percentage(pct),
            for_vars,
            vec![item],
            MatchAnchor::None,
        );

        let visited: Vec<ExprId> = ir
            .dfs_iter(of)
            .filter_map(|evt| match evt {
                Event::Enter((id, _, _)) => Some(id),
                Event::Leave(_) => None,
            })
            .collect();

        assert_eq!(visited, vec![of, pct, item]);
    }

    #[test]
    fn dfs_field_access_context() {
        use std::rc::Rc;

        use crate::types::{FuncSignature, MangledFnName};

        let mut ir = IR::new();

        // Build an IR tree shaped like `a.b[i].c.d[0].f.g.fn(arg)`:
        //   outer_fa: FIELD_ACCESS
        //     lookup_0: LOOKUP (a.b[i])
        //       inner_fa_0: FIELD_ACCESS (a.b)
        //         a, b
        //       idx_0
        //     lookup_1: LOOKUP (c.d[0])
        //       inner_fa_1: FIELD_ACCESS (c.d)
        //         c, d
        //       idx_1
        //     fn_call: FN_CALL (f.g.fn(arg))
        //       inner_fa_2: FIELD_ACCESS (f.g)
        //         f, g
        //       arg
        let a = ir.constant(TypeValue::unknown_signed_integer());
        let b = ir.constant(TypeValue::unknown_signed_integer());
        let inner_fa_0 = ir.field_access(vec![a, b]);
        let idx_0 = ir.constant(TypeValue::unknown_signed_integer());
        let lookup_0 =
            ir.lookup(TypeValue::unknown_signed_integer(), inner_fa_0, idx_0);

        let c = ir.constant(TypeValue::unknown_signed_integer());
        let d = ir.constant(TypeValue::unknown_signed_integer());
        let inner_fa_1 = ir.field_access(vec![c, d]);
        let idx_1 = ir.constant(TypeValue::unknown_signed_integer());
        let lookup_1 =
            ir.lookup(TypeValue::unknown_signed_integer(), inner_fa_1, idx_1);

        let f = ir.constant(TypeValue::unknown_signed_integer());
        let g = ir.constant(TypeValue::unknown_signed_integer());
        let inner_fa_2 = ir.field_access(vec![f, g]);
        let arg = ir.constant(TypeValue::unknown_signed_integer());
        let fn_call = ir.func_call(
            Some(inner_fa_2),
            vec![arg],
            Rc::new(FuncSignature {
                mangled_name: MangledFnName::from(""),
                args: vec![],
                result: TypeValue::unknown_signed_integer(),
                doc: None,
            }),
        );

        let outer_fa = ir.field_access(vec![lookup_0, lookup_1, fn_call]);

        let enter_events: Vec<(ExprId, bool)> = ir
            .dfs_iter(outer_fa)
            .filter_map(|evt| match evt {
                Event::Enter((id, _, ctx)) => {
                    Some((id, matches!(ctx, EventContext::FieldAccess)))
                }
                Event::Leave(_) => None,
            })
            .collect();

        assert_eq!(
            enter_events,
            vec![
                (outer_fa, false),
                // First operand (`a.b[i]`) is not preceded by a sibling, so
                // `lookup_0` and `inner_fa_0` (`a.b`) have `EventContext::None`.
                (lookup_0, false),
                (inner_fa_0, false),
                (a, false),
                (b, true),
                (idx_0, false),
                // Second operand (`c.d[0]`) depends on `lookup_0`, so
                // `EventContext::FieldAccess` propagates into `inner_fa_1`
                // (`c.d`), while `idx_1` (`0`) stays `EventContext::None`.
                (lookup_1, true),
                (inner_fa_1, true),
                (c, true),
                (d, true),
                (idx_1, false),
                // Third operand (`f.g.fn(arg)`) depends on `lookup_1`, so
                // `EventContext::FieldAccess` propagates into `inner_fa_2`
                // (`f.g`), while `arg` stays `EventContext::None`.
                (fn_call, true),
                (inner_fa_2, true),
                (f, true),
                (g, true),
                (arg, false),
            ]
        );
    }
}
