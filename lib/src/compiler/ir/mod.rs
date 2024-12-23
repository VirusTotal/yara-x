/*! Intermediate representation (IR) for a set of YARA rules.

The IR is a tree representing a set of YARA rules. This tree is similar to the
AST, but it contains type information for expressions and identifiers, something
that the AST doesn't have. The IR is generated from the AST, and the compiled
[Rules] are generated from the IR. This means that the IR is further away from
the original source code than the AST, and closer to the emitted code. The build
process goes like:

  `source code -> CST -> AST -> IR -> compiled rules`

Contrary to the AST, the IR doesn't have a one-to-one correspondence to the
original source code, the compiler is free to transform the IR in ways that
maintain the semantics of the original source code but doesn't match the code
exactly. This could be done for example for optimization purposes. Another
example is constant folding, which is done while the IR is being built,
converting expressions like `2+2+2` into the constant `6`.

The portions of the IR representing regular expressions and hex patterns
are entrusted to the [regex_syntax] crate, particularly to its [Hir] type. This
crate parses regular expressions and produce the corresponding [Hir]. For hex
patterns the [Hir] is generated from the AST by the [`hex2hir`] module.

Using a common representation for both regular expressions and hex patterns
allows using the same regex engine for matching both types of patterns.

[Rules]: crate::compiler::Rules
[regex_syntax]: https://docs.rs/regex-syntax/latest/regex_syntax/
[Hir]: regex_syntax::hir::Hir
*/

use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::mem;
use std::mem::discriminant;
use std::ops::Index;
use std::ops::RangeInclusive;
use std::rc::Rc;

use bitmask::bitmask;
use bstr::BString;
use itertools::Itertools;
use rustc_hash::{FxHashMap, FxHasher};
use serde::{Deserialize, Serialize};

use yara_x_parser::Span;

use crate::compiler::context::{Var, VarStack};
use crate::compiler::ir::dfs::{
    dfs_common, DFSIter, DFSWithScopeIter, Event, EventContext,
};

use crate::re;
use crate::symbols::Symbol;
use crate::types::{Func, FuncSignature, Type, TypeValue, Value};

pub(in crate::compiler) use ast2ir::patterns_from_ast;
pub(in crate::compiler) use ast2ir::rule_condition_from_ast;
use yara_x_parser::ast::Ident;

mod ast2ir;
mod dfs;
mod hex2hir;

#[cfg(test)]
mod tests;

bitmask! {
    /// Flags associated to rule patterns.
    ///
    /// Each of these flags correspond to one of the allowed YARA pattern
    /// modifiers, and generally they are set if the corresponding modifier
    /// appears alongside the pattern in the source code. The only exception is
    /// the `Ascii` flag, which will be set when `Wide` is not set regardless
    /// of what the source code says. This follows the semantics of YARA
    /// pattern modifiers, in which a pattern is considered `ascii` by default
    /// when neither `ascii` nor `wide` modifiers are used.
    ///
    /// In resume either the `Ascii` or the `Wide` flags (or both) will be set.
    #[derive(Debug, Hash, Serialize, Deserialize)]
    pub mask PatternFlagSet: u16 where flags PatternFlags  {
        Ascii                = 0x0001,
        Wide                 = 0x0002,
        Nocase               = 0x0004,
        Base64               = 0x0008,
        Base64Wide           = 0x0010,
        Xor                  = 0x0020,
        Fullword             = 0x0040,
        Private              = 0x0080,
        NonAnchorable        = 0x0100,
    }
}

/// Represents a pattern in the context of a specific rule.
///
/// It encapsulates a [`Pattern`] alongside an identifier and information
/// regarding whether the pattern is anchored. The key distinction between
/// this type and [`Pattern`] lies in the context: while the latter defines
/// a pattern in a generic context, this structure represents a pattern
/// within the confines of a specific rule. If two distinct rules declare
/// precisely the same pattern, including any modifiers, they will reference
/// the same [`Pattern`] instance.
pub(crate) struct PatternInRule<'src> {
    identifier: Ident<'src>,
    pattern: Pattern,
    span: Span,
    in_use: bool,
}

impl<'src> PatternInRule<'src> {
    #[inline]
    pub fn identifier(&self) -> &Ident<'src> {
        &self.identifier
    }

    #[inline]
    pub fn into_pattern(self) -> Pattern {
        self.pattern
    }

    #[inline]
    pub fn pattern(&self) -> &Pattern {
        &self.pattern
    }

    #[inline]
    pub fn span(&self) -> &Span {
        &self.span
    }

    #[inline]
    pub fn anchored_at(&self) -> Option<usize> {
        self.pattern.anchored_at()
    }

    #[inline]
    pub fn in_use(&self) -> bool {
        self.in_use
    }

    /// Anchor the pattern to a given offset. This means that the pattern can
    /// match only at that offset and nowhere else. This is a no-op for
    /// patterns that are flagged as non-anchorable.
    ///
    /// Also, if this function is called twice with different offsets, the
    /// pattern becomes non-anchorable because it can't be anchored to two
    /// different offsets.
    ///
    /// This is used when the condition contains an expression like `$a at 0`
    /// in order to indicate that the pattern (the `$a` pattern in this case)
    /// can match only at a fixed offset.
    pub fn anchor_at(&mut self, offset: usize) -> &mut Self {
        self.pattern.anchor_at(offset);
        self
    }

    /// Make the pattern non-anchorable. Any existing anchor is removed and
    /// future calls to [`PatternInRule::anchor_at`] are ignored.
    ///
    /// This function is used to indicate that a certain pattern can't be
    /// anchored at any fixed offset because it is used in ways that require
    /// finding all the possible matches. For example, in a condition like
    /// `#a > 0 and $a at 0`, the use of `#a` (which returns the number of
    /// occurrences of `$a`), makes `$a` non-anchorable because we need to find
    /// all occurrences of `$a`.
    pub fn make_non_anchorable(&mut self) -> &mut Self {
        self.pattern.make_non_anchorable();
        self
    }

    /// Marks the pattern as used.
    ///
    /// When a pattern is used in the rule's condition this function is called
    /// to indicate that the pattern is in use.
    pub fn mark_as_used(&mut self) -> &mut Self {
        self.in_use = true;
        self
    }
}

/// Represents a pattern in YARA.
///
/// This type represents a pattern independently of the rule in which it was
/// declared. Multiple rules declaring exactly the same pattern will share the
/// same instance of [`Pattern`]. For representing a pattern in the context of
/// a specific rule we have [`PatternInRule`], which contains a [`Pattern`] and
/// additional information about how the pattern is used in a rule.
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) enum Pattern {
    Text(LiteralPattern),
    Regexp(RegexpPattern),
    Hex(RegexpPattern),
}

impl Pattern {
    #[inline]
    pub fn flags(&self) -> &PatternFlagSet {
        match self {
            Pattern::Text(literal) => &literal.flags,
            Pattern::Regexp(regexp) => &regexp.flags,
            Pattern::Hex(regexp) => &regexp.flags,
        }
    }

    #[inline]
    pub fn flags_mut(&mut self) -> &mut PatternFlagSet {
        match self {
            Pattern::Text(literal) => &mut literal.flags,
            Pattern::Regexp(regexp) => &mut regexp.flags,
            Pattern::Hex(regexp) => &mut regexp.flags,
        }
    }

    #[inline]
    pub fn anchored_at(&self) -> Option<usize> {
        match self {
            Pattern::Text(literal) => literal.anchored_at,
            Pattern::Regexp(regexp) => regexp.anchored_at,
            Pattern::Hex(regexp) => regexp.anchored_at,
        }
    }

    /// Anchor the pattern to a given offset. This means that the pattern can
    /// match only at that offset and nowhere else. This is a no-op for
    /// patterns that are flagged as non-anchorable.
    ///
    /// Also, if this function is called twice with different offsets, the
    /// pattern becomes non-anchorable because it can't be anchored to two
    /// different offsets.
    ///
    /// This is used when the condition contains an expression like `$a at 0`
    /// in order to indicate that the pattern (the `$a` pattern in this case)
    /// can match only at a fixed offset.
    pub fn anchor_at(&mut self, offset: usize) {
        let is_anchorable =
            !self.flags().contains(PatternFlags::NonAnchorable);

        let anchored_at = match self {
            Pattern::Text(literal) => &mut literal.anchored_at,
            Pattern::Regexp(regexp) => &mut regexp.anchored_at,
            Pattern::Hex(regexp) => &mut regexp.anchored_at,
        };

        match anchored_at {
            Some(o) if *o != offset => {
                *anchored_at = None;
                self.flags_mut().set(PatternFlags::NonAnchorable);
            }
            None => {
                if is_anchorable {
                    *anchored_at = Some(offset);
                }
            }
            _ => {}
        }
    }

    /// Make the pattern non-anchorable. Any existing anchor is removed and
    /// future calls to [`PatternInRule::anchor_at`] are ignored.
    ///
    /// This function is used to indicate that a certain pattern can't be
    /// anchored at any fixed offset because it is used in ways that require
    /// finding all the possible matches. For example, in a condition like
    /// `#a > 0 and $a at 0`, the use of `#a` (which returns the number of
    /// occurrences of `$a`), makes `$a` non-anchorable because we need to
    /// find all occurrences of `$a`.
    pub fn make_non_anchorable(&mut self) {
        match self {
            Pattern::Text(literal) => literal.anchored_at = None,
            Pattern::Regexp(regexp) => regexp.anchored_at = None,
            Pattern::Hex(regexp) => regexp.anchored_at = None,
        };
        self.flags_mut().set(PatternFlags::NonAnchorable);
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct LiteralPattern {
    pub flags: PatternFlagSet,
    pub text: BString,
    pub anchored_at: Option<usize>,
    pub xor_range: Option<RangeInclusive<u8>>,
    pub base64_alphabet: Option<String>,
    pub base64wide_alphabet: Option<String>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct RegexpPattern {
    pub flags: PatternFlagSet,
    pub hir: re::hir::Hir,
    pub anchored_at: Option<usize>,
}

/// The index of a pattern in the rule that declares it.
///
/// The first pattern in the rule has index 0, the second has index 1, and
/// so on.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) struct PatternIdx(usize);

impl PatternIdx {
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl From<usize> for PatternIdx {
    #[inline]
    fn from(value: usize) -> Self {
        Self(value)
    }
}

/// Identifies an expression in the IR tree.
#[derive(Clone, Copy, PartialEq, Eq, Ord, Hash, PartialOrd)]
pub(crate) struct ExprId(u32);

impl ExprId {
    pub const fn none() -> Self {
        ExprId(u32::MAX)
    }
}

impl Debug for ExprId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0 == u32::MAX {
            write!(f, "None")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl From<usize> for ExprId {
    #[inline]
    fn from(value: usize) -> Self {
        Self(value as u32)
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    NumberOutOfRange,
}

/// Intermediate representation (IR) of a rule condition.
///
/// The IR is a tree representing a rule condition. It is generated from the
/// Abstract Syntax Tree (AST), and then transformed when optimizations are
/// applied. Finally, the IR is used as input by the code emitter.
///
/// The tree is represented using a vector of [`Expr`], each expression can
/// reference other expressions (like it its operands) using an [`ExprId`],
/// which is an index in the vector.
pub(crate) struct IR {
    constant_folding: bool,
    /// The [`ExprId`] corresponding to the root node.
    root: Option<ExprId>,
    /// Vector that contains all the nodes in the IR. An [`ExprId`] is an index
    /// within this vector.
    nodes: Vec<Expr>,
    /// Vector that indicates the parent of a node. An [`ExprId`] is an index
    /// within this vector. `parents[expr_id]` returns the node of the expression
    /// identified by `expr_id`.
    parents: Vec<ExprId>,
}

impl IR {
    /// Creates a new [`IR`].
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            parents: Vec::new(),
            root: None,
            constant_folding: false,
        }
    }

    /// Enable constant folding.
    pub fn constant_folding(&mut self, yes: bool) -> &mut Self {
        self.constant_folding = yes;
        self
    }

    /// Clears the tree, removing all nodes.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.parents.clear();
    }

    /// Given an [`ExprId`] returns a reference to the corresponding [`Expr`].
    #[inline]
    pub fn get(&self, expr_id: ExprId) -> &Expr {
        self.nodes.get(expr_id.0 as usize).unwrap()
    }

    /// Given an [`ExprId`] returns a mutable reference to the corresponding
    /// [`Expr`].
    #[inline]
    pub fn get_mut(&mut self, expr_id: ExprId) -> &mut Expr {
        self.nodes.get_mut(expr_id.0 as usize).unwrap()
    }

    pub fn replace(&mut self, expr_id: ExprId, expr: Expr) -> Expr {
        mem::replace(&mut self.nodes[expr_id.0 as usize], expr)
    }

    #[inline]
    pub fn get_parent(&self, expr_id: ExprId) -> Option<ExprId> {
        let parent = self.parents[expr_id.0 as usize];
        if parent == ExprId::none() {
            return None;
        }
        Some(parent)
    }

    #[inline]
    pub fn set_parent(&mut self, expr_id: ExprId, parent_id: ExprId) {
        self.parents[expr_id.0 as usize] = parent_id;
    }

    /// Pushes an [`Expr`] into the IR tree.
    ///
    /// Returns the [`ExprId`] the identifies the pushed expression in the
    /// IR tree.
    pub fn push(&mut self, expr: Expr) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());

        self.parents.push(ExprId::none());
        self.nodes.push(expr);

        // If the original expression has children, those children were
        // pointing to some other parent, adjust the parent of the
        // children so that they point to the new location.
        for child in self.children(expr_id).collect::<Vec<ExprId>>() {
            self.parents[child.0 as usize] = expr_id;
        }

        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Increase the index of variables used by an expression (including
    /// its subexpressions) by a certain amount.
    ///
    /// The index of variables used by the expression identified by `expr_id`
    /// will be increased by `shift_amount` if the variable has an index that
    /// is larger or equal to `from_index`.
    ///
    /// The purpose of this function is displacing every variable that resides
    /// at some index and above to a higher index, creating a "hole" that can
    /// be occupied by other variables.
    pub fn shift_vars(
        &mut self,
        expr_id: ExprId,
        from_index: i32,
        shift_amount: i32,
    ) {
        self.dfs_mut(expr_id, |evt| match evt {
            Event::Enter((_, expr, _)) => {
                expr.shift_vars(from_index, shift_amount)
            }
            Event::Leave(_) => {}
        });
    }

    /// Returns an iterator that performs a depth first search starting at
    /// the given node.
    pub fn dfs_iter(&self, start: ExprId) -> DFSIter {
        DFSIter::new(start, self)
    }

    /// Similar to [`IR::dfs_iter`] but returns an iterator that also can offer
    /// information about the current scopes.
    ///
    /// See [`DFSWithScopeIter`] for details.
    pub fn dfs_with_scope(&self, start: ExprId) -> DFSWithScopeIter {
        DFSWithScopeIter::new(start, self)
    }

    /// Performs a depth-first traversal of the IR tree, calling the `f`
    /// function both upon entering and leaving each node.
    pub fn dfs_mut<F>(&mut self, start: ExprId, mut f: F)
    where
        F: FnMut(Event<(ExprId, &mut Expr, EventContext)>),
    {
        let mut stack = vec![Event::Enter((start, EventContext::None))];

        while let Some(evt) = stack.pop() {
            if let Event::Enter(expr) = evt {
                stack.push(Event::Leave(expr));
            }
            f(match &evt {
                Event::Enter((expr_id, ctx)) => {
                    Event::Enter((*expr_id, self.get_mut(*expr_id), *ctx))
                }
                Event::Leave((expr_id, ctx)) => {
                    Event::Leave((*expr_id, self.get_mut(*expr_id), *ctx))
                }
            });
            if let Event::Enter((expr, _)) = evt {
                dfs_common(&self.nodes[expr.0 as usize], &mut stack);
            }
        }
    }

    /// Finds the first expression in DFS order starting at the `start` node
    /// that matches the given `predicate`, but avoids traversing the
    /// descendants of nodes matching the condition indicated by `prune_if`.
    pub fn dfs_find<P, C>(
        &self,
        start: ExprId,
        predicate: P,
        prune_if: C,
    ) -> Option<&Expr>
    where
        P: Fn(&Expr) -> bool,
        C: Fn(&Expr) -> bool,
    {
        let mut dfs = self.dfs_iter(start);

        while let Some(evt) = dfs.next() {
            if let Event::Enter((_, expr, _)) = evt {
                if predicate(expr) {
                    return Some(expr);
                }
                if prune_if(expr) {
                    dfs.prune();
                }
            }
        }

        None
    }

    /// Returns an iterator that yields the ancestors of the given expression.
    ///
    /// The first item yielded by the iterator is the [`ExprId`] corresponding
    /// to the parent of `expr`, and then keeps going up the ancestors chain
    /// until it reaches the root expression.
    pub fn ancestors(&self, expr: ExprId) -> Ancestors<'_> {
        Ancestors { ir: self, current: expr }
    }

    /// Returns an iterator that yields the children of the given expression.
    pub fn children(&self, expr: ExprId) -> Children {
        // The children iterator uses a DFS iterator under the hood. By using
        // the `DFSIter::prune` method we avoid traversing all the descendants
        // of the given expression and traverse only its children.
        let mut dfs = self.dfs_iter(expr);
        // The first item returned by the DFS iterator is the Event::Enter
        // that corresponds to `expr` itself, skip it.
        dfs.next();
        // Now the DFS is ready to return the first child.
        Children { dfs }
    }

    /// Finds the common ancestor of a given set of expressions in the IR tree.
    ///
    /// This function traverses the ancestor chain of each expression to identify
    /// where they converge. In the worst-case scenario, the common ancestor will
    /// be the root expression.
    pub fn common_ancestor(&self, exprs: &[ExprId]) -> ExprId {
        if exprs.is_empty() {
            return ExprId::none();
        }

        // Vector where each item is an ancestors iterator for one of the
        // expressions passed to this function.
        let mut ancestor_iterators: Vec<Ancestors> =
            exprs.iter().map(|expr| self.ancestors(*expr)).collect();

        let mut exprs = exprs.to_vec();

        // In each iteration of this loop, we move one step up the ancestor
        // chain for each expression, except for the expression with the highest
        // ExprId. This process continues until all ancestor chains converge at
        // the same ExprId.
        //
        // This algorithm leverages the property that each node in the IR tree
        // has a higher ExprId than any of its descendants. This means that if
        // node A has a lower ExprId than node B, B cannot be a descendant of
        // A. We can therefore traverse up A’s ancestor chain until finding B
        // or some other node with an ExprId higher than B's.
        while !exprs.iter().all_equal() {
            let max = exprs.iter().cloned().max().unwrap();
            let expr_with_ancestors =
                exprs.iter_mut().zip_eq(&mut ancestor_iterators);
            // Advance the ancestor iterators by one, except the iterator
            // corresponding to the expression with the highest ExprId.
            for (expr, ancestors) in expr_with_ancestors {
                if *expr != max {
                    *expr = ancestors.next().unwrap();
                }
            }
        }

        // At this point all expressions have converged to the same ExprId, we
        // can return any of them.
        exprs[0]
    }

    /// Computes the hash corresponding to each expression in the IR.
    ///
    /// For each expression in the IR, except constants, identifiers and
    /// `filesize`, the `f` is invoked with the [`ExprId`] and the hash
    /// corresponding to that expression.
    pub fn compute_expr_hashes<F>(&self, start: ExprId, mut f: F)
    where
        F: FnMut(ExprId, u64),
    {
        let mut hashers = Vec::new();

        // Function that decides which expressions should be ignored. Some
        // expressions are ignored because de-duplicating them doesn't make
        // sense. For instance, constants are not de-duplicated because they
        // are cheap to evaluate, and the same happens with `filesize`.
        let ignore = |expr: &Expr| {
            matches!(expr, Expr::Const(_) | Expr::Filesize | Expr::Symbol(_))
        };

        for evt in self.dfs_iter(start) {
            match evt {
                Event::Enter((_, expr, _)) => {
                    if !ignore(expr) {
                        hashers.push(FxHasher::default());
                    }
                    for h in hashers.iter_mut() {
                        expr.hash(h);
                    }
                }
                Event::Leave((expr_id, expr, _)) => {
                    if !ignore(expr) {
                        let hasher = hashers.pop().unwrap();
                        f(expr_id, hasher.finish());
                    }
                }
            }
        }
    }

    /// Returns true if expressions `a` and `b` are equal.
    pub fn equal(&self, a: ExprId, b: ExprId) -> bool {
        // Traverse the IR of both expressions in DFS order.
        let mut dfs_a = self.dfs_iter(a);
        let mut dfs_b = self.dfs_iter(b);

        // If both expressions are equal their IR trees will be equal,
        // and we should be able to iterate both them in lockstep.
        for (a, b) in dfs_a.by_ref().zip(dfs_b.by_ref()) {
            match (a, b) {
                (Event::Leave((_, _, _)), Event::Leave((_, _, _))) => {}
                (Event::Enter((_, a, _)), Event::Enter((_, b, _))) => {
                    if discriminant(a) != discriminant(b) {
                        return false;
                    }
                    let eq = match (a, b) {
                        (Expr::Const(a), Expr::Const(b)) => a == b,
                        (
                            Expr::PatternMatch {
                                pattern: pattern_a,
                                anchor: anchor_a,
                            },
                            Expr::PatternMatch {
                                pattern: pattern_b,
                                anchor: anchor_b,
                            },
                        ) => {
                            discriminant(anchor_a) == discriminant(anchor_b)
                                && pattern_a == pattern_b
                        }
                        (
                            Expr::PatternMatchVar {
                                symbol: symbol_a,
                                anchor: anchor_a,
                            },
                            Expr::PatternMatchVar {
                                symbol: symbol_b,
                                anchor: anchor_b,
                            },
                        ) => {
                            discriminant(anchor_a) == discriminant(anchor_b)
                                && symbol_a == symbol_b
                        }
                        (
                            Expr::PatternCount {
                                pattern: pattern_a,
                                range: range_a,
                            },
                            Expr::PatternCount {
                                pattern: pattern_b,
                                range: range_b,
                            },
                        ) => {
                            discriminant(range_a) == discriminant(range_b)
                                && pattern_a == pattern_b
                        }
                        (
                            Expr::PatternCountVar {
                                symbol: symbol_a,
                                range: range_a,
                            },
                            Expr::PatternCountVar {
                                symbol: symbol_b,
                                range: range_b,
                            },
                        ) => {
                            discriminant(range_a) == discriminant(range_b)
                                && symbol_a == symbol_b
                        }
                        (
                            Expr::PatternOffset {
                                pattern: pattern_a,
                                index: index_a,
                            },
                            Expr::PatternOffset {
                                pattern: pattern_b,
                                index: index_b,
                            },
                        ) => {
                            discriminant(index_a) == discriminant(index_b)
                                && pattern_a == pattern_b
                        }
                        (
                            Expr::PatternOffsetVar {
                                symbol: symbol_a,
                                index: index_a,
                            },
                            Expr::PatternOffsetVar {
                                symbol: symbol_b,
                                index: index_b,
                            },
                        ) => {
                            discriminant(index_a) == discriminant(index_b)
                                && symbol_a == symbol_b
                        }
                        (
                            Expr::PatternLength {
                                pattern: pattern_a,
                                index: index_a,
                            },
                            Expr::PatternLength {
                                pattern: pattern_b,
                                index: index_b,
                            },
                        ) => {
                            discriminant(index_a) == discriminant(index_b)
                                && pattern_a == pattern_b
                        }
                        (
                            Expr::PatternLengthVar {
                                symbol: symbol_a,
                                index: index_a,
                            },
                            Expr::PatternLengthVar {
                                symbol: symbol_b,
                                index: index_b,
                            },
                        ) => {
                            discriminant(index_a) == discriminant(index_b)
                                && symbol_a == symbol_b
                        }
                        (Expr::OfExprTuple(a), Expr::OfExprTuple(b)) => {
                            discriminant(&a.quantifier)
                                == discriminant(&b.quantifier)
                                && discriminant(&a.anchor)
                                    == discriminant(&b.anchor)
                        }
                        (Expr::OfPatternSet(a), Expr::OfPatternSet(b)) => {
                            discriminant(&a.quantifier)
                                == discriminant(&b.quantifier)
                                && discriminant(&a.anchor)
                                    == discriminant(&b.anchor)
                        }
                        (Expr::ForOf(a), Expr::ForOf(b)) => {
                            discriminant(&a.quantifier)
                                == discriminant(&b.quantifier)
                                && a.pattern_set == b.pattern_set
                        }
                        (Expr::ForIn(a), Expr::ForIn(b)) => {
                            discriminant(&a.quantifier)
                                == discriminant(&b.quantifier)
                                && discriminant(&a.iterable)
                                    == discriminant(&b.iterable)
                        }
                        (Expr::FuncCall(a), Expr::FuncCall(b)) => {
                            a.func == b.func
                                && a.signature_index == b.signature_index
                                && a.type_value == b.type_value
                        }
                        _ => true,
                    };
                    if !eq {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        let a_has_more = dfs_a.next().is_some();
        let b_has_more = dfs_b.next().is_some();

        !a_has_more && !b_has_more
    }

    /// Traverses the IR tree for the given expression looking for
    /// sub-expressions that are identical.
    ///
    /// The result is a vector where each item describes a set of identical
    /// expressions. Each item in the vector is a tuple where the first element
    /// is the deepest common ancestor of all the identical expressions, and
    /// the second element is a vector containing these identical expressions.
    pub fn find_common_subexprs(
        &self,
        expr_id: ExprId,
    ) -> Vec<(ExprId, Vec<ExprId>)> {
        // Map where keys are ExprId and values are the hash associated
        // to the expression identified by that ExprId.
        let mut hashes: FxHashMap<ExprId, u64> = FxHashMap::default();

        // Map where keys are expression hashes and values are vectors
        // with the ExprId of every expression with that hash.
        let mut map: FxHashMap<u64, Vec<ExprId>> = FxHashMap::default();

        self.compute_expr_hashes(expr_id, |expr_id, hash| {
            hashes.insert(expr_id, hash);
            map.entry(hash).or_default().push(expr_id);
        });

        let mut dfs = self.dfs_iter(expr_id);
        let mut result = Vec::new();

        'dfs: while let Some(evt) = dfs.next() {
            match evt {
                Event::Enter((expr_id, _, _)) => {
                    // Get hash for the current expression. This can return
                    // `None` because the hash is not computed for all
                    // expressions.
                    let hash = match hashes.get(&expr_id) {
                        Some(hash) => hash,
                        None => continue 'dfs,
                    };
                    if !map.contains_key(hash) {
                        // When the entry was not found is because it was
                        // previously deleted while processing another expression
                        // that was equal to the current one. In such cases we
                        // won't need to traverse the current expression.
                        dfs.prune();
                    }
                }
                Event::Leave((expr_id, _, ctx)) => {
                    // All other expressions could be moved around, except those
                    // that are operands of a field access. That's because the
                    // operands of a field access can depend on the results
                    // produced by their siblings. For instance, in `foo[i].bar[0]`
                    // `bar[0]` depends on the result produced by `foo[i]`,
                    // `bar[0]` doesn't depend on `i` itself, but it depends on
                    // the result of `foo[i]`, which does.
                    if matches!(ctx, EventContext::FieldAccess) {
                        continue 'dfs;
                    }
                    let hash = match hashes.get(&expr_id) {
                        Some(hash) => hash,
                        None => continue 'dfs,
                    };
                    // Get vector with all the expressions that have the same
                    // hash as the current expression, including the current
                    // expression itself. The entry is removed from the map,
                    // which guarantees that each set of equal expressions are
                    // processed only once.
                    let exprs = match map.remove(hash) {
                        Some(exprs) => exprs,
                        None => continue 'dfs,
                    };
                    // Make sure that all the expressions are actually equal.
                    // All the expressions have the same hash, but that's not
                    // a guarantee of equality due to hash collisions.
                    for (a, b) in exprs.iter().tuple_windows() {
                        if !self.equal(*a, *b) {
                            continue 'dfs;
                        }
                    }
                    if exprs.len() > 1 {
                        result.push((
                            self.common_ancestor(exprs.as_slice()),
                            exprs,
                        ));
                    }
                }
            }
        }

        result
    }

    /// Optimizes the IR by eliminating common subexpressions.
    ///
    /// This function searches for instances of identical subexpressions
    /// and replace them with a single variable holding the computed value.
    ///
    /// https://en.wikipedia.org/wiki/Common_subexpression_elimination
    pub fn cse(&mut self) -> ExprId {
        for (common_ancestor, subexpressions) in
            self.find_common_subexprs(self.root.unwrap())
        {
            // This is the index of the new variable.
            let var_index = self
                .ancestors(common_ancestor)
                .map(|expr_id| self.get(expr_id).stack_frame_size())
                .sum::<i32>();

            // Shift all variables with an index greater or equal than
            // var_index one position to the left in order to make room for
            // the new variable used by the `with` statement that will be
            // inserted.
            self.shift_vars(common_ancestor, var_index, 1);

            let mut subexpressions = subexpressions.into_iter();
            let first = subexpressions.next().unwrap();
            let type_value = self.get(first).type_value();
            let var = Var::new(0, type_value.ty(), var_index);

            // Replace the first of the subexpressions with a variable. The
            // replaced subexpression will be added as a declaration to the
            // `with` statement.
            let replaced = self.replace(
                first,
                Expr::Symbol(Box::new(Symbol::Var {
                    var,
                    type_value: type_value.clone(),
                })),
            );

            // The expression that initializes the variable is the one that is
            // being replaced with the variable.
            let var_init_stmt = self.push(replaced);

            // Get the current parent of the common ancestor. This must be done
            // before creating the `with` statement because the common ancestor's
            // parent will become the `with` statement.
            let parent = self.get_parent(common_ancestor);

            // Create the `with` statement where the body is the common ancestor
            // of all the identical subexpressions.
            let with_stmt =
                self.with(vec![(var, var_init_stmt)], common_ancestor);

            if let Some(parent) = parent {
                self.set_parent(with_stmt, parent);
                self.get_mut(parent).replace_child(common_ancestor, with_stmt);
            } else {
                self.root = Some(with_stmt);
            }

            for s in subexpressions {
                self.replace(
                    s,
                    Expr::Symbol(Box::new(Symbol::Var {
                        var,
                        type_value: type_value.clone(),
                    })),
                );
            }
        }

        self.root.unwrap()
    }

    /// Traverses the IR tree identifying loop-invariant expressions that can
    /// be safely moved outside the loop they are nested in.
    ///
    /// This function returns a vector of pairs `(ExprId, ExprId)`, where the
    /// first element represents the ID of an expression that can be moved out
    /// of a loop, and the second represents the ID of the loop from which it
    /// can be moved. This always corresponds to the outermost loop in which
    /// the expression remains invariant. See: [`IR::hoisting`].
    ///
    /// # Algorithm Overview
    ///
    /// ## Step 1: Dependency Analysis
    ///
    /// - Traverse the IR tree in **Depth-First Search (DFS)** order to compute
    ///   variable dependencies for each expression.
    /// - When a node uses a variable, mark all its ancestors (up to the root)
    ///   as dependent on that variable, unless the node is already marked
    ///   dependent on a variable declared in a statement lower in the tree
    ///   (closer to the leaves).
    /// - This results in a dependency vector where each element corresponds to
    ///   an IR node, specifying the variable(s) upon which the corresponding
    ///   expression depends.
    ///
    /// ## Step 2: Hoisting candidates identification
    ///
    /// - Traverse the IR tree again in **DFS** order, processing nodes during
    ///   the "leave" event (when recursion unwinds). This ensures that nodes
    ///   closer to the leaves are visited first.
    /// - Add a node to the result vector only if its parent does not depend on
    ///   the same variable. This avoids hoisting sub-expressions that are part
    ///   of a larger expression also eligible to be hoisted from the same loop.
    /// - The number of candidates is limited to 100. Too many candidates produce
    ///   very deep IR trees with many nested `with` statement, which often
    ///   results in code that is slower than the original one.
    ///
    /// The final result is a list of loop-invariant expressions and the loops
    /// they can be hoisted from, ensuring optimal code motion without redundant
    /// or unnecessary hoisting.
    pub fn find_hoisting_candidates(&self) -> Vec<(ExprId, ExprId)> {
        // This vector contains one entry per node in the IR tree. Each entry
        // at `depends_on[expr_id]` provides information about the variable on
        // which the expression identified by `expr_id` depends.
        //
        // - If `depends_on[expr_id]` is `None`, the expression does not depend
        //   on any variable.
        //
        // - If `depends_on[expr_id]` is `Some((e, v))`, then `e` is the ExprId
        //   that identifies the expression that declared the variable, and `v`
        //   is the index of the variable on which `expr_id` depends on. If the
        //   expression depends on multiple variables, `depends_on[expr_id]`
        //   will refer to the outermost variable (i.e., the variable that
        //   corresponds to the outermost loop or with statement).
        //
        let mut depends_on = vec![None; self.nodes.len()];

        // The result is a vector of tuples (ExprId, ExprId), where the first
        // item is the expression that must be moved out of a loop, and the
        // second one is the loop from where the expression must be moved out.
        // This implies that the first expression is a sub-expression of the
        // second one.
        let mut result = Vec::new();

        let mut dfs = self.dfs_with_scope(self.root.unwrap());

        while let Some(event) = dfs.next() {
            let current_expr_id = match event {
                Event::Enter((expr_id, _)) => expr_id,
                Event::Leave(_) => continue,
            };

            let symbol = match self.get(current_expr_id) {
                Expr::Symbol(symbol) => symbol,
                _ => continue,
            };

            let var = match symbol.as_ref() {
                Symbol::Var { var, .. } => var.index(),
                _ => continue,
            };

            // Try to find the statement that declared the variable.
            let stmt_declaring_var =
                match dfs.scopes().find(|expr_id| match self.get(*expr_id) {
                    Expr::With(with) => {
                        with.declarations.iter().any(|(v, _)| v.index() == var)
                    }
                    Expr::ForIn(for_in) => {
                        for_in.variables.iter().any(|v| v.index() == var)
                    }
                    _ => false,
                }) {
                    Some(stmt) => stmt,
                    None => continue,
                };

            // Iterate the ancestors of the current statement up to the
            // statement that declared the variable (not included), and mark
            // them as dependent on that variable.
            for ancestor in self
                .ancestors(current_expr_id)
                .take_while(|ancestor| ancestor.ne(&stmt_declaring_var))
            {
                match &mut depends_on[ancestor.0 as usize] {
                    // If already depends on some variable that was defined by
                    // an inner expression, the existing dependency prevails.
                    // We rely on the fact that variables defined by an inner
                    // expression has a higher index.
                    Some((_, v)) if *v >= var => {}
                    // In all other cases, save the statement that declared the
                    // variable (either a `with` or a `for` statement), the
                    // loop that is immediately inside that statement, and the
                    // variable itself.
                    entry => *entry = Some((stmt_declaring_var, var)),
                }
            }
        }

        let mut dfs = self.dfs_with_scope(self.root.unwrap());

        while let Some(event) = dfs.next() {
            let (current_expr_id, ctx) = match event {
                Event::Enter(_) => continue,
                Event::Leave((expr_id, ctx)) => (expr_id, ctx),
            };

            match self.get(current_expr_id) {
                // Constants and `filesize` are fast and don't need to be moved
                // out of loops.
                Expr::Const(_) | Expr::Filesize | Expr::Symbol(_) => {}
                // All other expressions could be moved out of loops, except
                // those that are operands of a field access. That's because
                // the operands of a field access can depend on the results
                // produced by their siblings. For instance, in `foo[i].bar[0]`
                // `bar[0]` depends on the result produced by `foo[i]`,
                // `bar[0]` doesn't depend on `i` itself, but it depends on the
                // result of `foo[i]`, which does.
                _ if !matches!(ctx, EventContext::FieldAccess) => {
                    let current_depends_on =
                        depends_on[current_expr_id.0 as usize];

                    let parent_depends_on = self
                        .get_parent(current_expr_id)
                        .and_then(|e| depends_on[e.0 as usize]);

                    match (current_depends_on, parent_depends_on) {
                        (Some((c, _)), Some((p, _))) if c == p => continue,
                        _ => {}
                    }

                    match current_depends_on {
                        // The expression doesn't depend on any variable, move
                        // it out of the outermost loop, if any.
                        None => {
                            if let Some(outermost) = dfs.for_scopes().next() {
                                result.push((current_expr_id, outermost));
                            }
                        }
                        // The expression depends on some variable that was
                        // defined by `defining_expr`.
                        Some((defining_expr, _)) => {
                            // If the expression defining the variable is not a
                            // loop, there's nothing else to do.
                            match self.get(defining_expr) {
                                Expr::ForIn(_) => {}
                                _ => continue,
                            }
                            let mut scopes = dfs.for_scopes();
                            // Find the loop that defined the variable...
                            for expr_id in scopes.by_ref() {
                                if expr_id == defining_expr {
                                    break;
                                }
                            }
                            // .. and take the loop that inside directly inside
                            // the one that defined the variable
                            if let Some(inner_loop) = scopes.next() {
                                result.push((current_expr_id, inner_loop));
                            }
                            // Limit the number of candidates to a reasonable
                            // number.
                            if result.len() > 100 {
                                return result;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        result
    }

    /// Optimizes the IR (Intermediate Representation) by moving loop-invariant
    /// expressions outside the loop they are nested in.
    ///
    /// Loop hoisting optimizes performance by relocating expressions whose
    /// values remain constant across all iterations of the loop, thus reducing
    /// redundant calculations.
    ///
    /// For example:
    ///
    /// ```text
    /// for any i in (0..100) : (
    ///   for any j in (0..100) : (
    ///     a[j] == b[i] || func(1,2)
    ///   )
    /// )
    /// ```
    ///
    /// In this example, `a[j]` cannot be hoisted out of any loop, as it depends
    /// on `j`, which changes with each iteration of the inner loop. Conversely,
    /// `b[i]` can be hoisted out of the inner loop since it remains unchanged
    /// with respect to `j`, and `func(1,2)` can be hoisted out of both loops,
    /// as it is independent of both `i` and `j`.
    pub fn hoisting(&mut self) -> ExprId {
        for (expr_id, loop_expr_id) in self.find_hoisting_candidates() {
            let loop_parent = self.get_parent(loop_expr_id);

            let var_index = self
                .ancestors(loop_expr_id)
                .map(|expr_id| self.get(expr_id).stack_frame_size())
                .sum::<i32>();

            // Shift all variables with an index greater or equal than
            // var_index one position to the left in order to make room for
            // the new variable used by the `with` statement that will be
            // inserted.
            self.shift_vars(loop_expr_id, var_index, 1);

            let type_value = self.get(expr_id).type_value();
            let var = Var::new(0, type_value.ty(), var_index);

            // Replace the moved expression with variable. The moved expression
            // will be added as a declaration to the `with` statement.
            let replaced = self.replace(
                expr_id,
                Expr::Symbol(Box::new(Symbol::Var {
                    var,
                    type_value: type_value.clone(),
                })),
            );

            // The expression that initializes the variable is the one that is
            // being replaced with the variable.
            let var_init_stmt = self.push(replaced);

            // The body of the `with` statement is the loop. From now on
            // the loop's parent is the `with` statement.
            let with_stmt =
                self.with(vec![(var, var_init_stmt)], loop_expr_id);

            // The previous parent of the `with` statement becomes the parent
            // of the `with` statement, if not, the `with` statement is the new
            // root.
            if let Some(loop_parent) = loop_parent {
                self.set_parent(with_stmt, loop_parent);
                self.get_mut(loop_parent)
                    .replace_child(loop_expr_id, with_stmt);
            } else {
                self.root = Some(with_stmt);
            }
        }

        self.root.unwrap()
    }
}

impl IR {
    /// Creates a new [`Expr::FileSize`].
    pub fn filesize(&mut self) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Filesize);
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Const`].
    pub fn constant(&mut self, type_value: TypeValue) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Const(type_value));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Symbol`].
    pub fn ident(&mut self, symbol: Symbol) -> ExprId {
        if self.constant_folding {
            let type_value = symbol.type_value();
            if type_value.is_const() {
                return self.constant(type_value.clone());
            }
        }

        let expr_id = ExprId::from(self.nodes.len());
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Symbol(Box::new(symbol)));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Lookup`].
    pub fn lookup(
        &mut self,
        type_value: TypeValue,
        primary: ExprId,
        index: ExprId,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[primary.0 as usize] = expr_id;
        self.parents[index.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Lookup(Box::new(Lookup {
            type_value,
            primary,
            index,
        })));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Not`].
    pub fn not(&mut self, operand: ExprId) -> ExprId {
        if self.constant_folding {
            if let Some(v) = self.get(operand).try_as_const_bool() {
                return self.constant(TypeValue::const_bool_from(!v));
            }
        }
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[operand.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Not { operand });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::And`].
    pub fn and(&mut self, mut operands: Vec<ExprId>) -> Result<ExprId, Error> {
        if self.constant_folding {
            // Retain the operands whose value is not constant, or is
            // constant but false, remove those that are known to be
            // true. True values in the list of operands don't alter
            // the result of the AND operation.
            operands.retain(|op| {
                let type_value = self.get(*op).type_value().cast_to_bool();
                !type_value.is_const() || !type_value.as_bool()
            });

            // No operands left, all were true and therefore the AND is
            // also true.
            if operands.is_empty() {
                return Ok(self.constant(TypeValue::const_bool_from(true)));
            }

            // If any of the remaining operands is constant it has to be
            // false because true values were removed, the result is false
            // regardless of the operands with unknown values.
            if operands.iter().any(|op| self.get(*op).type_value().is_const())
            {
                return Ok(self.constant(TypeValue::const_bool_from(false)));
            }
        }

        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::And { operands });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        Ok(expr_id)
    }

    /// Creates a new [`Expr::Or`].
    pub fn or(&mut self, mut operands: Vec<ExprId>) -> Result<ExprId, Error> {
        if self.constant_folding {
            // Retain the operands whose value is not constant, or is
            // constant but true, remove those that are known to be
            // false. False values in the list of operands don't alter
            // the result of the OR operation.
            operands.retain(|op| {
                let type_value = self.get(*op).type_value().cast_to_bool();
                !type_value.is_const() || type_value.as_bool()
            });

            // No operands left, all were false and therefore the OR is
            // also false.
            if operands.is_empty() {
                return Ok(self.constant(TypeValue::const_bool_from(false)));
            }

            // If any of the remaining operands is constant it has to be
            // true because false values were removed, the result is true
            // regardless of the operands with unknown values.
            if operands.iter().any(|op| self.get(*op).type_value().is_const())
            {
                return Ok(self.constant(TypeValue::const_bool_from(true)));
            }
        }

        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Or { operands });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        Ok(expr_id)
    }

    /// Creates a new [`Expr::Minus`].
    pub fn minus(&mut self, operand: ExprId) -> ExprId {
        if self.constant_folding {
            match self.get(operand).type_value() {
                TypeValue::Integer(Value::Const(v)) => {
                    return self.constant(TypeValue::const_integer_from(-v));
                }
                TypeValue::Float(Value::Const(v)) => {
                    return self.constant(TypeValue::const_float_from(-v));
                }
                _ => {}
            }
        }

        let expr_id = ExprId::from(self.nodes.len());
        self.parents[operand.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Minus {
            operand,
            is_float: matches!(self.get(operand).ty(), Type::Float),
        });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Defined`].
    pub fn defined(&mut self, operand: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[operand.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Defined { operand });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::BitwiseNot`].
    pub fn bitwise_not(&mut self, operand: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[operand.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::BitwiseNot { operand });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::BitwiseAnd`].
    pub fn bitwise_and(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::BitwiseAnd { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::BitwiseOr`].
    pub fn bitwise_or(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::BitwiseOr { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::BitwiseXor`].
    pub fn bitwise_xor(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::BitwiseXor { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Shl`].
    pub fn shl(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Shl { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Shr`].
    pub fn shr(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Shr { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Add`].
    pub fn add(&mut self, operands: Vec<ExprId>) -> Result<ExprId, Error> {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));

        if self.constant_folding {
            if let Some(value) = self.fold_arithmetic(
                operands.as_slice(),
                is_float,
                |acc, x| acc + x,
            )? {
                return Ok(self.constant(value));
            }
        }

        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Add { operands, is_float });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        Ok(expr_id)
    }

    /// Creates a new [`Expr::Sub`].
    pub fn sub(&mut self, operands: Vec<ExprId>) -> Result<ExprId, Error> {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));

        if self.constant_folding {
            if let Some(value) = self.fold_arithmetic(
                operands.as_slice(),
                is_float,
                |acc, x| acc - x,
            )? {
                return Ok(self.constant(value));
            }
        }

        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Sub { operands, is_float });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        Ok(expr_id)
    }

    /// Creates a new [`Expr::Mul`].
    pub fn mul(&mut self, operands: Vec<ExprId>) -> Result<ExprId, Error> {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));

        if self.constant_folding {
            if let Some(value) = self.fold_arithmetic(
                operands.as_slice(),
                is_float,
                |acc, x| acc * x,
            )? {
                return Ok(self.constant(value));
            }
        }

        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Mul { operands, is_float });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        Ok(expr_id)
    }

    /// Creates a new [`Expr::Div`].
    pub fn div(&mut self, operands: Vec<ExprId>) -> Result<ExprId, Error> {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));
        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Div { operands, is_float });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        Ok(expr_id)
    }

    /// Creates a new [`Expr::Mod`].
    pub fn modulus(&mut self, operands: Vec<ExprId>) -> Result<ExprId, Error> {
        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Mod { operands });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        Ok(expr_id)
    }

    /// Creates a new [`Expr::FieldAccess`].
    pub fn field_access(&mut self, operands: Vec<ExprId>) -> ExprId {
        let type_value = self.get(*operands.last().unwrap()).type_value();

        // If the last operand is constant, the whole expression is constant.
        if self.constant_folding && type_value.is_const() {
            return self.constant(type_value.clone());
        }

        let expr_id = ExprId::from(self.nodes.len());
        for operand in operands.iter() {
            self.parents[operand.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::FieldAccess(Box::new(FieldAccess {
            operands,
            type_value,
        })));
        expr_id
    }

    /// Creates a new [`Expr::Eq`].
    pub fn eq(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Eq { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Ne`].
    pub fn ne(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Ne { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Ge`].
    pub fn ge(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Ge { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Gt`].
    pub fn gt(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Gt { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Le`].
    pub fn le(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Le { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Lt`].
    pub fn lt(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Lt { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Contains`].
    pub fn contains(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Contains { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::IContains`].
    pub fn icontains(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::IContains { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::StartsWith`].
    pub fn starts_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::StartsWith { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::IStartsWith`].
    pub fn istarts_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::IStartsWith { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::EndsWith`].
    pub fn ends_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::EndsWith { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::IEndsWith`].
    pub fn iends_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::IEndsWith { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::IEquals`].
    pub fn iequals(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::IEquals { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::Matches`].
    pub fn matches(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        self.parents[lhs.0 as usize] = expr_id;
        self.parents[rhs.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::Matches { lhs, rhs });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternMatch`]
    pub fn pattern_match(
        &mut self,
        pattern: PatternIdx,
        anchor: MatchAnchor,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        match &anchor {
            MatchAnchor::None => {}
            MatchAnchor::At(expr) => {
                self.parents[expr.0 as usize] = expr_id;
            }
            MatchAnchor::In(range) => {
                self.parents[range.lower_bound.0 as usize] = expr_id;
                self.parents[range.upper_bound.0 as usize] = expr_id;
            }
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::PatternMatch { pattern, anchor });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternMatchVar`]
    pub fn pattern_match_var(
        &mut self,
        symbol: Symbol,
        anchor: MatchAnchor,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        match &anchor {
            MatchAnchor::None => {}
            MatchAnchor::At(expr) => {
                self.parents[expr.0 as usize] = expr_id;
            }
            MatchAnchor::In(range) => {
                self.parents[range.lower_bound.0 as usize] = expr_id;
                self.parents[range.upper_bound.0 as usize] = expr_id;
            }
        }
        self.parents.push(ExprId::none());
        self.nodes
            .push(Expr::PatternMatchVar { symbol: Box::new(symbol), anchor });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternLength`]
    pub fn pattern_length(
        &mut self,
        pattern: PatternIdx,
        index: Option<ExprId>,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        if let Some(index) = &index {
            self.parents[index.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::PatternLength { pattern, index });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternLengthVar`]
    pub fn pattern_length_var(
        &mut self,
        symbol: Symbol,
        index: Option<ExprId>,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        if let Some(index) = &index {
            self.parents[index.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes
            .push(Expr::PatternLengthVar { symbol: Box::new(symbol), index });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternOffset`]
    pub fn pattern_offset(
        &mut self,
        pattern: PatternIdx,
        index: Option<ExprId>,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        if let Some(index) = &index {
            self.parents[index.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::PatternOffset { pattern, index });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternOffsetVar`]
    pub fn pattern_offset_var(
        &mut self,
        symbol: Symbol,
        index: Option<ExprId>,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        if let Some(index) = &index {
            self.parents[index.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes
            .push(Expr::PatternOffsetVar { symbol: Box::new(symbol), index });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternCount`]
    pub fn pattern_count(
        &mut self,
        pattern: PatternIdx,
        range: Option<Range>,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        if let Some(range) = &range {
            self.parents[range.lower_bound.0 as usize] = expr_id;
            self.parents[range.upper_bound.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::PatternCount { pattern, range });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::PatternCountVar`]
    pub fn pattern_count_var(
        &mut self,
        symbol: Symbol,
        range: Option<Range>,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        if let Some(range) = &range {
            self.parents[range.lower_bound.0 as usize] = expr_id;
            self.parents[range.upper_bound.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes
            .push(Expr::PatternCountVar { symbol: Box::new(symbol), range });
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::FuncCall`]
    pub fn func_call(
        &mut self,
        object: Option<ExprId>,
        args: Vec<ExprId>,
        func: Rc<Func>,
        type_value: TypeValue,
        signature_index: usize,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        for arg in args.iter() {
            self.parents[arg.0 as usize] = expr_id
        }
        if let Some(obj) = &object {
            self.parents[obj.0 as usize] = expr_id;
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::FuncCall(Box::new(FuncCall {
            object,
            args,
            func,
            type_value,
            signature_index,
        })));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::OfExprTuple`]
    pub fn of_expr_tuple(
        &mut self,
        quantifier: Quantifier,
        for_vars: ForVars,
        next_expr_var: Var,
        items: Vec<ExprId>,
        anchor: MatchAnchor,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        match quantifier {
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                self.parents[expr.0 as usize] = expr_id
            }
            _ => {}
        }
        for item in items.iter() {
            self.parents[item.0 as usize] = expr_id;
        }
        match &anchor {
            MatchAnchor::None => {}
            MatchAnchor::At(expr) => {
                self.parents[expr.0 as usize] = expr_id;
            }
            MatchAnchor::In(range) => {
                self.parents[range.lower_bound.0 as usize] = expr_id;
                self.parents[range.upper_bound.0 as usize] = expr_id;
            }
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::OfExprTuple(Box::new(OfExprTuple {
            quantifier,
            items,
            anchor,
            for_vars,
            next_expr_var,
        })));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::OfPatternSet`]
    pub fn of_pattern_set(
        &mut self,
        quantifier: Quantifier,
        for_vars: ForVars,
        next_pattern_var: Var,
        items: Vec<PatternIdx>,
        anchor: MatchAnchor,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        match quantifier {
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                self.parents[expr.0 as usize] = expr_id
            }
            _ => {}
        }
        match &anchor {
            MatchAnchor::None => {}
            MatchAnchor::At(expr) => {
                self.parents[expr.0 as usize] = expr_id;
            }
            MatchAnchor::In(range) => {
                self.parents[range.lower_bound.0 as usize] = expr_id;
                self.parents[range.upper_bound.0 as usize] = expr_id;
            }
        }
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::OfPatternSet(Box::new(OfPatternSet {
            quantifier,
            items,
            anchor,
            for_vars,
            next_pattern_var,
        })));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::ForOf`].
    pub fn for_of(
        &mut self,
        quantifier: Quantifier,
        variable: Var,
        for_vars: ForVars,
        pattern_set: Vec<PatternIdx>,
        body: ExprId,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        match quantifier {
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                self.parents[expr.0 as usize] = expr_id
            }
            _ => {}
        }
        self.parents[body.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::ForOf(Box::new(ForOf {
            quantifier,
            variable,
            pattern_set,
            body,
            for_vars,
        })));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::ForIn`].
    pub fn for_in(
        &mut self,
        quantifier: Quantifier,
        variables: Vec<Var>,
        for_vars: ForVars,
        iterable_var: Var,
        iterable: Iterable,
        body: ExprId,
    ) -> ExprId {
        let expr_id = ExprId::from(self.nodes.len());
        match quantifier {
            Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                self.parents[expr.0 as usize] = expr_id
            }
            _ => {}
        }
        match &iterable {
            Iterable::Range(range) => {
                self.parents[range.lower_bound.0 as usize] = expr_id;
                self.parents[range.upper_bound.0 as usize] = expr_id;
            }
            Iterable::ExprTuple(exprs) => {
                for expr in exprs.iter() {
                    self.parents[expr.0 as usize] = expr_id;
                }
            }
            Iterable::Expr(expr) => {
                self.parents[expr.0 as usize] = expr_id;
            }
        }
        self.parents[body.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::ForIn(Box::new(ForIn {
            quantifier,
            variables,
            for_vars,
            iterable_var,
            iterable,
            body,
        })));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }

    /// Creates a new [`Expr::With`].
    pub fn with(
        &mut self,
        declarations: Vec<(Var, ExprId)>,
        body: ExprId,
    ) -> ExprId {
        let type_value = self.get(body).type_value();
        let expr_id = ExprId::from(self.nodes.len());
        for (_, expr) in declarations.iter() {
            self.parents[expr.0 as usize] = expr_id;
        }
        self.parents[body.0 as usize] = expr_id;
        self.parents.push(ExprId::none());
        self.nodes.push(Expr::With(Box::new(With {
            type_value,
            declarations,
            body,
        })));
        debug_assert_eq!(self.parents.len(), self.nodes.len());
        expr_id
    }
}

impl IR {
    fn fold_arithmetic<F>(
        &mut self,
        operands: &[ExprId],
        is_float: bool,
        f: F,
    ) -> Result<Option<TypeValue>, Error>
    where
        F: FnMut(f64, f64) -> f64,
    {
        debug_assert!(!operands.is_empty());

        // Some operands are not constant, there's nothing to fold.
        if !operands.iter().all(|op| self.get(*op).type_value().is_const()) {
            return Ok(None);
        }

        // Fold all operands into a single value.
        let folded = operands
            .iter()
            .map(|op| match self.get(*op).type_value() {
                TypeValue::Integer(Value::Const(v)) => v as f64,
                TypeValue::Float(Value::Const(v)) => v,
                _ => unreachable!(),
            })
            .reduce(f) // It's safe to call unwrap because there must be at least
            // one operand.
            .unwrap();

        if is_float {
            Ok(Some(TypeValue::const_float_from(folded)))
        } else if folded >= i64::MIN as f64 && folded <= i64::MAX as f64 {
            Ok(Some(TypeValue::const_integer_from(folded as i64)))
        } else {
            Err(Error::NumberOutOfRange)
        }
    }
}

impl Debug for IR {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut level = 1;

        let anchor_str = |anchor: &MatchAnchor| match anchor {
            MatchAnchor::None => "",
            MatchAnchor::At(_) => " AT",
            MatchAnchor::In(_) => " IN",
        };

        let range_str = |range: &Option<_>| {
            if range.is_some() { " IN" } else { "" }
        };

        let index_str = |index: &Option<_>| {
            if index.is_some() { " INDEX" } else { "" }
        };

        let mut expr_hashes = vec![0; self.nodes.len()];

        self.compute_expr_hashes(self.root.unwrap(), |expr_id, hash| {
            expr_hashes[expr_id.0 as usize] = hash;
        });

        for event in self.dfs_iter(self.root.unwrap()) {
            match event {
                Event::Leave(_) => level -= 1,
                Event::Enter((expr_id, expr,_)) => {
                    for _ in 0..level {
                        write!(f, "  ")?;
                    }
                    level += 1;
                    write!(f, "{:?}: ", expr_id)?;
                    let expr_hash = expr_hashes[expr_id.0 as usize];
                    match expr {
                        Expr::Const(c) => write!(f, "CONST {}", c)?,
                        Expr::Filesize => write!(f, "FILESIZE")?,
                        Expr::Not { .. } => write!(f, "NOT -- hash: {:#08x}", expr_hash)?,
                        Expr::And { .. } => write!(f, "AND -- hash: {:#08x}", expr_hash)?,
                        Expr::Or { .. } => write!(f, "OR -- hash: {:#08x}", expr_hash)?,
                        Expr::Minus { .. } => write!(f, "MINUS -- hash: {:#08x}", expr_hash)?,
                        Expr::Add { .. } => write!(f, "ADD -- hash: {:#08x}", expr_hash)?,
                        Expr::Sub { .. } => write!(f, "SUB -- hash: {:#08x}", expr_hash)?,
                        Expr::Mul { .. } => write!(f, "MUL -- hash: {:#08x}", expr_hash)?,
                        Expr::Div { .. } => write!(f, "DIV -- hash: {:#08x}", expr_hash)?,
                        Expr::Mod { .. } => write!(f, "MOD -- hash: {:#08x}", expr_hash)?,
                        Expr::Shl { .. } => write!(f, "SHL -- hash: {:#08x}", expr_hash)?,
                        Expr::Shr { .. } => write!(f, "SHR -- hash: {:#08x}", expr_hash)?,
                        Expr::Eq { .. } => write!(f, "EQ -- hash: {:#08x}", expr_hash)?,
                        Expr::Ne { .. } => write!(f, "NE -- hash: {:#08x}", expr_hash)?,
                        Expr::Lt { .. } => write!(f, "LT -- hash: {:#08x}", expr_hash)?,
                        Expr::Gt { .. } => write!(f, "GT -- hash: {:#08x}", expr_hash)?,
                        Expr::Le { .. } => write!(f, "LE -- hash: {:#08x}", expr_hash)?,
                        Expr::Ge { .. } => write!(f, "GE -- hash: {:#08x}", expr_hash)?,
                        Expr::BitwiseNot { .. } => write!(f, "BITWISE_NOT -- hash: {:#08x}", expr_hash)?,
                        Expr::BitwiseAnd { .. } => write!(f, "BITWISE_AND -- hash: {:#08x}", expr_hash)?,
                        Expr::BitwiseOr { .. } => write!(f, "BITWISE_OR -- hash: {:#08x}", expr_hash)?,
                        Expr::BitwiseXor { .. } => write!(f, "BITWISE_XOR -- hash: {:#08x}", expr_hash)?,
                        Expr::Contains { .. } => write!(f, "CONTAINS -- hash: {:#08x}", expr_hash)?,
                        Expr::IContains { .. } => write!(f, "ICONTAINS -- hash: {:#08x}", expr_hash)?,
                        Expr::StartsWith { .. } => write!(f, "STARTS_WITH -- hash: {:#08x}", expr_hash)?,
                        Expr::IStartsWith { .. } => write!(f, "ISTARTS_WITH -- hash: {:#08x}", expr_hash)?,
                        Expr::EndsWith { .. } => write!(f, "ENDS_WITH -- hash: {:#08x}", expr_hash)?,
                        Expr::IEndsWith { .. } => write!(f, "IENDS_WITH -- hash: {:#08x}", expr_hash)?,
                        Expr::IEquals { .. } => write!(f, "IEQUALS -- hash: {:#08x}", expr_hash)?,
                        Expr::Matches { .. } => write!(f, "MATCHES -- hash: {:#08x}", expr_hash)?,
                        Expr::Defined { .. } => write!(f, "DEFINED -- hash: {:#08x}", expr_hash)?,
                        Expr::FieldAccess { .. } => write!(f, "FIELD_ACCESS -- hash: {:#08x}", expr_hash)?,
                        Expr::With { .. } => write!(f, "WITH -- hash: {:#08x}", expr_hash)?,
                        Expr::Symbol(symbol) => write!(f, "SYMBOL {:?}", symbol)?,
                        Expr::OfExprTuple(_) => write!(f, "OF -- hash: {:#08x}", expr_hash)?,
                        Expr::OfPatternSet(_) => write!(f, "OF -- hash: {:#08x}", expr_hash)?,
                        Expr::ForOf(_) => write!(f, "FOR_OF -- hash: {:#08x}", expr_hash)?,
                        Expr::ForIn(_) => write!(f, "FOR_IN -- hash: {:#08x}", expr_hash)?,
                        Expr::Lookup(_) => write!(f, "LOOKUP -- hash: {:#08x}", expr_hash)?,
                        Expr::FuncCall(func_call) => write!(f,
                            "FN_CALL {} -- hash: {:#08x}",
                            func_call.mangled_name(),
                            expr_hash
                        )?,
                        Expr::PatternMatch { pattern, anchor } => write!(
                            f,
                            "PATTERN_MATCH {:?}{} -- hash: {:#08x}",
                            pattern,
                            anchor_str(anchor),
                            expr_hash
                        )?,
                        Expr::PatternMatchVar { symbol, anchor } => write!(
                            f,
                            "PATTERN_MATCH {:?}{} -- hash: {:#08x}",
                            symbol,
                            anchor_str(anchor),
                            expr_hash
                        )?,
                        Expr::PatternCount { pattern, range } => write!(
                            f,
                            "PATTERN_COUNT {:?}{} -- hash: {:#08x}",
                            pattern,
                            range_str(range),
                            expr_hash
                        )?,
                        Expr::PatternCountVar { symbol, range } => write!(
                            f,
                            "PATTERN_COUNT {:?}{} -- hash: {:#08x}",
                            symbol,
                            range_str(range),
                            expr_hash
                        )?,
                        Expr::PatternOffset { pattern, index } => write!(
                            f,
                            "PATTERN_OFFSET {:?}{} -- hash: {:#08x}",
                            pattern,
                            index_str(index),
                            expr_hash
                        )?,
                        Expr::PatternOffsetVar { symbol, index } => write!(
                            f,
                            "PATTERN_OFFSET {:?}{} -- hash: {:#08x}",
                            symbol,
                            index_str(index),
                            expr_hash
                        )?,
                        Expr::PatternLength { pattern, index } => write!(
                            f,
                            "PATTERN_LENGTH {:?}{} -- hash: {:#08x}",
                            pattern,
                            index_str(index),
                            expr_hash
                        )?,
                        Expr::PatternLengthVar { symbol, index } => write!(
                            f,
                            "PATTERN_LENGTH {:?}{} -- hash: {:#08x}",
                            symbol,
                            index_str(index),
                            expr_hash
                        )?,
                    }
                    writeln!(f, " -- parent: {:?} ", self.parents[expr_id.0 as usize])?;

                }
            }
        }

        Ok(())
    }
}

/// Iterator that returns the ancestors for a given expression in the
/// IR tree.
///
/// The first item returned by the iterator is the parent of the original
/// expression, then the parent's parent, and so on until reaching the
/// root node.
pub(crate) struct Ancestors<'a> {
    ir: &'a IR,
    current: ExprId,
}

impl<'a> Iterator for Ancestors<'a> {
    type Item = ExprId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current == ExprId::none() {
            return None;
        }
        self.current = self.ir.parents[self.current.0 as usize];
        if self.current == ExprId::none() {
            return None;
        }
        Some(self.current)
    }
}

/// Iterator that yields the children of a given expression in the IR tree.
pub(crate) struct Children<'a> {
    dfs: DFSIter<'a>,
}

impl<'a> Iterator for Children<'a> {
    type Item = ExprId;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.dfs.next()? {
                Event::Enter((expr_id, _, _)) => {
                    self.dfs.prune();
                    return Some(expr_id);
                }
                Event::Leave(_) => {}
            }
        }
    }
}

/// Intermediate representation (IR) for an expression.
pub(crate) enum Expr {
    /// Constant value (i.e: the value is known at compile time).
    /// The value in `TypeValue` is not `None`.
    Const(TypeValue),

    /// `filesize` expression.
    Filesize,

    /// Boolean `not` expression.
    Not { operand: ExprId },

    /// Boolean `and` expression.
    And { operands: Vec<ExprId> },

    /// Boolean `or` expression.
    Or { operands: Vec<ExprId> },

    /// Arithmetic minus.
    Minus { is_float: bool, operand: ExprId },

    /// Arithmetic addition (`+`) expression.
    Add { is_float: bool, operands: Vec<ExprId> },

    /// Arithmetic subtraction (`-`) expression.
    Sub { is_float: bool, operands: Vec<ExprId> },

    /// Arithmetic multiplication (`*`) expression.
    Mul { is_float: bool, operands: Vec<ExprId> },

    /// Arithmetic division (`\`) expression.
    Div { is_float: bool, operands: Vec<ExprId> },

    /// Arithmetic modulus (`%`) expression.
    Mod { operands: Vec<ExprId> },

    /// Bitwise not (`~`) expression.
    BitwiseNot { operand: ExprId },

    /// Bitwise and (`&`) expression.
    BitwiseAnd { rhs: ExprId, lhs: ExprId },

    /// Bitwise shift left (`<<`) expression.
    Shl { rhs: ExprId, lhs: ExprId },

    /// Bitwise shift right (`>>`) expression.
    Shr { rhs: ExprId, lhs: ExprId },

    /// Bitwise or (`|`) expression.
    BitwiseOr { rhs: ExprId, lhs: ExprId },

    /// Bitwise xor (`^`) expression.
    BitwiseXor { rhs: ExprId, lhs: ExprId },

    /// Equal (`==`) expression.
    Eq { rhs: ExprId, lhs: ExprId },

    /// Not equal (`!=`) expression.
    Ne { rhs: ExprId, lhs: ExprId },

    /// Less than (`<`) expression.
    Lt { rhs: ExprId, lhs: ExprId },

    /// Greater than (`>`) expression.
    Gt { rhs: ExprId, lhs: ExprId },

    /// Less or equal (`<=`) expression.
    Le { rhs: ExprId, lhs: ExprId },

    /// Greater or equal (`>=`) expression.
    Ge { rhs: ExprId, lhs: ExprId },

    /// `contains` expression.
    Contains { rhs: ExprId, lhs: ExprId },

    /// `icontains` expression
    IContains { rhs: ExprId, lhs: ExprId },

    /// `startswith` expression.
    StartsWith { rhs: ExprId, lhs: ExprId },

    /// `istartswith` expression
    IStartsWith { rhs: ExprId, lhs: ExprId },

    /// `endswith` expression.
    EndsWith { rhs: ExprId, lhs: ExprId },

    /// `iendswith` expression
    IEndsWith { rhs: ExprId, lhs: ExprId },

    /// `iequals` expression.
    IEquals { rhs: ExprId, lhs: ExprId },

    /// `matches` expression.
    Matches { rhs: ExprId, lhs: ExprId },

    /// A `defined` expression (e.g. `defined foo`)
    Defined { operand: ExprId },

    /// Pattern match expression (e.g. `$a`)
    PatternMatch { pattern: PatternIdx, anchor: MatchAnchor },

    /// Pattern match expression where the pattern is variable (e.g: `$`).
    PatternMatchVar { symbol: Box<Symbol>, anchor: MatchAnchor },

    /// Pattern count expression (e.g. `#a`, `#a in (0..10)`)
    PatternCount { pattern: PatternIdx, range: Option<Range> },

    /// Pattern count expression where the pattern is variable (e.g. `#`, `# in (0..10)`)
    PatternCountVar { symbol: Box<Symbol>, range: Option<Range> },

    /// Pattern offset expression (e.g. `@a`, `@a[1]`)
    PatternOffset { pattern: PatternIdx, index: Option<ExprId> },

    /// Pattern count expression where the pattern is variable (e.g. `@`, `@[1]`)
    PatternOffsetVar { symbol: Box<Symbol>, index: Option<ExprId> },

    /// Pattern length expression (e.g. `!a`, `!a[1]`)
    PatternLength { pattern: PatternIdx, index: Option<ExprId> },

    /// Pattern count expression where the pattern is variable (e.g. `!`, `![1]`)
    PatternLengthVar { symbol: Box<Symbol>, index: Option<ExprId> },

    /// A symbol can be a variable, rule, field or function.
    Symbol(Box<Symbol>),

    /// A `with <identifiers> : ...` expression. (e.g. `with $a, $b : ( ... )`)
    With(Box<With>),

    /// Field access expression (e.g. `foo.bar.baz`)
    FieldAccess(Box<FieldAccess>),

    /// Function call.
    FuncCall(Box<FuncCall>),

    /// An `of` expression with a tuple of expressions (e.g. `1 of (true, false)`).
    OfExprTuple(Box<OfExprTuple>),

    /// An `of` expression with at pattern set (e.g. `1 of ($a, $b)`, `all of them`).
    OfPatternSet(Box<OfPatternSet>),

    /// A `for <quantifier> of ...` expression. (e.g. `for any of ($a, $b) : ( ... )`)
    ForOf(Box<ForOf>),

    /// A `for <quantifier> <vars> in ...` expression. (e.g. `for all i in (1..100) : ( ... )`)
    ForIn(Box<ForIn>),

    /// Array or dictionary lookup expression (e.g. `array[1]`, `dict["key"]`)
    Lookup(Box<Lookup>),
}

/// A lookup operation in an array or dictionary.
pub(crate) struct Lookup {
    pub type_value: TypeValue,
    pub primary: ExprId,
    pub index: ExprId,
}

/// A field access expression.
pub(crate) struct FieldAccess {
    pub type_value: TypeValue,
    pub operands: Vec<ExprId>,
}

/// An expression representing a function or method call.
pub(crate) struct FuncCall {
    pub object: Option<ExprId>,
    /// The function or method being called.
    pub func: Rc<Func>,
    /// The arguments passed to the function or method in this call.
    pub args: Vec<ExprId>,
    /// Type and value for the result.
    pub type_value: TypeValue,
    /// Due to function overloading, the same function may have multiple
    /// signatures. This field indicates the index of the signature that
    /// matched the provided arguments.
    pub signature_index: usize,
}

impl FuncCall {
    /// Returns the mangled function name for this function call.
    pub fn signature(&self) -> &FuncSignature {
        &self.func.signatures()[self.signature_index]
    }

    /// Returns the mangled function name for this function call.
    pub fn mangled_name(&self) -> &str {
        self.signature().mangled_name.as_str()
    }
}

/// An `of` expression with a tuple of expressions (e.g. `1 of (true, false)`).
pub(crate) struct OfExprTuple {
    pub quantifier: Quantifier,
    pub items: Vec<ExprId>,
    pub for_vars: ForVars,
    pub next_expr_var: Var,
    pub anchor: MatchAnchor,
}

/// An `of` expression with at pattern set (e.g. `1 of ($a, $b)`, `all of them`).
pub(crate) struct OfPatternSet {
    pub quantifier: Quantifier,
    pub items: Vec<PatternIdx>,
    pub for_vars: ForVars,
    pub next_pattern_var: Var,
    pub anchor: MatchAnchor,
}

/// A `for .. of` expression (e.g `for all of them : (..)`,
/// `for 1 of ($a,$b) : (..)`)
pub(crate) struct ForOf {
    pub quantifier: Quantifier,
    pub variable: Var,
    pub for_vars: ForVars,
    pub pattern_set: Vec<PatternIdx>,
    pub body: ExprId,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
pub(crate) struct ForIn {
    pub quantifier: Quantifier,
    pub variables: Vec<Var>,
    pub for_vars: ForVars,
    pub iterable_var: Var,
    pub iterable: Iterable,
    pub body: ExprId,
}

/// A quantifier used in `for` and `of` expressions.
pub(crate) enum Quantifier {
    None,
    All,
    Any,
    Percentage(ExprId),
    Expr(ExprId),
}

/// Variables used in `for` loop.
#[derive(PartialEq, Eq)]
pub(crate) struct ForVars {
    /// Maximum number of iterations.
    pub n: Var,
    /// Current iteration number.
    pub i: Var,
    /// Number of loop iterations that must return true.
    pub max_count: Var,
    /// Number of loop iterations that actually returned true.
    pub count: Var,
}

impl ForVars {
    pub fn shift(&mut self, after: i32, amount: i32) {
        self.n.shift(after, amount);
        self.i.shift(after, amount);
        self.max_count.shift(after, amount);
        self.count.shift(after, amount);
    }
}

/// A `with <identifiers> : ...` expression. (e.g. `with $a, $b : ( ... )`)
pub(crate) struct With {
    pub type_value: TypeValue,
    pub declarations: Vec<(Var, ExprId)>,
    pub body: ExprId,
}

/// In expressions like `$a at 0` and `$b in (0..10)`, this type represents the
/// anchor (e.g. `at <expr>`, `in <range>`).
///
/// The anchor is the part of the expression that restricts the offset range
/// where the match can occur.
/// (e.g. `at <expr>`, `in <range>`).
pub(crate) enum MatchAnchor {
    None,
    At(ExprId),
    In(Range),
}

/// A pair of values conforming a range (e.g. `(0..10)`).
pub(crate) struct Range {
    pub lower_bound: ExprId,
    pub upper_bound: ExprId,
}

/// Possible iterable expressions that can use in a [`ForIn`].
pub(crate) enum Iterable {
    Range(Range),
    ExprTuple(Vec<ExprId>),
    Expr(ExprId),
}

impl Index<ExprId> for [Expr] {
    type Output = Expr;
    fn index(&self, index: ExprId) -> &Self::Output {
        self.get(index.0 as usize).unwrap()
    }
}

impl Hash for Expr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        discriminant(self).hash(state);
        match self {
            Expr::Const(type_value) => type_value.hash(state),
            Expr::Symbol(symbol) => symbol.hash(state),
            Expr::PatternMatch { pattern, anchor } => {
                pattern.hash(state);
                discriminant(anchor).hash(state);
            }
            Expr::PatternMatchVar { symbol, anchor } => {
                symbol.hash(state);
                discriminant(anchor).hash(state);
            }
            Expr::PatternCount { pattern, range } => {
                pattern.hash(state);
                discriminant(range).hash(state);
            }
            Expr::PatternCountVar { symbol, range } => {
                symbol.hash(state);
                discriminant(range).hash(state);
            }
            Expr::PatternOffset { pattern, index } => {
                pattern.hash(state);
                discriminant(index).hash(state);
            }
            Expr::PatternOffsetVar { symbol, index } => {
                symbol.hash(state);
                discriminant(index).hash(state);
            }
            Expr::PatternLength { pattern, index } => {
                pattern.hash(state);
                discriminant(index).hash(state);
            }
            Expr::PatternLengthVar { symbol, index } => {
                symbol.hash(state);
                discriminant(index).hash(state);
            }
            Expr::FuncCall(func_call) => {
                func_call.func.hash(state);
                func_call.signature_index.hash(state);
            }
            Expr::OfExprTuple(of_expr_tuple) => {
                discriminant(&of_expr_tuple.quantifier).hash(state);
                discriminant(&of_expr_tuple.anchor).hash(state);
            }
            Expr::OfPatternSet(of_pattern_set) => {
                discriminant(&of_pattern_set.quantifier).hash(state);
                discriminant(&of_pattern_set.anchor).hash(state);
                for item in of_pattern_set.items.iter() {
                    item.hash(state);
                }
            }
            Expr::ForOf(for_of) => {
                discriminant(&for_of.quantifier).hash(state);
                for item in for_of.pattern_set.iter() {
                    item.hash(state);
                }
            }
            Expr::ForIn(for_in) => {
                discriminant(&for_in.quantifier).hash(state);
                discriminant(&for_in.iterable).hash(state);
            }
            _ => {}
        }
    }
}

impl Expr {
    /// Returns the size of the stack frame for this expression.
    pub fn stack_frame_size(&self) -> i32 {
        match self {
            Expr::With(with) => with.declarations.len() as i32,
            Expr::ForOf(_) => VarStack::FOR_OF_FRAME_SIZE,
            Expr::ForIn(_) => VarStack::FOR_IN_FRAME_SIZE,
            Expr::OfExprTuple(_) => VarStack::OF_FRAME_SIZE,
            Expr::OfPatternSet(_) => VarStack::OF_FRAME_SIZE,
            _ => 0,
        }
    }

    /// Increase the index of variables used by this expression (including
    /// its subexpressions) by a certain amount.
    ///
    /// The index of variables used by the expression identified by `expr_id`
    /// will be increased by `shift_amount` if the variable has an index that
    /// is larger or equal to `from_index`.
    ///
    /// The purpose of this function is displacing every variable that resides
    /// at some index and above to a higher index, creating a "hole" that can
    /// be occupied by other variables.
    pub fn shift_vars(&mut self, from_index: i32, shift_amount: i32) {
        match self {
            Expr::Symbol(symbol)
            | Expr::PatternMatchVar { symbol, .. }
            | Expr::PatternCountVar { symbol, .. }
            | Expr::PatternOffsetVar { symbol, .. }
            | Expr::PatternLengthVar { symbol, .. } => {
                if let Symbol::Var { var, .. } = symbol.as_mut() {
                    var.shift(from_index, shift_amount)
                }
            }

            Expr::With(with) => {
                for (v, _) in with.declarations.iter_mut() {
                    v.shift(from_index, shift_amount)
                }
            }

            Expr::OfExprTuple(of) => {
                of.next_expr_var.shift(from_index, shift_amount);
                of.for_vars.shift(from_index, shift_amount);
            }

            Expr::OfPatternSet(of) => {
                of.next_pattern_var.shift(from_index, shift_amount);
                of.for_vars.shift(from_index, shift_amount);
            }

            Expr::ForOf(for_of) => {
                for_of.for_vars.shift(from_index, shift_amount);
            }

            Expr::ForIn(for_in) => {
                for_in.iterable_var.shift(from_index, shift_amount);
                for v in for_in.variables.iter_mut() {
                    v.shift(from_index, shift_amount)
                }
                for_in.for_vars.shift(from_index, shift_amount);
            }

            _ => {}
        }
    }

    /// Search for a specific child of the current expression and replace it
    /// with `replacement`.
    pub fn replace_child(&mut self, child: ExprId, replacement: ExprId) {
        let replace_in_slice = |exprs: &mut [ExprId]| {
            for expr in exprs {
                if *expr == child {
                    *expr = replacement;
                }
            }
        };

        let replace_in_quantifier =
            |quantifier: &mut Quantifier| match quantifier {
                Quantifier::None | Quantifier::All | Quantifier::Any => {}
                Quantifier::Percentage(expr) | Quantifier::Expr(expr) => {
                    if *expr == child {
                        *expr = replacement;
                    }
                }
            };

        let replace_in_range = |range: &mut Range| {
            if range.lower_bound == child {
                range.lower_bound = replacement;
            }
            if range.upper_bound == child {
                range.upper_bound = replacement;
            }
        };

        let replace_in_anchor = |anchor: &mut MatchAnchor| match anchor {
            MatchAnchor::None => {}
            MatchAnchor::At(expr) => {
                if *expr == child {
                    *expr = replacement;
                }
            }
            MatchAnchor::In(range) => replace_in_range(range),
        };

        match self {
            Expr::Const(_) => {}
            Expr::Filesize => {}
            Expr::Symbol(_) => {}

            Expr::Not { operand }
            | Expr::Minus { operand, .. }
            | Expr::Defined { operand }
            | Expr::BitwiseNot { operand } => {
                if *operand == child {
                    *operand = replacement;
                }
            }

            Expr::And { operands }
            | Expr::Or { operands }
            | Expr::Add { operands, .. }
            | Expr::Sub { operands, .. }
            | Expr::Mul { operands, .. }
            | Expr::Div { operands, .. }
            | Expr::Mod { operands, .. } => {
                replace_in_slice(operands.as_mut_slice());
            }

            Expr::BitwiseAnd { lhs, rhs }
            | Expr::Shl { lhs, rhs }
            | Expr::Shr { lhs, rhs }
            | Expr::BitwiseOr { lhs, rhs }
            | Expr::BitwiseXor { lhs, rhs }
            | Expr::Eq { lhs, rhs }
            | Expr::Ne { lhs, rhs }
            | Expr::Lt { lhs, rhs }
            | Expr::Gt { lhs, rhs }
            | Expr::Le { lhs, rhs }
            | Expr::Ge { lhs, rhs }
            | Expr::Contains { lhs, rhs }
            | Expr::IContains { lhs, rhs }
            | Expr::StartsWith { lhs, rhs }
            | Expr::IStartsWith { lhs, rhs }
            | Expr::EndsWith { lhs, rhs }
            | Expr::IEndsWith { lhs, rhs }
            | Expr::IEquals { lhs, rhs }
            | Expr::Matches { lhs, rhs } => {
                if *lhs == child {
                    *lhs = replacement;
                }
                if *rhs == child {
                    *rhs = replacement;
                }
            }
            Expr::PatternMatch { anchor, .. }
            | Expr::PatternMatchVar { anchor, .. } => {
                replace_in_anchor(anchor)
            }

            Expr::PatternCount { range, .. }
            | Expr::PatternCountVar { range, .. } => {
                if let Some(range) = range {
                    replace_in_range(range)
                }
            }

            Expr::PatternOffset { index, .. }
            | Expr::PatternOffsetVar { index, .. }
            | Expr::PatternLength { index, .. }
            | Expr::PatternLengthVar { index, .. } => {
                if let Some(index) = index {
                    if *index == child {
                        *index = replacement
                    }
                }
            }

            Expr::With(with) => {
                for (_, expr) in with.declarations.iter_mut() {
                    if *expr == child {
                        *expr = replacement
                    }
                }
                if with.body == child {
                    with.body = replacement
                }
            }

            Expr::FieldAccess(field_access) => {
                replace_in_slice(field_access.operands.as_mut_slice());
            }

            Expr::FuncCall(func_call) => {
                if let Some(expr) = &mut func_call.object {
                    if *expr == child {
                        *expr = replacement
                    }
                }
                replace_in_slice(func_call.args.as_mut_slice());
            }

            Expr::OfExprTuple(of) => {
                replace_in_slice(of.items.as_mut_slice());
                replace_in_anchor(&mut of.anchor);
            }

            Expr::OfPatternSet(of) => {
                replace_in_anchor(&mut of.anchor);
            }

            Expr::ForOf(for_of) => {
                replace_in_quantifier(&mut for_of.quantifier);
                if for_of.body == child {
                    for_of.body = replacement
                }
            }

            Expr::ForIn(for_in) => {
                replace_in_quantifier(&mut for_in.quantifier);
                if for_in.body == child {
                    for_in.body = replacement
                }
            }

            Expr::Lookup(lookup) => {
                if lookup.primary == child {
                    lookup.primary = replacement;
                }
                if lookup.index == child {
                    lookup.index = replacement;
                }
            }
        }
    }

    /// Returns the type of this expression.
    pub fn ty(&self) -> Type {
        match self {
            Expr::Const(type_value) => type_value.ty(),

            Expr::Defined { .. }
            | Expr::Not { .. }
            | Expr::And { .. }
            | Expr::Or { .. }
            | Expr::Eq { .. }
            | Expr::Ne { .. }
            | Expr::Ge { .. }
            | Expr::Gt { .. }
            | Expr::Le { .. }
            | Expr::Lt { .. }
            | Expr::Contains { .. }
            | Expr::IContains { .. }
            | Expr::StartsWith { .. }
            | Expr::IStartsWith { .. }
            | Expr::EndsWith { .. }
            | Expr::IEndsWith { .. }
            | Expr::IEquals { .. }
            | Expr::Matches { .. }
            | Expr::PatternMatch { .. }
            | Expr::PatternMatchVar { .. }
            | Expr::OfExprTuple(_)
            | Expr::OfPatternSet(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_) => Type::Bool,

            Expr::Minus { is_float, .. } => {
                if *is_float {
                    Type::Float
                } else {
                    Type::Integer
                }
            }

            Expr::Add { is_float, .. }
            | Expr::Sub { is_float, .. }
            | Expr::Mul { is_float, .. }
            | Expr::Div { is_float, .. } => {
                if *is_float {
                    Type::Float
                } else {
                    Type::Integer
                }
            }

            Expr::Filesize
            | Expr::PatternCount { .. }
            | Expr::PatternCountVar { .. }
            | Expr::PatternOffset { .. }
            | Expr::PatternOffsetVar { .. }
            | Expr::PatternLength { .. }
            | Expr::PatternLengthVar { .. }
            | Expr::Mod { .. }
            | Expr::BitwiseNot { .. }
            | Expr::BitwiseAnd { .. }
            | Expr::BitwiseOr { .. }
            | Expr::BitwiseXor { .. }
            | Expr::Shl { .. }
            | Expr::Shr { .. } => Type::Integer,

            Expr::Symbol(symbol) => symbol.ty(),
            Expr::FieldAccess(field_access) => field_access.type_value.ty(),
            Expr::FuncCall(func_call) => func_call.type_value.ty(),
            Expr::Lookup(lookup) => lookup.type_value.ty(),
            Expr::With(with) => with.type_value.ty(),
        }
    }

    pub fn type_value(&self) -> TypeValue {
        match self {
            Expr::Const(type_value) => type_value.clone(),

            Expr::Defined { .. }
            | Expr::Not { .. }
            | Expr::And { .. }
            | Expr::Or { .. }
            | Expr::Eq { .. }
            | Expr::Ne { .. }
            | Expr::Ge { .. }
            | Expr::Gt { .. }
            | Expr::Le { .. }
            | Expr::Lt { .. }
            | Expr::Contains { .. }
            | Expr::IContains { .. }
            | Expr::StartsWith { .. }
            | Expr::IStartsWith { .. }
            | Expr::EndsWith { .. }
            | Expr::IEndsWith { .. }
            | Expr::IEquals { .. }
            | Expr::Matches { .. }
            | Expr::PatternMatch { .. }
            | Expr::PatternMatchVar { .. }
            | Expr::OfExprTuple(_)
            | Expr::OfPatternSet(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_) => TypeValue::Bool(Value::Unknown),

            Expr::Minus { is_float, .. } => {
                if *is_float {
                    TypeValue::Float(Value::Unknown)
                } else {
                    TypeValue::Integer(Value::Unknown)
                }
            }

            Expr::Add { is_float, .. }
            | Expr::Sub { is_float, .. }
            | Expr::Mul { is_float, .. }
            | Expr::Div { is_float, .. } => {
                if *is_float {
                    TypeValue::Float(Value::Unknown)
                } else {
                    TypeValue::Integer(Value::Unknown)
                }
            }

            Expr::Filesize
            | Expr::PatternCount { .. }
            | Expr::PatternCountVar { .. }
            | Expr::PatternOffset { .. }
            | Expr::PatternOffsetVar { .. }
            | Expr::PatternLength { .. }
            | Expr::PatternLengthVar { .. }
            | Expr::Mod { .. }
            | Expr::BitwiseNot { .. }
            | Expr::BitwiseAnd { .. }
            | Expr::BitwiseOr { .. }
            | Expr::BitwiseXor { .. }
            | Expr::Shl { .. }
            | Expr::Shr { .. } => TypeValue::Integer(Value::Unknown),

            Expr::Symbol(symbol) => symbol.type_value().clone(),
            Expr::FieldAccess(field_access) => field_access.type_value.clone(),
            Expr::FuncCall(func_call) => func_call.type_value.clone(),
            Expr::Lookup(lookup) => lookup.type_value.clone(),
            Expr::With(with) => with.type_value.clone(),
        }
    }

    /// If the expression is a constant boolean, returns its value, if not
    /// returns [`None`]
    pub fn try_as_const_bool(&self) -> Option<bool> {
        if let TypeValue::Bool(Value::Const(v)) = self.type_value() {
            Some(v)
        } else {
            None
        }
    }

    /// If the expression is a constant integer, returns its value, if not
    /// returns [`None`]
    pub fn try_as_const_integer(&self) -> Option<i64> {
        if let TypeValue::Integer(Value::Const(v)) = self.type_value() {
            Some(v)
        } else {
            None
        }
    }
}
