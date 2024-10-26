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
use std::hash::Hash;
use std::ops::Index;
use std::ops::RangeInclusive;

use bitmask::bitmask;
use bstr::BString;
use serde::{Deserialize, Serialize};

use yara_x_parser::ast::Ident;
use yara_x_parser::Span;

use crate::compiler::context::{Var, VarStackFrame};
use crate::compiler::ir::dfs::{DepthFirstSearch, Event};
use crate::re;
use crate::symbols::Symbol;
use crate::types::{Type, TypeValue, Value};

pub(in crate::compiler) use ast2ir::patterns_from_ast;
pub(in crate::compiler) use ast2ir::rule_condition_from_ast;

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
    /// When a pattern is used in the condition this function is called to
    /// indicate that the pattern is in use.
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
#[derive(Debug, Clone, Copy)]
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

// TODO: change to u16?
// It makes sense if Expr gets smaller.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NodeIdx(u32);

impl From<usize> for NodeIdx {
    #[inline]
    fn from(value: usize) -> Self {
        Self(value as u32)
    }
}

pub(crate) struct IR {
    root: Option<NodeIdx>,
    nodes: Vec<Expr>,
}

impl IR {
    pub fn new() -> Self {
        Self { nodes: Vec::new(), root: None }
    }

    /// Clears the tree, removing all nodes.
    pub fn clear(&mut self) {
        self.nodes.clear()
    }

    /// Returns a reference to the [`Expr`] at the given index in the tree.
    #[inline]
    pub fn get(&self, idx: NodeIdx) -> &Expr {
        self.nodes.get(idx.0 as usize).unwrap()
    }

    /// Returns a mutable reference to the [`Expr`] at the given index in the
    /// tree.
    #[inline]
    pub fn get_mut(&mut self, idx: NodeIdx) -> &mut Expr {
        self.nodes.get_mut(idx.0 as usize).unwrap()
    }

    /// Returns an iterator that performs a depth first search starting at
    /// the given node.
    pub fn dfs_iter(&self, start: NodeIdx) -> DepthFirstSearch {
        DepthFirstSearch::new(start, self.nodes.as_slice())
    }

    /// Finds the first expression in DFS order starting at the `start` node
    /// that matches the given `predicate`, but avoids traversing the
    /// descendants of nodes matching the condition indicated by `prune_if`.
    pub fn dfs_find<P, C>(
        &self,
        start: NodeIdx,
        predicate: P,
        prune_if: C,
    ) -> Option<&Expr>
    where
        P: Fn(&Expr) -> bool,
        C: Fn(&Expr) -> bool,
    {
        let mut dfs = self.dfs_iter(start);

        while let Some(evt) = dfs.next() {
            if let Event::Enter((_, expr)) = evt {
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

    /// Checks if the given expression can be computed at compile time, and in
    /// that case returns a new a constant with the resulting value. For
    /// instance, the expression `true and false` will be folded into the `false`.
    ///
    /// If the expression can't be folded, returns the same [`NodeIdx`] that
    /// it received.
    ///
    /// Returns [`None`] if an integer overflow occurs while trying to fold
    /// integer expressions.
    pub fn fold(&mut self, expr: NodeIdx) -> Option<NodeIdx> {
        // We need a mutable reference to the expression itself, as well as
        // mutable references to its operands. However, Rust's borrow checker
        // does not allow mutable references to multiple items in a slice
        // without a workaround. To achieve this, we use `split_at_mut`, which
        // let us divide the slice into two mutable sub-slices.
        //
        // Luckily, the intermediate representation (IR) tree guarantees that
        // all descendants of a node appear before the node itself in the slice.
        // This means we can split the slice at the node corresponding to `expr`,
        // ensuring that the left sub-slice contains all its operands. The first
        // item in the right sub-slice will be the `expr` node itself.
        let (descedants, ascendants) =
            self.nodes.split_at_mut(expr.0 as usize);

        // `ascendants[0]` is the expression being folded.
        match &mut ascendants[0] {
            Expr::Minus { operand, .. } => {
                match descedants[operand.0 as usize].type_value() {
                    TypeValue::Integer(Value::Const(v)) => {
                        Some(self.constant(TypeValue::const_integer_from(-v)))
                    }
                    TypeValue::Float(Value::Const(v)) => {
                        Some(self.constant(TypeValue::const_float_from(-v)))
                    }
                    _ => Some(expr),
                }
            }
            Expr::And { ref mut operands } => {
                // Retain the operands whose value is not constant, or is
                // constant but false, remove those that are known to be
                // true. True values in the list of operands don't alter
                // the result of the AND operation.
                operands.retain(|op| {
                    let type_value =
                        descedants[op.0 as usize].type_value().cast_to_bool();
                    !type_value.is_const() || !type_value.as_bool()
                });

                // No operands left, all were true and therefore the AND is
                // also true.
                if operands.is_empty() {
                    return Some(
                        self.constant(TypeValue::const_bool_from(true)),
                    );
                }

                // If any of the remaining operands is constant it has to be
                // false because true values were removed, the result is false
                // regardless of the operands with unknown values.
                if operands.iter().any(|op| {
                    descedants[op.0 as usize].type_value().is_const()
                }) {
                    return Some(
                        self.constant(TypeValue::const_bool_from(false)),
                    );
                }

                Some(expr)
            }
            Expr::Or { ref mut operands } => {
                // Retain the operands whose value is not constant, or is
                // constant but true, remove those that are known to be false.
                // False values in the list of operands don't alter the result
                // of the OR operation.
                operands.retain(|op| {
                    let type_value =
                        descedants[op.0 as usize].type_value().cast_to_bool();
                    !type_value.is_const() || type_value.as_bool()
                });

                // No operands left, all were false and therefore the OR is
                // also false.
                if operands.is_empty() {
                    return Some(
                        self.constant(TypeValue::const_bool_from(false)),
                    );
                }

                // If any of the remaining operands is constant it has to be
                // true because false values were removed, the result is true
                // regardless of the operands with unknown values.
                if operands.iter().any(|op| {
                    descedants[op.0 as usize].type_value().is_const()
                }) {
                    return Some(
                        self.constant(TypeValue::const_bool_from(true)),
                    );
                }

                Some(expr)
            }
            Expr::Add { ref mut operands, .. } => {
                // If not all operands are constant, there's nothing to fold.
                if !operands.iter().all(|op| {
                    descedants[op.0 as usize].type_value().is_const()
                }) {
                    return Some(expr);
                }

                Self::fold_arithmetic(
                    descedants,
                    operands.as_slice(),
                    |acc, x| acc + x,
                )
                .map(|type_value| self.constant(type_value))
            }
            Expr::Sub { ref mut operands, .. } => {
                // If not all operands are constant, there's nothing to fold.
                if !operands.iter().all(|op| {
                    descedants[op.0 as usize].type_value().is_const()
                }) {
                    return Some(expr);
                }

                Self::fold_arithmetic(
                    descedants,
                    operands.as_slice(),
                    |acc, x| acc - x,
                )
                .map(|type_value| self.constant(type_value))
            }
            Expr::Mul { ref mut operands, .. } => {
                // If not all operands are constant, there's nothing to fold.
                if !operands.iter().all(|op| {
                    descedants[op.0 as usize].type_value().is_const()
                }) {
                    return Some(expr);
                }

                Self::fold_arithmetic(
                    descedants,
                    operands.as_slice(),
                    |acc, x| acc * x,
                )
                .map(|type_value| self.constant(type_value))
            }
            _ => Some(expr),
        }
    }

    pub fn fold_arithmetic<F>(
        nodes: &[Expr],
        operands: &[NodeIdx],
        f: F,
    ) -> Option<TypeValue>
    where
        F: FnMut(f64, f64) -> f64,
    {
        debug_assert!(!operands.is_empty());

        let mut is_float = false;

        let result = operands
            .iter()
            .map(|operand| match nodes[*operand].type_value() {
                TypeValue::Integer(Value::Const(v)) => v as f64,
                TypeValue::Float(Value::Const(v)) => {
                    is_float = true;
                    v
                }
                _ => unreachable!(),
            })
            .reduce(f)
            // It's safe to call unwrap because there must be at least
            // one operand.
            .unwrap();

        if is_float {
            Some(TypeValue::const_float_from(result))
        } else if result >= i64::MIN as f64 && result <= i64::MAX as f64 {
            Some(TypeValue::const_integer_from(result as i64))
        } else {
            None
        }
    }
}

impl IR {
    /// Creates a new [`Expr::FileSize`].
    pub fn filesize(&mut self) -> NodeIdx {
        self.nodes.push(Expr::Filesize);
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Const`].
    pub fn constant(&mut self, type_value: TypeValue) -> NodeIdx {
        self.nodes.push(Expr::Const(type_value));
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Ident`].
    pub fn ident(&mut self, symbol: Symbol) -> NodeIdx {
        self.nodes.push(Expr::Ident { symbol: Box::new(symbol) });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Lookup`].
    pub fn lookup(
        &mut self,
        type_value: TypeValue,
        primary: NodeIdx,
        index: NodeIdx,
    ) -> NodeIdx {
        self.nodes.push(Expr::Lookup(Box::new(Lookup {
            type_value,
            primary,
            index,
        })));
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Not`].
    pub fn not(&mut self, operand: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Not { operand });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::And`].
    pub fn and(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        self.nodes.push(Expr::And { operands });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Or`].
    pub fn or(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        self.nodes.push(Expr::Or { operands });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Minus`].
    pub fn minus(&mut self, operand: NodeIdx) -> NodeIdx {
        let is_float = matches!(self.get(operand).ty(), Type::Float);
        self.nodes.push(Expr::Minus { operand, is_float });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Defined`].
    pub fn defined(&mut self, operand: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Defined { operand });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseNot`].
    pub fn bitwise_not(&mut self, operand: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::BitwiseNot { operand });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseAnd`].
    pub fn bitwise_and(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::BitwiseAnd { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseOr`].
    pub fn bitwise_or(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::BitwiseOr { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseXor`].
    pub fn bitwise_xor(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::BitwiseXor { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Shl`].
    pub fn shl(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Shl { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Shr`].
    pub fn shr(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Shr { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Add`].
    pub fn add(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));
        self.nodes.push(Expr::Add { operands, is_float });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Sub`].
    pub fn sub(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));
        self.nodes.push(Expr::Sub { operands, is_float });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Mul`].
    pub fn mul(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));
        self.nodes.push(Expr::Mul { operands, is_float });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Div`].
    pub fn div(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));
        self.nodes.push(Expr::Div { operands, is_float });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Mod`].
    pub fn modulus(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        self.nodes.push(Expr::Mod { operands });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::FieldAccess`].
    pub fn field_access(&mut self, operands: Vec<NodeIdx>) -> NodeIdx {
        let type_value = self.get(*operands.last().unwrap()).type_value();
        self.nodes.push(Expr::FieldAccess { operands, type_value });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Eq`].
    pub fn eq(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Eq { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Ne`].
    pub fn ne(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Ne { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Ge`].
    pub fn ge(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Ge { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Gt`].
    pub fn gt(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Gt { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Le`].
    pub fn le(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Le { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Lt`].
    pub fn lt(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Lt { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Contains`].
    pub fn contains(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Contains { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IContains`].
    pub fn icontains(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::IContains { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::StartsWith`].
    pub fn starts_with(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::StartsWith { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IStartsWith`].
    pub fn istarts_with(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::IStartsWith { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::EndsWith`].
    pub fn ends_with(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::EndsWith { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IEndsWith`].
    pub fn iends_with(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::IEndsWith { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IEquals`].
    pub fn iequals(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::IEquals { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Matches`].
    pub fn matches(&mut self, lhs: NodeIdx, rhs: NodeIdx) -> NodeIdx {
        self.nodes.push(Expr::Matches { lhs, rhs });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternMatch`]
    pub fn pattern_match(
        &mut self,
        pattern: PatternIdx,
        anchor: MatchAnchor,
    ) -> NodeIdx {
        self.nodes.push(Expr::PatternMatch { pattern, anchor });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternMatchVar`]
    pub fn pattern_match_var(
        &mut self,
        symbol: Symbol,
        anchor: MatchAnchor,
    ) -> NodeIdx {
        self.nodes
            .push(Expr::PatternMatchVar { symbol: Box::new(symbol), anchor });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternLength`]
    pub fn pattern_length(
        &mut self,
        pattern: PatternIdx,
        index: Option<NodeIdx>,
    ) -> NodeIdx {
        self.nodes.push(Expr::PatternLength { pattern, index });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternLengthVar`]
    pub fn pattern_length_var(
        &mut self,
        symbol: Symbol,
        index: Option<NodeIdx>,
    ) -> NodeIdx {
        self.nodes
            .push(Expr::PatternLengthVar { symbol: Box::new(symbol), index });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternOffset`]
    pub fn pattern_offset(
        &mut self,
        pattern: PatternIdx,
        index: Option<NodeIdx>,
    ) -> NodeIdx {
        self.nodes.push(Expr::PatternOffset { pattern, index });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternOffsetVar`]
    pub fn pattern_offset_var(
        &mut self,
        symbol: Symbol,
        index: Option<NodeIdx>,
    ) -> NodeIdx {
        self.nodes
            .push(Expr::PatternOffsetVar { symbol: Box::new(symbol), index });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternCount`]
    pub fn pattern_count(
        &mut self,
        pattern: PatternIdx,
        range: Option<Range>,
    ) -> NodeIdx {
        self.nodes.push(Expr::PatternCount { pattern, range });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternCountVar`]
    pub fn pattern_count_var(
        &mut self,
        symbol: Symbol,
        range: Option<Range>,
    ) -> NodeIdx {
        self.nodes
            .push(Expr::PatternCountVar { symbol: Box::new(symbol), range });
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::FuncCall`]
    pub fn func_call(
        &mut self,
        callable: NodeIdx,
        args: Vec<NodeIdx>,
        type_value: TypeValue,
        signature_index: usize,
    ) -> NodeIdx {
        self.nodes.push(Expr::FuncCall(Box::new(FuncCall {
            callable,
            args,
            type_value,
            signature_index,
        })));
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Of`]
    pub fn of(
        &mut self,
        quantifier: Quantifier,
        items: OfItems,
        anchor: MatchAnchor,
        stack_frame: VarStackFrame,
    ) -> NodeIdx {
        self.nodes.push(Expr::Of(Box::new(Of {
            quantifier,
            items,
            anchor,
            stack_frame,
        })));
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::ForOf`]
    pub fn for_of(
        &mut self,
        quantifier: Quantifier,
        variable: Var,
        pattern_set: Vec<PatternIdx>,
        condition: NodeIdx,
        stack_frame: VarStackFrame,
    ) -> NodeIdx {
        self.nodes.push(Expr::ForOf(Box::new(ForOf {
            quantifier,
            variable,
            pattern_set,
            condition,
            stack_frame,
        })));
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::ForIn`]
    pub fn for_in(
        &mut self,
        quantifier: Quantifier,
        variables: Vec<Var>,
        iterable: Iterable,
        condition: NodeIdx,
        stack_frame: VarStackFrame,
    ) -> NodeIdx {
        self.nodes.push(Expr::ForIn(Box::new(ForIn {
            quantifier,
            variables,
            iterable,
            condition,
            stack_frame,
        })));
        NodeIdx::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::With`]
    pub fn with(
        &mut self,
        declarations: Vec<(Var, NodeIdx)>,
        condition: NodeIdx,
    ) -> NodeIdx {
        self.nodes
            .push(Expr::With(Box::new(With { declarations, condition })));

        NodeIdx::from(self.nodes.len() - 1)
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

        for event in self.dfs_iter(self.root.unwrap()) {
            match event {
                Event::Leave(_) => level -= 1,
                Event::Enter((_, expr)) => {
                    for _ in 0..level {
                        write!(f, "  ")?;
                    }
                    level += 1;
                    match expr {
                        Expr::Const(c) => writeln!(f, "CONST {}", c)?,
                        Expr::Filesize => writeln!(f, "FILESIZE")?,
                        Expr::Not { .. } => writeln!(f, "NOT")?,
                        Expr::And { .. } => writeln!(f, "AND")?,
                        Expr::Or { .. } => writeln!(f, "OR")?,
                        Expr::Minus { .. } => writeln!(f, "MINUS")?,
                        Expr::Add { .. } => writeln!(f, "ADD")?,
                        Expr::Sub { .. } => writeln!(f, "SUB")?,
                        Expr::Mul { .. } => writeln!(f, "MUL")?,
                        Expr::Div { .. } => writeln!(f, "DIV")?,
                        Expr::Mod { .. } => writeln!(f, "MOD")?,
                        Expr::Shl { .. } => writeln!(f, "SHL")?,
                        Expr::Shr { .. } => writeln!(f, "SHR")?,
                        Expr::Eq { .. } => writeln!(f, "EQ")?,
                        Expr::Ne { .. } => writeln!(f, "NE")?,
                        Expr::Lt { .. } => writeln!(f, "LT")?,
                        Expr::Gt { .. } => writeln!(f, "GT")?,
                        Expr::Le { .. } => writeln!(f, "LE")?,
                        Expr::Ge { .. } => writeln!(f, "GE")?,
                        Expr::BitwiseNot { .. } => writeln!(f, "BITWISE_NOT")?,
                        Expr::BitwiseAnd { .. } => writeln!(f, "BITWISE_AND")?,
                        Expr::BitwiseOr { .. } => writeln!(f, "BITWISE_OR")?,
                        Expr::BitwiseXor { .. } => writeln!(f, "BITWISE_XOR")?,
                        Expr::Contains { .. } => writeln!(f, "CONTAINS")?,
                        Expr::IContains { .. } => writeln!(f, "ICONTAINS")?,
                        Expr::StartsWith { .. } => writeln!(f, "STARTS_WITH")?,
                        Expr::IStartsWith { .. } => writeln!(f, "ISTARTS_WITH")?,
                        Expr::EndsWith { .. } => writeln!(f, "ENDS_WITH")?,
                        Expr::IEndsWith { .. } => writeln!(f, "IENDS_WITH")?,
                        Expr::IEquals { .. } => writeln!(f, "IEQUALS")?,
                        Expr::Matches { .. } => writeln!(f, "MATCHES")?,
                        Expr::Defined { .. } => writeln!(f, "DEFINED")?,
                        Expr::FieldAccess { .. } => writeln!(f, "FIELD_ACCESS")?,
                        Expr::Ident { symbol } => writeln!(f, "IDENT {:?}", symbol)?,
                        Expr::FuncCall(_) => writeln!(f, "FN_CALL")?,
                        Expr::Of(_) => writeln!(f, "OF")?,
                        Expr::ForOf(_) => writeln!(f, "FOR_OF")?,
                        Expr::ForIn(_) => writeln!(f, "FOR_IN")?,
                        Expr::With(_) => writeln!(f, "WITH")?,
                        Expr::Lookup(_) => writeln!(f, "LOOKUP")?,
                        Expr::PatternMatch { pattern, anchor } => writeln!(
                            f,
                            "PATTERN_MATCH {:?}{}",
                            pattern,
                            anchor_str(anchor),
                        )?,
                        Expr::PatternMatchVar { symbol, anchor } => writeln!(
                            f,
                            "PATTERN_MATCH {:?}{}",
                            symbol,
                            anchor_str(anchor),
                        )?,
                        Expr::PatternCount { pattern, range } => writeln!(
                            f,
                            "PATTERN_COUNT {:?}{}",
                            pattern,
                            range_str(range),
                        )?,
                        Expr::PatternCountVar { symbol, range } => writeln!(
                            f,
                            "PATTERN_COUNT {:?}{}",
                            symbol,
                            range_str(range),
                        )?,
                        Expr::PatternOffset { pattern, index } => writeln!(
                            f,
                            "PATTERN_OFFSET {:?}{}",
                            pattern,
                            index_str(index),
                        )?,
                        Expr::PatternOffsetVar { symbol, index } => writeln!(
                            f,
                            "PATTERN_OFFSET {:?}{}",
                            symbol,
                            index_str(index),
                        )?,
                        Expr::PatternLength { pattern, index } => writeln!(
                            f,
                            "PATTERN_LENGTH {:?}{}",
                            pattern,
                            index_str(index),
                        )?,
                        Expr::PatternLengthVar { symbol, index } => writeln!(
                            f,
                            "PATTERN_LENGTH {:?}{}",
                            symbol,
                            index_str(index),
                        )?,
                    }
                }
            }
        }

        Ok(())
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
    Not {
        operand: NodeIdx,
    },

    /// Boolean `and` expression.
    And {
        operands: Vec<NodeIdx>,
    },

    /// Boolean `or` expression.
    Or {
        operands: Vec<NodeIdx>,
    },

    /// Arithmetic minus.
    Minus {
        is_float: bool,
        operand: NodeIdx,
    },

    /// Arithmetic addition (`+`) expression.
    Add {
        is_float: bool,
        operands: Vec<NodeIdx>,
    },

    /// Arithmetic subtraction (`-`) expression.
    Sub {
        is_float: bool,
        operands: Vec<NodeIdx>,
    },

    /// Arithmetic multiplication (`*`) expression.
    Mul {
        is_float: bool,
        operands: Vec<NodeIdx>,
    },

    /// Arithmetic division (`\`) expression.
    Div {
        is_float: bool,
        operands: Vec<NodeIdx>,
    },

    /// Arithmetic modulus (`%`) expression.
    Mod {
        operands: Vec<NodeIdx>,
    },

    /// Bitwise not (`~`) expression.
    BitwiseNot {
        operand: NodeIdx,
    },

    /// Bitwise and (`&`) expression.
    BitwiseAnd {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Bitwise shift left (`<<`) expression.
    Shl {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Bitwise shift right (`>>`) expression.
    Shr {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Bitwise or (`|`) expression.
    BitwiseOr {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Bitwise xor (`^`) expression.
    BitwiseXor {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Equal (`==`) expression.
    Eq {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Not equal (`!=`) expression.
    Ne {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Less than (`<`) expression.
    Lt {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Greater than (`>`) expression.
    Gt {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Less or equal (`<=`) expression.
    Le {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// Greater or equal (`>=`) expression.
    Ge {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `contains` expression.
    Contains {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `icontains` expression
    IContains {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `startswith` expression.
    StartsWith {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `istartswith` expression
    IStartsWith {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `endswith` expression.
    EndsWith {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `iendswith` expression
    IEndsWith {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `iequals` expression.
    IEquals {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// `matches` expression.
    Matches {
        rhs: NodeIdx,
        lhs: NodeIdx,
    },

    /// A `defined` expression (e.g. `defined foo`)
    Defined {
        operand: NodeIdx,
    },

    Ident {
        symbol: Box<Symbol>,
    },

    /// Pattern match expression (e.g. `$a`)
    PatternMatch {
        pattern: PatternIdx,
        anchor: MatchAnchor,
    },

    /// Pattern match expression where the pattern is variable (e.g: `$`).
    PatternMatchVar {
        symbol: Box<Symbol>,
        anchor: MatchAnchor,
    },

    /// Pattern count expression (e.g. `#a`, `#a in (0..10)`)
    PatternCount {
        pattern: PatternIdx,
        range: Option<Range>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `#`, `# in (0..10)`)
    PatternCountVar {
        symbol: Box<Symbol>,
        range: Option<Range>,
    },

    /// Pattern offset expression (e.g. `@a`, `@a[1]`)
    PatternOffset {
        pattern: PatternIdx,
        index: Option<NodeIdx>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `@`, `@[1]`)
    PatternOffsetVar {
        symbol: Box<Symbol>,
        index: Option<NodeIdx>,
    },

    /// Pattern length expression (e.g. `!a`, `!a[1]`)
    PatternLength {
        pattern: PatternIdx,
        index: Option<NodeIdx>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `!`, `![1]`)
    PatternLengthVar {
        symbol: Box<Symbol>,
        index: Option<NodeIdx>,
    },

    /// Field access expression (e.g. `foo.bar.baz`)
    FieldAccess(Box<FieldAccess>),

    /// Function call.
    FuncCall(Box<FuncCall>),

    /// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`)
    Of(Box<Of>),

    /// A `for <quantifier> of ...` expression. (e.g. `for any of ($a, $b) : ( ... )`)
    ForOf(Box<ForOf>),

    /// A `for <quantifier> <vars> in ...` expression. (e.g. `for all i in (1..100) : ( ... )`)
    ForIn(Box<ForIn>),

    /// A `with <identifiers> : ...` expression. (e.g. `with $a, $b : ( ... )`)
    With(Box<With>),

    /// Array or dictionary lookup expression (e.g. `array[1]`, `dict["key"]`)
    Lookup(Box<Lookup>),
}

/// A lookup operation in an array or dictionary.
pub(crate) struct Lookup {
    pub type_value: TypeValue,
    pub primary: NodeIdx,
    pub index: NodeIdx,
}

/// A field access expression.
pub(crate) struct FieldAccess {
    pub type_value: TypeValue,
    pub operands: Vec<NodeIdx>,
}

/// An expression representing a function call.
pub(crate) struct FuncCall {
    /// The callable expression, which must resolve in some function identifier.
    pub callable: NodeIdx,
    /// The arguments passed to the function in this call.
    pub args: Vec<NodeIdx>,
    /// Type and value for the function's result.
    pub type_value: TypeValue,
    /// Due to function overloading, the same function may have multiple
    /// signatures. This field indicates the index of the signature that
    /// matched the provided arguments.
    pub signature_index: usize,
}

/// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`,
/// `any of (true, false)`)
pub(crate) struct Of {
    pub quantifier: Quantifier,
    pub items: OfItems,
    pub anchor: MatchAnchor,
    pub stack_frame: VarStackFrame,
}

/// A `for .. of` expression (e.g `for all of them : (..)`,
/// `for 1 of ($a,$b) : (..)`)
pub(crate) struct ForOf {
    pub quantifier: Quantifier,
    pub variable: Var,
    pub pattern_set: Vec<PatternIdx>,
    pub condition: NodeIdx,
    pub stack_frame: VarStackFrame,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
pub(crate) struct ForIn {
    pub quantifier: Quantifier,
    pub variables: Vec<Var>,
    pub iterable: Iterable,
    pub condition: NodeIdx,
    pub stack_frame: VarStackFrame,
}

/// A `with` expression (e.g `with $a, $b : (..)`)
pub(crate) struct With {
    pub declarations: Vec<(Var, NodeIdx)>,
    pub condition: NodeIdx,
}

/// A quantifier used in `for` and `of` expressions.
pub(crate) enum Quantifier {
    None,
    All,
    Any,
    Percentage(NodeIdx),
    Expr(NodeIdx),
}

/// In expressions like `$a at 0` and `$b in (0..10)`, this type represents the
/// anchor (e.g. `at <expr>`, `in <range>`).
///
/// The anchor is the part of the expression that restricts the offset range
/// where the match can occur.
/// (e.g. `at <expr>`, `in <range>`).
pub(crate) enum MatchAnchor {
    None,
    At(NodeIdx),
    In(Range),
}

/// Items in a `of` expression.
pub(crate) enum OfItems {
    PatternSet(Vec<PatternIdx>),
    BoolExprTuple(Vec<NodeIdx>),
}

/// A pair of values conforming a range (e.g. `(0..10)`).
pub(crate) struct Range {
    pub lower_bound: NodeIdx,
    pub upper_bound: NodeIdx,
}

/// Possible iterable expressions that can use in a [`ForIn`].
pub(crate) enum Iterable {
    Range(Range),
    ExprTuple(Vec<NodeIdx>),
    Expr(NodeIdx),
}

impl Index<NodeIdx> for [Expr] {
    type Output = Expr;
    fn index(&self, index: NodeIdx) -> &Self::Output {
        self.get(index.0 as usize).unwrap()
    }
}

impl Expr {
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
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_)
            | Expr::With(_) => Type::Bool,

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

            Expr::Ident { symbol, .. } => symbol.type_value().ty(),
            Expr::FieldAccess(field_access) => field_access.type_value.ty(),
            Expr::FuncCall(fn_call) => fn_call.type_value.ty(),
            Expr::Lookup(lookup) => lookup.type_value.ty(),
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
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_)
            | Expr::With(_) => TypeValue::Bool(Value::Unknown),

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

            Expr::Ident { symbol, .. } => symbol.type_value().clone(),
            Expr::FieldAccess(field_access) => field_access.type_value.clone(),
            Expr::FuncCall(fn_call) => fn_call.type_value.clone(),
            Expr::Lookup(lookup) => lookup.type_value.clone(),
        }
    }
}
