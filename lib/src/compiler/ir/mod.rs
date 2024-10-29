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

use crate::compiler::context::Var;
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

/// Identifies an expression in the IR tree.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExprId(u32);

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
    root: Option<ExprId>,
    nodes: Vec<Expr>,
}

impl IR {
    /// Creates a new [`IR`].
    pub fn new() -> Self {
        Self { nodes: Vec::new(), root: None, constant_folding: false }
    }

    /// Enable constant folding.
    pub fn constant_folding(&mut self, yes: bool) -> &mut Self {
        self.constant_folding = yes;
        self
    }

    /// Clears the tree, removing all nodes.
    pub fn clear(&mut self) {
        self.nodes.clear()
    }

    /// Returns a reference to the [`Expr`] at the given index in the tree.
    #[inline]
    pub fn get(&self, idx: ExprId) -> &Expr {
        self.nodes.get(idx.0 as usize).unwrap()
    }

    /// Returns a mutable reference to the [`Expr`] at the given index in the
    /// tree.
    #[inline]
    pub fn get_mut(&mut self, idx: ExprId) -> &mut Expr {
        self.nodes.get_mut(idx.0 as usize).unwrap()
    }

    /// Returns an iterator that performs a depth first search starting at
    /// the given node.
    pub fn dfs_iter(&self, start: ExprId) -> DepthFirstSearch {
        DepthFirstSearch::new(start, self.nodes.as_slice())
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
}

impl IR {
    /// Creates a new [`Expr::FileSize`].
    pub fn filesize(&mut self) -> ExprId {
        self.nodes.push(Expr::Filesize);
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Const`].
    pub fn constant(&mut self, type_value: TypeValue) -> ExprId {
        self.nodes.push(Expr::Const(type_value));
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Ident`].
    pub fn ident(&mut self, symbol: Symbol) -> ExprId {
        self.nodes.push(Expr::Ident { symbol: Box::new(symbol) });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Lookup`].
    pub fn lookup(
        &mut self,
        type_value: TypeValue,
        primary: ExprId,
        index: ExprId,
    ) -> ExprId {
        self.nodes.push(Expr::Lookup(Box::new(Lookup {
            type_value,
            primary,
            index,
        })));
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Not`].
    pub fn not(&mut self, operand: ExprId) -> ExprId {
        if self.constant_folding {
            if let Some(v) = self.get(operand).try_as_const_bool() {
                return self.constant(TypeValue::const_bool_from(!v));
            }
        }
        self.nodes.push(Expr::Not { operand });
        ExprId::from(self.nodes.len() - 1)
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

        self.nodes.push(Expr::And { operands });
        Ok(ExprId::from(self.nodes.len() - 1))
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

        self.nodes.push(Expr::Or { operands });
        Ok(ExprId::from(self.nodes.len() - 1))
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
        self.nodes.push(Expr::Minus {
            operand,
            is_float: matches!(self.get(operand).ty(), Type::Float),
        });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Defined`].
    pub fn defined(&mut self, operand: ExprId) -> ExprId {
        self.nodes.push(Expr::Defined { operand });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseNot`].
    pub fn bitwise_not(&mut self, operand: ExprId) -> ExprId {
        self.nodes.push(Expr::BitwiseNot { operand });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseAnd`].
    pub fn bitwise_and(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::BitwiseAnd { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseOr`].
    pub fn bitwise_or(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::BitwiseOr { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::BitwiseXor`].
    pub fn bitwise_xor(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::BitwiseXor { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Shl`].
    pub fn shl(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Shl { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Shr`].
    pub fn shr(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Shr { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
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

        self.nodes.push(Expr::Add { operands, is_float });
        Ok(ExprId::from(self.nodes.len() - 1))
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

        self.nodes.push(Expr::Sub { operands, is_float });
        Ok(ExprId::from(self.nodes.len() - 1))
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

        self.nodes.push(Expr::Mul { operands, is_float });
        Ok(ExprId::from(self.nodes.len() - 1))
    }

    /// Creates a new [`Expr::Div`].
    pub fn div(&mut self, operands: Vec<ExprId>) -> Result<ExprId, Error> {
        let is_float = operands
            .iter()
            .any(|op| matches!(self.get(*op).ty(), Type::Float));
        self.nodes.push(Expr::Div { operands, is_float });
        Ok(ExprId::from(self.nodes.len() - 1))
    }

    /// Creates a new [`Expr::Mod`].
    pub fn modulus(&mut self, operands: Vec<ExprId>) -> Result<ExprId, Error> {
        self.nodes.push(Expr::Mod { operands });
        Ok(ExprId::from(self.nodes.len() - 1))
    }

    /// Creates a new [`Expr::FieldAccess`].
    pub fn field_access(&mut self, operands: Vec<ExprId>) -> ExprId {
        let type_value = self.get(*operands.last().unwrap()).type_value();
        self.nodes.push(Expr::FieldAccess(Box::new(FieldAccess {
            operands,
            type_value,
        })));
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Eq`].
    pub fn eq(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Eq { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Ne`].
    pub fn ne(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Ne { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Ge`].
    pub fn ge(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Ge { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Gt`].
    pub fn gt(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Gt { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Le`].
    pub fn le(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Le { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Lt`].
    pub fn lt(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Lt { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Contains`].
    pub fn contains(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Contains { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IContains`].
    pub fn icontains(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::IContains { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::StartsWith`].
    pub fn starts_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::StartsWith { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IStartsWith`].
    pub fn istarts_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::IStartsWith { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::EndsWith`].
    pub fn ends_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::EndsWith { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IEndsWith`].
    pub fn iends_with(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::IEndsWith { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::IEquals`].
    pub fn iequals(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::IEquals { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::Matches`].
    pub fn matches(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.nodes.push(Expr::Matches { lhs, rhs });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternMatch`]
    pub fn pattern_match(
        &mut self,
        pattern: PatternIdx,
        anchor: MatchAnchor,
    ) -> ExprId {
        self.nodes.push(Expr::PatternMatch { pattern, anchor });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternMatchVar`]
    pub fn pattern_match_var(
        &mut self,
        symbol: Symbol,
        anchor: MatchAnchor,
    ) -> ExprId {
        self.nodes
            .push(Expr::PatternMatchVar { symbol: Box::new(symbol), anchor });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternLength`]
    pub fn pattern_length(
        &mut self,
        pattern: PatternIdx,
        index: Option<ExprId>,
    ) -> ExprId {
        self.nodes.push(Expr::PatternLength { pattern, index });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternLengthVar`]
    pub fn pattern_length_var(
        &mut self,
        symbol: Symbol,
        index: Option<ExprId>,
    ) -> ExprId {
        self.nodes
            .push(Expr::PatternLengthVar { symbol: Box::new(symbol), index });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternOffset`]
    pub fn pattern_offset(
        &mut self,
        pattern: PatternIdx,
        index: Option<ExprId>,
    ) -> ExprId {
        self.nodes.push(Expr::PatternOffset { pattern, index });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternOffsetVar`]
    pub fn pattern_offset_var(
        &mut self,
        symbol: Symbol,
        index: Option<ExprId>,
    ) -> ExprId {
        self.nodes
            .push(Expr::PatternOffsetVar { symbol: Box::new(symbol), index });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternCount`]
    pub fn pattern_count(
        &mut self,
        pattern: PatternIdx,
        range: Option<Range>,
    ) -> ExprId {
        self.nodes.push(Expr::PatternCount { pattern, range });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::PatternCountVar`]
    pub fn pattern_count_var(
        &mut self,
        symbol: Symbol,
        range: Option<Range>,
    ) -> ExprId {
        self.nodes
            .push(Expr::PatternCountVar { symbol: Box::new(symbol), range });
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::FuncCall`]
    pub fn func_call(
        &mut self,
        callable: ExprId,
        args: Vec<ExprId>,
        type_value: TypeValue,
        signature_index: usize,
    ) -> ExprId {
        self.nodes.push(Expr::FuncCall(Box::new(FuncCall {
            callable,
            args,
            type_value,
            signature_index,
        })));
        ExprId::from(self.nodes.len() - 1)
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
        self.nodes.push(Expr::OfExprTuple(Box::new(OfExprTuple {
            quantifier,
            items,
            anchor,
            for_vars,
            next_expr_var,
        })));
        ExprId::from(self.nodes.len() - 1)
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
        self.nodes.push(Expr::OfPatternSet(Box::new(OfPatternSet {
            quantifier,
            items,
            anchor,
            for_vars,
            next_pattern_var,
        })));
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::ForOf`]
    pub fn for_of(
        &mut self,
        quantifier: Quantifier,
        variable: Var,
        for_vars: ForVars,
        pattern_set: Vec<PatternIdx>,
        condition: ExprId,
    ) -> ExprId {
        self.nodes.push(Expr::ForOf(Box::new(ForOf {
            quantifier,
            variable,
            pattern_set,
            condition,
            for_vars,
        })));
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::ForIn`]
    pub fn for_in(
        &mut self,
        quantifier: Quantifier,
        variables: Vec<Var>,
        for_vars: ForVars,
        iterable_var: Var,
        iterable: Iterable,
        condition: ExprId,
    ) -> ExprId {
        self.nodes.push(Expr::ForIn(Box::new(ForIn {
            quantifier,
            variables,
            for_vars,
            iterable_var,
            iterable,
            condition,
        })));
        ExprId::from(self.nodes.len() - 1)
    }

    /// Creates a new [`Expr::With`]
    pub fn with(
        &mut self,
        declarations: Vec<(Var, ExprId)>,
        condition: ExprId,
    ) -> ExprId {
        self.nodes.push(Expr::With { declarations, condition });
        ExprId::from(self.nodes.len() - 1)
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
                        Expr::With { .. } => writeln!(f, "WITH")?,
                        Expr::Ident { symbol } => writeln!(f, "IDENT {:?}", symbol)?,
                        Expr::FuncCall(_) => writeln!(f, "FN_CALL")?,
                        Expr::OfExprTuple(_) => writeln!(f, "OF")?,
                        Expr::OfPatternSet(_) => writeln!(f, "OF")?,
                        Expr::ForOf(_) => writeln!(f, "FOR_OF")?,
                        Expr::ForIn(_) => writeln!(f, "FOR_IN")?,
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
        operand: ExprId,
    },

    /// Boolean `and` expression.
    And {
        operands: Vec<ExprId>,
    },

    /// Boolean `or` expression.
    Or {
        operands: Vec<ExprId>,
    },

    /// Arithmetic minus.
    Minus {
        is_float: bool,
        operand: ExprId,
    },

    /// Arithmetic addition (`+`) expression.
    Add {
        is_float: bool,
        operands: Vec<ExprId>,
    },

    /// Arithmetic subtraction (`-`) expression.
    Sub {
        is_float: bool,
        operands: Vec<ExprId>,
    },

    /// Arithmetic multiplication (`*`) expression.
    Mul {
        is_float: bool,
        operands: Vec<ExprId>,
    },

    /// Arithmetic division (`\`) expression.
    Div {
        is_float: bool,
        operands: Vec<ExprId>,
    },

    /// Arithmetic modulus (`%`) expression.
    Mod {
        operands: Vec<ExprId>,
    },

    /// Bitwise not (`~`) expression.
    BitwiseNot {
        operand: ExprId,
    },

    /// Bitwise and (`&`) expression.
    BitwiseAnd {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Bitwise shift left (`<<`) expression.
    Shl {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Bitwise shift right (`>>`) expression.
    Shr {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Bitwise or (`|`) expression.
    BitwiseOr {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Bitwise xor (`^`) expression.
    BitwiseXor {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Equal (`==`) expression.
    Eq {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Not equal (`!=`) expression.
    Ne {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Less than (`<`) expression.
    Lt {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Greater than (`>`) expression.
    Gt {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Less or equal (`<=`) expression.
    Le {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// Greater or equal (`>=`) expression.
    Ge {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `contains` expression.
    Contains {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `icontains` expression
    IContains {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `startswith` expression.
    StartsWith {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `istartswith` expression
    IStartsWith {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `endswith` expression.
    EndsWith {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `iendswith` expression
    IEndsWith {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `iequals` expression.
    IEquals {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// `matches` expression.
    Matches {
        rhs: ExprId,
        lhs: ExprId,
    },

    /// A `defined` expression (e.g. `defined foo`)
    Defined {
        operand: ExprId,
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
        index: Option<ExprId>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `@`, `@[1]`)
    PatternOffsetVar {
        symbol: Box<Symbol>,
        index: Option<ExprId>,
    },

    /// Pattern length expression (e.g. `!a`, `!a[1]`)
    PatternLength {
        pattern: PatternIdx,
        index: Option<ExprId>,
    },

    /// Pattern count expression where the pattern is variable (e.g. `!`, `![1]`)
    PatternLengthVar {
        symbol: Box<Symbol>,
        index: Option<ExprId>,
    },

    /// A `with <identifiers> : ...` expression. (e.g. `with $a, $b : ( ... )`)
    With {
        declarations: Vec<(Var, ExprId)>,
        condition: ExprId,
    },

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

/// An expression representing a function call.
pub(crate) struct FuncCall {
    /// The callable expression, which must resolve in some function identifier.
    pub callable: ExprId,
    /// The arguments passed to the function in this call.
    pub args: Vec<ExprId>,
    /// Type and value for the function's result.
    pub type_value: TypeValue,
    /// Due to function overloading, the same function may have multiple
    /// signatures. This field indicates the index of the signature that
    /// matched the provided arguments.
    pub signature_index: usize,
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
    pub condition: ExprId,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
pub(crate) struct ForIn {
    pub quantifier: Quantifier,
    pub variables: Vec<Var>,
    pub for_vars: ForVars,
    pub iterable_var: Var,
    pub iterable: Iterable,
    pub condition: ExprId,
}

/// A quantifier used in `for` and `of` expressions.
pub(crate) enum Quantifier {
    None,
    All,
    Any,
    Percentage(ExprId),
    Expr(ExprId),
}

pub(crate) struct ForVars {
    /// Maximum number of iterations.
    pub n: Var,
    /// Current iteration number.
    pub i: Var,
    /// Number of loop conditions that must return true.
    pub max_count: Var,
    /// Number of loop conditions that actually returned true.
    pub count: Var,
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
            | Expr::With { .. }
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

            Expr::Ident { symbol, .. } => symbol.ty(),
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
            | Expr::With { .. }
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

            Expr::Ident { symbol, .. } => symbol.type_value().clone(),
            Expr::FieldAccess(field_access) => field_access.type_value.clone(),
            Expr::FuncCall(fn_call) => fn_call.type_value.clone(),
            Expr::Lookup(lookup) => lookup.type_value.clone(),
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
