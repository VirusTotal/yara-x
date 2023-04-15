/*! Abstract Syntax Tree (AST) for YARA rules.

Each structure defined in this module corresponds to some construct in the
YARA language, like a rule, expression, identifier, import statement, etc.

# Example

```rust
use yara_x_parser::{Parser, GrammarRule};
let rule = r#"
 rule test {
   condition:
     true
 }
"#;

let ast = Parser::new().build_ast(rule).unwrap();
```

*/
#[cfg(feature = "ascii-tree")]
mod ascii_tree;
mod span;

use std::borrow::Cow;
use std::collections::btree_map::Values;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::{fmt, mem};

use bitmask::bitmask;
use bstr::BStr;
use yara_x_macros::*;

use crate::cst::CSTNode;
use crate::types::*;
use crate::warnings::Warning;

pub use crate::ast::span::*;
pub use crate::types::Type;

/// Abstract Syntax Tree (AST) for YARA rules.
pub struct AST<'src> {
    pub namespaces: Vec<Namespace<'src>>,
    /// Warnings generated while building this AST.
    pub warnings: Vec<Warning>,
}

#[cfg(feature = "ascii-tree")]
impl<'src> Debug for AST<'src> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use std::borrow::Borrow;
        ::ascii_tree::write_tree(f, self.ascii_tree().borrow())
    }
}

#[cfg(not(feature = "ascii-tree"))]
impl<'src> Debug for AST<'src> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AST")
    }
}

#[cfg(feature = "ascii-tree")]
impl<'src> AST<'src> {
    /// Returns a printable ASCII tree representing the AST.
    pub fn ascii_tree(&self) -> ::ascii_tree::Tree {
        use crate::ast::ascii_tree::namespace_ascii_tree;
        ::ascii_tree::Tree::Node(
            "root".to_string(),
            self.namespaces.iter().map(namespace_ascii_tree).collect(),
        )
    }
}

/// A namespace containing YARA rules.
///
/// Within each namespace rule identifiers are unique.
#[derive(Debug)]
pub struct Namespace<'src> {
    pub rules: Vec<Rule<'src>>,
    pub imports: Vec<Import>,
}

bitmask! {
    /// A set of flags associated to a YARA rule.
    #[derive(Debug)]
    pub mask RuleFlags: u8 where
    /// Each of the flags that a YARA rule can have.
    flags RuleFlag {
        Private = 0x01,
        Global = 0x02,
    }
}

/// An import statement.
#[derive(Debug, HasSpan)]
pub struct Import {
    pub span: Span,
    pub module_name: String,
}

/// A YARA rule.
#[derive(Debug)]
pub struct Rule<'src> {
    pub flags: RuleFlags,
    pub identifier: Ident<'src>,
    pub tags: Option<HashSet<&'src str>>,
    pub meta: Option<Vec<Meta<'src>>>,
    pub patterns: Option<Vec<Pattern<'src>>>,
    pub condition: Expr<'src>,
}

/// A metadata entry in a YARA rule.
#[derive(Debug)]
pub struct Meta<'src> {
    pub identifier: Ident<'src>,
    pub value: MetaValue<'src>,
}

/// Each of the possible values that can have a metadata entry.
#[derive(Debug)]
pub enum MetaValue<'src> {
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(&'src str),
}

impl<'src> Display for MetaValue<'src> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Integer(v) => write!(f, "{}", v),
            Self::Float(v) => write!(f, "{:.1}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

/// Types of patterns (a.k.a strings) that can appear in a YARA rule.
///
/// Possible types are: text patterns, hex patterns and regular expressions.
///
/// This type implements the [`Hash`] trait, which produces the same hash for
/// patterns that are equal and have the same modifiers. The pattern identifier
/// or the rule it belongs to is not taken into account while computing the
/// hash, which allows identifying patterns that are defined in more than one
/// YARA rule in an identical way. Notice however that some patterns may be
/// semantically equivalent, but their hashes may differ due to being declared
/// in different ways. For example: `{ 01 [-] 02 }` is equivalent to
/// `{ 01 [0-] 03 }` but they don't have the same hash because their
/// definitions are not identical.
#[derive(Hash, Debug)]
pub enum Pattern<'src> {
    Text(Box<TextPattern<'src>>),
    Hex(Box<HexPattern<'src>>),
    Regexp(Box<RegexpPattern<'src>>),
}

impl<'src> Pattern<'src> {
    pub fn identifier(&self) -> &Ident<'src> {
        match self {
            Pattern::Text(p) => &p.identifier,
            Pattern::Regexp(p) => &p.identifier,
            Pattern::Hex(p) => &p.identifier,
        }
    }
}

/// A set of modifiers associated to a pattern.
#[derive(Debug, Default)]
pub struct PatternModifiers<'src> {
    modifiers: BTreeMap<&'src str, PatternModifier<'src>>,
}

impl<'src> PatternModifiers<'src> {
    pub(crate) fn new(
        modifiers: BTreeMap<&'src str, PatternModifier<'src>>,
    ) -> Self {
        Self { modifiers }
    }

    /// Returns an iterator for all the modifiers associated to the pattern.
    #[inline]
    pub fn iter(&self) -> PatternModifiersIter {
        PatternModifiersIter { iter: self.modifiers.values() }
    }

    #[inline]
    pub fn ascii(&self) -> Option<&PatternModifier> {
        self.modifiers.get("ascii")
    }

    #[inline]
    pub fn wide(&self) -> Option<&PatternModifier> {
        self.modifiers.get("wide")
    }

    #[inline]
    pub fn base64(&self) -> Option<&PatternModifier> {
        self.modifiers.get("base64")
    }

    #[inline]
    pub fn base64wide(&self) -> Option<&PatternModifier> {
        self.modifiers.get("base64wide")
    }

    #[inline]
    pub fn fullword(&self) -> Option<&PatternModifier> {
        self.modifiers.get("fullword")
    }

    #[inline]
    pub fn nocase(&self) -> Option<&PatternModifier> {
        self.modifiers.get("nocase")
    }

    #[inline]
    pub fn xor(&self) -> Option<&PatternModifier> {
        self.modifiers.get("xor")
    }
}

/// Iterator that returns all the modifiers in a [`PatternModifiers`].
///
/// This is the result of [`PatternModifiers::iter`].
pub struct PatternModifiersIter<'src> {
    iter: Values<'src, &'src str, PatternModifier<'src>>,
}

impl<'src> Iterator for PatternModifiersIter<'src> {
    type Item = &'src PatternModifier<'src>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// A pattern (a.k.a string) modifier.
#[derive(Debug, HasSpan)]
pub enum PatternModifier<'src> {
    Ascii { span: Span },
    Wide { span: Span },
    Nocase { span: Span },
    Private { span: Span },
    Fullword { span: Span },
    Base64 { span: Span, alphabet: Option<&'src str> },
    Base64Wide { span: Span, alphabet: Option<&'src str> },
    Xor { span: Span, start: u8, end: u8 },
}

impl PatternModifier<'_> {
    pub fn as_text(&self) -> &'static str {
        match self {
            PatternModifier::Ascii { .. } => "ascii",
            PatternModifier::Wide { .. } => "wide",
            PatternModifier::Nocase { .. } => "nocase",
            PatternModifier::Private { .. } => "private",
            PatternModifier::Fullword { .. } => "fullword",
            PatternModifier::Base64 { .. } => "base64",
            PatternModifier::Base64Wide { .. } => "base64wide",
            PatternModifier::Xor { .. } => "xor",
        }
    }
}

impl Hash for PatternModifier<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);
        match self {
            PatternModifier::Base64 { alphabet, .. } => {
                alphabet.hash(state);
            }
            PatternModifier::Base64Wide { alphabet, .. } => {
                alphabet.hash(state);
            }
            PatternModifier::Xor { start, end, .. } => {
                start.hash(state);
                end.hash(state);
            }
            _ => {}
        }
    }
}

impl Display for PatternModifier<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PatternModifier::Ascii { .. } => {
                write!(f, "ascii")
            }
            PatternModifier::Wide { .. } => {
                write!(f, "wide")
            }
            PatternModifier::Nocase { .. } => {
                write!(f, "nocase")
            }
            PatternModifier::Private { .. } => {
                write!(f, "private")
            }
            PatternModifier::Fullword { .. } => {
                write!(f, "fullword")
            }
            PatternModifier::Base64 { alphabet, .. } => {
                if let Some(alphabet) = alphabet {
                    write!(f, "base64({})", alphabet)
                } else {
                    write!(f, "base64")
                }
            }
            PatternModifier::Base64Wide { alphabet, .. } => {
                if let Some(alphabet) = alphabet {
                    write!(f, "base64wide({})", alphabet)
                } else {
                    write!(f, "base64wide")
                }
            }
            PatternModifier::Xor { start, end, .. } => {
                if *start == 0 && *end == 255 {
                    write!(f, "xor")
                } else if *start == *end {
                    write!(f, "xor({})", start)
                } else {
                    write!(f, "xor({}-{})", start, end)
                }
            }
        }
    }
}

/// A text pattern (a.k.a text string) in a YARA rule.
#[derive(Debug, HasSpan)]
pub struct TextPattern<'src> {
    pub span: Span,
    pub identifier: Ident<'src>,
    pub value: Cow<'src, BStr>,
    pub modifiers: PatternModifiers<'src>,
}

impl Hash for TextPattern<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
        for modifier in self.modifiers.iter() {
            modifier.hash(state);
        }
    }
}

/// A regular expression pattern in a YARA rule.
#[derive(Debug, HasSpan)]
pub struct RegexpPattern<'src> {
    pub span: Span,
    pub identifier: Ident<'src>,
    pub regexp: Regexp<'src>,
    pub modifiers: PatternModifiers<'src>,
}

impl Hash for RegexpPattern<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.regexp.hash(state);
        for modifier in self.modifiers.iter() {
            modifier.hash(state);
        }
    }
}

/// A hex pattern (a.k.a hex string) in a YARA rule.
#[derive(Debug, HasSpan)]
pub struct HexPattern<'src> {
    pub span: Span,
    pub identifier: Ident<'src>,
    pub tokens: HexTokens,
    pub modifiers: PatternModifiers<'src>,
}

impl Hash for HexPattern<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tokens.hash(state);
        for modifier in self.modifiers.iter() {
            modifier.hash(state);
        }
    }
}

/// A sequence of tokens that conform a hex pattern (a.k.a hex string).
#[derive(Hash, Debug)]
pub struct HexTokens {
    pub tokens: Vec<HexToken>,
}

/// Each of the types of tokens in a hex pattern (a.k.a hex string).
///
/// A token can be a single byte, a negated byte (e.g. `~XX`), an
/// alternative (e.g `(XXXX|YYYY)`), or a jump (e.g `[0-10]`).
#[derive(Hash, Debug)]
pub enum HexToken {
    Byte(Box<HexByte>),
    NotByte(Box<HexByte>),
    Alternative(Box<HexAlternative>),
    Jump(Box<HexJump>),
}

/// A single byte in a hex pattern (a.k.a hex string).
///
/// The byte is accompanied by a mask which will be 0xFF for non-masked bytes.
#[derive(Hash, Debug)]
pub struct HexByte {
    pub value: u8,
    pub mask: u8,
}

/// An alternative in a hex pattern (a.k.a hex string).
///
/// Alternatives are sequences of hex tokens separated by `|`.
#[derive(Hash, Debug)]
pub struct HexAlternative {
    pub alternatives: Vec<HexTokens>,
}

/// A jump in a hex pattern (a.k.a hex string).
#[derive(Hash, Debug)]
pub struct HexJump {
    pub start: Option<u16>,
    pub end: Option<u16>,
}

impl HexJump {
    /// Coalesce this jump with another one.
    ///
    /// This is useful when two or more consecutive jumps appear in a hex
    /// pattern. In such cases the jumps can be coalesced together into a
    /// single one. For example:
    ///
    ///  `[1-2][3-4]` becomes `[4-6]`
    ///  `[0-2][5-]` becomes `[5-]`
    ///  `[4][0-7]`  becomes `[4-11]`
    ///
    pub(crate) fn coalesce(&mut self, other: HexJump) {
        match (self.start, other.start) {
            (Some(s1), Some(s2)) => self.start = Some(s1 + s2),
            (Some(s1), None) => self.start = Some(s1),
            (None, Some(s2)) => self.start = Some(s2),
            (None, None) => self.start = None,
        }
        match (self.end, other.end) {
            (Some(e1), Some(e2)) => self.end = Some(e1 + e2),
            (_, _) => self.end = None,
        }
    }
}

impl Display for HexJump {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match (self.start, self.end) {
            (Some(start), Some(end)) => write!(f, "[{}-{}]", start, end),
            (Some(start), None) => write!(f, "[{}-]", start),
            (None, Some(end)) => write!(f, "[-{}]", end),
            (None, None) => write!(f, "[-]"),
        }
    }
}

/// An expression in the AST.
#[derive(Debug, HasSpan)]
pub enum Expr<'src> {
    True {
        span: Span,
    },

    False {
        span: Span,
    },

    Filesize {
        span: Span,
    },

    Entrypoint {
        span: Span,
    },

    /// A literal, (e.g: `1`, `2.0`, `"abcd"`)
    Literal(Box<Literal<'src>>),

    /// A regular expression (e.g: `/ab.*cd/i`)
    Regexp(Box<Regexp<'src>>),

    /// Identifier (e.g. `some_identifier`).
    Ident(Box<Ident<'src>>),

    /// Pattern match expression (e.g. `$a`, `$a at 0`, `$a in (0..10)`)
    PatternMatch(Box<PatternMatch<'src>>),

    /// Pattern count expression (e.g. `#a`, `#a in (0..10)`)
    PatternCount(Box<IdentWithRange<'src>>),

    /// Pattern offset expression (e.g. `@a`, `@a[1]`)
    PatternOffset(Box<IdentWithIndex<'src>>),

    /// Pattern length expression (e.g. `!a`, `!a[1]`)
    PatternLength(Box<IdentWithIndex<'src>>),

    /// Array or dictionary lookup expression (e.g. `array[1]`, `dict["key"]`)
    Lookup(Box<Lookup<'src>>),

    /// A field lookup expression (e.g. `foo.bar`)
    FieldAccess(Box<BinaryExpr<'src>>),

    /// A function call expression (e.g. `foo()`, `bar(1,2)`)
    FnCall(Box<FnCall<'src>>),

    /// A `defined` expression (e.g. `defined foo`)
    Defined(Box<UnaryExpr<'src>>),

    /// Boolean `not` expression.
    Not(Box<UnaryExpr<'src>>),

    /// Boolean `and` expression.
    And(Box<BinaryExpr<'src>>),

    /// Boolean `or` expression.
    Or(Box<BinaryExpr<'src>>),

    /// Arithmetic minus.
    Minus(Box<UnaryExpr<'src>>),

    /// Arithmetic add (`+`) expression.
    Add(Box<BinaryExpr<'src>>),

    /// Arithmetic subtraction (`-`) expression.
    Sub(Box<BinaryExpr<'src>>),

    /// Arithmetic multiplication (`*`) expression.
    Mul(Box<BinaryExpr<'src>>),

    /// Arithmetic division (`\`) expression.
    Div(Box<BinaryExpr<'src>>),

    /// Arithmetic modulus (`%`) expression.
    Modulus(Box<BinaryExpr<'src>>),

    /// Bitwise not (`~`) expression.
    BitwiseNot(Box<UnaryExpr<'src>>),

    /// Bitwise shift left (`<<`) expression.
    Shl(Box<BinaryExpr<'src>>),

    /// Bitwise shift right (`>>`) expression.
    Shr(Box<BinaryExpr<'src>>),

    /// Bitwise and (`&`) expression.
    BitwiseAnd(Box<BinaryExpr<'src>>),

    /// Bitwise or (`|`) expression.
    BitwiseOr(Box<BinaryExpr<'src>>),

    /// Bitwise xor (`^`) expression.
    BitwiseXor(Box<BinaryExpr<'src>>),

    /// Equal (`==`) expression.
    Eq(Box<BinaryExpr<'src>>),

    /// Not equal (`!=`) expression.
    Ne(Box<BinaryExpr<'src>>),

    /// Less than (`<`) expression.
    Lt(Box<BinaryExpr<'src>>),

    /// Greater than (`>`) expression.
    Gt(Box<BinaryExpr<'src>>),

    /// Less or equal (`<=`) expression.
    Le(Box<BinaryExpr<'src>>),

    /// Greater or equal (`>=`) expression.
    Ge(Box<BinaryExpr<'src>>),

    /// `contains` expression.
    Contains(Box<BinaryExpr<'src>>),

    /// `icontains` expression
    IContains(Box<BinaryExpr<'src>>),

    /// `startswith` expression.
    StartsWith(Box<BinaryExpr<'src>>),

    /// `istartswith` expression
    IStartsWith(Box<BinaryExpr<'src>>),

    /// `endswith` expression.
    EndsWith(Box<BinaryExpr<'src>>),

    /// `iendswith` expression
    IEndsWith(Box<BinaryExpr<'src>>),

    /// `iequals` expression.
    IEquals(Box<BinaryExpr<'src>>),

    /// `matches` expression.
    Matches(Box<BinaryExpr<'src>>),

    /// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`)
    Of(Box<Of<'src>>),

    /// A `for <quantifier> of ...` expression. (e.g. `for any of ($a, $b) : ( ... )`)
    ForOf(Box<ForOf<'src>>),

    /// A `for <quantifier> <vars> in ...` expression. (e.g. `for all i in (1..100) : ( ... )`)
    ForIn(Box<ForIn<'src>>),
}

/// A pattern match expression (e.g. `$a`, `$b at 0`, `$c in (0..10)`).
#[derive(Debug, HasSpan)]
pub struct PatternMatch<'src> {
    pub span: Span,
    pub identifier: Ident<'src>,
    pub anchor: Option<MatchAnchor<'src>>,
}

/// In expressions like `$a at 0` and `$b in (0..10)`, this type represents the
/// anchor (e.g. `at <expr>`, `in <range>`).
///
/// The anchor is the part of the expression that restricts the offset range
/// where the match can occur.
/// (e.g. `at <expr>`, `in <range>`).
#[derive(Debug, HasSpan)]
pub enum MatchAnchor<'src> {
    At(Box<At<'src>>),
    In(Box<In<'src>>),
}

/// In expressions like `$a at 0`, this type represents the anchor
/// (e.g. `at <expr>`).
#[derive(Debug, HasSpan)]
pub struct At<'src> {
    pub span: Span,
    pub expr: Expr<'src>,
}

/// A pair of values conforming a range (e.g. `(0..10)`).
#[derive(Debug, HasSpan)]
pub struct Range<'src> {
    pub span: Span,
    pub lower_bound: Expr<'src>,
    pub upper_bound: Expr<'src>,
}

/// In expressions like `$a in (0..10)`, this structs represents the anchor
/// e.g. `in <range>`).
#[derive(Debug, HasSpan)]
pub struct In<'src> {
    pub span: Span,
    pub range: Range<'src>,
}

/// An identifier (e.g. `some_ident`).
#[derive(Debug, Clone, HasSpan)]
pub struct Ident<'src> {
    pub span: Span,
    #[doc(hidden)]
    pub type_value: TypeValue,
    pub name: &'src str,
}

impl<'src> Ident<'src> {
    pub(crate) fn new(name: &'src str, span: Span) -> Self {
        Self { name, span, type_value: TypeValue::Unknown }
    }

    pub(crate) fn with_type_and_value(
        name: &'src str,
        span: Span,
        type_value: TypeValue,
    ) -> Self {
        Self { name, span, type_value }
    }

    /// Returns the identifier's type.
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.type_value.ty()
    }

    #[doc(hidden)]
    pub fn set_type_value(&mut self, type_value: TypeValue) -> &Self {
        let current_ty = self.type_value.ty();
        if current_ty != Type::Unknown && current_ty != type_value.ty() {
            panic!(
                "setting type `{:?}` to expression that was previously `{:?}",
                type_value.ty(),
                current_ty
            );
        }
        self.type_value = type_value;
        self
    }
}

/// Creates an [`Ident`] directly from a [`CSTNode`].
impl<'src> From<CSTNode<'src>> for Ident<'src> {
    fn from(node: CSTNode<'src>) -> Self {
        Self {
            type_value: TypeValue::Unknown,
            span: node.as_span().into(),
            name: node.as_str(),
        }
    }
}

/// An expression where an identifier can be accompanied by a range
/// (e.g. `#a in <range>`).
///
/// The range is optional thought, so expressions like `#a` are also
/// represented by this struct.
#[derive(Debug, HasSpan)]
pub struct IdentWithRange<'src> {
    pub span: Span,
    pub name: &'src str,
    pub range: Option<Range<'src>>,
}

/// An expression where an identifier can be accompanied by an index
/// (e.g. `@a[2]`).
///
/// The index is optional thought, so expressions like `@a` are also
/// represented by this struct.
#[derive(Debug, HasSpan)]
pub struct IdentWithIndex<'src> {
    pub span: Span,
    pub name: &'src str,
    pub index: Option<Expr<'src>>,
}

/// A regular expression in a YARA rule.
///
/// Used both as part of a [`RegexpPattern`] and as the right operand
/// of a `matches` operator.
#[derive(Debug, HasSpan)]
pub struct Regexp<'src> {
    pub span: Span,
    #[doc(hidden)]
    pub type_value: TypeValue,
    pub regexp: &'src str,
    pub case_insensitive: bool,
    pub dotall: bool,
}

impl Hash for Regexp<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.regexp.hash(state);
        self.case_insensitive.hash(state);
        self.dotall.hash(state);
    }
}

/// A literal value of any type (e.g: `1`, `2.0`, `"abcd"`, `true`).
#[derive(Debug, HasSpan)]
pub struct Literal<'src> {
    pub span: Span,
    #[doc(hidden)]
    pub type_value: TypeValue,
    /// The literal value as it appears in the source code.
    pub literal: &'src str,
}

impl<'src> Literal<'src> {
    pub(crate) fn new(
        literal: &'src str,
        span: Span,
        type_value: TypeValue,
    ) -> Self {
        Self { literal, span, type_value }
    }

    /// Returns the literal's type
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.type_value.ty()
    }
}

/// An expression with a single operand.
#[derive(Debug, HasSpan)]
pub struct UnaryExpr<'src> {
    pub span: Span,
    #[doc(hidden)]
    pub type_value: TypeValue,
    pub operand: Expr<'src>,
}

impl<'src> UnaryExpr<'src> {
    pub(crate) fn new(
        operand: Expr<'src>,
        span: Span,
        type_value: TypeValue,
    ) -> Self {
        Self { operand, span, type_value }
    }

    /// Returns the expression's type
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.type_value.ty()
    }

    #[doc(hidden)]
    pub fn set_type_value(&mut self, type_value: TypeValue) -> &Self {
        let current_ty = self.type_value.ty();
        if current_ty != Type::Unknown && current_ty != type_value.ty() {
            panic!(
                "setting type `{:?}` to expression that was previously `{:?}",
                type_value.ty(),
                current_ty
            );
        }
        self.type_value = type_value;
        self
    }
}

/// An expression with two operands.
#[derive(Debug)]
pub struct BinaryExpr<'src> {
    #[doc(hidden)]
    pub type_value: TypeValue,
    /// Left-hand side.
    pub lhs: Expr<'src>,
    /// Right-hand side.
    pub rhs: Expr<'src>,
}

impl<'src> BinaryExpr<'src> {
    pub(crate) fn new(
        lhs: Expr<'src>,
        rhs: Expr<'src>,
        type_value: TypeValue,
    ) -> Self {
        Self { lhs, rhs, type_value }
    }

    /// Returns the expression's type
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.type_value.ty()
    }

    #[doc(hidden)]
    pub fn set_type_value(&mut self, type_value: TypeValue) -> &Self {
        let current_ty = self.type_value.ty();
        if current_ty != Type::Unknown && current_ty != type_value.ty() {
            panic!(
                "setting type `{:?}` to expression that was previously `{:?}",
                type_value.ty(),
                current_ty
            );
        }
        self.type_value = type_value;
        self
    }
}

/// An expression representing a function call.
#[derive(Debug, HasSpan)]
pub struct FnCall<'src> {
    pub span: Span,
    #[doc(hidden)]
    pub type_value: TypeValue,
    pub callable: Expr<'src>,
    pub args: Vec<Expr<'src>>,
    #[doc(hidden)]
    pub fn_signature_index: Option<usize>,
}

impl<'src> FnCall<'src> {
    // Returns the function's return type.
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.type_value.ty()
    }

    #[doc(hidden)]
    pub fn set_type_value(&mut self, type_value: TypeValue) -> &Self {
        let current_ty = self.type_value.ty();
        if current_ty != Type::Unknown && current_ty != type_value.ty() {
            panic!(
                "setting type `{:?}` to expression that was previously `{:?}",
                type_value.ty(),
                current_ty
            );
        }
        self.type_value = type_value;
        self
    }
}

/// A lookup operation in an array or dictionary.
#[derive(Debug, HasSpan)]
pub struct Lookup<'src> {
    pub span: Span,
    #[doc(hidden)]
    pub type_value: TypeValue,
    pub primary: Expr<'src>,
    pub index: Expr<'src>,
}

impl<'src> Lookup<'src> {
    pub(crate) fn new(
        primary: Expr<'src>,
        index: Expr<'src>,
        span: Span,
        type_value: TypeValue,
    ) -> Self {
        Self { primary, index, span, type_value }
    }

    /// Returns the expression's type
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.type_value.ty()
    }

    #[doc(hidden)]
    pub fn set_type_value(&mut self, type_value: TypeValue) -> &Self {
        let current_ty = self.type_value.ty();
        if current_ty != Type::Unknown && current_ty != type_value.ty() {
            panic!(
                "setting type `{:?}` to expression that was previously `{:?}",
                type_value.ty(),
                current_ty
            );
        }
        self.type_value = type_value;
        self
    }
}

/// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`,
/// `any of (true, false)`)
#[derive(Debug, HasSpan)]
pub struct Of<'src> {
    pub span: Span,
    pub quantifier: Quantifier<'src>,
    pub items: OfItems<'src>,
    pub anchor: Option<MatchAnchor<'src>>,
}

/// A `for .. of` expression (e.g `for all of them : (..)`,
/// `for 1 of ($a,$b) : (..)`)
#[derive(Debug, HasSpan)]
pub struct ForOf<'src> {
    pub span: Span,
    pub quantifier: Quantifier<'src>,
    pub pattern_set: PatternSet<'src>,
    pub condition: Expr<'src>,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
#[derive(Debug, HasSpan)]
pub struct ForIn<'src> {
    pub span: Span,
    pub quantifier: Quantifier<'src>,
    pub variables: Vec<Ident<'src>>,
    pub iterable: Iterable<'src>,
    pub condition: Expr<'src>,
}

/// Items in a `of` expression.
#[derive(Debug)]
pub enum OfItems<'src> {
    PatternSet(PatternSet<'src>),
    BoolExprTuple(Vec<Expr<'src>>),
}

/// A quantifier used in `for` and `of` expressions.
#[derive(Debug, HasSpan)]
pub enum Quantifier<'src> {
    None {
        span: Span,
    },
    All {
        span: Span,
    },
    Any {
        span: Span,
    },
    /// Used in expressions like `10% of them`.
    Percentage(Expr<'src>),
    /// Used in expressions like `10 of them`.
    Expr(Expr<'src>),
}

/// Possible iterable expressions that can use in a [`ForIn`].
#[derive(Debug, HasSpan)]
pub enum Iterable<'src> {
    Range(Range<'src>),
    ExprTuple(Vec<Expr<'src>>),
    Expr(Expr<'src>),
}

/// Either a set of pattern identifiers (possibly with wildcards), or the
/// special set `them`, which includes all the patterns declared in the rule.
#[derive(Debug)]
pub enum PatternSet<'src> {
    Them,
    Set(Vec<PatternSetItem<'src>>),
}

/// Each individual item in a set of patterns.
///
/// In the pattern set `($a, $b*)`, `$a` and `$b*` are represented by a
/// [`PatternSetItem`].
#[derive(Debug, HasSpan)]
pub struct PatternSetItem<'src> {
    pub span: Span,
    pub identifier: &'src str,
}

impl PatternSetItem<'_> {
    /// Returns true if `ident` matches this [`PatternSetItem`].
    ///
    /// For example, identifiers `$a` and `$abc` both match the
    /// [`PatternSetItem`] for `$a*`.
    pub fn matches(&self, ident: &str) -> bool {
        if let Some(prefix) = self.identifier.strip_suffix('*') {
            ident.starts_with(prefix)
        } else {
            ident == self.identifier
        }
    }
}

impl<'src> Expr<'src> {
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.type_value().ty()
    }

    #[doc(hidden)]
    pub fn type_value(&self) -> &TypeValue {
        match self {
            Expr::FieldAccess(expr)
            | Expr::And(expr)
            | Expr::Or(expr)
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
            | Expr::Matches(expr)
            | Expr::Add(expr)
            | Expr::Sub(expr)
            | Expr::Mul(expr)
            | Expr::Div(expr)
            | Expr::Modulus(expr)
            | Expr::Shl(expr)
            | Expr::Shr(expr)
            | Expr::BitwiseAnd(expr)
            | Expr::BitwiseOr(expr)
            | Expr::BitwiseXor(expr) => &expr.type_value,

            Expr::Lookup(expr) => &expr.type_value,
            Expr::Ident(ident) => &ident.type_value,
            Expr::Regexp(regexp) => &regexp.type_value,
            Expr::FnCall(fn_call) => &fn_call.type_value,

            Expr::Literal(l) => &l.type_value,
            Expr::True { .. } => &TRUE,
            Expr::False { .. } => &FALSE,

            Expr::PatternMatch(_)
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_) => &UNKNOWN_BOOL,

            Expr::Filesize { .. }
            | Expr::Entrypoint { .. }
            | Expr::PatternCount(_)
            | Expr::PatternOffset(_)
            | Expr::PatternLength(_) => &UNKNOWN_INT,

            Expr::Defined(expr)
            | Expr::Not(expr)
            | Expr::BitwiseNot(expr)
            | Expr::Minus(expr) => &expr.type_value,
        }
    }
}
