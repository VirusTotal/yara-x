/*! Abstract Syntax Tree (AST) for YARA rules.

Each structure or enum in this module corresponds to some construct in the YARA
language, like a rule, expression, identifier, import statement, etc.

*/

use std::borrow::Cow;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::slice::Iter;

use ::ascii_tree::write_tree;
use bitmask::bitmask;
use bstr::{BStr, BString, ByteSlice, Utf8Error};

use crate::ast::cst2ast::Builder;
use crate::cst::SyntaxKind::{
    ASCII_KW, BASE64WIDE_KW, BASE64_KW, FULLWORD_KW, NOCASE_KW, WIDE_KW,
    XOR_KW,
};
use crate::{Parser, Span};

mod ascii_tree;
mod cst2ast;
mod errors;

pub use errors::Error;

/// Abstract Syntax Tree (AST) for YARA rules.
pub struct AST<'src> {
    /// The list of imports.
    pub imports: Vec<Import<'src>>,
    /// The list of rules in the AST.
    rules: Vec<Rule<'src>>,
    /// Errors that occurred while parsing the rules.
    errors: Vec<Error>,
}

impl<'src> From<Parser<'src>> for AST<'src> {
    /// Crates an [`AST`] from the given parser.
    fn from(parser: Parser<'src>) -> Self {
        Builder::new(parser).build_ast()
    }
}

impl<'src> AST<'src> {
    /// Returns the import statements in the AST.
    #[inline]
    pub fn imports(&self) -> &[Import<'src>] {
        self.imports.as_slice()
    }

    /// Returns the rules in the AST.
    #[inline]
    pub fn rules(&self) -> &[Rule<'src>] {
        self.rules.as_slice()
    }

    /// Returns the errors found while parsing the source code.
    #[inline]
    pub fn errors(&self) -> &[Error] {
        self.errors.as_slice()
    }

    /// Consumes the parser, and returns the errors found while
    /// parsing the source code as a vector.
    #[inline]
    pub fn into_errors(self) -> Vec<Error> {
        self.errors
    }
}

impl Debug for AST<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for rule in &self.rules {
            write_tree(f, &ascii_tree::rule_ascii_tree(rule))?;
            writeln!(f)?;
        }

        if !self.errors.is_empty() {
            writeln!(f, "ERRORS:")?;
            for err in &self.errors {
                writeln!(f, "- {:?}", err)?;
            }
        }

        Ok(())
    }
}

/// An import statement.
#[derive(Debug)]
pub struct Import<'src> {
    span: Span,
    pub module_name: &'src str,
}

/// A YARA rule.
#[derive(Debug)]
pub struct Rule<'src> {
    pub flags: RuleFlags,
    pub identifier: Ident<'src>,
    pub tags: Option<Vec<Ident<'src>>>,
    pub meta: Option<Vec<Meta<'src>>>,
    pub patterns: Option<Vec<Pattern<'src>>>,
    pub condition: Expr<'src>,
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
    Bytes(BString),
}

impl<'src> Display for MetaValue<'src> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Integer(v) => write!(f, "{}", v),
            Self::Float(v) => write!(f, "{:.1}", v),
            Self::String(v) => write!(f, "\"{}\"", v),
            Self::Bytes(v) => write!(f, "\"{}\"", v),
        }
    }
}

/// An identifier (e.g. `some_ident`).
#[derive(Debug, Clone, Default)]
pub struct Ident<'src> {
    span: Span,
    #[doc(hidden)]
    pub name: &'src str,
}

impl<'src> Ident<'src> {
    #[doc(hidden)]
    pub fn new(name: &'src str) -> Self {
        Self { name, span: Default::default() }
    }

    pub fn starts_with(&self, pat: &str) -> bool {
        self.name.starts_with(pat)
    }
}

/// An expression where an identifier can be accompanied by a range
/// (e.g. `#a in <range>`).
///
/// The range is optional thought, so expressions like `#a` are also
/// represented by this struct.
#[derive(Debug)]
pub struct IdentWithRange<'src> {
    span: Span,
    pub ident: Ident<'src>,
    pub range: Option<Range<'src>>,
}

/// An expression where an identifier can be accompanied by an index
/// (e.g. `@a[2]`).
///
/// The index is optional thought, so expressions like `@a` are also
/// represented by this struct.
#[derive(Debug)]
pub struct IdentWithIndex<'src> {
    span: Span,
    pub ident: Ident<'src>,
    pub index: Option<Expr<'src>>,
}

/// Types of patterns (a.k.a. strings) that can appear in a YARA rule.
///
/// Possible types are: text patterns, hex patterns and regular expressions.
#[derive(Debug)]
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

    pub fn modifiers(&self) -> &PatternModifiers<'src> {
        match self {
            Pattern::Text(p) => &p.modifiers,
            Pattern::Hex(p) => &p.modifiers,
            Pattern::Regexp(p) => &p.modifiers,
        }
    }
}

/// A text pattern (a.k.a. text string) in a YARA rule.
#[derive(Debug)]
pub struct TextPattern<'src> {
    pub identifier: Ident<'src>,
    pub text: LiteralString<'src>,
    pub modifiers: PatternModifiers<'src>,
}

/// A regular expression pattern in a YARA rule.
#[derive(Debug)]
pub struct RegexpPattern<'src> {
    pub identifier: Ident<'src>,
    pub regexp: Regexp<'src>,
    pub modifiers: PatternModifiers<'src>,
}

/// A hex pattern (a.k.a. hex string) in a YARA rule.
#[derive(Debug, Default)]
pub struct HexPattern<'src> {
    pub identifier: Ident<'src>,
    pub tokens: HexTokens,
    pub modifiers: PatternModifiers<'src>,
}

/// A sequence of tokens that conform a hex pattern (a.k.a. hex string).
#[derive(Debug, Default)]
pub struct HexTokens {
    // TODO: rename to HexSubPattern
    pub tokens: Vec<HexToken>,
}

/// Each of the types of tokens in a hex pattern (a.k.a. hex string).
///
/// A token can be a single byte, a negated byte (e.g. `~XX`), an
/// alternative (e.g `(XXXX|YYYY)`), or a jump (e.g `[0-10]`).
#[derive(Debug)]
pub enum HexToken {
    Byte(HexByte),
    NotByte(HexByte),
    Alternative(Box<HexAlternative>),
    Jump(HexJump),
}

/// A single byte in a hex pattern (a.k.a. hex string).
///
/// The byte's value is accompanied by a mask that indicates which bits in the
/// value are taken into account during matching, and which are ignored. A bit
/// set to 1 in the mask indicates that the corresponding bit in the value is
/// taken into account, while a bit set to 0 indicates that the corresponding
/// bit in the value is ignored. Ignored bits are always set to 0 in the value.
///
/// For example, for pattern `A?` the value is `A0` and the mask is `F0`, and
/// for pattern `?1` the value is `01` and the mask is `0F`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexByte {
    span: Span,
    pub value: u8,
    pub mask: u8,
}

impl HexByte {
    #[doc(hidden)]
    pub fn new(value: u8, mask: u8) -> Self {
        Self { value, mask, span: Span::default() }
    }
}

/// An alternative in a hex pattern (a.k.a. hex string).
///
/// Alternatives are sequences of hex tokens separated by `|`.
#[derive(Debug, Default)]
pub struct HexAlternative {
    span: Span,
    pub alternatives: Vec<HexTokens>,
}

impl HexAlternative {
    #[doc(hidden)]
    pub fn new(alternatives: Vec<HexTokens>) -> Self {
        Self { alternatives, span: Span::default() }
    }
}

/// A jump in a hex pattern (a.k.a. hex string).
#[derive(Debug, Clone, Default)]
pub struct HexJump {
    span: Span,
    pub start: Option<u16>,
    pub end: Option<u16>,
}

impl HexJump {
    #[doc(hidden)]
    pub fn new(start: Option<u16>, end: Option<u16>) -> Self {
        Self { start, end, span: Span::default() }
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

/// An `of` expression (e.g. `1 of ($a, $b)`, `all of them`,
/// `any of (true, false)`)
#[derive(Debug)]
pub struct Of<'src> {
    span: Span,
    pub quantifier: Quantifier<'src>,
    pub items: OfItems<'src>,
    pub anchor: Option<MatchAnchor<'src>>,
}

/// A `for .. of` expression (e.g `for all of them : (..)`,
/// `for 1 of ($a,$b) : (..)`)
#[derive(Debug)]
pub struct ForOf<'src> {
    span: Span,
    pub quantifier: Quantifier<'src>,
    pub pattern_set: PatternSet<'src>,
    pub condition: Expr<'src>,
}

/// A `for .. in` expression (e.g `for all x in iterator : (..)`)
#[derive(Debug)]
pub struct ForIn<'src> {
    span: Span,
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
#[derive(Debug)]
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
#[derive(Debug)]
pub enum Iterable<'src> {
    Range(Range<'src>),
    ExprTuple(Vec<Expr<'src>>),
    Expr(Expr<'src>),
}

/// Either a set of pattern identifiers (possibly with wildcards), or the
/// special set `them`, which includes all the patterns declared in the rule.
#[derive(Debug)]
pub enum PatternSet<'src> {
    Them { span: Span },
    Set(Vec<PatternSetItem<'src>>),
}

/// Each individual item in a set of patterns.
///
/// In the pattern set `($a, $b*)`, `$a` and `$b*` are represented by a
/// [`PatternSetItem`].
#[derive(Debug)]
pub struct PatternSetItem<'src> {
    span: Span,
    pub identifier: &'src str,
    pub wildcard: bool,
}

impl PatternSetItem<'_> {
    /// Returns true if `ident` matches this [`PatternSetItem`].
    ///
    /// For example, identifiers `$a` and `$abc` both match the
    /// [`PatternSetItem`] for `$a*`.
    pub fn matches(&self, ident: &Ident) -> bool {
        if self.wildcard {
            ident.name.starts_with(self.identifier)
        } else {
            ident.name == self.identifier
        }
    }
}

/// An expression in the AST.
#[derive(Debug)]
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

    /// A literal string, (e.g: `"abcd"`)
    LiteralString(Box<LiteralString<'src>>),

    /// A literal integer, (e.g: `1`, `0xAB`)
    LiteralInteger(Box<LiteralInteger<'src>>),

    /// A literal float, (e.g: `2.0`, `3.14`)
    LiteralFloat(Box<LiteralFloat<'src>>),

    /// A regular expression (e.g: `/ab.*cd/i`)
    Regexp(Box<Regexp<'src>>),

    /// Identifier (e.g. `some_identifier`).
    Ident(Box<Ident<'src>>),

    /// Pattern match expression (e.g. `$`, `$a`, `$a at 0`, `$a in (0..10)`)
    PatternMatch(Box<PatternMatch<'src>>),

    /// Pattern count expression (e.g. `#`, `#a`, `#a in (0..10)`)
    PatternCount(Box<IdentWithRange<'src>>),

    /// Pattern offset expression (e.g. `@` `@a`, `@a[1]`)
    PatternOffset(Box<IdentWithIndex<'src>>),

    /// Pattern length expression (e.g. `!`, `!a`, `!a[1]`)
    PatternLength(Box<IdentWithIndex<'src>>),

    /// Array or dictionary lookup expression (e.g. `array[1]`, `dict["key"]`)
    Lookup(Box<Lookup<'src>>),

    /// A field lookup expression (e.g. `foo.bar`)
    FieldAccess(Box<NAryExpr<'src>>),

    /// A function call expression (e.g. `foo()`, `bar(1,2)`)
    FuncCall(Box<FuncCall<'src>>),

    /// A `defined` expression (e.g. `defined foo`)
    Defined(Box<UnaryExpr<'src>>),

    /// Boolean `not` expression.
    Not(Box<UnaryExpr<'src>>),

    /// Boolean `and` expression.
    And(Box<NAryExpr<'src>>),

    /// Boolean `or` expression.
    Or(Box<NAryExpr<'src>>),

    /// Arithmetic minus.
    Minus(Box<UnaryExpr<'src>>),

    /// Arithmetic add (`+`) expression.
    Add(Box<NAryExpr<'src>>),

    /// Arithmetic subtraction (`-`) expression.
    Sub(Box<NAryExpr<'src>>),

    /// Arithmetic multiplication (`*`) expression.
    Mul(Box<NAryExpr<'src>>),

    /// Arithmetic division (`\`) expression.
    Div(Box<NAryExpr<'src>>),

    /// Arithmetic modulus (`%`) expression.
    Mod(Box<NAryExpr<'src>>),

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

/// A set of modifiers associated to a pattern.
#[derive(Debug, Default)]
pub struct PatternModifiers<'src> {
    modifiers: Vec<PatternModifier<'src>>,
}

impl<'src> PatternModifiers<'src> {
    pub(crate) fn new(modifiers: Vec<PatternModifier<'src>>) -> Self {
        Self { modifiers }
    }

    /// Returns an iterator for all the modifiers associated to the pattern.
    #[inline]
    pub fn iter(&self) -> PatternModifiersIter {
        PatternModifiersIter { iter: self.modifiers.iter() }
    }

    /// Returns true if the pattern has no modifiers.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.modifiers.is_empty()
    }

    #[inline]
    pub fn ascii(&self) -> Option<&PatternModifier<'src>> {
        self.modifiers
            .iter()
            .find(|m| matches!(m, PatternModifier::Ascii { .. }))
    }

    #[inline]
    pub fn wide(&self) -> Option<&PatternModifier<'src>> {
        self.modifiers
            .iter()
            .find(|m| matches!(m, PatternModifier::Wide { .. }))
    }

    #[inline]
    pub fn base64(&self) -> Option<&PatternModifier<'src>> {
        self.modifiers
            .iter()
            .find(|m| matches!(m, PatternModifier::Base64 { .. }))
    }

    #[inline]
    pub fn base64wide(&self) -> Option<&PatternModifier<'src>> {
        self.modifiers
            .iter()
            .find(|m| matches!(m, PatternModifier::Base64Wide { .. }))
    }

    #[inline]
    pub fn fullword(&self) -> Option<&PatternModifier<'src>> {
        self.modifiers
            .iter()
            .find(|m| matches!(m, PatternModifier::Fullword { .. }))
    }

    #[inline]
    pub fn nocase(&self) -> Option<&PatternModifier<'src>> {
        self.modifiers
            .iter()
            .find(|m| matches!(m, PatternModifier::Nocase { .. }))
    }

    #[inline]
    pub fn xor(&self) -> Option<&PatternModifier<'src>> {
        self.modifiers
            .iter()
            .find(|m| matches!(m, PatternModifier::Xor { .. }))
    }
}

/// Iterator that returns all the modifiers in a [`PatternModifiers`].
///
/// This is the result of [`PatternModifiers::iter`].
pub struct PatternModifiersIter<'src> {
    iter: Iter<'src, PatternModifier<'src>>,
}

impl<'src> Iterator for PatternModifiersIter<'src> {
    type Item = &'src PatternModifier<'src>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// A pattern (a.k.a. string) modifier.
#[derive(Debug)]
pub enum PatternModifier<'src> {
    Ascii { span: Span },
    Wide { span: Span },
    Nocase { span: Span },
    Private { span: Span },
    Fullword { span: Span },
    Base64 { span: Span, alphabet: Option<LiteralString<'src>> },
    Base64Wide { span: Span, alphabet: Option<LiteralString<'src>> },
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
                    write!(f, "base64({})", alphabet.literal)
                } else {
                    write!(f, "base64")
                }
            }
            PatternModifier::Base64Wide { alphabet, .. } => {
                if let Some(alphabet) = alphabet {
                    write!(f, "base64wide({})", alphabet.literal)
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

/// A pattern match expression (e.g. `$a`, `$b at 0`, `$c in (0..10)`).
#[derive(Debug)]
pub struct PatternMatch<'src> {
    pub identifier: Ident<'src>,
    pub anchor: Option<MatchAnchor<'src>>,
}

/// In expressions like `$a at 0` and `$b in (0..10)`, this type represents the
/// anchor (e.g. `at <expr>`, `in <range>`).
///
/// The anchor is the part of the expression that restricts the offset range
/// where the match can occur.
/// (e.g. `at <expr>`, `in <range>`).
#[derive(Debug)]
pub enum MatchAnchor<'src> {
    At(Box<At<'src>>),
    In(Box<In<'src>>),
}

/// In expressions like `$a at 0`, this type represents the anchor
/// (e.g. `at <expr>`).
#[derive(Debug)]
pub struct At<'src> {
    span: Span,
    pub expr: Expr<'src>,
}

/// A pair of values conforming a range (e.g. `(0..10)`).
#[derive(Debug)]
pub struct Range<'src> {
    span: Span,
    pub lower_bound: Expr<'src>,
    pub upper_bound: Expr<'src>,
}

/// In expressions like `$a in (0..10)`, this struct represents the anchor
/// e.g. `in <range>`).
#[derive(Debug)]
pub struct In<'src> {
    span: Span,
    pub range: Range<'src>,
}

/// An expression representing a function call.
#[derive(Debug)]
pub struct FuncCall<'src> {
    span: Span,
    args_span: Span,
    pub callable: Expr<'src>,
    pub args: Vec<Expr<'src>>,
}

impl FuncCall<'_> {
    /// Span covered by the function's arguments in the source code.
    pub fn args_span(&self) -> Span {
        self.args_span.clone()
    }
}

/// A lookup operation in an array or dictionary.
#[derive(Debug)]
pub struct Lookup<'src> {
    span: Span,
    pub primary: Expr<'src>,
    pub index: Expr<'src>,
}

/// A literal string (e.g: `"abcd"`).
#[derive(Debug)]
pub struct LiteralString<'src> {
    span: Span,
    /// The literal string as it appears in the source code, including the
    /// quotes.
    pub literal: &'src str,
    /// The value of the string literal. Escaped characters, if any, are
    /// unescaped. Doesn't include the quotes.
    pub value: Cow<'src, BStr>,
}

impl LiteralString<'_> {
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        match &self.value {
            // SAFETY: When the literal string is borrowed from the original
            // source code, it's safe to assume that it's valid UTF-8. This
            // has been already checked during parsing.
            Cow::Borrowed(s) => Ok(unsafe { s.to_str_unchecked() }),
            // When the literal string is owned is because the original string
            // contained some escaped character. It may contain invalid UTF-8
            // characters.
            Cow::Owned(s) => s.to_str(),
        }
    }
}

/// A literal integer (e.g: `1`, `0xAB`).
#[derive(Debug)]
pub struct LiteralInteger<'src> {
    span: Span,
    /// The literal value as it appears in the source code.
    pub literal: &'src str,
    /// The value of the integer literal.
    pub value: i64,
}

/// A literal float (e.g: `2.0`, `3.14`).
#[derive(Debug)]
pub struct LiteralFloat<'src> {
    span: Span,
    /// The literal value as it appears in the source code.
    pub literal: &'src str,
    /// The value of the integer literal.
    pub value: f64,
}

/// A regular expression in a YARA rule.
///
/// Used both as part of a [`RegexpPattern`] and as the right operand
/// of a `matches` operator.
#[derive(Debug)]
pub struct Regexp<'src> {
    span: Span,
    /// The regular expressions as it appears in the source code, including
    /// the opening and closing slashes (`/`), and the modifiers `i` and `s`,
    /// if they are present.
    pub literal: &'src str,
    /// The regexp source code. Doesn't include the opening and closing `/`.
    pub src: &'src str,
    /// True if the regular expression was followed by /i
    pub case_insensitive: bool,
    /// True if the regular expression was followed by /s
    pub dot_matches_new_line: bool,
}

/// An expression with a single operand.
#[derive(Debug)]
pub struct UnaryExpr<'src> {
    span: Span,
    pub operand: Expr<'src>,
}

/// An expression with two operands.
#[derive(Debug)]
pub struct BinaryExpr<'src> {
    /// Left-hand side.
    pub lhs: Expr<'src>,
    /// Right-hand side.
    pub rhs: Expr<'src>,
}

/// An expression with multiple operands.
#[derive(Debug)]
pub struct NAryExpr<'src> {
    pub operands: Vec<Expr<'src>>,
}

impl<'src> NAryExpr<'src> {
    #[inline]
    pub fn operands(&self) -> Iter<'_, Expr<'src>> {
        self.operands.iter()
    }

    #[inline]
    pub fn add(&mut self, expr: Expr<'src>) {
        self.operands.push(expr);
    }

    pub fn first(&self) -> &Expr<'src> {
        self.operands
            .first()
            .expect("expression is expected to have at least one operand")
    }

    pub fn last(&self) -> &Expr<'src> {
        self.operands
            .last()
            .expect("expression is expected to have at least one operand")
    }

    #[inline]
    pub fn as_slice(&self) -> &[Expr<'src>] {
        self.operands.as_slice()
    }
}

impl<'src> From<Vec<Expr<'src>>> for NAryExpr<'src> {
    fn from(value: Vec<Expr<'src>>) -> Self {
        Self { operands: value }
    }
}

/// Trait implemented by every node in the AST that has an associated span.
///
/// [`WithSpan::span`] returns a [`Span`] that indicates the starting and ending
/// position of the AST node in the original source code.
pub trait WithSpan {
    /// Returns the starting and ending position within the source code for
    /// some node in the AST.
    fn span(&self) -> Span;
}

impl WithSpan for LiteralString<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for LiteralInteger<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for LiteralFloat<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for Regexp<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for HexAlternative {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for HexByte {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for HexJump {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for HexToken {
    fn span(&self) -> Span {
        match self {
            HexToken::Byte(byte) => byte.span(),
            HexToken::NotByte(byte) => byte.span(),
            HexToken::Alternative(alt) => alt.span(),
            HexToken::Jump(jump) => jump.span(),
        }
    }
}

impl WithSpan for HexTokens {
    fn span(&self) -> Span {
        let span = self.tokens.first().map(|t| t.span()).unwrap_or_default();
        if self.tokens.len() == 1 {
            return span;
        }
        span.combine(&self.tokens.last().map(|t| t.span()).unwrap_or_default())
    }
}

impl WithSpan for Ident<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for IdentWithIndex<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for IdentWithRange<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for ForOf<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for ForIn<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for Of<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for OfItems<'_> {
    fn span(&self) -> Span {
        match self {
            OfItems::PatternSet(patterns) => patterns.span(),
            OfItems::BoolExprTuple(tuple) => tuple.span(),
        }
    }
}

impl WithSpan for Iterable<'_> {
    fn span(&self) -> Span {
        match self {
            Iterable::Range(range) => range.span(),
            Iterable::ExprTuple(tuple) => tuple.span(),
            Iterable::Expr(expr) => expr.span(),
        }
    }
}

impl WithSpan for Import<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for FuncCall<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for Pattern<'_> {
    fn span(&self) -> Span {
        match self {
            Pattern::Text(p) => p.span(),
            Pattern::Hex(p) => p.span(),
            Pattern::Regexp(p) => p.span(),
        }
    }
}

impl WithSpan for TextPattern<'_> {
    fn span(&self) -> Span {
        if self.modifiers.is_empty() {
            self.identifier.span().combine(&self.text.span)
        } else {
            self.identifier.span().combine(&self.modifiers.span())
        }
    }
}

impl WithSpan for HexPattern<'_> {
    fn span(&self) -> Span {
        if self.modifiers.is_empty() {
            self.identifier.span().combine(&self.tokens.span())
        } else {
            self.identifier.span().combine(&self.modifiers.span())
        }
    }
}

impl WithSpan for RegexpPattern<'_> {
    fn span(&self) -> Span {
        if self.modifiers.is_empty() {
            self.identifier.span().combine(&self.regexp.span)
        } else {
            self.identifier.span().combine(&self.modifiers.span())
        }
    }
}

impl WithSpan for Range<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for PatternSet<'_> {
    fn span(&self) -> Span {
        match self {
            PatternSet::Them { span } => span.clone(),
            PatternSet::Set(items) => {
                let span =
                    items.first().map(|item| item.span()).unwrap_or_default();

                if items.len() == 1 {
                    return span;
                }

                span.combine(
                    &items.last().map(|item| item.span()).unwrap_or_default(),
                )
            }
        }
    }
}

impl WithSpan for PatternModifier<'_> {
    fn span(&self) -> Span {
        match self {
            PatternModifier::Ascii { span }
            | PatternModifier::Wide { span }
            | PatternModifier::Nocase { span }
            | PatternModifier::Private { span }
            | PatternModifier::Fullword { span }
            | PatternModifier::Base64 { span, .. }
            | PatternModifier::Base64Wide { span, .. }
            | PatternModifier::Xor { span, .. } => span.clone(),
        }
    }
}

impl WithSpan for PatternModifiers<'_> {
    fn span(&self) -> Span {
        let span = self
            .modifiers
            .first()
            .expect("calling span() on an empty Vec<PatternModifier>")
            .span();

        if self.modifiers.len() > 1 {
            span.combine(&self.modifiers.last().unwrap().span())
        } else {
            span
        }
    }
}

impl WithSpan for PatternSetItem<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for Quantifier<'_> {
    fn span(&self) -> Span {
        match self {
            Quantifier::None { span } => span.clone(),
            Quantifier::All { span } => span.clone(),
            Quantifier::Any { span } => span.clone(),
            Quantifier::Percentage(expr) => expr.span(),
            Quantifier::Expr(expr) => expr.span(),
        }
    }
}

impl WithSpan for UnaryExpr<'_> {
    fn span(&self) -> Span {
        self.span.clone()
    }
}

impl WithSpan for BinaryExpr<'_> {
    fn span(&self) -> Span {
        self.lhs.span().combine(&self.rhs.span())
    }
}

impl WithSpan for NAryExpr<'_> {
    fn span(&self) -> Span {
        self.first().span().combine(&self.last().span())
    }
}

impl WithSpan for &Vec<Expr<'_>> {
    fn span(&self) -> Span {
        let span =
            self.first().expect("calling span() on an empty Vec<Expr>").span();

        if self.len() > 1 {
            span.combine(&self.last().unwrap().span())
        } else {
            span
        }
    }
}

impl WithSpan for PatternMatch<'_> {
    fn span(&self) -> Span {
        let mut span = self.identifier.span();
        if let Some(anchor) = &self.anchor {
            span = span.combine(&anchor.span())
        }
        span
    }
}

impl WithSpan for MatchAnchor<'_> {
    fn span(&self) -> Span {
        match self {
            MatchAnchor::At(a) => a.span.clone(),
            MatchAnchor::In(i) => i.span.clone(),
        }
    }
}

impl WithSpan for Expr<'_> {
    fn span(&self) -> Span {
        match self {
            Expr::False { span, .. }
            | Expr::True { span, .. }
            | Expr::Filesize { span, .. }
            | Expr::Entrypoint { span, .. } => span.clone(),

            Expr::Defined(expr)
            | Expr::Not(expr)
            | Expr::Minus(expr)
            | Expr::BitwiseNot(expr) => expr.span(),

            Expr::Shl(expr)
            | Expr::Shr(expr)
            | Expr::BitwiseAnd(expr)
            | Expr::BitwiseOr(expr)
            | Expr::BitwiseXor(expr)
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
            | Expr::Matches(expr) => expr.span(),

            Expr::And(expr)
            | Expr::Or(expr)
            | Expr::Add(expr)
            | Expr::Sub(expr)
            | Expr::Mul(expr)
            | Expr::Div(expr)
            | Expr::Mod(expr)
            | Expr::FieldAccess(expr) => expr.span(),

            Expr::LiteralString(s) => s.span.clone(),
            Expr::LiteralFloat(f) => f.span.clone(),
            Expr::LiteralInteger(i) => i.span.clone(),
            Expr::Ident(i) => i.span.clone(),
            Expr::Regexp(r) => r.span.clone(),
            Expr::Lookup(l) => l.span.clone(),
            Expr::FuncCall(f) => f.span.clone(),
            Expr::PatternMatch(p) => p.span(),
            Expr::PatternCount(p) => p.span(),
            Expr::PatternLength(p) => p.span(),
            Expr::PatternOffset(p) => p.span(),
            Expr::ForOf(f) => f.span(),
            Expr::ForIn(f) => f.span(),
            Expr::Of(o) => o.span(),
        }
    }
}
