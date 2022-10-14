use ariadne::Color;
use ascii_tree::Tree::*;
use bitmask::bitmask;
use bstr::BString;
use lazy_static::lazy_static;
use num::{Bounded, CheckedMul, FromPrimitive, Integer};
use pest::iterators::Pair;
use pest::pratt_parser::{Assoc, Op, PrattParser};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::iter::Iterator;
use std::{fmt, str, string};
use yara_derive::*;

use crate::parser::span::HasSpan;
use crate::parser::GrammarRule;
use crate::parser::{CSTNode, Context, Error, Span, CST};

pub use crate::parser::expr::*;

/// Ensures that the kind of `expr` is in a list of allowed ones.
///
/// `expr` must be some identifier of type [`Expr`], and the last argument is
/// a sequence of one or more values of `ExprKind` separated by pipes.
///
/// If `expr` is of any of the kinds in the list, `Ok(())` is returned, if not,
/// an error is returned.
///
/// # Examples
///
/// ```ignore
/// check_kind!(ctx, expr, ExprKind::Bool);
/// check_kind!(ctx, expr, ExprKind::Integer|ExprKind::Float);
/// ```
macro_rules! check_kind {
    ($ctx:ident, $expr:ident, $( $pattern:path )|+) => {
        {
            if matches!($expr.kind(), $( $pattern )|+) {
                Ok(())
            } else {
                Err(Error::wrong_type(
                    $ctx.src,
                    &[$( $pattern ),+],
                    $expr.kind(),
                    $expr.span(),
                ))
            }
        }
    };
  }

/// Ensures that `expr` does not have a negative value.
///
/// `expr` must be some identifier of type [`Expr`]. If `expr` is not of kind
/// [`ExprKind::Integer`] or its value is negative, an error is returned.
///
/// `Ok(())` is returned if otherwise.
///
/// # Example
///
/// ```ignore
/// check_non_negative_integer!(ctx, expr);
/// ```
macro_rules! check_non_negative_integer {
    ($ctx:ident, $expr:ident) => {{
        check_kind!($ctx, $expr, ExprKind::Integer)?;
        if let Some(ExprValue::Integer(value)) = $expr.value() {
            if value < 0 {
                return Err(Error::unexpected_negative(
                    $ctx.src,
                    $expr.span(),
                ));
            }
        }
        Ok(())
    }};
}

/// Macro that creates a new binary expression after validating that both
/// operands (`lhs` and `rhs`) have any of the specified expression kinds.
///
/// Both `lhs` and `rhs` must be of type [`Expr`], and the result is of type
/// `Result<Expr>`.
///
/// # Examples
///
/// ```ignore
/// new_expression!(
///     ctx,
///     Expr::Add,
///     lhs,
///     rhs,
///     ExprKind::Integer | ExprKind::Float
///  )
/// ```
macro_rules! new_expression {
    ($op:expr, $lhs:ident, $rhs:ident, $( $pattern:path )|*) => {{
        let lhs = $lhs;
        let rhs = $rhs;

        // TODO
        // check_kind!($ctx, lhs, $( $pattern )|+)?;
        // check_kind!($ctx, rhs, $( $pattern )|+)?;

        Ok($op(Box::new(BinaryExpr { lhs, rhs })))
    }};
}

macro_rules! expect {
    ($next:expr, $parser_rule:expr) => {{
        assert_eq!(
            $parser_rule,
            $next.as_rule(),
            "expecting {:?} but found {:?}",
            $parser_rule,
            $next.as_rule()
        );
    }};
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

/// Abstract Syntax Tree (AST) for YARA rules.
pub struct AST<'src> {
    pub namespaces: HashMap<&'src str, Namespace<'src>>,
}

impl<'src> Debug for AST<'src> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        ascii_tree::write_tree(f, self.ascii_tree().borrow())
    }
}

impl<'src> AST<'src> {
    /// Returns a printable ASCII tree representing the AST.
    pub fn ascii_tree(&self) -> ascii_tree::Tree {
        Node(
            "root".to_string(),
            self.namespaces.iter().map(|(_, ns)| ns.ascii_tree()).collect(),
        )
    }
}

impl<'src> AST<'src> {
    pub(crate) fn from_cst(
        ctx: &mut Context<'src>,
        cst: CST<'src>,
    ) -> Result<Self, Error> {
        // Ignore comments and whitespaces, they won't be visible while
        // traversing the CST as we don't need them for building the AST.
        let cst = cst.comments(false).whitespaces(false);
        let root = cst.into_iter().next().unwrap();
        // The root of the CST must be the grammar rule `source_file`.
        expect!(root, GrammarRule::source_file);

        let namespaces = HashMap::from([(
            "default",
            Namespace::from_cst(ctx, root.into_inner())?,
        )]);

        Ok(Self { namespaces })
    }
}

/// A namespace containing YARA rules.
///
/// Within each namespace rule identifiers are unique.
#[derive(Debug)]
pub struct Namespace<'src> {
    pub rules: HashMap<&'src str, Rule<'src>>,
    pub imports: HashSet<&'src str>,
}

impl<'src> Namespace<'src> {
    /// Creates a namespace from a CST.
    pub(crate) fn from_cst(
        ctx: &mut Context<'src>,
        cst: CST<'src>,
    ) -> Result<Self, Error> {
        let mut rules: HashMap<&str, Rule> = HashMap::new();
        let mut imports: HashSet<&str> = HashSet::new();
        for node in cst {
            match node.as_rule() {
                GrammarRule::import_stmt => {
                    let mut children = node.into_inner();
                    expect!(children.next().unwrap(), GrammarRule::k_IMPORT);
                    let ident = children.next().unwrap();
                    imports.insert(ident.as_str());
                }
                GrammarRule::rule_decl => {
                    let new_rule = rule_from_cst(ctx, node)?;
                    // Check if another rule was already defined with the same name.
                    if let Some(existing_rule) =
                        rules.get(new_rule.identifier.name)
                    {
                        return Err(ctx.error_builder.duplicate_identifier(
                            &ctx.src,
                            "rule",
                            &existing_rule.identifier,
                            &new_rule.identifier,
                        ));
                    }
                    rules.insert(new_rule.identifier.name, new_rule);
                }
                // The End Of Input (EOI) rule is ignored.
                GrammarRule::EOI => {}
                // Under `source_file` the grammar doesn't have any other types of
                // rules. This should not be reached.
                rule => unreachable!("unexpected grammar rule: `{:?}`", rule),
            }
        }
        Ok(Self { rules, imports })
    }
}

/// A YARA rule.
#[derive(Debug)]
pub struct Rule<'src> {
    flags: RuleFlags,
    identifier: Ident<'src>,
    tags: Option<HashSet<&'src str>>,
    meta: Option<Vec<Meta<'src>>>,
    strings: Option<Vec<String<'src>>>,
    condition: Expr<'src>,
}

/// A metadata entry in a YARA rule.
#[derive(Debug)]
pub struct Meta<'src> {
    identifier: Ident<'src>,
    value: MetaValue<'src>,
}

/// Each of the possible values that can have a metadata entry.
#[derive(Debug)]
pub enum MetaValue<'src> {
    Bool(bool),
    Integer(i64),
    Float(f32),
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

/// Each of the string types that can appear in a YARA rule.
///
/// There are three types of them, text strings, hex strings and regular
/// expressions.
#[derive(Debug)]
pub enum String<'src> {
    Text(Box<TextString<'src>>),
    Hex(Box<HexString<'src>>),
    Regexp(Box<Regexp<'src>>),
}

impl<'src> String<'src> {
    pub fn identifier(&self) -> &Ident<'src> {
        match self {
            String::Text(t) => &t.identifier,
            String::Regexp(r) => &r.identifier,
            String::Hex(h) => &h.identifier,
        }
    }
}

/// A string modifier.
#[derive(Debug, HasSpan)]
pub enum StringModifier {
    Ascii { span: Span },
    Wide { span: Span },
    Nocase { span: Span },
    Private { span: Span },
    Fullword { span: Span },
    Base64 { span: Span, alphabet: Option<BString> },
    Base64Wide { span: Span, alphabet: Option<BString> },
    Xor { span: Span, start: u8, end: u8 },
}

impl Display for StringModifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            StringModifier::Ascii { .. } => {
                write!(f, "ascii")
            }
            StringModifier::Wide { .. } => {
                write!(f, "wide")
            }
            StringModifier::Nocase { .. } => {
                write!(f, "nocase")
            }
            StringModifier::Private { .. } => {
                write!(f, "private")
            }
            StringModifier::Fullword { .. } => {
                write!(f, "fullword")
            }
            StringModifier::Base64 { alphabet, .. } => {
                if let Some(alphabet) = alphabet {
                    write!(f, "base64({})", alphabet)
                } else {
                    write!(f, "base64")
                }
            }
            StringModifier::Base64Wide { alphabet, .. } => {
                if let Some(alphabet) = alphabet {
                    write!(f, "base64wide({})", alphabet)
                } else {
                    write!(f, "base64wide")
                }
            }
            StringModifier::Xor { start, end, .. } => {
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

/// A text string in a YARA rule.
///
/// The value is stored as a [`BString`] instead of a [`String`] because
/// text strings in YARA can contain arbitrary bytes, including zeroes,
/// while [`String`] requires valid UTF-8. [`BString`] in the other hand
/// does not enforce valid UTF-8.
#[derive(Debug, HasSpan)]
pub struct TextString<'src> {
    span: Span,
    identifier: Ident<'src>,
    value: BString,
    modifiers: Option<HashMap<&'src str, StringModifier>>,
}

/// A hex string in a YARA rule.
#[derive(Debug, HasSpan)]
pub struct HexString<'src> {
    span: Span,
    identifier: Ident<'src>,
    pattern: HexPattern,
    modifiers: Option<HashMap<&'src str, StringModifier>>,
}

/// A sequence of tokens that conform a hex string.
#[derive(Debug)]
pub struct HexPattern {
    tokens: Vec<HexToken>,
}

/// Each of the types of tokens in a hex string.
///
/// A token can be a single byte, a negated byte (e.g. `~XX`), an
/// alternative (e.g `(XXXX|YYYY)`), or a jump (e.g `[0-10]`).
#[derive(Debug)]
pub enum HexToken {
    Byte(Box<HexByte>),
    NotByte(Box<HexByte>),
    Alternative(Box<HexAlternative>),
    Jump(Box<HexJump>),
}

/// A single byte in an hex string.
///
/// The byte is accompanied by a mask, which will be 0xFF for
/// non-masked bytes.
#[derive(Debug)]
pub struct HexByte {
    value: u8,
    mask: u8,
}

/// An alternative in a hex string.
///
/// Alternatives are hex patterns separated by `|`.
#[derive(Debug)]
pub struct HexAlternative {
    alternatives: Vec<HexPattern>,
}

/// An hex jump.
#[derive(Debug)]
pub struct HexJump {
    start: Option<u16>,
    end: Option<u16>,
}

impl HexJump {
    /// Coalesce this jump with another one.
    ///
    /// This is useful when two or more consecutive jumps appear in a hex
    /// string. In such cases the jumps can be coalesced together into a
    /// single one. For example:
    ///
    ///  `[1-2][3-4]` becomes `[4-6]`
    ///  `[0-2][5-]` becomes `[5-]`
    ///
    fn coalesce(&mut self, jump: HexJump) {
        match (self.start, jump.start) {
            (Some(s1), Some(s2)) => self.start = Some(s1 + s2),
            (Some(s1), None) => self.start = Some(s1),
            (None, Some(s2)) => self.start = Some(s2),
            (None, None) => self.start = None,
        }
        match (self.end, jump.end) {
            (Some(e1), Some(e2)) => self.end = Some(e1 + e2),
            (_, _) => self.end = None,
        }
    }
}

#[derive(Debug, HasSpan)]
pub struct Regexp<'src> {
    span: Span,
    identifier: Ident<'src>,
    regexp: &'src str,
    modifiers: Option<HashMap<&'src str, StringModifier>>,
}

impl<'src> Namespace<'src> {
    pub fn ascii_tree(&self) -> ascii_tree::Tree {
        Node(
            "namespace".to_string(),
            self.rules.iter().map(|(_, rule)| rule.ascii_tree()).collect(),
        )
    }
}

impl<'src> Rule<'src> {
    fn ascii_tree(&self) -> ascii_tree::Tree {
        let mut rule_children = vec![];

        if let Some(meta) = &self.meta {
            rule_children.push(Node(
                "meta".to_owned(),
                meta.iter()
                    .map(|m| {
                        Leaf(vec![format!(
                            "{} = {}",
                            m.identifier.name, m.value
                        )])
                    })
                    .collect(),
            ))
        }

        if let Some(strings) = &self.strings {
            rule_children.push(Node(
                "strings".to_owned(),
                strings.iter().map(|s| s.ascii_tree()).collect(),
            ))
        }

        rule_children.push(Node(
            "condition".to_owned(),
            vec![self.condition.ascii_tree()],
        ));

        let mut modifiers = vec![];

        if self.flags.contains(RuleFlag::Private) {
            modifiers.push("private");
        }

        if self.flags.contains(RuleFlag::Global) {
            modifiers.push("global");
        }

        Node(
            if modifiers.is_empty() {
                format!("rule {}", self.identifier.name)
            } else {
                format!(
                    "{} rule {}",
                    modifiers.join(" "),
                    self.identifier.name
                )
            },
            rule_children,
        )
    }
}

impl<'src> String<'src> {
    fn ascii_tree(&self) -> ascii_tree::Tree {
        match self {
            String::Text(s) => {
                let modifiers = if let Some(modifiers) = &s.modifiers {
                    // The string has modifiers let's generate a textual
                    // representation of them.
                    let mut m = modifiers
                        .values()
                        .map(|s| s.to_string())
                        .collect::<Vec<string::String>>();
                    // .values() doesn't guarantee a stable order, so we need
                    // to explicitly sort the vector in order to have a
                    // predictable result.
                    m.sort();
                    m.join(" ")
                } else {
                    "".to_string()
                };

                Leaf(vec![format!(
                    "{} = \"{}\" {}",
                    s.identifier.name, s.value, modifiers
                )])
            }
            String::Hex(h) => Node(
                h.identifier.name.to_string(),
                vec![h.pattern.ascii_tree()],
            ),
            String::Regexp(r) => Leaf(vec![r.identifier.name.to_string()]),
        }
    }
}

impl HexPattern {
    fn ascii_tree(&self) -> ascii_tree::Tree {
        let nodes = self
            .tokens
            .iter()
            .map(|t| match t {
                HexToken::Byte(b) => Leaf(vec![format!(
                    "{:#04X} mask: {:#04X}",
                    b.value, b.mask
                )]),
                HexToken::NotByte(b) => Leaf(vec![format!(
                    "~ {:#04X} mask: {:#04X}",
                    b.value, b.mask
                )]),
                HexToken::Alternative(a) => Node(
                    "alt".to_string(),
                    a.alternatives
                        .iter()
                        .map(|alt| alt.ascii_tree())
                        .collect(),
                ),
                HexToken::Jump(j) => Leaf(vec![format!(
                    "[{}-{}]",
                    j.start.map_or("".to_string(), |v| v.to_string()),
                    j.end.map_or("".to_string(), |v| v.to_string())
                )]),
            })
            .collect();

        Node("hex".to_string(), nodes)
    }
}

fn create_binary_expr<'src>(
    lhs: Expr<'src>,
    op: GrammarRule,
    rhs: Expr<'src>,
) -> Result<Expr<'src>, Error> {
    match op {
        // Boolean
        GrammarRule::k_OR => {
            new_expression!(Expr::Or, lhs, rhs, ExprKind::Bool)
        }
        GrammarRule::k_AND => {
            new_expression!(Expr::And, lhs, rhs, ExprKind::Bool)
        }
        // Arithmetic
        GrammarRule::ADD => new_expression!(
            Expr::Add,
            lhs,
            rhs,
            ExprKind::Integer | ExprKind::Float
        ),
        GrammarRule::SUB => new_expression!(
            Expr::Sub,
            lhs,
            rhs,
            ExprKind::Integer | ExprKind::Float
        ),
        GrammarRule::MUL => new_expression!(
            Expr::Mul,
            lhs,
            rhs,
            ExprKind::Integer | ExprKind::Float
        ),
        GrammarRule::DIV => new_expression!(
            Expr::Div,
            lhs,
            rhs,
            ExprKind::Integer | ExprKind::Float
        ),
        GrammarRule::MOD => new_expression!(
            Expr::Modulus,
            lhs,
            rhs,
            ExprKind::Integer | ExprKind::Float
        ),
        // Bitwise
        GrammarRule::SHL => {
            // TODO
            // check_non_negative_integer!(ctx, rhs)?;
            new_expression!(Expr::Shl, lhs, rhs, ExprKind::Integer)
        }
        GrammarRule::SHR => {
            // TODO
            // check_non_negative_integer!(ctx, rhs)?;
            new_expression!(Expr::Shr, lhs, rhs, ExprKind::Integer)
        }
        GrammarRule::BITWISE_AND => {
            new_expression!(Expr::BitwiseAnd, lhs, rhs, ExprKind::Integer)
        }
        GrammarRule::BITWISE_OR => {
            new_expression!(Expr::BitwiseOr, lhs, rhs, ExprKind::Integer)
        }
        GrammarRule::BITWISE_XOR => {
            new_expression!(Expr::BitwiseXor, lhs, rhs, ExprKind::Integer)
        }
        // Comparison
        GrammarRule::EQ => new_expression!(
            Expr::Eq,
            lhs,
            rhs,
            ExprKind::Float | ExprKind::Integer | ExprKind::String
        ),
        GrammarRule::NEQ => new_expression!(
            Expr::Neq,
            lhs,
            rhs,
            ExprKind::Float | ExprKind::Integer | ExprKind::String
        ),
        GrammarRule::LT => new_expression!(
            Expr::Lt,
            lhs,
            rhs,
            ExprKind::Float | ExprKind::Integer | ExprKind::String
        ),
        GrammarRule::LE => new_expression!(
            Expr::Le,
            lhs,
            rhs,
            ExprKind::Float | ExprKind::Integer | ExprKind::String
        ),
        GrammarRule::GT => new_expression!(
            Expr::Gt,
            lhs,
            rhs,
            ExprKind::Float | ExprKind::Integer | ExprKind::String
        ),
        GrammarRule::GE => new_expression!(
            Expr::Ge,
            lhs,
            rhs,
            ExprKind::Float | ExprKind::Integer | ExprKind::String
        ),
        GrammarRule::k_CONTAINS => {
            new_expression!(Expr::Contains, lhs, rhs, ExprKind::String)
        }
        GrammarRule::k_ICONTAINS => {
            new_expression!(Expr::IContains, lhs, rhs, ExprKind::String)
        }
        GrammarRule::k_STARTSWITH => {
            new_expression!(Expr::StartsWith, lhs, rhs, ExprKind::String)
        }
        GrammarRule::k_ISTARTSWITH => {
            new_expression!(Expr::IStartsWith, lhs, rhs, ExprKind::String)
        }
        GrammarRule::k_ENDSWITH => {
            new_expression!(Expr::EndsWith, lhs, rhs, ExprKind::String)
        }
        GrammarRule::k_IENDSWITH => {
            new_expression!(Expr::IEndsWith, lhs, rhs, ExprKind::String)
        }
        GrammarRule::DOT => new_expression!(Expr::FieldAccess, lhs, rhs,),
        rule => unreachable!("{:?}", rule),
    }
}

lazy_static! {
    // Map that indicates which modifiers are accepted by each type of strings.
    // For example, `private` modifiers is accepted by text strings, hex strings
    // and regexps, while `base64` is only accepted by text strings.
    static ref ACCEPTED_MODIFIERS: HashMap<&'static str, Vec<GrammarRule>> =
        HashMap::from([
            (
                "private",
                vec![
                    GrammarRule::string_lit,
                    GrammarRule::regexp,
                    GrammarRule::hex_string,
                ],
            ),
            ("ascii", vec![GrammarRule::string_lit, GrammarRule::regexp]),
            ("wide", vec![GrammarRule::string_lit, GrammarRule::regexp]),
            ("nocase", vec![GrammarRule::string_lit, GrammarRule::regexp]),
            ("fullword", vec![GrammarRule::string_lit, GrammarRule::regexp]),
            ("base64", vec![GrammarRule::string_lit]),
            ("base64wide", vec![GrammarRule::string_lit]),
            ("xor", vec![GrammarRule::string_lit]),
        ]);
}

/// Check if the set of modifiers of a string are valid.
///
/// Certain string modifiers can't be used in conjunction, and this function
/// returns an error in those cases.
fn check_string_modifiers<'src>(
    ctx: &mut Context<'src>,
    rule_type: GrammarRule,
    modifiers: &HashMap<&'src str, StringModifier>,
) -> Result<(), Error> {
    let xor = modifiers.get("xor");
    let nocase = modifiers.get("nocase");
    let fullword = modifiers.get("fullword");
    let base64 = modifiers.get("base64");
    let base64wide = modifiers.get("base64wide");

    for (name, modifier) in modifiers.iter() {
        if !ACCEPTED_MODIFIERS[name].contains(&rule_type) {
            let msg = match rule_type {
                GrammarRule::hex_string => {
                    "this modifier can't be applied to a hex string"
                }
                GrammarRule::regexp => {
                    "this modifier can't be applied to a regexp"
                }
                _ => unreachable!(),
            };
            return Err(ctx.error_builder.simple_error(
                &ctx.src,
                modifier.span(),
                "invalid string modifier",
                msg,
            ));
        }
    }

    let invalid_combinations = [
        ("xor", xor, "nocase", nocase),
        ("base64", base64, "nocase", nocase),
        ("base64wide", base64wide, "nocase", nocase),
        ("base64", base64, "fullword", fullword),
        ("base64wide", base64wide, "fullword", fullword),
        ("base64", base64, "nocase", nocase),
        ("base64wide", base64wide, "nocase", nocase),
        ("base64", base64, "xor", xor),
        ("base64wide", base64wide, "xor", xor),
    ];

    for (name1, modifier1, name2, modifier2) in invalid_combinations {
        if modifier1.is_some() && modifier2.is_some() {
            let modifier1 = modifier1.unwrap();
            let modifier2 = modifier2.unwrap();
            return Err(ctx.error_builder.create_report(
                &ctx.src,
                modifier1.span(),
                format!("invalid modifier combination: `{name1}` `{name2}`"),
                vec![
                    (
                        modifier1.span(),
                        format!("`{name1}` modifier used here"),
                        Color::Red.style().bold(),
                    ),
                    (
                        modifier2.span(),
                        format!("`{name2}` modifier used here"),
                        Color::Red.style().bold(),
                    ),
                ],
                Some("These two modifiers can't be used together"),
            ));
        }
    }

    Ok(())
}

/// Given a CST node corresponding to the grammar rule` rule_decl`, returns a
/// [`Rule`] structure describing the rule.
fn rule_from_cst<'src>(
    ctx: &mut Context<'src>,
    rule_decl: CSTNode<'src>,
) -> Result<Rule<'src>, Error> {
    expect!(rule_decl, GrammarRule::rule_decl);

    let mut children = rule_decl.into_inner();
    let mut node = children.next().unwrap();
    let mut flags = RuleFlags::none();

    // Process rule modifiers if any (i.e: private, global). The CST for the
    // modifiers looks like:
    //
    // rule_mods
    // ├─ k_PRIVATE "private"
    // └─ k_GLOBAL "global"
    //
    if let GrammarRule::rule_mods = node.as_rule() {
        for modifier in node.into_inner() {
            match modifier.as_rule() {
                GrammarRule::k_PRIVATE => flags.set(RuleFlag::Private),
                GrammarRule::k_GLOBAL => flags.set(RuleFlag::Global),
                parser_rule => {
                    panic!("unexpected rule modifier {:?}", parser_rule)
                }
            }
        }
        node = children.next().unwrap();
    }

    // The `rule` keyword is expected after the modifiers, or as the first
    // token if the rule doesn't have any modifiers.
    expect!(node, GrammarRule::k_RULE);
    node = children.next().unwrap();

    // The rule identifier should be right after the `rule` keyword.
    expect!(node, GrammarRule::ident);

    let identifier = Ident::from(node);
    node = children.next().unwrap();

    // Process rule tags, if any. The CST looks like:
    //
    // rule_tags
    // ├─ COLON ":"
    // ├─ ident "foo"
    // ├─ ident "bar"
    // └─ ident "baz"
    //
    let tags = if let GrammarRule::rule_tags = node.as_rule() {
        let mut tags = HashSet::new();

        // Iterate over all `ident`s that are children of `rule_tags`,
        // ignoring other grammar rules like `COLON`.
        let idents = node
            .into_inner()
            .filter(|item| item.as_rule() == GrammarRule::ident);

        for ident in idents {
            if !tags.insert(ident.as_str()) {
                return Err(ctx.error_builder.duplicate_tag(
                    &ctx.src,
                    format!(
                        "duplicate tag `{}` for rule `{}`",
                        ident.as_str(),
                        identifier.name
                    ),
                    Span {
                        start: ident.as_span().start(),
                        end: ident.as_span().end(),
                    },
                ));
            }
        }

        node = children.next().unwrap();

        Some(tags)
    } else {
        None
    };

    // The opening brace should come next.
    expect!(node, GrammarRule::LBRACE);
    node = children.next().unwrap();

    // Process the `meta` section, if any.
    let meta = if let GrammarRule::meta_defs = node.as_rule() {
        let meta = meta_from_cst(ctx, node)?;
        node = children.next().unwrap();
        Some(meta)
    } else {
        None
    };

    // Process the `strings` section, if any.
    let strings = if let GrammarRule::string_defs = node.as_rule() {
        let strings = strings_from_cst(ctx, node)?;
        node = children.next().unwrap();
        Some(strings)
    } else {
        None
    };

    // The condition section must start with "condition" ...
    expect!(node, GrammarRule::k_CONDITION);
    node = children.next().unwrap();

    // ... followed by a colon (:)
    expect!(node, GrammarRule::COLON);
    node = children.next().unwrap();

    // And then the condition's boolean expression.
    let condition = boolean_expr_from_cst(ctx, node)?;
    node = children.next().unwrap();

    // Any identifier left in ctx.string_identifiers is not being
    // used in the condition.
    if let Some((_, ident)) = ctx.string_identifiers.drain().next() {
        return Err(ctx.error_builder.simple_error(
            &ctx.src,
            ident.span,
            format!("unused string `{}`", ident.name),
            "this was not used in the condition",
        ));
    }

    // The closing brace should come next.
    expect!(node, GrammarRule::RBRACE);

    // Nothing more after the closing brace.
    assert!(children.next().is_none());

    Ok(Rule { flags, identifier, tags, meta, strings, condition })
}

/// Given a CST node corresponding to the grammar rule` string_defs`, returns
/// a vector of [`String`] structs describing the defined strings.
fn strings_from_cst<'src>(
    ctx: &mut Context<'src>,
    string_defs: CSTNode<'src>,
) -> Result<Vec<String<'src>>, Error> {
    expect!(string_defs, GrammarRule::string_defs);

    let mut children = string_defs.into_inner();

    // The first two children are the `strings` keyword and the colon (`:`).
    expect!(children.next().unwrap(), GrammarRule::k_STRINGS);
    expect!(children.next().unwrap(), GrammarRule::COLON);

    let mut strings: Vec<String> = vec![];

    // All the remaining children are `string_def`.
    for string_def in children {
        expect!(string_def, GrammarRule::string_def);
        let new_string = string_from_cst(ctx, string_def)?;
        let new_string_ident = new_string.identifier().clone();

        // Check if another string with the same identifier already exists, but
        // only if the identifier is not `$`.
        if new_string_ident.name != "$" {
            if let Some(existing_string_ident) =
                ctx.string_identifiers.get(&new_string_ident.name[1..])
            {
                return Err(ctx.error_builder.duplicate_identifier(
                    &ctx.src,
                    "string",
                    existing_string_ident,
                    &new_string_ident,
                ));
            }
        }

        // Store the string identifiers that are declared. These identifiers
        // will be removed from this map as they are used in the condition.
        // Any identifier left in the map when the condition has been fully
        // parsed is an unused identifier. Notice that identifiers are stored
        // without the `$` prefix.
        ctx.string_identifiers
            .insert(&new_string_ident.name[1..], new_string_ident);

        strings.push(new_string);
    }

    Ok(strings)
}

/// Given a CST node corresponding to the grammar rule` string_def`, returns
/// a [`String`] struct describing the defined string.
fn string_from_cst<'src>(
    ctx: &mut Context<'src>,
    string_def: CSTNode<'src>,
) -> Result<String<'src>, Error> {
    expect!(string_def, GrammarRule::string_def);

    let mut children = string_def.into_inner();

    // The first child of the `string_def` rule is the string identifier,
    // let's store it in ctx.current_string_identifier.
    ctx.current_string_identifier =
        Some(Ident::from(children.next().unwrap()));

    // The identifier must be followed by the equal sign.
    expect!(children.next().unwrap(), GrammarRule::EQUAL);

    let node = children.next().unwrap();

    // The remaining children are the actual string definition, which
    // vary depending on the type of string.
    let string = match node.as_rule() {
        GrammarRule::hex_string => {
            let span = node.as_span();
            let mut hex_string = node.into_inner();

            // Hex strings start with a left brace `{`.
            expect!(hex_string.next().unwrap(), GrammarRule::LBRACE);

            // Parse the content in-between the braces. While this is done
            // the identifier is stored in ctx.current_string_identifier.
            let pattern =
                hex_pattern_from_cst(ctx, hex_string.next().unwrap())?;

            // Take the identifier and set ctx.current_string_identifier
            // to None.
            let identifier = ctx.current_string_identifier.take().unwrap();

            // Check for the closing brace `}`.
            expect!(hex_string.next().unwrap(), GrammarRule::RBRACE);

            let modifiers = if let Some(modifiers) = children.next() {
                Some(string_mods_from_cst(
                    ctx,
                    GrammarRule::hex_string,
                    modifiers,
                )?)
            } else {
                None
            };

            String::Hex(Box::new(HexString {
                span: span.into(),
                identifier,
                pattern,
                modifiers,
            }))
        }
        GrammarRule::string_lit => {
            let span = node.as_span().into();
            let value = string_lit_from_cst(ctx, node)?;
            let modifiers = if let Some(modifiers) = children.next() {
                Some(string_mods_from_cst(
                    ctx,
                    GrammarRule::string_lit,
                    modifiers,
                )?)
            } else {
                None
            };
            // Take the identifier and set ctx.current_string_identifier
            // to None.
            let identifier = ctx.current_string_identifier.take().unwrap();

            String::Text(Box::new(TextString {
                identifier,
                value,
                span,
                modifiers,
            }))
        }
        GrammarRule::regexp => {
            let modifiers = if let Some(modifiers) = children.next() {
                Some(string_mods_from_cst(
                    ctx,
                    GrammarRule::regexp,
                    modifiers,
                )?)
            } else {
                None
            };
            // Take the identifier and set ctx.current_string_identifier
            // to None.
            let identifier = ctx.current_string_identifier.take().unwrap();

            String::Regexp(Box::new(Regexp {
                identifier,
                modifiers,
                span: node.as_span().into(),
                regexp: node.as_str(),
            }))
        }
        rule => unreachable!("{:?}", rule),
    };

    Ok(string)
}

/// Given a CST node corresponding to the grammar rule `string_mods`, returns
/// a hash set of [`StringModifier`] structs describing the modifiers.
fn string_mods_from_cst<'src>(
    ctx: &mut Context<'src>,
    rule_type: GrammarRule,
    string_mods: CSTNode<'src>,
) -> Result<HashMap<&'src str, StringModifier>, Error> {
    expect!(string_mods, GrammarRule::string_mods);

    let mut children = string_mods.into_inner().peekable();
    let mut modifiers = HashMap::new();

    while let Some(node) = children.next() {
        let modifier = match node.as_rule() {
            GrammarRule::k_ASCII => {
                StringModifier::Ascii { span: node.as_span().into() }
            }
            GrammarRule::k_WIDE => {
                StringModifier::Wide { span: node.as_span().into() }
            }
            GrammarRule::k_PRIVATE => {
                StringModifier::Private { span: node.as_span().into() }
            }
            GrammarRule::k_FULLWORD => {
                StringModifier::Fullword { span: node.as_span().into() }
            }
            GrammarRule::k_NOCASE => {
                StringModifier::Nocase { span: node.as_span().into() }
            }
            GrammarRule::k_XOR => {
                let mut lower_bound = 0;
                let mut upper_bound = 255;
                // The `xor` modifier may be followed by arguments describing
                // the xor range. e.g: `xor(2)`, `xor(0-10)`. If not, the
                // default range is 0-255.
                if let Some(node) = children.peek() {
                    if node.as_rule() == GrammarRule::LPAREN {
                        children.next().unwrap();

                        let node = children.next().unwrap();
                        let lower_bound_span = node.as_span().into();

                        // Parse the integer after the opening parenthesis `(`.
                        lower_bound = integer_lit_from_cst::<u8>(ctx, node)?;

                        // See what comes next, it could be a hyphen `-` or the
                        // closing parenthesis `)`
                        upper_bound = match children.next().unwrap().as_rule()
                        {
                            // If it is the closing parenthesis, the upper bound
                            // of the xor range is equal to the lower bound.
                            GrammarRule::RPAREN => lower_bound,
                            // If a hyphen follows, parse the integer after the
                            // hyphen.
                            GrammarRule::HYPHEN => {
                                let integer = integer_lit_from_cst::<u8>(
                                    ctx,
                                    children.next().unwrap(),
                                )?;
                                expect!(
                                    children.next().unwrap(),
                                    GrammarRule::RPAREN
                                );
                                integer
                            }
                            rule => unreachable!("{:?}", rule),
                        };

                        if lower_bound > upper_bound {
                            return Err(ctx.error_builder.invalid_range(
                                &ctx.src,
                                lower_bound_span,
                                format!(
                                    "lower bound ({}) is greater than upper bound ({})",
                                    lower_bound, upper_bound),
                            ));
                        }
                    }
                }

                StringModifier::Xor {
                    span: node.as_span().into(),
                    end: upper_bound,
                    start: lower_bound,
                }
            }
            rule @ (GrammarRule::k_BASE64 | GrammarRule::k_BASE64WIDE) => {
                let mut alphabet = None;
                if let Some(node) = children.peek() {
                    if node.as_rule() == GrammarRule::LPAREN {
                        children.next().unwrap();
                        alphabet = Some(string_lit_from_cst(
                            ctx,
                            children.next().unwrap(),
                        )?);
                        expect!(children.next().unwrap(), GrammarRule::RPAREN);
                    }
                }
                match rule {
                    GrammarRule::k_BASE64 => StringModifier::Base64 {
                        span: node.as_span().into(),
                        alphabet,
                    },
                    GrammarRule::k_BASE64WIDE => StringModifier::Base64Wide {
                        span: node.as_span().into(),
                        alphabet,
                    },
                    _ => unreachable!(),
                }
            }
            rule => unreachable!("{:?}", rule),
        };

        let span = modifier.span();
        if let Some(_) = modifiers.insert(node.as_str(), modifier) {
            return Err(ctx
                .error_builder
                .duplicate_string_modifier(&ctx.src, span));
        }
    }

    // Check for invalid combinations of string modifiers.
    check_string_modifiers(ctx, rule_type, &modifiers)?;

    Ok(modifiers)
}

/// Given a CST node corresponding to the grammar rule` meta_defs`, returns
/// a vector of [`Meta`] structs describing the defined metadata.
fn meta_from_cst<'src>(
    ctx: &mut Context<'src>,
    meta_defs: CSTNode<'src>,
) -> Result<Vec<Meta<'src>>, Error> {
    expect!(meta_defs, GrammarRule::meta_defs);

    let mut children = meta_defs.into_inner();

    // The first two children are the `meta` keyword and the colon.
    expect!(children.next().unwrap(), GrammarRule::k_META);
    expect!(children.next().unwrap(), GrammarRule::COLON);

    let mut result = vec![];

    // All the remaining children are `meta_def`.
    for meta_def in children {
        expect!(meta_def, GrammarRule::meta_def);

        let mut nodes = meta_def.into_inner();
        let identifier = Ident::from(nodes.next().unwrap());

        expect!(nodes.next().unwrap(), GrammarRule::EQUAL);

        let value_node = nodes.next().unwrap();
        let value = match value_node.as_rule() {
            GrammarRule::k_TRUE => MetaValue::Bool(true),
            GrammarRule::k_FALSE => MetaValue::Bool(false),
            GrammarRule::integer_lit => {
                MetaValue::Integer(integer_lit_from_cst(ctx, value_node)?)
            }
            GrammarRule::float_lit => {
                MetaValue::Float(float_lit_from_cst(ctx, value_node)?)
            }
            GrammarRule::string_lit => MetaValue::String(value_node.as_str()),
            rule => unreachable!("{:?}", rule),
        };

        result.push(Meta { identifier, value });
    }

    Ok(result)
}

// Operator precedence rules are defined here. Operators are added to
// PrattParser in order of precedence, with low precedence operators
// added first. Operators with the same precedence are added in a single
// call to the `op` function, with operators separated by a pipe `|`.
//
// `PRATT_PARSER` has a `parse` function that receives a sequence of expressions
// interleaved with operators. For example, it can receive..
//
// <expr> <infix op> <expr>
//
// <expr> <infix op> <expr> <infix op> <expr>
//
// In general...
//
//  <expr> ( <infix op> <expr> )*
//
// Notice that the a single <expr> is also acceptable.
//
// All the expressions are passed through a "map" function (the argument to
// map_primary), which transforms each expression in a certain value of any
// type you want, let's call it T.
//
// Another function F (the argument to map_infix) receives three arguments
// <operand> <infix op> <operand>, where operands are of type T. The result
// of this function is also a T. This behaves like a "reduce" function, that
// keeps reducing the original sequence by merging two Ts together, until we
// have a final T, which will be the result returned by `parse`. The difference
// with a standard "reduce" is that the order in which the elements of the
// original sequence are passed to F is defined by the precedence rules in
// PrattParser.
//
// For example, for the sequence 1 + 2 * 3, the first call to G will be with
// arguments (2, *, 3), which produces a T1. In a second call to F the arguments
// will be (1, +, T1) and its result T2 will be returned by `parse` because
// there's no more expression to reduce.
//
// More details:
// https://en.wikipedia.org/wiki/Operator-precedence_parser#Pratt_parsing
lazy_static! {
    static ref PRATT_PARSER: PrattParser<GrammarRule> = PrattParser::new()
        .op(Op::infix(GrammarRule::k_OR, Assoc::Left))
        .op(Op::infix(GrammarRule::k_AND, Assoc::Left))
        .op(Op::infix(GrammarRule::EQ, Assoc::Left)
            | Op::infix(GrammarRule::NEQ, Assoc::Left)
            | Op::infix(GrammarRule::k_CONTAINS, Assoc::Left)
            | Op::infix(GrammarRule::k_ICONTAINS, Assoc::Left)
            | Op::infix(GrammarRule::k_STARTSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_ISTARTSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_ENDSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_IENDSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_MATCHES, Assoc::Left))
        .op(Op::infix(GrammarRule::LT, Assoc::Left)
            | Op::infix(GrammarRule::LE, Assoc::Left)
            | Op::infix(GrammarRule::GT, Assoc::Left)
            | Op::infix(GrammarRule::GE, Assoc::Left))
        .op(Op::infix(GrammarRule::BITWISE_OR, Assoc::Left))
        .op(Op::infix(GrammarRule::BITWISE_XOR, Assoc::Left))
        .op(Op::infix(GrammarRule::BITWISE_AND, Assoc::Left))
        .op(Op::infix(GrammarRule::SHL, Assoc::Left)
            | Op::infix(GrammarRule::SHR, Assoc::Left))
        .op(Op::infix(GrammarRule::ADD, Assoc::Left)
            | Op::infix(GrammarRule::SUB, Assoc::Left))
        .op(Op::infix(GrammarRule::MUL, Assoc::Left)
            | Op::infix(GrammarRule::DIV, Assoc::Left)
            | Op::infix(GrammarRule::MOD, Assoc::Left))
        .op(Op::infix(GrammarRule::DOT, Assoc::Left));
}

/// From a CST node corresponding to the grammar rule `boolean_expr`, returns
/// an [`Expr`] describing the boolean expression.
fn boolean_expr_from_cst<'src>(
    ctx: &mut Context<'src>,
    boolean_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(boolean_expr, GrammarRule::boolean_expr);

    // This is where the magic for grouping terms according to operator
    // precedence rules happens. See the comment in the definition of
    // `PRATT_PARSER` for more details about how it works.
    PRATT_PARSER
        .map_primary(|pair| {
            boolean_term_from_cst(
                ctx,
                CSTNode::from(pair).comments(false).whitespaces(false),
            )
        })
        .map_infix(
            |lhs: Result<Expr, Error>,
             op: Pair<'src, GrammarRule>,
             rhs: Result<Expr, Error>| {
                create_binary_expr(lhs?, op.as_rule(), rhs?)
            },
        )
        .parse(boolean_expr.into_inner_pairs())
}

/// From a CST node corresponding to the grammar rule `boolean_term`, returns
/// an [`Expr`] describing the boolean term.
fn boolean_term_from_cst<'src>(
    ctx: &mut Context<'src>,
    boolean_term: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(boolean_term, GrammarRule::boolean_term);

    let boolean_term_span = boolean_term.as_span();
    let mut children = boolean_term.into_inner().peekable();

    // Based on the first child we decide what to do next, but the first child
    // is not consumed from the iterator at this moment.
    let expr = match children.peek().unwrap().as_rule() {
        GrammarRule::k_TRUE => {
            Expr::True { span: children.next().unwrap().as_span().into() }
        }
        GrammarRule::k_FALSE => {
            Expr::False { span: children.next().unwrap().as_span().into() }
        }
        GrammarRule::k_NOT => {
            // Consume the first child, corresponding to the `not` keyword.
            let not = children.next().unwrap();

            // The child after the `not` is the negated boolean term.
            let term = children.next().unwrap();

            Expr::Not(Box::new(UnaryExpr {
                span: Span {
                    start: not.as_span().start(),
                    end: term.as_span().end(),
                },
                operand: boolean_term_from_cst(ctx, term)?,
            }))
        }
        GrammarRule::LPAREN => {
            // Consume the opening parenthesis.
            children.next();

            // The next node should be a boolean expression.
            let expr = boolean_expr_from_cst(ctx, children.next().unwrap())?;

            // The boolean expression must be followed by a closing
            // parenthesis.
            expect!(children.next().unwrap(), GrammarRule::RPAREN);

            expr
        }
        GrammarRule::string_ident => {
            let ident = children.next().unwrap();
            let ident_name = ident.as_str();
            let anchor = anchor_from_cst(ctx, children)?;

            // The use of `$` in the condition doesn't mean that all anonymous
            // string identifiers are used. Anonymous string identifiers are
            // considered used when the `them` keyword is used, or when the
            // pattern `$*` appears in a string identifiers tuple.
            if ident_name != "$" {
                ctx.string_identifiers.remove(&ident_name[1..]);
            }
            // `$` used outside a `for .. of` statement, that's invalid.
            else if !ctx.inside_for_of {
                return Err(ctx.error_builder.simple_error(
                    &ctx.src,
                    ident.as_span().into(),
                    "wrong use of `$` placeholder",
                    "this `$` is outside of the condition of a `for .. of` statement",
                ));
            }

            Expr::StringMatch(Box::new(StringMatch {
                // TODO: this is not the best way of computing the span for
                // StringMatch, as this covers the space that can follow, like
                // in:
                //   $a in (0..100)
                //   ^^^^^^^^^^^^^^^
                // The best way is using the anchor's span end.
                span: boolean_term_span.into(),
                identifier: Ident {
                    span: ident.as_span().into(),
                    name: ident_name,
                },
                anchor,
            }))
        }
        GrammarRule::expr => {
            // See comments in `boolean_expr_from_cst` for some explanation
            // of the logic below.
            let expr = PRATT_PARSER
                .map_primary(|pair| {
                    expr_from_cst(
                        ctx,
                        CSTNode::from(pair).comments(false).whitespaces(false),
                    )
                })
                .map_infix(
                    |lhs: Result<Expr, Error>,
                     op: Pair<'src, GrammarRule>,
                     rhs: Result<Expr, Error>| {
                        create_binary_expr(lhs?, op.as_rule(), rhs?)
                    },
                )
                .parse(children.map(|node| node.into_pair()))?;

            // TODO
            // Make sure that the expression returned is of boolean kind.
            // check_kind!(ctx, expr, ExprKind::Bool)?;
            expr
        }
        GrammarRule::of_expr => {
            of_expr_from_cst(ctx, children.next().unwrap())?
        }
        GrammarRule::for_expr => {
            for_expr_from_cst(ctx, children.next().unwrap())?
        }
        _ => unreachable!(),
    };

    Ok(expr)
}

/// From a CST node corresponding to the grammar rule `expr`, returns an
/// [`Expr`] describing the expression.
fn expr_from_cst<'src>(
    ctx: &mut Context<'src>,
    expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(expr, GrammarRule::expr);

    let mut children = expr.into_inner().peekable();

    match children.peek().unwrap().as_rule() {
        GrammarRule::term => PRATT_PARSER
            .map_primary(|pair| {
                term_from_cst(
                    ctx,
                    CSTNode::from(pair).comments(false).whitespaces(false),
                )
            })
            .map_infix(
                |lhs: Result<Expr, Error>,
                 op: Pair<'src, GrammarRule>,
                 rhs: Result<Expr, Error>| {
                    create_binary_expr(lhs?, op.as_rule(), rhs?)
                },
            )
            .parse(children.map(|node| node.into_pair())),
        rule => unreachable!("{:?}", rule),
    }
}

/// From a CST node corresponding to the grammar rule `term` , returns
/// an [`Expr`] describing the term.
fn term_from_cst<'src>(
    ctx: &mut Context<'src>,
    term: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(term, GrammarRule::term);

    let mut children = term.into_inner();
    let node = children.next().unwrap();

    let expr = match node.as_rule() {
        GrammarRule::indexing_expr => indexing_expr_from_cst(ctx, node)?,
        GrammarRule::func_call_expr => func_call_expr_from_cst(ctx, node)?,
        GrammarRule::primary_expr => primary_expr_from_cst(ctx, node)?,
        rule => unreachable!("{:?}", rule),
    };

    // Make sure that there are no more children.
    assert!(children.next().is_none());

    Ok(expr)
}

/// From a CST node corresponding to the grammar rule `primary_expr` , returns
/// an [`Expr`] describing the expression.
fn primary_expr_from_cst<'src>(
    ctx: &mut Context<'src>,
    primary_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    // The CST node passed to this function must correspond to a primary
    // expression.
    expect!(primary_expr, GrammarRule::primary_expr);

    let term_span = primary_expr.as_span();
    let mut children = primary_expr.into_inner();
    let node = children.next().unwrap();

    let expr = match node.as_rule() {
        GrammarRule::ident => {
            let mut expr = Expr::Ident(Box::new(Ident {
                span: node.as_span().into(),
                name: node.as_str(),
            }));

            // The identifier can be followed by a field access operator,
            // (e.g. `foo.bar.baz`).
            while let Some(node) = children.next() {
                // In fact, if something follows the identifier it must
                // be a field access operator `.`, nothing else.
                expect!(node, GrammarRule::DOT);

                let node = children.next().unwrap();

                expr = Expr::FieldAccess(Box::new(BinaryExpr {
                    lhs: expr,
                    rhs: Expr::Ident(Box::new(Ident {
                        span: node.as_span().into(),
                        name: node.as_str(),
                    })),
                }));
            }

            expr
        }
        GrammarRule::k_FILESIZE => {
            Expr::Filesize { span: node.as_span().into() }
        }
        GrammarRule::k_ENTRYPOINT => {
            Expr::Entrypoint { span: node.as_span().into() }
        }
        GrammarRule::MINUS => {
            let operand = term_from_cst(ctx, children.next().unwrap())?;
            // TODO
            // check_kind!(ctx, operand, ExprKind::Integer | ExprKind::Float)?;
            Expr::Minus(Box::new(UnaryExpr {
                span: term_span.into(),
                operand,
            }))
        }
        GrammarRule::BITWISE_NOT => {
            let operand = term_from_cst(ctx, children.next().unwrap())?;
            // TODO
            // check_non_negative_integer!(ctx, operand)?;
            Expr::BitwiseNot(Box::new(UnaryExpr {
                span: term_span.into(),
                operand,
            }))
        }
        GrammarRule::LPAREN => {
            let expr = expr_from_cst(ctx, children.next().unwrap())?;
            expect!(children.next().unwrap(), GrammarRule::RPAREN);
            expr
        }
        GrammarRule::string_lit => Expr::LiteralStr(Box::new(LiteralStr {
            span: node.as_span().into(),
            literal: node.as_span().as_str(),
            value: string_lit_from_cst(ctx, node)?,
        })),
        GrammarRule::float_lit => Expr::LiteralFlt(Box::new(LiteralFlt {
            span: node.as_span().into(),
            literal: node.as_span().as_str(),
            value: float_lit_from_cst(ctx, node)?,
        })),
        GrammarRule::integer_lit => Expr::LiteralInt(Box::new(LiteralInt {
            span: node.as_span().into(),
            literal: node.as_span().as_str(),
            value: integer_lit_from_cst(ctx, node)?,
        })),
        GrammarRule::string_count => {
            // Is there some range after the string count?
            // Example: #a in (0..10)
            let range = if let Some(node) = children.next() {
                expect!(node, GrammarRule::k_IN);
                let (lower_bound, upper_bound) =
                    range_from_cst(ctx, children.next().unwrap())?;
                Some((lower_bound, upper_bound))
            } else {
                None
            };

            let ident_name = node.as_span().as_str();

            // Remove from ctx.string_identifiers, indicating that the
            // identifier has been used.
            ctx.string_identifiers.remove(&ident_name[1..]);

            Expr::StringCount(Box::new(IdentWithRange {
                span: term_span.into(),
                name: ident_name,
                range,
            }))
        }
        // String lengths (`!a`) and string offsets (`@a`) can both be used
        // with indexes like in `!a[1]` and  `@a[1]`, so let's handle them
        // together.
        rule @ (GrammarRule::string_length | GrammarRule::string_offset) => {
            // The index is optional, if the next child exists it should be
            // the left bracket, if not, there's no indexing at all.
            let index = if let Some(bracket) = children.next() {
                expect!(bracket, GrammarRule::LBRACKET);
                let expr = expr_from_cst(ctx, children.next().unwrap())?;
                // TODO
                // check_non_negative_integer!(ctx, expr)?;
                expect!(children.next().unwrap(), GrammarRule::RBRACKET);
                Some(expr)
            } else {
                None
            };
            let expr_type = match rule {
                GrammarRule::string_length => Expr::StringLength,
                GrammarRule::string_offset => Expr::StringOffset,
                _ => unreachable!(),
            };

            let ident_name = node.as_span().as_str();

            // Remove from ctx.string_identifiers, indicating that the
            // identifier has been used.
            ctx.string_identifiers.remove(&ident_name[1..]);

            expr_type(Box::new(IdentWithIndex {
                span: term_span.into(),
                name: ident_name,
                index,
            }))
        }
        rule => unreachable!("{:?}", rule),
    };

    assert!(children.next().is_none());

    Ok(expr)
}

fn indexing_expr_from_cst<'src>(
    ctx: &mut Context<'src>,
    indexing_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(indexing_expr, GrammarRule::indexing_expr);

    let span = indexing_expr.as_span();
    let mut children = indexing_expr.into_inner();

    let primary = primary_expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::LBRACKET);

    let index = expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::RBRACKET);

    Ok(Expr::LookupIndex(Box::new(LookupIndex {
        span: span.into(),
        primary,
        index,
    })))
}

fn func_call_expr_from_cst<'src>(
    ctx: &mut Context<'src>,
    func_call_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(func_call_expr, GrammarRule::func_call_expr);

    let span = func_call_expr.as_span();
    let mut children = func_call_expr.into_inner();

    let callable = primary_expr_from_cst(ctx, children.next().unwrap())?;

    // After the callable expression follows the opening parenthesis
    // enclosing the arguments.
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut args = Vec::new();

    // For all CST nodes after the opening parenthesis...
    for node in children.by_ref() {
        match node.as_rule() {
            // ... if the node is an expression, add it to the function
            // arguments.
            GrammarRule::expr => {
                args.push(expr_from_cst(ctx, node)?);
            }
            // ... if the node is a comma separating the arguments, or the
            // closing parenthesis, do nothing and continue.
            GrammarRule::COMMA | GrammarRule::RPAREN => {}
            rule => unreachable!("{:?}", rule),
        }
    }

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(Expr::FnCall(Box::new(FnCall { span: span.into(), callable, args })))
}

/// From a CST node corresponding to the grammar rule `range`, returns a tuple
/// ([`Expr`], [`Expr`]) with the lower and upper bounds of the range.
fn range_from_cst<'src>(
    ctx: &mut Context<'src>,
    range: CSTNode<'src>,
) -> Result<(Expr<'src>, Expr<'src>), Error> {
    expect!(range, GrammarRule::range);

    let mut children = range.into_inner();

    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let lower_bound = expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::DOT_DOT);

    let upper_bound = expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::RPAREN);

    // TODO
    // Range bounds should be integers.
    // check_kind!(ctx, lower_bound, ExprKind::Integer)?;
    // check_kind!(ctx, upper_bound, ExprKind::Integer)?;

    // The the upper bound, if known at compile time, should be larger the
    // lower bound, and both should be positive.
    if let (Some(ExprValue::Integer(lower)), Some(ExprValue::Integer(upper))) =
        (lower_bound.value(), upper_bound.value())
    {
        if lower < 0 || upper < 0 {
            return Err(ctx.error_builder.invalid_range(
                &ctx.src,
                (if lower < 0 { lower_bound } else { upper_bound }).span(),
                "range bound can not be negative",
            ));
        }

        if lower > upper {
            return Err(ctx.error_builder.invalid_range(
                &ctx.src,
                lower_bound.span(),
                format!(
                    "lower bound ({lower}) is greater than upper bound ({lower})"
                ),
            ));
        };
    }

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok((lower_bound, upper_bound))
}

/// From a CST node corresponding to the grammar rule `of_expr`, returns
/// an [`Expr`] describing the `of` statement.
fn of_expr_from_cst<'src>(
    ctx: &mut Context<'src>,
    of_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(of_expr, GrammarRule::of_expr);

    let span = of_expr.as_span();
    let mut children = of_expr.into_inner();

    let quantifier = quantifier_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::k_OF);

    let node = children.next().unwrap();

    let items = match node.as_rule() {
        GrammarRule::k_THEM => {
            ctx.string_identifiers.clear();
            OfItems::StringSet(StringSet::Them)
        }
        GrammarRule::string_ident_tuple => OfItems::StringSet(StringSet::Set(
            string_ident_tuple_from_cst(ctx, node)?,
        )),
        GrammarRule::boolean_expr_tuple => {
            OfItems::BoolExprTuple(boolean_expr_tuple_from_cst(ctx, node)?)
        }
        rule => unreachable!("{:?}", rule),
    };

    let anchor = anchor_from_cst(ctx, &mut children)?;

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(Expr::Of(Box::new(Of { span: span.into(), quantifier, items, anchor })))
}

/// From a CST node corresponding to the grammar rule `for_expr`, returns
/// an [`Expr`] describing the `for` statement.
fn for_expr_from_cst<'src>(
    ctx: &mut Context<'src>,
    for_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(for_expr, GrammarRule::for_expr);

    let span = for_expr.as_span();
    let mut children = for_expr.into_inner().peekable();

    // The statement starts with the `for` keyword...
    expect!(children.next().unwrap(), GrammarRule::k_FOR);

    // ...and then follows the quantifier.
    let quantifier = quantifier_from_cst(ctx, children.next().unwrap())?;

    let mut string_set = None;
    let mut iterator = None;
    let mut variables = vec![];

    if let GrammarRule::k_OF = children.peek().unwrap().as_rule() {
        // Consume the `of` keyword.
        children.next().unwrap();
        // After the `of` keyword follows `them` or a tuple of string
        // identifiers.
        let node = children.next().unwrap();
        string_set = Some(match node.as_rule() {
            GrammarRule::k_THEM => StringSet::Them,
            GrammarRule::string_ident_tuple => {
                StringSet::Set(string_ident_tuple_from_cst(ctx, node)?)
            }
            rule => unreachable!("{:?}", rule),
        });

        ctx.inside_for_of = true
    } else {
        // It's a `for .. in ..` expression. After the `for` keyword
        // follows one or more identifiers separated by commas, as in..
        //
        //   for all k,v in iterator ...
        //
        for node in children.by_ref() {
            match node.as_rule() {
                GrammarRule::ident => {
                    variables.push(Ident {
                        span: node.as_span().into(),
                        name: node.as_str(),
                    });
                }
                GrammarRule::COMMA => {}
                GrammarRule::k_IN => {
                    break;
                }
                rule => unreachable!("{:?}", rule),
            }
        }
        // The iterator must follow after the identifiers.
        iterator = Some(iterator_from_cst(ctx, children.next().unwrap())?);
    }

    expect!(children.next().unwrap(), GrammarRule::COLON);
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let condition = boolean_expr_from_cst(ctx, children.next().unwrap())?;

    ctx.inside_for_of = false;

    expect!(children.next().unwrap(), GrammarRule::RPAREN);

    let expr = if let Some(string_set) = string_set {
        Expr::ForOf(Box::new(ForOf {
            span: span.into(),
            quantifier,
            string_set,
            condition,
        }))
    } else if let Some(iterator) = iterator {
        Expr::ForIn(Box::new(ForIn {
            span: span.into(),
            quantifier,
            variables,
            iterable: iterator,
            condition,
        }))
    } else {
        unreachable!()
    };

    Ok(expr)
}

fn anchor_from_cst<'src>(
    ctx: &mut Context<'src>,
    mut iter: impl Iterator<Item = CSTNode<'src>>,
) -> Result<Option<MatchAnchor<'src>>, Error> {
    let anchor = if let Some(node) = iter.next() {
        match node.as_rule() {
            GrammarRule::k_AT => {
                let expr = expr_from_cst(ctx, iter.next().unwrap())?;
                // TODO
                // check_non_negative_integer!(ctx, expr)?;
                Some(MatchAnchor::At(expr))
            }
            GrammarRule::k_IN => Some(MatchAnchor::In(range_from_cst(
                ctx,
                iter.next().unwrap(),
            )?)),
            rule => unreachable!("{:?}", rule),
        }
    } else {
        None
    };
    Ok(anchor)
}

/// From a CST node corresponding to the grammar rule `quantifier`, returns
/// a [`Quantifier`].
fn quantifier_from_cst<'src>(
    ctx: &mut Context<'src>,
    quantifier: CSTNode<'src>,
) -> Result<Quantifier<'src>, Error> {
    expect!(quantifier, GrammarRule::quantifier);

    let mut children = quantifier.into_inner();
    let node = children.next().unwrap();

    let quantifier = match node.as_rule() {
        GrammarRule::k_ALL => Quantifier::All { span: node.as_span().into() },
        GrammarRule::k_ANY => Quantifier::Any { span: node.as_span().into() },
        GrammarRule::k_NONE => {
            Quantifier::None { span: node.as_span().into() }
        }
        GrammarRule::expr => {
            let expr = expr_from_cst(ctx, node)?;
            // If there's some node after the expression it should be the
            // percent `%` symbol.
            if let Some(node) = children.next() {
                expect!(node, GrammarRule::PERCENT);
                Quantifier::Percentage(expr)
            } else {
                Quantifier::Expr(expr)
            }
        }
        rule => unreachable!("{:?}", rule),
    };

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(quantifier)
}

/// From a CST node corresponding to the grammar rule `string_ident_tuple`, returns
/// a vector of [`StringSetItem`].
fn string_ident_tuple_from_cst<'src>(
    ctx: &mut Context<'src>,
    string_ident_tuple: CSTNode<'src>,
) -> Result<Vec<StringSetItem<'src>>, Error> {
    expect!(string_ident_tuple, GrammarRule::string_ident_tuple);

    let mut children = string_ident_tuple.into_inner();

    // The tuple should start with an opening parenthesis.
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut result = vec![];

    // For all CST nodes after the opening parenthesis...
    for node in children.by_ref() {
        match node.as_rule() {
            // ... if the node is string_ident_pattern
            GrammarRule::string_ident_pattern => {
                // The pattern can be simply a string identifier, like `$a`
                // or a string identifier ending in a wildcard, like `$a*`.
                // Notice however that the `$` is ignored.
                let pattern = &node.as_str()[1..];

                if let Some(prefix) = pattern.strip_suffix('*') {
                    // If the pattern has a wildcard, removes all identifiers
                    // that starts with the prefix before the wildcard.
                    ctx.string_identifiers
                        .retain(|ident, _| !ident.starts_with(prefix));
                } else {
                    ctx.string_identifiers.remove(pattern);
                }

                result.push(StringSetItem {
                    span: node.as_span().into(),
                    identifier: node.as_str(),
                });
            }
            // ... if the node is a comma or a closing parenthesis
            // ignore it and continue.
            GrammarRule::COMMA | GrammarRule::RPAREN => {}
            rule => unreachable!("{:?}", rule),
        };
    }

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(result)
}

/// From a CST node corresponding to the grammar rule `boolean_expr_tuple`, returns
/// a vector of [`Expr`].
fn boolean_expr_tuple_from_cst<'src>(
    ctx: &mut Context<'src>,
    boolean_expr_tuple: CSTNode<'src>,
) -> Result<Vec<Expr<'src>>, Error> {
    expect!(boolean_expr_tuple, GrammarRule::boolean_expr_tuple);

    let mut children = boolean_expr_tuple.into_inner();

    // The tuple should start with an opening parenthesis.
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut result = vec![];

    // For all CST nodes after the opening parenthesis...
    for node in children.by_ref() {
        match node.as_rule() {
            // ... if the node is string_ident_pattern
            GrammarRule::boolean_expr => {
                result.push(boolean_expr_from_cst(ctx, node)?);
            }
            // ... if the node is a comma or a closing parenthesis
            // ignore it and continue.
            GrammarRule::COMMA | GrammarRule::RPAREN => {}
            rule => unreachable!("{:?}", rule),
        };
    }

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(result)
}

/// From a CST node corresponding to the grammar rule `expr_tuple`, returns
/// a vector of [`Expr`].
fn expr_tuple_from_cst<'src>(
    ctx: &mut Context<'src>,
    expr_tuple: CSTNode<'src>,
) -> Result<Vec<Expr<'src>>, Error> {
    expect!(expr_tuple, GrammarRule::expr_tuple);

    let mut children = expr_tuple.into_inner();

    // The tuple should start with an opening parenthesis.
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut result = vec![];

    // For all CST nodes after the opening parenthesis...
    for node in children.by_ref() {
        match node.as_rule() {
            // ... if the node is string_ident_pattern
            GrammarRule::expr => {
                result.push(expr_from_cst(ctx, node)?);
            }
            // ... if the node is a comma or a closing parenthesis
            // ignore it and continue.
            GrammarRule::COMMA | GrammarRule::RPAREN => {}
            rule => unreachable!("{:?}", rule),
        };
    }

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(result)
}

/// From a CST node corresponding to the grammar rule `iterable`, returns
/// a [`Iterable`].
fn iterator_from_cst<'src>(
    ctx: &mut Context<'src>,
    iterator: CSTNode<'src>,
) -> Result<Iterable<'src>, Error> {
    expect!(iterator, GrammarRule::iterable);
    let mut children = iterator.into_inner();
    let node = children.next().unwrap();
    let expr = match node.as_rule() {
        GrammarRule::range => Iterable::Range(range_from_cst(ctx, node)?),
        GrammarRule::expr_tuple => {
            Iterable::ExprTuple(expr_tuple_from_cst(ctx, node)?)
        }
        GrammarRule::ident => Iterable::Ident(Box::new(Ident {
            span: node.as_span().into(),
            name: node.as_str(),
        })),
        rule => unreachable!("{:?}", rule),
    };
    Ok(expr)
}

/// From a CST node corresponding to the grammar rule `integer_lit`, returns
/// the the corresponding integer. This a generic function that can be used
/// for obtaining any type of integer, like u8, i64, etc.
fn integer_lit_from_cst<'src, T>(
    ctx: &mut Context<'src>,
    integer_lit: CSTNode<'src>,
) -> Result<T, Error>
where
    T: Integer + Bounded + CheckedMul + FromPrimitive + std::fmt::Display,
{
    expect!(integer_lit, GrammarRule::integer_lit);

    let span = integer_lit.as_span().into();
    let mut literal = integer_lit.as_str();
    let mut multiplier = 1;

    if let Some(without_suffix) = literal.strip_suffix("KB") {
        literal = without_suffix;
        multiplier = 1024;
    }

    if let Some(without_suffix) = literal.strip_suffix("MB") {
        literal = without_suffix;
        multiplier = 1024 * 1024;
    }

    let value = if literal.starts_with("0x") {
        T::from_str_radix(literal.strip_prefix("0x").unwrap(), 16)
    } else if literal.starts_with("0o") {
        T::from_str_radix(literal.strip_prefix("0o").unwrap(), 8)
    } else {
        T::from_str_radix(literal, 10)
    };

    let mut build_error = || {
        ctx.error_builder.simple_error(
            &ctx.src,
            span,
            format!("invalid integer `{}`", literal),
            format!(
                "this number is out of the valid range: [{}, {}]",
                T::min_value(),
                T::max_value()
            ),
        )
    };

    // Report errors that occur while parsing the literal. Some errors
    // (like invalid characters or empty literals) never occur, because
    // the grammar ensures that only valid integers reach this point,
    // however the grammar doesn't make sure that the integer fits in
    // type T.
    let value = value.map_err(|_| build_error())?;

    // The multiplier may not fit in type T.
    let multiplier = T::from_i32(multiplier).ok_or_else(&mut build_error)?;

    // The value after applying the multiplier may not fit in type T.
    let value = value.checked_mul(&multiplier).ok_or_else(&mut build_error)?;

    Ok(value)
}

/// From a CST node corresponding to the grammar rule `float_lit`, returns
/// the `f32` representing the literal.
fn float_lit_from_cst<'src>(
    ctx: &mut Context<'src>,
    float_lit: CSTNode<'src>,
) -> Result<f32, Error> {
    expect!(float_lit, GrammarRule::float_lit);

    let literal = float_lit.as_str();
    let span = float_lit.as_span().into();

    literal.parse::<f32>().map_err(|err| {
        ctx.error_builder.simple_error(
            &ctx.src,
            span,
            format!("invalid float `{}`", literal),
            err,
        )
    })
}

/// From a CST node corresponding to the grammar rule `string_lit`, returns
/// a `BString` representing the literal. Literal strings in YARA can
/// contain arbitrary sequences of bytes, including zeroes, so it can't be
/// represented by a Rust string slice, which requires valid UTF-8.
fn string_lit_from_cst<'src>(
    ctx: &mut Context<'src>,
    string_lit: CSTNode<'src>,
) -> Result<BString, Error> {
    expect!(string_lit, GrammarRule::string_lit);

    let literal = string_lit.as_str();

    // The string literal must be enclosed in double quotes.
    debug_assert!(literal.starts_with('\"'));
    debug_assert!(literal.ends_with('\"'));

    // From now on ignore the quotes.
    let literal = &literal[1..literal.len() - 1];

    // The point in the source code where the literal starts, skipping the
    // opening double quote.
    let literal_start = string_lit.as_span().start() + 1;

    let mut bytes = literal.bytes().enumerate();

    let mut result = BString::new(Vec::with_capacity(literal.len()));

    while let Some((backslash_pos, b)) = bytes.next() {
        match b {
            // The backslash indicates an escape sequence.
            b'\\' => {
                // Consume the backslash and see what's next.
                let next_byte = bytes.next();

                // No more bytes following the backslash, this is an invalid
                // escape sequence.
                if next_byte.is_none() {
                    return Err(ctx.error_builder.simple_error(
                        &ctx.src,
                        Span {
                            start: literal_start + backslash_pos,
                            end: literal_start + backslash_pos + 1,
                        },
                        "invalid escape sequence",
                        r"missing escape sequence after `\`",
                    ));
                }

                let next_byte = next_byte.unwrap();

                let (_, b) = next_byte;
                match b {
                    b'\\' => result.push(b'\\'),
                    b'n' => result.push(b'\n'),
                    b'r' => result.push(b'\r'),
                    b't' => result.push(b'\t'),
                    b'0' => result.push(b'\0'),
                    b'"' => result.push(b'"'),
                    b'x' => match (bytes.next(), bytes.next()) {
                        (Some((start, _)), Some((end, _))) => {
                            if let Ok(hex_value) =
                                u8::from_str_radix(&literal[start..=end], 16)
                            {
                                result.push(hex_value);
                            } else {
                                return Err(ctx.error_builder.invalid_escape_sequence(
                                    &ctx.src,
                                    Span {
                                        start: literal_start + start,
                                        end: literal_start + end + 1,
                                    },
                                    format!(
                                        r"invalid hex value `{}` after `\x`",
                                        &literal[start..=end]
                                    ),
                                ));
                            }
                        }
                        _ => {
                            return Err(ctx
                                .error_builder
                                .invalid_escape_sequence(
                                    &ctx.src,
                                    Span {
                                        start: literal_start + backslash_pos,
                                        end: literal_start + backslash_pos + 2,
                                    },
                                    r"expecting two hex digits after `\x`",
                                ));
                        }
                    },
                    _ => {
                        return Err(ctx
                            .error_builder
                            .invalid_escape_sequence(
                                &ctx.src,
                                Span {
                                    start: literal_start + backslash_pos,
                                    end: literal_start + backslash_pos + 2,
                                },
                                format!(
                                    "invalid escape sequence `{}`",
                                    &literal[backslash_pos..backslash_pos + 2]
                                ),
                            ));
                    }
                }
            }
            // Any not escaped byte is copies as is.
            b => result.push(b),
        }
    }

    Ok(result)
}

/// From a CST node corresponding to the grammar rule `hex_string`, returns
/// the [`HexPattern`] representing it.
fn hex_pattern_from_cst<'src>(
    ctx: &mut Context<'src>,
    hex_pattern: CSTNode<'src>,
) -> Result<HexPattern, Error> {
    expect!(hex_pattern, GrammarRule::hex_pattern);

    let mut children = hex_pattern.into_inner().peekable();
    let mut pattern = HexPattern { tokens: vec![] };

    while let Some(node) = children.next() {
        let token = match node.as_rule() {
            GrammarRule::hex_byte => {
                let mut byte_literal = node.as_str();
                let mut value: u8 = 0x00;
                let mut mask: u8 = 0xFF;
                let mut negated = false;

                // If the byte starts with `~` is a negated byte.
                if let Some(b) = byte_literal.strip_prefix('~') {
                    negated = true;
                    byte_literal = b;
                }

                let mut nibbles = byte_literal.chars();
                let high_nibble = nibbles.next().unwrap();

                // High nibble is `?`, then it should be masked out.
                if high_nibble == '?' {
                    mask &= 0x0F;
                } else {
                    value |= (high_nibble.to_digit(16).unwrap() << 4) as u8;
                }

                // The low nibble is missing when the there are an odd number
                // nibbles in a byte sequence (e.g. { 000 }). The grammar
                // allows this case, even if invalid, precisely for detecting
                // it and providing a meaningful error message.
                if let Some(low_nibble) = nibbles.next() {
                    // Low nibble is `?`, then it should be masked out.
                    if low_nibble == '?' {
                        mask &= 0xF0;
                    } else {
                        value |= low_nibble.to_digit(16).unwrap() as u8;
                    }
                } else {
                    return Err(ctx.error_builder.simple_error(
                        &ctx.src,
                        node.as_span().into(),
                        format!(
                            "invalid hex string `{}`",
                            ctx.current_string_identifier
                                .as_ref()
                                .unwrap()
                                .name
                        ),
                        "uneven number of nibbles",
                    ));
                }

                // ~?? is not allowed.
                if negated && mask == 0x00 {
                    return Err(ctx.error_builder.simple_error(
                        &ctx.src,
                        node.as_span().into(),
                        format!(
                            "invalid hex string `{}`",
                            ctx.current_string_identifier
                                .as_ref()
                                .unwrap()
                                .name
                        ),
                        "negation of `??` is not allowed",
                    ));
                }

                let token =
                    if negated { HexToken::NotByte } else { HexToken::Byte };

                token(Box::new(HexByte { value, mask }))
            }
            GrammarRule::hex_alternative => HexToken::Alternative(Box::new(
                hex_alternative_from_cst(ctx, node)?,
            )),
            GrammarRule::hex_jump => {
                let mut jump_span: Span = node.as_span().into();
                let mut jump = hex_jump_from_cst(ctx, node)?;
                let mut note = None;

                // If there are two consecutive jumps they will be coalesced
                // together. For example: [1-2][2-3] is converted into [3-5].
                // TODO: raise a warning
                if let Some(node) = children.peek() {
                    if node.as_rule() == GrammarRule::hex_jump {
                        let span = node.as_span();
                        jump.coalesce(hex_jump_from_cst(
                            ctx,
                            children.next().unwrap(),
                        )?);
                        jump_span = jump_span.combine(&span.into());
                        note = Some(
                            "consecutive jumps were coalesced into a single one".to_string());
                    }
                }

                if let (Some(start), Some(end)) = (jump.start, jump.end) {
                    if start > end {
                        return Err(ctx.error_builder.simple_error_with_note(
                            &ctx.src,
                            jump_span,
                            format!(
                                "invalid hex jump in `{}`", 
                                ctx.current_string_identifier
                                    .as_ref()
                                    .unwrap()
                                    .name),
                            format!(
                                "lower bound ({}) is greater than upper bound ({})", 
                                start, end),
                            note,
                        ));
                    }
                }

                HexToken::Jump(Box::new(jump))
            }
            rule => unreachable!("{:?}", rule),
        };

        pattern.tokens.push(token);
    }

    Ok(pattern)
}

/// From a CST node corresponding to the grammar rule `hex_jump`, returns
/// the [`HexPattern`] representing it.
fn hex_jump_from_cst<'src>(
    ctx: &mut Context<'src>,
    hex_jump: CSTNode<'src>,
) -> Result<HexJump, Error> {
    expect!(hex_jump, GrammarRule::hex_jump);

    let mut children = hex_jump.into_inner();

    expect!(children.next().unwrap(), GrammarRule::LBRACKET);

    let mut node = children.next().unwrap();

    let mut start = None;
    let mut end = None;

    if let GrammarRule::integer_lit = node.as_rule() {
        start = Some(integer_lit_from_cst(ctx, node)?);
    };

    node = children.next().unwrap();

    if let GrammarRule::HYPHEN = node.as_rule() {
        node = children.next().unwrap();
        if let GrammarRule::integer_lit = node.as_rule() {
            end = Some(integer_lit_from_cst(ctx, node)?);
            node = children.next().unwrap();
        }
    }

    expect!(node, GrammarRule::RBRACKET);

    Ok(HexJump { start, end })
}

/// From a CST node corresponding to the grammar rule `hex_alternative`, returns
/// the [`HexAlternative`] representing it.
fn hex_alternative_from_cst<'src>(
    ctx: &mut Context<'src>,
    hex_alternative: CSTNode<'src>,
) -> Result<HexAlternative, Error> {
    expect!(hex_alternative, GrammarRule::hex_alternative);

    let mut children = hex_alternative.into_inner();

    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut hex_alt = HexAlternative { alternatives: vec![] };

    for node in children {
        match node.as_rule() {
            GrammarRule::hex_pattern => {
                hex_alt.alternatives.push(hex_pattern_from_cst(ctx, node)?);
            }
            GrammarRule::PIPE | GrammarRule::RPAREN => {}
            rule => unreachable!("{:?}", rule),
        }
    }

    Ok(hex_alt)
}
