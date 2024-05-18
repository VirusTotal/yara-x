/*! Functions for converting a CST into an AST. */

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::iter::Iterator;
use std::str;

use crate::{ast, Warning};
use bstr::{BStr, BString, ByteSlice, ByteVec};
use lazy_static::lazy_static;
use num_traits::{Bounded, CheckedMul, FromPrimitive, Num};
use pest::iterators::Pair;
use pest::pratt_parser::{Assoc, Op, PrattParser};

use crate::ast::*;
use crate::cst::*;
use crate::parser::{Context, Error, ErrorInfo, GrammarRule};

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

// Macro that returns an AST node for a binary operation.
//
// If `lhs` represents an operation than is equal to the one being processed,
// then `rhs` can be added to `lhs` without creating new nodes in the AST tree.
// For example, if `lhs` is an AST node that represents the expression `a + b`,
// `rhs` represents the expression `c`, and the new operation is `+`, we don't
// need to create a new AST node for representing the sum of `a + b` plus `c`,
// instead, we can simply add `c` to the list of operands of the `lhs` node,
// which becomes `a + b + c`.
//
// This way, instead of having this AST tree:
//
//  add (+)
//  ├ add (+)
//  │ ├─ a
//  │ └─ b
//  └─ c
//
// We have this other AST:
//
//  add (+)
//  ├─ a
//  ├─ b
//  └─ c
//
// The more flat is our AST the better, as it reduces the stack size required
// for recursive tree traversal and the amount of memory required for storing
// the AST.
macro_rules! new_n_ary_expr {
    ($variant:path, $lhs:ident, $rhs:ident) => {{
        match $lhs {
            $variant(ref mut operands) => {
                operands.add($rhs);
                Ok($lhs)
            }
            _ => Ok($variant(Box::new(NAryExpr::new($lhs, $rhs)))),
        }
    }};
}

macro_rules! new_binary_expr {
    ($variant:path, $lhs:ident, $rhs:ident) => {{
        Ok($variant(Box::new(BinaryExpr::new($lhs, $rhs))))
    }};
}

fn create_unary_expr<'src>(
    ctx: &Context<'_, '_>,
    operator: CSTNode<'src>,
    operand: Expr<'src>,
) -> Result<Expr<'src>, Error> {
    let span = ctx.span(&operator).combine(&operand.span());

    let expr = match operator.as_rule() {
        GrammarRule::BITWISE_NOT => {
            Expr::BitwiseNot(Box::new(UnaryExpr::new(operand, span)))
        }
        GrammarRule::k_NOT => {
            Expr::Not(Box::new(UnaryExpr::new(operand, span)))
        }
        GrammarRule::k_DEFINED => {
            Expr::Defined(Box::new(UnaryExpr::new(operand, span)))
        }
        GrammarRule::MINUS => {
            Expr::Minus(Box::new(UnaryExpr::new(operand, span)))
        }
        rule => unreachable!("{:?}", rule),
    };
    Ok(expr)
}

fn create_binary_expr<'src>(
    mut lhs: Expr<'src>,
    op: GrammarRule,
    rhs: Expr<'src>,
) -> Result<Expr<'src>, Error> {
    match op {
        GrammarRule::DOT => {
            new_n_ary_expr!(Expr::FieldAccess, lhs, rhs)
        }
        // Boolean
        GrammarRule::k_OR => {
            new_n_ary_expr!(Expr::Or, lhs, rhs)
        }
        GrammarRule::k_AND => {
            new_n_ary_expr!(Expr::And, lhs, rhs)
        }
        // Arithmetic
        GrammarRule::ADD => {
            new_n_ary_expr!(Expr::Add, lhs, rhs)
        }
        GrammarRule::SUB => {
            new_n_ary_expr!(Expr::Sub, lhs, rhs)
        }
        GrammarRule::MUL => {
            new_n_ary_expr!(Expr::Mul, lhs, rhs)
        }
        GrammarRule::DIV => {
            new_n_ary_expr!(Expr::Div, lhs, rhs)
        }
        GrammarRule::MOD => {
            new_n_ary_expr!(Expr::Mod, lhs, rhs)
        }
        // Bitwise
        GrammarRule::SHL => {
            new_binary_expr!(Expr::Shl, lhs, rhs)
        }
        GrammarRule::SHR => {
            new_binary_expr!(Expr::Shr, lhs, rhs)
        }
        GrammarRule::BITWISE_AND => {
            new_binary_expr!(Expr::BitwiseAnd, lhs, rhs)
        }
        GrammarRule::BITWISE_OR => {
            new_binary_expr!(Expr::BitwiseOr, lhs, rhs)
        }
        GrammarRule::BITWISE_XOR => {
            new_binary_expr!(Expr::BitwiseXor, lhs, rhs)
        }
        // Comparison
        GrammarRule::EQ => {
            new_binary_expr!(Expr::Eq, lhs, rhs)
        }
        GrammarRule::NE => {
            new_binary_expr!(Expr::Ne, lhs, rhs)
        }
        GrammarRule::LT => {
            new_binary_expr!(Expr::Lt, lhs, rhs)
        }
        GrammarRule::LE => {
            new_binary_expr!(Expr::Le, lhs, rhs)
        }
        GrammarRule::GT => {
            new_binary_expr!(Expr::Gt, lhs, rhs)
        }
        GrammarRule::GE => {
            new_binary_expr!(Expr::Ge, lhs, rhs)
        }
        GrammarRule::k_STARTSWITH => {
            new_binary_expr!(Expr::StartsWith, lhs, rhs)
        }
        GrammarRule::k_ISTARTSWITH => {
            new_binary_expr!(Expr::IStartsWith, lhs, rhs)
        }
        GrammarRule::k_ENDSWITH => {
            new_binary_expr!(Expr::EndsWith, lhs, rhs)
        }
        GrammarRule::k_IENDSWITH => {
            new_binary_expr!(Expr::IEndsWith, lhs, rhs)
        }
        GrammarRule::k_CONTAINS => {
            new_binary_expr!(Expr::Contains, lhs, rhs)
        }
        GrammarRule::k_ICONTAINS => {
            new_binary_expr!(Expr::IContains, lhs, rhs)
        }
        GrammarRule::k_IEQUALS => {
            new_binary_expr!(Expr::IEquals, lhs, rhs)
        }
        GrammarRule::k_MATCHES => {
            new_binary_expr!(Expr::Matches, lhs, rhs)
        }

        rule => unreachable!("{:?}", rule),
    }
}

lazy_static! {
    // Map that indicates which modifiers are accepted by each type of patterns.
    // For example, the `private` modifier is accepted by text patterns, hex patterns
    // and regexps, while `base64` is only accepted by text patterns.
    static ref ACCEPTED_MODIFIERS: HashMap<&'static str, Vec<GrammarRule>> =
        HashMap::from([
            (
                "private",
                vec![
                    GrammarRule::string_lit,
                    GrammarRule::regexp,
                    GrammarRule::hex_pattern,
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

/// Check if the set of modifiers for a pattern are valid.
///
/// Certain modifiers can't be used in conjunction, and this function
/// returns an error in those cases.
fn check_pattern_modifiers(
    ctx: &Context<'_, '_>,
    rule_type: GrammarRule,
    modifiers: &PatternModifiers,
) -> Result<(), Error> {
    let xor = modifiers.xor();
    let nocase = modifiers.nocase();
    let fullword = modifiers.fullword();
    let base64 = modifiers.base64();
    let base64wide = modifiers.base64wide();

    for modifier in modifiers.iter() {
        if !ACCEPTED_MODIFIERS[modifier.as_text()].contains(&rule_type) {
            let error_detail = match rule_type {
                GrammarRule::hex_pattern => {
                    "this modifier can't be applied to a hex pattern"
                }
                GrammarRule::regexp => {
                    "this modifier can't be applied to a regexp"
                }
                _ => unreachable!(),
            };

            return Err(Error::from(ErrorInfo::invalid_modifier(
                ctx.report_builder,
                error_detail.to_string(),
                modifier.span(),
            )));
        }
    }

    let invalid_combinations = [
        ("xor", xor, "nocase", nocase),
        ("base64", base64, "nocase", nocase),
        ("base64wide", base64wide, "nocase", nocase),
        ("base64", base64, "fullword", fullword),
        ("base64wide", base64wide, "fullword", fullword),
        ("base64", base64, "xor", xor),
        ("base64wide", base64wide, "xor", xor),
    ];

    for (name1, modifier1, name2, modifier2) in invalid_combinations {
        if let (Some(modifier1), Some(modifier2)) = (modifier1, modifier2) {
            return Err(Error::from(ErrorInfo::invalid_modifier_combination(
                ctx.report_builder,
                name1.to_string(),
                name2.to_string(),
                modifier1.span(),
                modifier2.span(),
                Some("these two modifiers can't be used together".to_string()),
            )));
        };
    }

    Ok(())
}

pub(crate) fn ast_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    cst: CST<'src>,
) -> Result<(Vec<Import>, Vec<Rule<'src>>), Error> {
    let mut imports: Vec<Import> = Vec::new();
    let mut rules: Vec<Rule> = Vec::new();

    for node in cst {
        match node.as_rule() {
            // Top level rules are either import statements...
            GrammarRule::import_stmt => {
                let span = ctx.span(&node);
                let mut children = node.into_inner();
                expect!(children.next().unwrap(), GrammarRule::k_IMPORT);

                let module_name =
                    utf8_string_lit_from_cst(ctx, children.next().unwrap())?;

                imports.push(Import {
                    span,
                    module_name: module_name.to_string(),
                });
            }
            // .. or rule declarations.
            GrammarRule::rule_decl => {
                rules.push(rule_from_cst(ctx, node)?);
            }
            // The End Of Input (EOI) rule is ignored.
            GrammarRule::EOI => {}
            // Under `source_file` the grammar doesn't have any other rule.
            // This should not be reached.
            rule => unreachable!("unexpected grammar rule: `{:?}`", rule),
        }
    }
    Ok((imports, rules))
}

/// Given a CST node corresponding to the grammar rule` rule_decl`, returns a
/// [`Rule`] structure describing the rule.
fn rule_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
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

    let identifier = ident_from_cst(ctx, node);

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
                return Err(Error::from(ErrorInfo::duplicate_tag(
                    ctx.report_builder,
                    ident.as_str().to_string(),
                    ctx.span(&ident),
                )));
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

    // Process the `strings` (a.k.a `patterns) section if any.
    // `ctx.declared_patterns` and `ctx.unused_patterns` will be populated
    // with the declared patterns.
    let patterns = if let GrammarRule::pattern_defs = node.as_rule() {
        let patterns = patterns_from_cst(ctx, node)?;
        node = children.next().unwrap();
        Some(patterns)
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

    // Any identifier left in ctx.unused_pattern is not being
    // used in the condition.
    for unused_pattern in ctx.unused_patterns.drain() {
        let ident = ctx.declared_patterns.get(unused_pattern).unwrap();
        // Pattern identifiers that start with underscore (e.g: `$_a`) are
        // allowed to remain unused.
        if !unused_pattern.starts_with('_') {
            return Err(Error::from(ErrorInfo::unused_pattern(
                ctx.report_builder,
                ident.name.to_string(),
                ident.span,
            )));
        }
    }

    // Clear `declared_patterns` so that the next call to `rule_from_cst`
    // finds it empty.
    ctx.declared_patterns.clear();

    // The closing brace should come next.
    expect!(node, GrammarRule::RBRACE);

    // Nothing more after the closing brace.
    assert!(children.next().is_none());

    Ok(Rule { flags, identifier, tags, meta, patterns, condition })
}

/// Given a CST node corresponding to the grammar rule` pattern_defs`, returns
/// a vector of [`Pattern`] structs describing the defined patterns.
fn patterns_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    pattern_defs: CSTNode<'src>,
) -> Result<Vec<Pattern<'src>>, Error> {
    expect!(pattern_defs, GrammarRule::pattern_defs);

    let mut children = pattern_defs.into_inner();

    // The first two children are the `strings` keyword and the colon (`:`).
    expect!(children.next().unwrap(), GrammarRule::k_STRINGS);
    expect!(children.next().unwrap(), GrammarRule::COLON);

    let mut patterns: Vec<Pattern> = Vec::new();

    // All the remaining children are `pattern_def`.
    for pattern_def in children {
        expect!(pattern_def, GrammarRule::pattern_def);
        let new_pattern = pattern_from_cst(ctx, pattern_def)?;
        let new_pattern_ident = new_pattern.identifier().clone();

        // Check if another pattern with the same identifier already exists,
        // but only if the identifier is not `$`.
        if new_pattern_ident.name != "$" {
            if let Some(existing_pattern_ident) =
                ctx.declared_patterns.get(&new_pattern_ident.name[1..])
            {
                return Err(Error::from(ErrorInfo::duplicate_pattern(
                    ctx.report_builder,
                    new_pattern_ident.name.to_string(),
                    new_pattern_ident.span,
                    existing_pattern_ident.span,
                )));
            }
        }

        // String identifiers are also stored in `unused_patterns`, they will
        // be removed from the set when they are used in the condition.
        // Any identifier left in the set when the condition has been fully
        // parsed is an unused pattern. Notice that identifiers are stored
        // without the `$` prefix.
        ctx.unused_patterns.insert(&new_pattern_ident.name[1..]);

        // Store the identifiers for each pattern declared in the rule.
        // They are stored without the `$` prefix.
        ctx.declared_patterns
            .insert(&new_pattern_ident.name[1..], new_pattern_ident);

        patterns.push(new_pattern);
    }

    Ok(patterns)
}

/// Given a CST node corresponding to the grammar rule `pattern_def`, returns
/// a [`Pattern`] struct describing the defined pattern.
fn pattern_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    pattern_def: CSTNode<'src>,
) -> Result<Pattern<'src>, Error> {
    expect!(pattern_def, GrammarRule::pattern_def);

    let mut children = pattern_def.into_inner();
    let identifier = ident_from_cst(ctx, children.next().unwrap());

    // The first child of the `pattern_def` rule is the pattern identifier,
    // let's store it in ctx.current_pattern.
    ctx.current_pattern = Some(identifier);

    // The identifier must be followed by the equal sign.
    expect!(children.next().unwrap(), GrammarRule::EQUAL);

    let node = children.next().unwrap();

    // The remaining children are the actual pattern definition, which
    // vary depending on the type of pattern.
    let pattern = match node.as_rule() {
        GrammarRule::hex_pattern => {
            let span = ctx.span(&node);
            let mut hex_pattern = node.into_inner();

            // Hex strings start with a left brace `{`.
            expect!(hex_pattern.next().unwrap(), GrammarRule::LBRACE);

            // Parse the content in-between the braces. While this is done
            // the identifier is stored in ctx.current_pattern.
            let pattern =
                hex_pattern_from_cst(ctx, hex_pattern.next().unwrap())?;

            // Take the identifier and set ctx.current_pattern
            // to None.
            let identifier = ctx.current_pattern.take().unwrap();

            // Check for the closing brace `}`.
            expect!(hex_pattern.next().unwrap(), GrammarRule::RBRACE);

            let modifiers = if let Some(modifiers) = children.next() {
                pattern_mods_from_cst(
                    ctx,
                    GrammarRule::hex_pattern,
                    modifiers,
                )?
            } else {
                PatternModifiers::default()
            };

            Pattern::Hex(Box::new(HexPattern {
                span,
                identifier,
                tokens: pattern,
                modifiers,
            }))
        }
        GrammarRule::string_lit => {
            let span = ctx.span(&node);
            let text = string_lit_from_cst(ctx, node, true)?;
            let modifiers = if let Some(modifiers) = children.next() {
                pattern_mods_from_cst(ctx, GrammarRule::string_lit, modifiers)?
            } else {
                PatternModifiers::default()
            };

            let (min_len, note) = if modifiers.base64().is_some() {
                (3, Some("`base64` requires that pattern is at least 3 bytes long".to_string()))
            } else if modifiers.base64wide().is_some() {
                (3, Some("`base64wide` requires that pattern is at least 3 bytes long".to_string()))
            } else {
                (1, None)
            };

            if text.len() < min_len {
                return Err(Error::from(ErrorInfo::invalid_pattern(
                    ctx.report_builder,
                    ctx.current_pattern_ident(),
                    "this pattern is too short".to_string(),
                    span,
                    note,
                )));
            }

            // Take the identifier and set ctx.current_pattern
            // to None.
            let identifier = ctx.current_pattern.take().unwrap();

            Pattern::Text(Box::new(TextPattern {
                identifier,
                text,
                span,
                modifiers,
            }))
        }
        GrammarRule::regexp => {
            let modifiers = if let Some(modifiers) = children.next() {
                pattern_mods_from_cst(ctx, GrammarRule::regexp, modifiers)?
            } else {
                PatternModifiers::default()
            };

            // Take the identifier and set ctx.current_pattern
            // to None.
            let identifier = ctx.current_pattern.take().unwrap();

            let pattern = Box::new(RegexpPattern {
                identifier,
                modifiers,
                span: ctx.span(&node),
                regexp: regexp_from_cst(ctx, node)?,
            });

            Pattern::Regexp(pattern)
        }
        rule => unreachable!("{:?}", rule),
    };

    Ok(pattern)
}

/// Given a CST node corresponding to the grammar rule `regexp`, returns the
/// corresponding [`Regexp`] struct describing the regexp.
fn regexp_from_cst<'src>(
    ctx: &Context<'src, '_>,
    regexp: CSTNode<'src>,
) -> Result<Regexp<'src>, Error> {
    let re = regexp.as_str();

    // Regular expressions must start with a slash (/)
    debug_assert!(re.starts_with('/'));

    // It must contain a closing slash too, but not necessarily at the end
    // because the closing slash may be followed by a regexp modifier like "i"
    // and "s" (e.g. /foo/i)
    let closing_slash = re.rfind('/').unwrap();

    let mut case_insensitive = false;
    let mut dot_matches_new_line = false;

    for (i, modifier) in re[closing_slash + 1..].char_indices() {
        match modifier {
            'i' => case_insensitive = true,
            's' => dot_matches_new_line = true,
            c => {
                let span = ctx.span(&regexp).subspan(
                    closing_slash + 1 + i,
                    closing_slash + 1 + i + c.len_utf8(),
                );

                return Err(Error::from(ErrorInfo::invalid_regexp_modifier(
                    ctx.report_builder,
                    format!("{}", c),
                    span,
                )));
            }
        }
    }

    // The regexp span without the opening and closing `/`.
    let span = ctx.span(&regexp).subspan(1, closing_slash);

    Ok(Regexp {
        span,
        literal: re,
        src: &re[1..closing_slash],
        case_insensitive,
        dot_matches_new_line,
    })
}

/// Given a CST node corresponding to the grammar rule `pattern_mods`, returns
/// a [`PatternModifiers`] struct describing the modifiers.
fn pattern_mods_from_cst<'src>(
    ctx: &Context<'src, '_>,
    rule_type: GrammarRule,
    pattern_mods: CSTNode<'src>,
) -> Result<PatternModifiers<'src>, Error> {
    expect!(pattern_mods, GrammarRule::pattern_mods);

    let mut children = pattern_mods.into_inner().peekable();
    let mut modifiers = BTreeMap::new();

    while let Some(node) = children.next() {
        let modifier = match node.as_rule() {
            GrammarRule::k_ASCII => {
                PatternModifier::Ascii { span: ctx.span(&node) }
            }
            GrammarRule::k_WIDE => {
                PatternModifier::Wide { span: ctx.span(&node) }
            }
            GrammarRule::k_PRIVATE => {
                PatternModifier::Private { span: ctx.span(&node) }
            }
            GrammarRule::k_FULLWORD => {
                PatternModifier::Fullword { span: ctx.span(&node) }
            }
            GrammarRule::k_NOCASE => {
                PatternModifier::Nocase { span: ctx.span(&node) }
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
                        let lower_bound_span = ctx.span(&node);

                        // Parse the integer after the opening parenthesis `(`.
                        lower_bound = integer_lit_from_cst::<u8>(ctx, node)?;

                        // See what comes next, it could be a hyphen `-` or the
                        // closing parenthesis `)`
                        upper_bound = match children.next().unwrap().as_rule()
                        {
                            // If it is the closing parenthesis, the upper
                            // bound of the xor
                            // range is equal to the lower bound.
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
                            return Err(Error::from(ErrorInfo::invalid_range(
                               ctx.report_builder,
                               format!(
                                   "lower bound ({}) is greater than upper bound ({})",
                                   lower_bound, upper_bound),
                                lower_bound_span,
                            )));
                        }
                    }
                }

                PatternModifier::Xor {
                    span: ctx.span(&node),
                    end: upper_bound,
                    start: lower_bound,
                }
            }
            rule @ (GrammarRule::k_BASE64 | GrammarRule::k_BASE64WIDE) => {
                let mut alphabet = None;
                if let Some(node) = children.peek() {
                    if node.as_rule() == GrammarRule::LPAREN {
                        children.next().unwrap();
                        let node = children.next().unwrap();
                        let span = ctx.span(&node);
                        let lit = utf8_string_lit_from_cst(ctx, node)?;

                        // Make sure the base64 alphabet is a valid one.
                        if let Err(err) = base64::alphabet::Alphabet::new(lit)
                        {
                            return Err(Error::from(
                                ErrorInfo::invalid_base_64_alphabet(
                                    ctx.report_builder,
                                    err.to_string().to_lowercase(),
                                    span,
                                ),
                            ));
                        }

                        alphabet = Some(lit);

                        expect!(children.next().unwrap(), GrammarRule::RPAREN);
                    }
                }
                match rule {
                    GrammarRule::k_BASE64 => PatternModifier::Base64 {
                        span: ctx.span(&node),
                        alphabet,
                    },
                    GrammarRule::k_BASE64WIDE => PatternModifier::Base64Wide {
                        span: ctx.span(&node),
                        alphabet,
                    },
                    _ => unreachable!(),
                }
            }
            rule => unreachable!("{:?}", rule),
        };

        let span = modifier.span();
        if modifiers.insert(node.as_str(), modifier).is_some() {
            return Err(Error::from(ErrorInfo::duplicate_modifier(
                ctx.report_builder,
                span,
            )));
        }
    }

    let modifiers = PatternModifiers::new(modifiers);

    // Check for invalid combinations of modifiers.
    check_pattern_modifiers(ctx, rule_type, &modifiers)?;

    Ok(modifiers)
}

/// Given a CST node corresponding to the grammar rule` meta_defs`, returns
/// a vector of [`Meta`] structs describing the defined metadata.
fn meta_from_cst<'src>(
    ctx: &Context<'src, '_>,
    meta_defs: CSTNode<'src>,
) -> Result<Vec<Meta<'src>>, Error> {
    expect!(meta_defs, GrammarRule::meta_defs);

    let mut children = meta_defs.into_inner();

    // The first two children are the `meta` keyword and the colon.
    expect!(children.next().unwrap(), GrammarRule::k_META);
    expect!(children.next().unwrap(), GrammarRule::COLON);

    let mut result = Vec::new();

    // All the remaining children are `meta_def`.
    for meta_def in children {
        expect!(meta_def, GrammarRule::meta_def);

        let mut nodes = meta_def.into_inner();
        let identifier = ident_from_cst(ctx, nodes.next().unwrap());

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
// `PRATT_PARSER` has a `parse` function that receives a sequence of
// expressions interleaved with operators. For example, it can receive..
//
// <expr> <infix op> <expr>
//
// <expr> <infix op> <expr> <infix op> <expr>
//
// In general...
//
//  <expr> ( <infix op> <expr> )*
//
// Notice that a single <expr> is also acceptable.
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
// For example, for the sequence 1 + 2 * 3, the first call to F will be with
// arguments (2, *, 3), which produces a T1. In a second call to F the
// arguments will be (1, +, T1) and its result T2 will be returned by `parse`
// because there's no more expression to reduce.
//
// More details:
// https://en.wikipedia.org/wiki/Operator-precedence_parser#Pratt_parsing
lazy_static! {
    static ref PRATT_PARSER: PrattParser<GrammarRule> = PrattParser::new()
        .op(Op::infix(GrammarRule::k_OR, Assoc::Left))
        .op(Op::infix(GrammarRule::k_AND, Assoc::Left))
        .op(Op::infix(GrammarRule::EQ, Assoc::Left)
            | Op::infix(GrammarRule::NE, Assoc::Left)
            | Op::infix(GrammarRule::k_CONTAINS, Assoc::Left)
            | Op::infix(GrammarRule::k_ICONTAINS, Assoc::Left)
            | Op::infix(GrammarRule::k_STARTSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_ISTARTSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_ENDSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_IENDSWITH, Assoc::Left)
            | Op::infix(GrammarRule::k_IEQUALS, Assoc::Left)
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
    ctx: &mut Context<'src, '_>,
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
    ctx: &mut Context<'src, '_>,
    boolean_term: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(boolean_term, GrammarRule::boolean_term);

    let boolean_term_span = ctx.span(&boolean_term);
    let mut children = boolean_term.into_inner().peekable();

    // Based on the first child we decide what to do next, but the first child
    // is not consumed from the iterator at this moment.
    let expr = match children.peek().unwrap().as_rule() {
        GrammarRule::k_TRUE => {
            Expr::True { span: ctx.span(&children.next().unwrap()) }
        }
        GrammarRule::k_FALSE => {
            Expr::False { span: ctx.span(&children.next().unwrap()) }
        }
        GrammarRule::k_NOT => {
            // Consume the first child, corresponding to the `not` keyword.
            let not = children.next().unwrap();

            // The child after the `not` is the negated boolean term.
            let term = children.next().unwrap();
            let expr = boolean_term_from_cst(ctx, term)?;

            create_unary_expr(ctx, not, expr)?
        }
        GrammarRule::k_DEFINED => {
            // Consume the first child, corresponding to the `defined` keyword.
            let defined = children.next().unwrap();

            // The child after the `defined` is the boolean term.
            let term = children.next().unwrap();
            let expr = boolean_term_from_cst(ctx, term)?;

            create_unary_expr(ctx, defined, expr)?
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
        GrammarRule::pattern_ident => {
            let ident = children.next().unwrap();
            let ident_name = ident.as_str();
            let anchor = anchor_from_cst(ctx, children)?;

            // The use of `$` in the condition doesn't mean that all anonymous
            // pattern identifiers are used. Anonymous pattern identifiers are
            // considered used when the `them` keyword is used, or when the
            // pattern `$*` appears in a pattern identifiers tuple.
            if ident_name != "$" {
                if ctx.declared_patterns.get(&ident_name[1..]).is_none() {
                    return Err(Error::from(ErrorInfo::unknown_pattern(
                        ctx.report_builder,
                        ident_name.to_string(),
                        ctx.span(&ident),
                    )));
                }
                ctx.unused_patterns.remove(&ident_name[1..]);
            }
            // `$` used outside a `for .. of` statement, that's invalid.
            else if !ctx.inside_for_of {
                return Err(Error::from(ErrorInfo::syntax_error(
                    ctx.report_builder,
                    "this `$` is outside of the condition of a `for .. of` statement".to_string(),
                    ctx.span(&ident),
                )));
            }

            Expr::PatternMatch(Box::new(PatternMatch {
                // TODO: this is not the best way of computing the span for
                // PatternMatch, as this covers the space that can follow, like
                // in:
                //   $a in (0..100)
                //   ^^^^^^^^^^^^^^^
                // The best way is using the anchor's span end.
                span: boolean_term_span,
                identifier: ident_from_cst(ctx, ident),
                anchor,
            }))
        }
        GrammarRule::expr => {
            // See comments in `boolean_expr_from_cst` for some explanation
            // of the logic below.
            PRATT_PARSER
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
                .parse(children.map(|node| node.into_pair()))?
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
    ctx: &mut Context<'src, '_>,
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
    ctx: &mut Context<'src, '_>,
    term: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(term, GrammarRule::term);

    let mut children = term.into_inner();
    let node = children.next().unwrap();

    let expr = match node.as_rule() {
        GrammarRule::indexing_expr => indexing_expr_from_cst(ctx, node)?,
        GrammarRule::func_call_expr => func_call_from_cst(ctx, node)?,
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
    ctx: &mut Context<'src, '_>,
    primary_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    // The CST node passed to this function must correspond to a primary
    // expression.
    expect!(primary_expr, GrammarRule::primary_expr);

    let term_span = ctx.span(&primary_expr);
    let mut children = primary_expr.into_inner();
    let node = children.next().unwrap();

    let expr = match node.as_rule() {
        GrammarRule::ident => {
            let mut idents =
                vec![Expr::Ident(Box::new(ident_from_cst(ctx, node)))];

            // The identifier can be followed by a field access operator,
            // (e.g. `foo.bar.baz`).
            while let Some(node) = children.next() {
                // In fact, if something follows the identifier it must
                // be a field access operator `.`, nothing else.
                expect!(node, GrammarRule::DOT);
                let node = children.next().unwrap();
                idents.push(Expr::Ident(Box::new(ident_from_cst(ctx, node))));
            }

            if idents.len() == 1 {
                idents.pop().unwrap()
            } else {
                Expr::FieldAccess(Box::new(NAryExpr::from(idents)))
            }
        }
        GrammarRule::k_FILESIZE => Expr::Filesize { span: ctx.span(&node) },
        GrammarRule::k_ENTRYPOINT => {
            Expr::Entrypoint { span: ctx.span(&node) }
        }
        GrammarRule::MINUS => {
            let operand = term_from_cst(ctx, children.next().unwrap())?;
            create_unary_expr(ctx, node, operand)?
        }
        GrammarRule::BITWISE_NOT => {
            let operand = term_from_cst(ctx, children.next().unwrap())?;
            create_unary_expr(ctx, node, operand)?
        }
        GrammarRule::LPAREN => {
            let expr = expr_from_cst(ctx, children.next().unwrap())?;
            expect!(children.next().unwrap(), GrammarRule::RPAREN);
            expr
        }
        GrammarRule::string_lit => {
            Expr::LiteralString(Box::new(LiteralString::new(
                node.as_span().as_str(),
                ctx.span(&node),
                string_lit_from_cst(ctx, node, true)?,
            )))
        }
        GrammarRule::float_lit => {
            Expr::LiteralFloat(Box::new(LiteralFloat::new(
                node.as_span().as_str(),
                ctx.span(&node),
                float_lit_from_cst(ctx, node)?,
            )))
        }
        GrammarRule::integer_lit => {
            Expr::LiteralInteger(Box::new(LiteralInteger::new(
                node.as_span().as_str(),
                ctx.span(&node),
                integer_lit_from_cst(ctx, node)?,
            )))
        }
        GrammarRule::regexp => {
            Expr::Regexp(Box::new(regexp_from_cst(ctx, node)?))
        }
        GrammarRule::pattern_count => {
            // Is there some range after the pattern count?
            // Example: #a in (0..10)
            let range = if let Some(node) = children.next() {
                expect!(node, GrammarRule::k_IN);
                Some(range_from_cst(ctx, children.next().unwrap())?)
            } else {
                None
            };

            let ident_name = node.as_span().as_str();

            if ident_name != "#"
                && ctx.declared_patterns.get(&ident_name[1..]).is_none()
            {
                return Err(Error::from(ErrorInfo::unknown_pattern(
                    ctx.report_builder,
                    ident_name.to_string(),
                    ctx.span(&node),
                )));
            }

            // Remove from ctx.unused_patterns, indicating that the
            // identifier has been used.
            ctx.unused_patterns.remove(&ident_name[1..]);

            Expr::PatternCount(Box::new(IdentWithRange {
                span: term_span,
                name: ident_name,
                range,
            }))
        }
        // Pattern lengths (`!a`) and pattern offsets (`@a`) can both be used
        // with indexes like in `!a[1]` and  `@a[1]`, so let's handle them
        // together.
        rule @ (GrammarRule::pattern_length | GrammarRule::pattern_offset) => {
            // The index is optional, if the next child exists it should be
            // the left bracket, if not, there's no indexing at all.
            let index = if let Some(bracket) = children.next() {
                expect!(bracket, GrammarRule::LBRACKET);
                let expr = expr_from_cst(ctx, children.next().unwrap())?;
                expect!(children.next().unwrap(), GrammarRule::RBRACKET);
                Some(expr)
            } else {
                None
            };

            let expr_type = match rule {
                GrammarRule::pattern_length => Expr::PatternLength,
                GrammarRule::pattern_offset => Expr::PatternOffset,
                _ => unreachable!(),
            };

            let ident_name = node.as_span().as_str();

            if ident_name.len() > 1
                && ctx.declared_patterns.get(&ident_name[1..]).is_none()
            {
                return Err(Error::from(ErrorInfo::unknown_pattern(
                    ctx.report_builder,
                    ident_name.to_string(),
                    ctx.span(&node),
                )));
            }

            // Remove from ctx.unused_patterns, indicating that the
            // identifier has been used.
            ctx.unused_patterns.remove(&ident_name[1..]);

            expr_type(Box::new(IdentWithIndex {
                span: term_span,
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
    ctx: &mut Context<'src, '_>,
    indexing_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(indexing_expr, GrammarRule::indexing_expr);

    let span = ctx.span(&indexing_expr);
    let mut children = indexing_expr.into_inner();

    let primary = primary_expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::LBRACKET);

    let index = expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::RBRACKET);

    Ok(Expr::Lookup(Box::new(Lookup::new(primary, index, span))))
}

fn func_call_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    func_call_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(func_call_expr, GrammarRule::func_call_expr);

    let span = ctx.span(&func_call_expr);
    let mut children = func_call_expr.into_inner();

    let callable = primary_expr_from_cst(ctx, children.next().unwrap())?;

    // After the callable expression follows the opening parenthesis
    // enclosing the arguments.
    let lparen = children.next().unwrap();
    expect!(lparen, GrammarRule::LPAREN);

    let mut args = Vec::new();
    let mut children = children.peekable();

    // For all CST nodes after the opening parenthesis, and before the closing
    // parenthesis...
    while let Some(node) =
        children.next_if(|n| !matches!(n.as_rule(), GrammarRule::RPAREN))
    {
        match node.as_rule() {
            // ... if the node is an expression, add it to the function
            // arguments.
            GrammarRule::boolean_expr => {
                args.push(boolean_expr_from_cst(ctx, node)?);
            }
            // ... if the node is a comma separating the arguments, do
            // nothing and continue.
            GrammarRule::COMMA => {}
            rule => unreachable!("{:?}", rule),
        }
    }

    // The function arguments must be followed by a closing parenthesis
    let rparen = children.next().unwrap();
    expect!(rparen, GrammarRule::RPAREN);

    let args_span = Span::new(
        ctx.report_builder.current_source_id().unwrap(),
        lparen.as_span().start(),
        rparen.as_span().end(),
    );

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(Expr::FuncCall(Box::new(FuncCall { span, args_span, callable, args })))
}

/// From a CST node corresponding to the grammar rule `range`, returns a
/// [`Range`] with the lower and upper bounds of the range.
fn range_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    range: CSTNode<'src>,
) -> Result<Range<'src>, Error> {
    expect!(range, GrammarRule::range);

    let span = ctx.span(&range);
    let mut children = range.into_inner();

    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let lower_bound = expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::DOT_DOT);

    let upper_bound = expr_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::RPAREN);

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(Range { span, lower_bound, upper_bound })
}

/// From a CST node corresponding to the grammar rule `of_expr`, returns
/// an [`Expr`] describing the `of` statement.
fn of_expr_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    of_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(of_expr, GrammarRule::of_expr);

    let span = ctx.span(&of_expr);
    let mut children = of_expr.into_inner();

    let quantifier = quantifier_from_cst(ctx, children.next().unwrap())?;

    expect!(children.next().unwrap(), GrammarRule::k_OF);

    let node = children.next().unwrap();

    let items = match node.as_rule() {
        GrammarRule::k_THEM => {
            // `them` was used in the condition, all the patterns are used.
            ctx.unused_patterns.clear();
            OfItems::PatternSet(PatternSet::Them { span: ctx.span(&node) })
        }
        GrammarRule::pattern_ident_tuple => OfItems::PatternSet(
            PatternSet::Set(pattern_ident_tuple(ctx, node)?),
        ),
        GrammarRule::boolean_expr_tuple => {
            OfItems::BoolExprTuple(boolean_expr_tuple_from_cst(ctx, node)?)
        }
        rule => unreachable!("{:?}", rule),
    };

    let anchor = anchor_from_cst(ctx, &mut children)?;

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(Expr::Of(Box::new(Of { span, quantifier, items, anchor })))
}

/// From a CST node corresponding to the grammar rule `for_expr`, returns
/// an [`Expr`] describing the `for` statement.
fn for_expr_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    for_expr: CSTNode<'src>,
) -> Result<Expr<'src>, Error> {
    expect!(for_expr, GrammarRule::for_expr);

    let span = ctx.span(&for_expr);
    let mut children = for_expr.into_inner().peekable();

    // The statement starts with the `for` keyword...
    expect!(children.next().unwrap(), GrammarRule::k_FOR);

    // ...and then follows the quantifier.
    let quantifier = quantifier_from_cst(ctx, children.next().unwrap())?;

    let mut pattern_set = None;
    let mut iterator = None;
    let mut variables = Vec::new();

    if let GrammarRule::k_OF = children.peek().unwrap().as_rule() {
        // Consume the `of` keyword.
        children.next().unwrap();
        // After the `of` keyword follows `them` or a tuple of pattern
        // identifiers.
        let node = children.next().unwrap();
        pattern_set = Some(match node.as_rule() {
            GrammarRule::k_THEM => {
                // `them` was used in the condition, all the patterns are used.
                ctx.unused_patterns.clear();
                PatternSet::Them { span: ctx.span(&node) }
            }
            GrammarRule::pattern_ident_tuple => {
                PatternSet::Set(pattern_ident_tuple(ctx, node)?)
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
                    variables.push(Ident::new(node.as_str(), ctx.span(&node)));
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

    let expr = if let Some(pattern_set) = pattern_set {
        Expr::ForOf(Box::new(ForOf {
            span,
            quantifier,
            pattern_set,
            condition,
        }))
    } else if let Some(iterator) = iterator {
        Expr::ForIn(Box::new(ForIn {
            span,
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
    ctx: &mut Context<'src, '_>,
    mut iter: impl Iterator<Item = CSTNode<'src>>,
) -> Result<Option<MatchAnchor<'src>>, Error> {
    let anchor = if let Some(node) = iter.next() {
        match node.as_rule() {
            GrammarRule::k_AT => {
                let expr = expr_from_cst(ctx, iter.next().unwrap())?;
                // The span of `at <expr>` is the span of `at` combined with
                // the span of `<expr>`.
                let span = ctx.span(&node).combine(&expr.span());
                Some(MatchAnchor::At(Box::new(At { span, expr })))
            }
            GrammarRule::k_IN => {
                let range = range_from_cst(ctx, iter.next().unwrap())?;
                // The span of `in <range>` is the span of `in` combined with
                // the span of `<range>`.
                let span = ctx.span(&node).combine(&range.span());
                Some(MatchAnchor::In(Box::new(In { span, range })))
            }
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
    ctx: &mut Context<'src, '_>,
    quantifier: CSTNode<'src>,
) -> Result<Quantifier<'src>, Error> {
    expect!(quantifier, GrammarRule::quantifier);

    let mut children = quantifier.into_inner();
    let node = children.next().unwrap();

    let quantifier = match node.as_rule() {
        GrammarRule::k_ALL => Quantifier::All { span: ctx.span(&node) },
        GrammarRule::k_ANY => Quantifier::Any { span: ctx.span(&node) },
        GrammarRule::k_NONE => Quantifier::None { span: ctx.span(&node) },
        GrammarRule::expr => Quantifier::Expr(expr_from_cst(ctx, node)?),
        GrammarRule::primary_expr => {
            let expr = primary_expr_from_cst(ctx, node)?;
            // The expression must be followed by the percent `%` symbol.
            expect!(children.next().unwrap(), GrammarRule::PERCENT);
            Quantifier::Percentage(expr)
        }
        rule => unreachable!("{:?}", rule),
    };

    // Make sure that there are no more nodes.
    assert!(children.next().is_none());

    Ok(quantifier)
}

/// From a CST node corresponding to the grammar rule `pattern_ident_tuple`,
/// returns a vector of [`PatternSetItem`].
fn pattern_ident_tuple<'src>(
    ctx: &mut Context<'src, '_>,
    pattern_ident_tuple: CSTNode<'src>,
) -> Result<Vec<PatternSetItem<'src>>, Error> {
    expect!(pattern_ident_tuple, GrammarRule::pattern_ident_tuple);

    let mut children = pattern_ident_tuple.into_inner();

    // The tuple should start with an opening parenthesis.
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut result = Vec::new();

    // For all CST nodes after the opening parenthesis...
    for node in children.by_ref() {
        match node.as_rule() {
            // ... if the node is pattern_ident_wildcarded
            GrammarRule::pattern_ident_wildcarded => {
                // The pattern can be simply a pattern identifier, like `$a`
                // or a pattern identifier ending in a wildcard, like `$a*`.
                // Notice however that the `$` is ignored.
                let pattern = &node.as_str()[1..];

                if let Some(prefix) = pattern.strip_suffix('*') {
                    // If the pattern has a wildcard, remove all identifiers
                    // that starts with the prefix before the wildcard.
                    ctx.unused_patterns
                        .retain(|ident| !ident.starts_with(prefix));
                } else {
                    ctx.unused_patterns.remove(pattern);
                }

                result.push(PatternSetItem {
                    span: ctx.span(&node),
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

/// From a CST node corresponding to the grammar rule `boolean_expr_tuple`,
/// returns a vector of [`Expr`].
fn boolean_expr_tuple_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    boolean_expr_tuple: CSTNode<'src>,
) -> Result<Vec<Expr<'src>>, Error> {
    expect!(boolean_expr_tuple, GrammarRule::boolean_expr_tuple);

    let mut children = boolean_expr_tuple.into_inner();

    // The tuple should start with an opening parenthesis.
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut result = Vec::new();

    // For all CST nodes after the opening parenthesis...
    for node in children.by_ref() {
        match node.as_rule() {
            // ... if the node is boolean_expr
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
    ctx: &mut Context<'src, '_>,
    expr_tuple: CSTNode<'src>,
) -> Result<Vec<Expr<'src>>, Error> {
    expect!(expr_tuple, GrammarRule::expr_tuple);

    let mut children = expr_tuple.into_inner();

    // The tuple should start with an opening parenthesis.
    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut result = Vec::new();

    // For all CST nodes after the opening parenthesis...
    for node in children.by_ref() {
        match node.as_rule() {
            // ... if the node is an expression.
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
    ctx: &mut Context<'src, '_>,
    iterator: CSTNode<'src>,
) -> Result<Iterable<'src>, Error> {
    expect!(iterator, GrammarRule::iterable);
    let mut children = iterator.into_inner();
    let node = children.next().unwrap();
    let expr = match node.as_rule() {
        GrammarRule::range => Iterable::Range(range_from_cst(ctx, node)?),
        GrammarRule::expr => Iterable::Expr(expr_from_cst(ctx, node)?),
        GrammarRule::expr_tuple => {
            Iterable::ExprTuple(expr_tuple_from_cst(ctx, node)?)
        }
        rule => unreachable!("{:?}", rule),
    };
    Ok(expr)
}

/// From a CST node corresponding to the grammar rule `integer_lit`, returns
/// the corresponding integer. This is a generic function that can be used
/// for obtaining any type of integer, like u8, i64, etc.
fn integer_lit_from_cst<'src, T>(
    ctx: &Context<'src, '_>,
    integer_lit: CSTNode<'src>,
) -> Result<T, Error>
where
    T: Num + Bounded + CheckedMul + FromPrimitive + std::fmt::Display,
{
    expect!(integer_lit, GrammarRule::integer_lit);

    let span = ctx.span(&integer_lit);
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

    if let Some(without_sign) = literal.strip_prefix('-') {
        literal = without_sign;
        multiplier = -multiplier;
    }

    let value = if literal.starts_with("0x") {
        T::from_str_radix(literal.strip_prefix("0x").unwrap(), 16)
    } else if literal.starts_with("0o") {
        T::from_str_radix(literal.strip_prefix("0o").unwrap(), 8)
    } else {
        T::from_str_radix(literal, 10)
    };

    let build_error = || {
        Error::from(ErrorInfo::invalid_integer(
            ctx.report_builder,
            format!(
                "this number is out of the valid range: [{}, {}]",
                T::min_value(),
                T::max_value()
            ),
            span,
        ))
    };

    // Report errors that occur while parsing the literal. Some errors
    // (like invalid characters or empty literals) never occur, because
    // the grammar ensures that only valid integers reach this point,
    // however the grammar doesn't make sure that the integer fits in
    // type T.
    let value = value.map_err(|_| build_error())?;

    // The multiplier may not fit in type T.
    let multiplier = T::from_i32(multiplier).ok_or_else(build_error)?;

    // The value after applying the multiplier may not fit in type T.
    let value = value.checked_mul(&multiplier).ok_or_else(build_error)?;

    Ok(value)
}

/// From a CST node corresponding to the grammar rule `float_lit`, returns
/// the `f64` representing the literal.
fn float_lit_from_cst<'src>(
    ctx: &Context<'src, '_>,
    float_lit: CSTNode<'src>,
) -> Result<f64, Error> {
    expect!(float_lit, GrammarRule::float_lit);

    let literal = float_lit.as_str();
    let span = ctx.span(&float_lit);

    literal.parse::<f64>().map_err(|err| {
        Error::from(ErrorInfo::invalid_float(
            ctx.report_builder,
            err.to_string(),
            span,
        ))
    })
}

/// From a CST node corresponding to the grammar rule `string_lit`, returns
/// a string representing the literal. `allow_escape_char` controls whether
/// escaped characters are accepted or not.
///
/// This function returns a [`Cow<'src, BStr>`]. If the string literal doesn't
/// contain escaped characters, the literal is exactly as it appears in the
/// source code and we can return a reference to the code in the form of a
/// &[`BStr`]. However, when the literal string contains escaped characters
/// they must be unescaped, and hence, this function returns a [`BString`]
/// instead.
///
/// As escape characters can introduce arbitrary bytes in the string, including
/// zeroes, they can't be represented by a Rust [`String`] or &[`str`] which
/// requires valid UTF-8. For that reason we use [`BString`] and &[`BStr`]
/// instead.
///
/// When called with `allow_escaped_char: false`, the returned string can be
/// safely converted to [`String`] or &[`str`].
fn string_lit_from_cst<'src>(
    ctx: &Context<'src, '_>,
    string_lit: CSTNode<'src>,
    allow_escape_char: bool,
) -> Result<Cow<'src, BStr>, Error> {
    expect!(string_lit, GrammarRule::string_lit);

    let literal = string_lit.as_str();

    // The string literal must be enclosed in double quotes.
    debug_assert!(literal.starts_with('\"'));
    debug_assert!(literal.ends_with('\"'));

    // The span doesn't include the quotes.
    let string_span = ctx.span(&string_lit).subspan(1, literal.len() - 1);

    // From now on ignore the quotes.
    let literal = &literal[1..literal.len() - 1];

    // Check if the string contains some backslash.
    let backslash_pos = if let Some(backslash_pos) = literal.find('\\') {
        if !allow_escape_char {
            return Err(Error::from(ErrorInfo::unexpected_escape_sequence(
                ctx.report_builder,
                ctx.span(&string_lit),
            )));
        }
        backslash_pos
    } else {
        // If the literal does not contain a backslash it can't contain escaped
        // characters, the literal is exactly as it appears in the source code.
        // Therefore, we can return a reference to it in the form of a &BStr,
        // allocating a new BString is not necessary.
        return Ok(Cow::from(BStr::new(literal)));
    };

    // Initially the result is a copy of the literal string up to the first
    // backslash found.
    let mut result = BString::from(&literal[..backslash_pos]);

    // Process the remaining part of the literal, starting at the backslash.
    let literal = &literal[backslash_pos..];
    let mut chars = literal.char_indices();

    while let Some((backslash_pos, b)) = chars.next() {
        match b {
            // The backslash indicates an escape sequence.
            '\\' => {
                // Consume the backslash and see what's next. A character must
                // follow the backslash, this is guaranteed by the grammar
                // itself.
                let escaped_char = chars.next().unwrap();

                match escaped_char.1 {
                    '\\' => result.push(b'\\'),
                    'n' => result.push(b'\n'),
                    'r' => result.push(b'\r'),
                    't' => result.push(b'\t'),
                    '0' => result.push(b'\0'),
                    '"' => result.push(b'"'),
                    'x' => match (chars.next(), chars.next()) {
                        (Some((start, _)), Some((end, _))) => {
                            if let Ok(hex_value) =
                                u8::from_str_radix(&literal[start..=end], 16)
                            {
                                result.push(hex_value);
                            } else {
                                return Err(Error::from(
                                    ErrorInfo::invalid_escape_sequence(
                                        ctx.report_builder,
                                        format!(
                                            r"invalid hex value `{}` after `\x`",
                                            &literal[start..=end]
                                        ),
                                        string_span.subspan(start, end + 1),
                                    ),
                                ));
                            }
                        }
                        _ => {
                            return Err(Error::from(
                                ErrorInfo::invalid_escape_sequence(
                                    ctx.report_builder,
                                    r"expecting two hex digits after `\x`"
                                        .to_string(),
                                    string_span.subspan(
                                        backslash_pos,
                                        escaped_char.0 + 1,
                                    ),
                                ),
                            ));
                        }
                    },
                    _ => {
                        let (escaped_char_pos, escaped_char) = escaped_char;

                        let escaped_char_end_pos =
                            escaped_char_pos + escaped_char.len_utf8();

                        return Err(Error::from(
                            ErrorInfo::invalid_escape_sequence(
                                ctx.report_builder,
                                format!(
                                    "invalid escape sequence `{}`",
                                    &literal
                                        [backslash_pos..escaped_char_end_pos]
                                ),
                                string_span.subspan(
                                    backslash_pos,
                                    escaped_char_end_pos,
                                ),
                            ),
                        ));
                    }
                }
            }
            // Non-escaped characters are copied as is.
            c => result.push_char(c),
        }
    }

    Ok(Cow::Owned(result))
}

/// This function is similar [`string_lit_from_cst`] but guarantees that the
/// string is a valid UTF-8 string.
fn utf8_string_lit_from_cst<'src>(
    ctx: &Context<'src, '_>,
    string_lit: CSTNode<'src>,
) -> Result<&'src str, Error> {
    // Call string_lit_from_cst with allow_escape_char set to false. This
    // guarantees that the returned string is borrowed from the source code
    // and is valid UTF-8, therefore is safe to convert it to &str without
    // additional checks.
    match string_lit_from_cst(ctx, string_lit, false)? {
        Cow::Borrowed(a) => unsafe { Ok(a.to_str_unchecked()) },
        _ => unreachable!(),
    }
}

/// From a CST node corresponding to the grammar rule `hex_pattern`, returns
/// the [`HexPattern`] representing it.
fn hex_pattern_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    hex_tokens: CSTNode<'src>,
) -> Result<HexTokens, Error> {
    expect!(hex_tokens, GrammarRule::hex_tokens);

    let mut children = hex_tokens.into_inner().peekable();
    let mut pattern = HexTokens { tokens: Vec::new() };

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

                if let Some(low_nibble) = nibbles.next() {
                    // Low nibble is `?`, then it should be masked out.
                    if low_nibble == '?' {
                        mask &= 0xF0;
                    } else {
                        value |= low_nibble.to_digit(16).unwrap() as u8;
                    }
                } else {
                    // The low nibble is missing when there is an odd number of
                    // nibbles in a byte sequence (e.g. { 000 }). The grammar
                    // allows this case, even if invalid, precisely for
                    // detecting it here and providing a
                    // meaningful error message.
                    return Err(Error::from(ErrorInfo::invalid_pattern(
                        ctx.report_builder,
                        ctx.current_pattern_ident(),
                        "uneven number of nibbles".to_string(),
                        ctx.span(&node),
                        None,
                    )));
                }

                // ~?? is not allowed.
                if negated && mask == 0x00 {
                    return Err(Error::from(ErrorInfo::invalid_pattern(
                        ctx.report_builder,
                        ctx.current_pattern_ident(),
                        "negation of `??` is not allowed".to_string(),
                        ctx.span(&node),
                        None,
                    )));
                }

                let token =
                    if negated { HexToken::NotByte } else { HexToken::Byte };

                token(HexByte { value, mask })
            }
            GrammarRule::hex_alternative => HexToken::Alternative(Box::new(
                hex_alternative_from_cst(ctx, node)?,
            )),
            GrammarRule::hex_jump => {
                let mut jump_span = ctx.span(&node);
                let mut jump = hex_jump_from_cst(ctx, node)?;
                let mut consecutive_jumps = false;

                // If there are two consecutive jumps they will be coalesced
                // together. For example: [1-2][2-3] is converted into [3-5].
                while let Some(node) = children.peek() {
                    if node.as_rule() != GrammarRule::hex_jump {
                        break;
                    }
                    let span = ctx.span(node);
                    jump.coalesce(hex_jump_from_cst(
                        ctx,
                        children.next().unwrap(),
                    )?);
                    jump_span = jump_span.combine(&span);
                    consecutive_jumps = true;
                }

                if consecutive_jumps {
                    let report_builder = ctx.report_builder;
                    let ident = ctx.current_pattern_ident();
                    ctx.warnings.add(|| {
                        Warning::consecutive_jumps(
                            report_builder,
                            ident.clone(),
                            format!("{}", jump),
                            jump_span,
                        )
                    });
                }

                match (jump.start, jump.end) {
                    (Some(0), Some(0)) => {
                        return Err(Error::from(ErrorInfo::invalid_pattern(
                            ctx.report_builder,
                            ctx.current_pattern_ident(),
                            "zero-length jumps are useless, remove it"
                                .to_string(),
                            jump_span,
                            None,
                        )));
                    }
                    (Some(start), Some(end)) if start > end => {
                        return Err(Error::from(ErrorInfo::invalid_pattern(
                            ctx.report_builder,
                            ctx.current_pattern_ident(),
                            format!(
                                "lower bound ({}) is greater than upper bound ({})",
                                start, end),
                            jump_span,
                            if consecutive_jumps {
                                Some("consecutive jumps were coalesced into a single one".to_string())
                            } else {
                                None
                            },
                        )));
                    }
                    _ => {}
                }

                HexToken::Jump(jump)
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
    ctx: &Context<'src, '_>,
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
    } else {
        end = start;
    }

    expect!(node, GrammarRule::RBRACKET);

    Ok(HexJump { start, end })
}

/// From a CST node corresponding to the grammar rule `hex_alternative`,
/// returns the [`HexAlternative`] where each item is an alternative.
fn hex_alternative_from_cst<'src>(
    ctx: &mut Context<'src, '_>,
    hex_alternative: CSTNode<'src>,
) -> Result<HexAlternative, Error> {
    expect!(hex_alternative, GrammarRule::hex_alternative);

    let mut children = hex_alternative.into_inner();

    expect!(children.next().unwrap(), GrammarRule::LPAREN);

    let mut alternatives = Vec::new();

    for node in children {
        match node.as_rule() {
            GrammarRule::hex_tokens => {
                alternatives.push(hex_pattern_from_cst(ctx, node)?);
            }
            GrammarRule::PIPE | GrammarRule::RPAREN => {}
            rule => unreachable!("{:?}", rule),
        }
    }

    Ok(HexAlternative { alternatives })
}

fn ident_from_cst<'src>(
    ctx: &Context<'src, '_>,
    ident: CSTNode<'src>,
) -> ast::Ident<'src> {
    ast::Ident { span: ctx.span(&ident), name: ident.as_str() }
}
