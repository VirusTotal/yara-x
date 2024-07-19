use pretty_assertions::assert_eq;
use yara_x_parser::cst::SyntaxKind;
use yara_x_parser::Parser;

use crate::processor::{actions, Processor};
use crate::tokens;
use crate::tokens::Token::*;
use crate::tokens::{categories, Token};

fn tokenize(source: &str) -> Vec<Token> {
    let events =
        Parser::new(source.as_bytes()).into_cst_stream().whitespaces(false);
    tokens::Tokens::new(events).collect()
}

#[test]
fn no_rules() {
    // The output of a processor with no rules must be equal to the input.
    let input_tokens: Vec<Token> =
        tokenize(r#"rule test { condition: true }"#);

    let processor = Processor::new(input_tokens.clone().into_iter());
    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(input_tokens, output_tokens);
}

#[test]
fn copy() {
    // Make sure that a processor with a single rule where the condition is
    // always true and the action is actions::copy returns an output that is
    // exactly equal to the input.
    let input_tokens: Vec<Token> =
        tokenize(r#"rule test { condition: true }"#);

    let processor = Processor::new(input_tokens.clone().into_iter())
        .add_rule(|_| true, actions::copy);

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(input_tokens, output_tokens);
}

#[test]
fn drop() {
    // Make sure that a processor with a single rule where the condition is
    // always true and the action is actions::drop doesn't return any tokens.
    let mut processor = Processor::new(
        tokenize(r#"rule test { condition: true }"#).into_iter(),
    )
    .add_rule(|_| true, actions::drop);

    assert!(processor.next().is_none());
}

#[test]
fn passthrough() {
    let input_tokens: Vec<Token> =
        tokenize(r#"rule test { condition: true }"#);

    // This processor should remove all tokens except control tokens.
    let processor = Processor::new(input_tokens.clone().into_iter())
        .set_passthrough(*categories::CONTROL)
        .add_rule(
            |ctx| {
                // All tokens seen by the rule should be TEXT, as CONTROL
                // tokens are not visible to rules. So this rule should always
                // true and all tokens should be dropped.
                ctx.token(1).is(*categories::TEXT)
                    && (ctx.token(2).is(*categories::TEXT)
                        || ctx.token(2) == &None)
                    && (ctx.token(-1).is(*categories::TEXT)
                        || ctx.token(-1) == &None)
            },
            actions::drop,
        );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![
            Begin(SyntaxKind::SOURCE_FILE),
            Begin(SyntaxKind::RULE_DECL),
            Begin(SyntaxKind::CONDITION_BLK),
            Begin(SyntaxKind::BOOLEAN_EXPR),
            Begin(SyntaxKind::BOOLEAN_TERM),
            End(SyntaxKind::BOOLEAN_TERM),
            End(SyntaxKind::BOOLEAN_EXPR),
            End(SyntaxKind::CONDITION_BLK),
            End(SyntaxKind::RULE_DECL),
            End(SyntaxKind::SOURCE_FILE),
        ]
    )
}

#[test]
fn swap() {
    let input_tokens =
        vec![Keyword(b"foo"), Begin(SyntaxKind::RULE_DECL), Keyword(b"bar")];

    let processor = Processor::new(input_tokens.clone().into_iter())
        .set_passthrough(*categories::CONTROL)
        .add_rule(
            |ctx| {
                ctx.token(1) == &Keyword(b"foo")
                    && ctx.token(2) == &Keyword(b"bar")
            },
            actions::swap(1, 2),
        );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![Keyword(b"bar"), Begin(SyntaxKind::RULE_DECL), Keyword(b"foo")]
    )
}

#[test]
fn drop_identifiers() {
    // Test a processor that drops only the tokens that are identifiers.
    let input_tokens: Vec<Token> =
        tokenize(r#"rule test { condition: true }"#);

    let processor = Processor::new(input_tokens.into_iter())
        // Drop identifiers.
        .add_rule(
            |ctx| ctx.token(1).is(*tokens::categories::IDENTIFIER),
            actions::drop,
        );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![
            Begin(SyntaxKind::SOURCE_FILE),
            Begin(SyntaxKind::RULE_DECL),
            Keyword(b"rule"),
            // This is the dropped identifier.
            // Identifier("test"),
            Punctuation(b"{"),
            Begin(SyntaxKind::CONDITION_BLK),
            Keyword(b"condition"),
            Punctuation(b":"),
            Begin(SyntaxKind::BOOLEAN_EXPR),
            Begin(SyntaxKind::BOOLEAN_TERM),
            Keyword(b"true"),
            End(SyntaxKind::BOOLEAN_TERM),
            End(SyntaxKind::BOOLEAN_EXPR),
            End(SyntaxKind::CONDITION_BLK),
            Punctuation(b"}"),
            End(SyntaxKind::RULE_DECL),
            End(SyntaxKind::SOURCE_FILE),
        ]
    )
}

#[test]
fn insert_global() {
    // Test a processor that inserts a "global" keyword before "rule".
    use crate::tokens::Token::*;

    let processor = Processor::new(
        tokenize(r#"rule test { condition: true }"#).into_iter(),
    )
    // Drop identifiers.
    .add_rule(
        |c| match (c.token(-1), c.token(1)) {
            // The "rule" keyword is already preceded by "global", do
            // nothing.
            (Keyword(b"global"), Keyword(b"rule")) => false,
            // In all other cases where "rule" is found insert "global".
            (_, Keyword(b"rule")) => true,
            // For all other tokens do nothing.
            _ => false,
        },
        actions::insert(Keyword(b"global")),
    );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![
            Begin(SyntaxKind::SOURCE_FILE),
            Begin(SyntaxKind::RULE_DECL),
            Keyword(b"global"),
            Keyword(b"rule"),
            Identifier(b"test"),
            Punctuation(b"{"),
            Begin(SyntaxKind::CONDITION_BLK),
            Keyword(b"condition"),
            Punctuation(b":"),
            Begin(SyntaxKind::BOOLEAN_EXPR),
            Begin(SyntaxKind::BOOLEAN_TERM),
            Keyword(b"true"),
            End(SyntaxKind::BOOLEAN_TERM),
            End(SyntaxKind::BOOLEAN_EXPR),
            End(SyntaxKind::CONDITION_BLK),
            Punctuation(b"}"),
            End(SyntaxKind::RULE_DECL),
            End(SyntaxKind::SOURCE_FILE),
        ]
    )
}

#[test]
fn in_rule() {
    // Test a processor that inserts a "global" keyword before "rule".
    use crate::tokens::Token::*;

    let tokens = Processor::new(
        tokenize(r#"rule test { condition: true }"#).into_iter(),
    )
    .add_rule(
        |c| {
            c.in_rule(SyntaxKind::BOOLEAN_EXPR, false)
                && c.token(-1)
                    .neq(&Literal(b"<next token is in boolean_expr>"))
        },
        actions::insert(Literal(b"<next token is in boolean_expr>")),
    )
    .add_rule(
        |c| {
            c.in_rule(SyntaxKind::BOOLEAN_TERM, false)
                && c.token(-1)
                    .neq(&Literal(b"<next token is in boolean_term>"))
        },
        actions::insert(Literal(b"<next token is in boolean_term>")),
    );

    let output_tokens: Vec<Token> = tokens.collect();

    assert_eq!(
        output_tokens,
        vec![
            Begin(SyntaxKind::SOURCE_FILE),
            Begin(SyntaxKind::RULE_DECL),
            Keyword(b"rule"),
            Identifier(b"test"),
            Punctuation(b"{"),
            Begin(SyntaxKind::CONDITION_BLK),
            Keyword(b"condition"),
            Punctuation(b":"),
            Begin(SyntaxKind::BOOLEAN_EXPR),
            Literal(b"<next token is in boolean_expr>"),
            Begin(SyntaxKind::BOOLEAN_TERM),
            Literal(b"<next token is in boolean_term>"),
            Keyword(b"true"),
            Literal(b"<next token is in boolean_expr>"),
            End(SyntaxKind::BOOLEAN_TERM),
            End(SyntaxKind::BOOLEAN_EXPR),
            End(SyntaxKind::CONDITION_BLK),
            Punctuation(b"}"),
            End(SyntaxKind::RULE_DECL),
            End(SyntaxKind::SOURCE_FILE),
        ]
    )
}
