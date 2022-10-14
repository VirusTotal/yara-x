use crate::formatter::processor::{actions, Processor};
use crate::formatter::tokens;
use crate::formatter::tokens::Token::*;
use crate::formatter::tokens::{categories, Token};
use crate::parser::{GrammarRule, Parser};
use pretty_assertions::assert_eq;

fn tokenize(source: &str) -> tokens::Tokens {
    tokens::Tokens::new(Parser::new().build_cst(source, Option::None).unwrap())
}

#[test]
fn no_rules() {
    // The output of a processor with no rules must be equal to the input.
    let input_tokens: Vec<Token> =
        tokenize(r#"rule test { condition: true }"#).collect();

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
        tokenize(r#"rule test { condition: true }"#).collect();

    let processor = Processor::new(input_tokens.clone().into_iter())
        .add_rule(|_| true, actions::copy);

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(input_tokens, output_tokens);
}

#[test]
fn drop() {
    // Make sure that a processor with a single rule where the condition is
    // always true and the action is actions::drop returns only the control
    // tokens.
    let mut processor =
        Processor::new(tokenize(r#"rule test { condition: true }"#))
            .add_rule(|_| true, actions::drop);

    assert!(processor.next().is_none());
}

#[test]
fn passthrough() {
    let input_tokens: Vec<Token> =
        tokenize(r#"rule test { condition: true }"#).collect();

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
            Begin(GrammarRule::source_file),
            Begin(GrammarRule::rule_decl),
            Begin(GrammarRule::boolean_expr),
            Begin(GrammarRule::boolean_term),
            End(GrammarRule::boolean_term),
            End(GrammarRule::boolean_expr),
            End(GrammarRule::rule_decl),
            End(GrammarRule::source_file),
        ]
    )
}

#[test]
fn swap() {
    let input_tokens =
        vec![Keyword("foo"), Begin(GrammarRule::rule_decl), Keyword("bar")];

    let processor = Processor::new(input_tokens.clone().into_iter())
        .set_passthrough(*categories::CONTROL)
        .add_rule(
            |ctx| {
                ctx.token(1) == &Keyword("foo")
                    && ctx.token(2) == &Keyword("bar")
            },
            actions::swap(1, 2),
        );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![Keyword("bar"), Begin(GrammarRule::rule_decl), Keyword("foo")]
    )
}

#[test]
fn drop_identifiers() {
    // Test a processor that drops only the tokens that are identifiers.
    let input_tokens = tokens::Tokens::new(
        Parser::new()
            .build_cst(r#"rule test { condition: true }"#, Option::None)
            .unwrap(),
    );

    let processor = Processor::new(input_tokens)
        // Drop identifiers.
        .add_rule(
            |ctx| ctx.token(1).is(*tokens::categories::IDENTIFIER),
            actions::drop,
        );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![
            Begin(GrammarRule::source_file),
            Begin(GrammarRule::rule_decl),
            Keyword("rule"),
            // This is the dropped identifier.
            // Identifier("test"),
            Punctuation("{"),
            Keyword("condition"),
            Punctuation(":"),
            Begin(GrammarRule::boolean_expr),
            Begin(GrammarRule::boolean_term),
            Keyword("true"),
            End(GrammarRule::boolean_term),
            End(GrammarRule::boolean_expr),
            Punctuation("}"),
            End(GrammarRule::rule_decl),
            End(GrammarRule::source_file),
        ]
    )
}

#[test]
fn insert_global() {
    // Test a processor that inserts a "global" keyword before "rule".
    use crate::formatter::tokens::Token::*;
    use crate::parser::GrammarRule;

    let processor =
        Processor::new(tokenize(r#"rule test { condition: true }"#))
            // Drop identifiers.
            .add_rule(
                |c| match (c.token(-1), c.token(1)) {
                    // The "rule" keyword is already preceded by "global", do
                    // nothing.
                    (Keyword("global"), Keyword("rule")) => false,
                    // In all other cases where "rule" is found insert "global".
                    (_, Keyword("rule")) => true,
                    // For all other tokens do nothing.
                    _ => false,
                },
                actions::insert(Keyword("global")),
            );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![
            Begin(GrammarRule::source_file),
            Begin(GrammarRule::rule_decl),
            Keyword("global"),
            Keyword("rule"),
            Identifier("test"),
            Punctuation("{"),
            Keyword("condition"),
            Punctuation(":"),
            Begin(GrammarRule::boolean_expr),
            Begin(GrammarRule::boolean_term),
            Keyword("true"),
            End(GrammarRule::boolean_term),
            End(GrammarRule::boolean_expr),
            Punctuation("}"),
            End(GrammarRule::rule_decl),
            End(GrammarRule::source_file),
        ]
    )
}

#[test]
fn in_rule() {
    // Test a processor that inserts a "global" keyword before "rule".
    use crate::formatter::tokens::Token::*;
    use crate::parser::GrammarRule;

    let processor =
        Processor::new(tokenize(r#"rule test { condition: true }"#))
            .add_rule(
                |c| {
                    c.token(1).eq(&Keyword("true"))
                        && c.token(-1).neq(&Literal("<before true>"))
                },
                actions::insert(Literal("<before true>")),
            )
            .add_rule(
                |c| c.token(-1).eq(&Token::Keyword("true")),
                actions::insert(Literal("<after true>")),
            )
            .add_rule(
                |c| {
                    c.token(1).eq(&Begin(GrammarRule::boolean_expr))
                        && c.token(-1)
                            .neq(&Literal("<begin Rule::boolean_expr>"))
                },
                actions::insert(Literal("<begin Rule::boolean_expr>")),
            )
            .add_rule(
                |c| {
                    c.token(1).eq(&End(GrammarRule::boolean_expr))
                        && c.token(-1)
                            .neq(&Literal("<end Rule::boolean_expr>"))
                },
                actions::insert(Literal("<end Rule::boolean_expr>")),
            );

    let output_tokens: Vec<Token> = processor.collect();

    assert_eq!(
        output_tokens,
        vec![
            Begin(GrammarRule::source_file),
            Begin(GrammarRule::rule_decl),
            Keyword("rule"),
            Identifier("test"),
            Punctuation("{"),
            Keyword("condition"),
            Punctuation(":"),
            Literal("<begin Rule::boolean_expr>"),
            Begin(GrammarRule::boolean_expr),
            Begin(GrammarRule::boolean_term),
            Literal("<before true>"),
            Keyword("true"),
            Literal("<after true>"),
            End(GrammarRule::boolean_term),
            Literal("<end Rule::boolean_expr>"),
            End(GrammarRule::boolean_expr),
            Punctuation("}"),
            End(GrammarRule::rule_decl),
            End(GrammarRule::source_file),
        ]
    )
}
