use pretty_assertions::assert_eq;
use yara_x_parser_ng::cst::SyntaxKind;

use crate::tokens::Token::*;
use crate::tokens::{Token, Tokens};
use yara_x_parser_ng::Parser;

#[test]
fn token_generation() {
    let rule = r#"
        rule test {
            strings:
                $a = { 00 01 }
                $b = "foo" ascii wide
            condition: true
        }"#;

    let events = Parser::new(rule.as_bytes())
        .into_cst_stream()
        .whitespaces(false)
        .newlines(false);

    let tokens: Vec<Token> = Tokens::new(events).collect();

    assert_eq!(
        tokens,
        vec![
            Begin(SyntaxKind::SOURCE_FILE),
            Begin(SyntaxKind::RULE_DECL),
            Keyword("rule"),
            Identifier("test"),
            Punctuation("{"),
            Begin(SyntaxKind::PATTERNS_BLK),
            Keyword("strings"),
            Punctuation(":"),
            Begin(SyntaxKind::PATTERN_DEF),
            Identifier("$a"),
            Punctuation("="),
            Begin(SyntaxKind::HEX_PATTERN),
            Punctuation("{"),
            Begin(SyntaxKind::HEX_SUB_PATTERN),
            Literal("00"),
            Literal("01"),
            End(SyntaxKind::HEX_SUB_PATTERN),
            Punctuation("}"),
            End(SyntaxKind::HEX_PATTERN),
            End(SyntaxKind::PATTERN_DEF),
            Begin(SyntaxKind::PATTERN_DEF),
            Identifier("$b"),
            Punctuation("="),
            Literal("\"foo\""),
            Begin(SyntaxKind::PATTERN_MODS),
            Begin(SyntaxKind::PATTERN_MOD),
            Keyword("ascii"),
            End(SyntaxKind::PATTERN_MOD),
            Begin(SyntaxKind::PATTERN_MOD),
            Keyword("wide"),
            End(SyntaxKind::PATTERN_MOD),
            End(SyntaxKind::PATTERN_MODS),
            End(SyntaxKind::PATTERN_DEF),
            End(SyntaxKind::PATTERNS_BLK),
            Begin(SyntaxKind::CONDITION_BLK),
            Keyword("condition"),
            Punctuation(":"),
            Begin(SyntaxKind::BOOLEAN_EXPR),
            Begin(SyntaxKind::BOOLEAN_TERM),
            Keyword("true"),
            End(SyntaxKind::BOOLEAN_TERM),
            End(SyntaxKind::BOOLEAN_EXPR),
            End(SyntaxKind::CONDITION_BLK),
            Punctuation("}"),
            End(SyntaxKind::RULE_DECL),
            End(SyntaxKind::SOURCE_FILE),
        ]
    )
}

#[test]
fn whitespaces() {
    let rule = r#"rule test {
        condition:
            true
    }"#;

    let events = Parser::new(rule.as_bytes()).into_cst_stream();
    let tokens: Vec<Token> = Tokens::new(events).collect();

    assert_eq!(
        tokens,
        vec![
            Begin(SyntaxKind::SOURCE_FILE),
            Begin(SyntaxKind::RULE_DECL),
            Keyword("rule"),
            Whitespace,
            Identifier("test"),
            Whitespace,
            Punctuation("{"),
            Newline,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Begin(SyntaxKind::CONDITION_BLK),
            Keyword("condition"),
            Punctuation(":"),
            Newline,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Begin(SyntaxKind::BOOLEAN_EXPR),
            Begin(SyntaxKind::BOOLEAN_TERM),
            Keyword("true"),
            End(SyntaxKind::BOOLEAN_TERM),
            End(SyntaxKind::BOOLEAN_EXPR),
            End(SyntaxKind::CONDITION_BLK),
            Newline,
            Whitespace,
            Whitespace,
            Whitespace,
            Whitespace,
            Punctuation("}"),
            End(SyntaxKind::RULE_DECL),
            End(SyntaxKind::SOURCE_FILE),
        ]
    )
}
