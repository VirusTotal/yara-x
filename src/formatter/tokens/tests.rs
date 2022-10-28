use pretty_assertions::assert_eq;

use crate::formatter::tokens::{Token, Tokens};
use crate::formatter::tokens::Token::*;
use crate::parser::{GrammarRule, Parser};

#[test]
fn token_generation() {
    let rule = r#"
        rule test {
            strings:
                $a = { 00 01 }
                $b = "foo" ascii wide
            condition: true
        }"#;

    let parse_tree = Parser::new().build_cst(rule).unwrap();
    let tokens: Vec<Token> = Tokens::new(parse_tree).collect();

    assert_eq!(
        tokens,
        vec![
            Begin(GrammarRule::source_file),
            Begin(GrammarRule::rule_decl),
            Keyword("rule"),
            Identifier("test"),
            Punctuation("{"),
            Begin(GrammarRule::pattern_defs),
            Keyword("strings"),
            Punctuation(":"),
            Begin(GrammarRule::pattern_def),
            Identifier("$a"),
            Punctuation("="),
            Begin(GrammarRule::hex_pattern),
            Punctuation("{"),
            Begin(GrammarRule::hex_tokens),
            Literal("00"),
            Literal("01"),
            End(GrammarRule::hex_tokens),
            Punctuation("}"),
            End(GrammarRule::hex_pattern),
            End(GrammarRule::pattern_def),
            Begin(GrammarRule::pattern_def),
            Identifier("$b"),
            Punctuation("="),
            Literal("\"foo\""),
            Begin(GrammarRule::pattern_mods),
            Keyword("ascii"),
            Keyword("wide"),
            End(GrammarRule::pattern_mods),
            End(GrammarRule::pattern_def),
            End(GrammarRule::pattern_defs),
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
