use crate::formatter::tokens::Token::*;
use crate::formatter::tokens::{Token, Tokens};
use crate::parser::{GrammarRule, Parser};
use pretty_assertions::assert_eq;

#[test]
fn token_generation() {
    let rule = r#"
        rule test {
            strings:
                $a = { 00 01 }
                $b = "foo" ascii wide
            condition: true
        }"#;

    let parse_tree = Parser::new().build_cst(rule, Option::None).unwrap();
    let tokens: Vec<Token> = Tokens::new(parse_tree).collect();

    assert_eq!(
        tokens,
        vec![
            Begin(GrammarRule::source_file),
            Begin(GrammarRule::rule_decl),
            Keyword("rule"),
            Identifier("test"),
            Punctuation("{"),
            Begin(GrammarRule::string_defs),
            Keyword("strings"),
            Punctuation(":"),
            Begin(GrammarRule::string_def),
            Identifier("$a"),
            Punctuation("="),
            Begin(GrammarRule::hex_string),
            Punctuation("{"),
            Begin(GrammarRule::hex_tokens),
            Literal("00"),
            Literal("01"),
            End(GrammarRule::hex_tokens),
            Punctuation("}"),
            End(GrammarRule::hex_string),
            End(GrammarRule::string_def),
            Begin(GrammarRule::string_def),
            Identifier("$b"),
            Punctuation("="),
            Literal("\"foo\""),
            Begin(GrammarRule::string_mods),
            Keyword("ascii"),
            Keyword("wide"),
            End(GrammarRule::string_mods),
            End(GrammarRule::string_def),
            End(GrammarRule::string_defs),
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
