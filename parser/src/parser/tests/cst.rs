use pretty_assertions::assert_eq;

use crate::parser::{GrammarRule, Parser};

#[test]
fn cst() {
    let tests = vec![
        /////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::rule_mods,
            r#"global private"#,
            r#"
 rule_mods
 ├─ k_GLOBAL "global"
 └─ k_PRIVATE "private"
"#,
        ),
        /////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::rule_mods,
            r#"private global"#,
            r#"
 rule_mods
 ├─ k_PRIVATE "private"
 └─ k_GLOBAL "global"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::source_file,
            r#"
rule test : foo bar baz {
  meta:
    a = "foo"
    b = true
    c = false
    d = 1
    e = -1
  condition:
    true
}"#,
            r#"
 source_file
 └─ rule_decl
    ├─ k_RULE "rule"
    ├─ ident "test"
    ├─ rule_tags
    │  ├─ COLON ":"
    │  ├─ ident "foo"
    │  ├─ ident "bar"
    │  └─ ident "baz"
    ├─ LBRACE "{"
    ├─ meta_defs
    │  ├─ k_META "meta"
    │  ├─ COLON ":"
    │  ├─ meta_def
    │  │  ├─ ident "a"
    │  │  ├─ EQUAL "="
    │  │  └─ string_lit ""foo""
    │  ├─ meta_def
    │  │  ├─ ident "b"
    │  │  ├─ EQUAL "="
    │  │  └─ k_TRUE "true"
    │  ├─ meta_def
    │  │  ├─ ident "c"
    │  │  ├─ EQUAL "="
    │  │  └─ k_FALSE "false"
    │  ├─ meta_def
    │  │  ├─ ident "d"
    │  │  ├─ EQUAL "="
    │  │  └─ integer_lit "1"
    │  └─ meta_def
    │     ├─ ident "e"
    │     ├─ EQUAL "="
    │     └─ integer_lit "-1"
    ├─ k_CONDITION "condition"
    ├─ COLON ":"
    ├─ boolean_expr
    │  └─ boolean_term
    │     └─ k_TRUE "true"
    └─ RBRACE "}"
"#,
        ),
        /////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::string_lit,
            r#""\nfoobar" "baz""#,
            r#"
 string_lit ""\nfoobar""
"#,
        ),
        /////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::regexp,
            r"/ab\/cd/   / ",
            r#"
 regexp "/ab\/cd/"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::pattern_def,
            r#"$a = "foo" ascii wide fullword nocase xor base64 base64wide"#,
            r#"
 pattern_def
 ├─ pattern_ident "$a"
 ├─ EQUAL "="
 ├─ string_lit ""foo""
 └─ pattern_mods
    ├─ k_ASCII "ascii"
    ├─ k_WIDE "wide"
    ├─ k_FULLWORD "fullword"
    ├─ k_NOCASE "nocase"
    ├─ k_XOR "xor"
    ├─ k_BASE64 "base64"
    └─ k_BASE64WIDE "base64wide"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::pattern_def,
            r#"$a = "foo" xor(32) base64("foo") base64wide("bar")"#,
            r#"
 pattern_def
 ├─ pattern_ident "$a"
 ├─ EQUAL "="
 ├─ string_lit ""foo""
 └─ pattern_mods
    ├─ k_XOR "xor"
    ├─ LPAREN "("
    ├─ integer_lit "32"
    ├─ RPAREN ")"
    ├─ k_BASE64 "base64"
    ├─ LPAREN "("
    ├─ string_lit ""foo""
    ├─ RPAREN ")"
    ├─ k_BASE64WIDE "base64wide"
    ├─ LPAREN "("
    ├─ string_lit ""bar""
    └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::pattern_def,
            r#"$a = "foo" xor(20-32)"#,
            r#"
 pattern_def
 ├─ pattern_ident "$a"
 ├─ EQUAL "="
 ├─ string_lit ""foo""
 └─ pattern_mods
    ├─ k_XOR "xor"
    ├─ LPAREN "("
    ├─ integer_lit "20"
    ├─ HYPHEN "-"
    ├─ integer_lit "32"
    └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::pattern_def,
            r#"$a = { 00 11 } private"#,
            r#"
 pattern_def
 ├─ pattern_ident "$a"
 ├─ EQUAL "="
 ├─ hex_pattern
 │  ├─ LBRACE "{"
 │  ├─ hex_tokens
 │  │  ├─ hex_byte "00"
 │  │  └─ hex_byte "11"
 │  └─ RBRACE "}"
 └─ pattern_mods
    └─ k_PRIVATE "private"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ 00 }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  └─ hex_byte "00"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ 00 01 }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  ├─ hex_byte "00"
 │  └─ hex_byte "01"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ 00 [1] 01 [1-2] 02 [10-] 03 [20-] 04 }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  ├─ hex_byte "00"
 │  ├─ hex_jump
 │  │  ├─ LBRACKET "["
 │  │  ├─ integer_lit "1"
 │  │  └─ RBRACKET "]"
 │  ├─ hex_byte "01"
 │  ├─ hex_jump
 │  │  ├─ LBRACKET "["
 │  │  ├─ integer_lit "1"
 │  │  ├─ HYPHEN "-"
 │  │  ├─ integer_lit "2"
 │  │  └─ RBRACKET "]"
 │  ├─ hex_byte "02"
 │  ├─ hex_jump
 │  │  ├─ LBRACKET "["
 │  │  ├─ integer_lit "10"
 │  │  ├─ HYPHEN "-"
 │  │  └─ RBRACKET "]"
 │  ├─ hex_byte "03"
 │  ├─ hex_jump
 │  │  ├─ LBRACKET "["
 │  │  ├─ integer_lit "20"
 │  │  ├─ HYPHEN "-"
 │  │  └─ RBRACKET "]"
 │  └─ hex_byte "04"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ (00 01 | 00 01) }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  └─ hex_alternative
 │     ├─ LPAREN "("
 │     ├─ hex_tokens
 │     │  ├─ hex_byte "00"
 │     │  └─ hex_byte "01"
 │     ├─ PIPE "|"
 │     ├─ hex_tokens
 │     │  ├─ hex_byte "00"
 │     │  └─ hex_byte "01"
 │     └─ RPAREN ")"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ (00 01 | 00 01 (02 | 03)) }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  └─ hex_alternative
 │     ├─ LPAREN "("
 │     ├─ hex_tokens
 │     │  ├─ hex_byte "00"
 │     │  └─ hex_byte "01"
 │     ├─ PIPE "|"
 │     ├─ hex_tokens
 │     │  ├─ hex_byte "00"
 │     │  ├─ hex_byte "01"
 │     │  └─ hex_alternative
 │     │     ├─ LPAREN "("
 │     │     ├─ hex_tokens
 │     │     │  └─ hex_byte "02"
 │     │     ├─ PIPE "|"
 │     │     ├─ hex_tokens
 │     │     │  └─ hex_byte "03"
 │     │     └─ RPAREN ")"
 │     └─ RPAREN ")"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ ?? ?0 0? }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  ├─ hex_byte "??"
 │  ├─ hex_byte "?0"
 │  └─ hex_byte "0?"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ ~00 ~?0 ~0? }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  ├─ hex_byte "~00"
 │  ├─ hex_byte "~?0"
 │  └─ hex_byte "~0?"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::hex_pattern,
            r#"{ 00 [1-2] [3-4] 01 }"#,
            r#"
 hex_pattern
 ├─ LBRACE "{"
 ├─ hex_tokens
 │  ├─ hex_byte "00"
 │  ├─ hex_jump
 │  │  ├─ LBRACKET "["
 │  │  ├─ integer_lit "1"
 │  │  ├─ HYPHEN "-"
 │  │  ├─ integer_lit "2"
 │  │  └─ RBRACKET "]"
 │  ├─ hex_jump
 │  │  ├─ LBRACKET "["
 │  │  ├─ integer_lit "3"
 │  │  ├─ HYPHEN "-"
 │  │  ├─ integer_lit "4"
 │  │  └─ RBRACKET "]"
 │  └─ hex_byte "01"
 └─ RBRACE "}"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#"true or not false and true"#,
            r#"
 boolean_expr
 ├─ boolean_term
 │  └─ k_TRUE "true"
 ├─ k_OR "or"
 ├─ boolean_term
 │  ├─ k_NOT "not"
 │  └─ boolean_term
 │     └─ k_FALSE "false"
 ├─ k_AND "and"
 └─ boolean_term
    └─ k_TRUE "true"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#"true or (false and true)"#,
            r#"
 boolean_expr
 ├─ boolean_term
 │  └─ k_TRUE "true"
 ├─ k_OR "or"
 └─ boolean_term
    ├─ LPAREN "("
    ├─ boolean_expr
    │  ├─ boolean_term
    │  │  └─ k_FALSE "false"
    │  ├─ k_AND "and"
    │  └─ boolean_term
    │     └─ k_TRUE "true"
    └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#"(true or false) and true"#,
            r#"
 boolean_expr
 ├─ boolean_term
 │  ├─ LPAREN "("
 │  ├─ boolean_expr
 │  │  ├─ boolean_term
 │  │  │  └─ k_TRUE "true"
 │  │  ├─ k_OR "or"
 │  │  └─ boolean_term
 │  │     └─ k_FALSE "false"
 │  └─ RPAREN ")"
 ├─ k_AND "and"
 └─ boolean_term
    └─ k_TRUE "true"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#"1 + 1"#,
            r#"
 boolean_expr
 └─ boolean_term
    └─ expr
       ├─ term
       │  └─ primary_expr
       │     └─ integer_lit "1"
       ├─ ADD "+"
       └─ term
          └─ primary_expr
             └─ integer_lit "1"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::expr,
            r#"~0x55 & 0xFF"#,
            r#"
 expr
 ├─ term
 │  └─ primary_expr
 │     ├─ BITWISE_NOT "~"
 │     └─ term
 │        └─ primary_expr
 │           └─ integer_lit "0x55"
 ├─ BITWISE_AND "&"
 └─ term
    └─ primary_expr
       └─ integer_lit "0xFF"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::expr,
            r#"foo.bar()"#,
            r#"
 expr
 └─ term
    └─ func_call_expr
       ├─ primary_expr
       │  ├─ ident "foo"
       │  ├─ DOT "."
       │  └─ ident "bar"
       ├─ LPAREN "("
       └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::expr,
            r#"baz.qux[3]"#,
            r#"
 expr
 └─ term
    └─ indexing_expr
       ├─ primary_expr
       │  ├─ ident "baz"
       │  ├─ DOT "."
       │  └─ ident "qux"
       ├─ LBRACKET "["
       ├─ expr
       │  └─ term
       │     └─ primary_expr
       │        └─ integer_lit "3"
       └─ RBRACKET "]"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::expr,
            r#"foo(1, "bar")"#,
            r#"
 expr
 └─ term
    └─ func_call_expr
       ├─ primary_expr
       │  └─ ident "foo"
       ├─ LPAREN "("
       ├─ boolean_expr
       │  └─ boolean_term
       │     └─ expr
       │        └─ term
       │           └─ primary_expr
       │              └─ integer_lit "1"
       ├─ COMMA ","
       ├─ boolean_expr
       │  └─ boolean_term
       │     └─ expr
       │        └─ term
       │           └─ primary_expr
       │              └─ string_lit ""bar""
       └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#"-1 -1 == -(1+1)"#,
            r#"
 boolean_expr
 └─ boolean_term
    ├─ expr
    │  ├─ term
    │  │  └─ primary_expr
    │  │     └─ integer_lit "-1"
    │  ├─ SUB "-"
    │  └─ term
    │     └─ primary_expr
    │        └─ integer_lit "1"
    ├─ EQ "=="
    └─ expr
       └─ term
          └─ primary_expr
             ├─ MINUS "-"
             └─ term
                └─ primary_expr
                   ├─ LPAREN "("
                   ├─ expr
                   │  ├─ term
                   │  │  └─ primary_expr
                   │  │     └─ integer_lit "1"
                   │  ├─ ADD "+"
                   │  └─ term
                   │     └─ primary_expr
                   │        └─ integer_lit "1"
                   └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#"2.5 * 2 * -1.0 == 5 + -(1)"#,
            r#"
 boolean_expr
 └─ boolean_term
    ├─ expr
    │  ├─ term
    │  │  └─ primary_expr
    │  │     └─ float_lit "2.5"
    │  ├─ MUL "*"
    │  ├─ term
    │  │  └─ primary_expr
    │  │     └─ integer_lit "2"
    │  ├─ MUL "*"
    │  └─ term
    │     └─ primary_expr
    │        └─ float_lit "-1.0"
    ├─ EQ "=="
    └─ expr
       ├─ term
       │  └─ primary_expr
       │     └─ integer_lit "5"
       ├─ ADD "+"
       └─ term
          └─ primary_expr
             ├─ MINUS "-"
             └─ term
                └─ primary_expr
                   ├─ LPAREN "("
                   ├─ expr
                   │  └─ term
                   │     └─ primary_expr
                   │        └─ integer_lit "1"
                   └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r"1 + 2 * 3.2 == 8 - 3 \ 3",
            r#"
 boolean_expr
 └─ boolean_term
    ├─ expr
    │  ├─ term
    │  │  └─ primary_expr
    │  │     └─ integer_lit "1"
    │  ├─ ADD "+"
    │  ├─ term
    │  │  └─ primary_expr
    │  │     └─ integer_lit "2"
    │  ├─ MUL "*"
    │  └─ term
    │     └─ primary_expr
    │        └─ float_lit "3.2"
    ├─ EQ "=="
    └─ expr
       ├─ term
       │  └─ primary_expr
       │     └─ integer_lit "8"
       ├─ SUB "-"
       ├─ term
       │  └─ primary_expr
       │     └─ integer_lit "3"
       ├─ DIV "\"
       └─ term
          └─ primary_expr
             └─ integer_lit "3"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r"(1 + 2) * 3 == (8) - (3 \ 3)",
            r#"
 boolean_expr
 └─ boolean_term
    ├─ expr
    │  ├─ term
    │  │  └─ primary_expr
    │  │     ├─ LPAREN "("
    │  │     ├─ expr
    │  │     │  ├─ term
    │  │     │  │  └─ primary_expr
    │  │     │  │     └─ integer_lit "1"
    │  │     │  ├─ ADD "+"
    │  │     │  └─ term
    │  │     │     └─ primary_expr
    │  │     │        └─ integer_lit "2"
    │  │     └─ RPAREN ")"
    │  ├─ MUL "*"
    │  └─ term
    │     └─ primary_expr
    │        └─ integer_lit "3"
    ├─ EQ "=="
    └─ expr
       ├─ term
       │  └─ primary_expr
       │     ├─ LPAREN "("
       │     ├─ expr
       │     │  └─ term
       │     │     └─ primary_expr
       │     │        └─ integer_lit "8"
       │     └─ RPAREN ")"
       ├─ SUB "-"
       └─ term
          └─ primary_expr
             ├─ LPAREN "("
             ├─ expr
             │  ├─ term
             │  │  └─ primary_expr
             │  │     └─ integer_lit "3"
             │  ├─ DIV "\"
             │  └─ term
             │     └─ primary_expr
             │        └─ integer_lit "3"
             └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#"$a at 0x200 + 0x200"#,
            r#"
 boolean_expr
 └─ boolean_term
    ├─ pattern_ident "$a"
    ├─ k_AT "at"
    └─ expr
       ├─ term
       │  └─ primary_expr
       │     └─ integer_lit "0x200"
       ├─ ADD "+"
       └─ term
          └─ primary_expr
             └─ integer_lit "0x200"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::boolean_expr,
            r#""foo" matches /foo/"#,
            r#"
 boolean_expr
 └─ boolean_term
    ├─ expr
    │  └─ term
    │     └─ primary_expr
    │        └─ string_lit ""foo""
    ├─ k_MATCHES "matches"
    └─ expr
       └─ term
          └─ primary_expr
             └─ regexp "/foo/"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::expr,
            r#"0x02 | 0o01 & 0x03"#,
            r#"
 expr
 ├─ term
 │  └─ primary_expr
 │     └─ integer_lit "0x02"
 ├─ BITWISE_OR "|"
 ├─ term
 │  └─ primary_expr
 │     └─ integer_lit "0o01"
 ├─ BITWISE_AND "&"
 └─ term
    └─ primary_expr
       └─ integer_lit "0x03"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::of_expr,
            r#"2 of ($a)"#,
            r#"
 of_expr
 ├─ quantifier
 │  └─ expr
 │     └─ term
 │        └─ primary_expr
 │           └─ integer_lit "2"
 ├─ k_OF "of"
 └─ pattern_ident_tuple
    ├─ LPAREN "("
    ├─ pattern_ident_wildcarded "$a"
    └─ RPAREN ")"
"#,
        ),
        //////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::of_expr,
            r#"none of ($a, $b)"#,
            r#"
 of_expr
 ├─ quantifier
 │  └─ k_NONE "none"
 ├─ k_OF "of"
 └─ pattern_ident_tuple
    ├─ LPAREN "("
    ├─ pattern_ident_wildcarded "$a"
    ├─ COMMA ","
    ├─ pattern_ident_wildcarded "$b"
    └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::of_expr,
            r#"all of ($a, false)"#,
            r#"
 of_expr
 ├─ quantifier
 │  └─ k_ALL "all"
 ├─ k_OF "of"
 └─ boolean_expr_tuple
    ├─ LPAREN "("
    ├─ boolean_expr
    │  └─ boolean_term
    │     └─ pattern_ident "$a"
    ├─ COMMA ","
    ├─ boolean_expr
    │  └─ boolean_term
    │     └─ k_FALSE "false"
    └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::of_expr,
            r#"any of them"#,
            r#"
 of_expr
 ├─ quantifier
 │  └─ k_ANY "any"
 ├─ k_OF "of"
 └─ k_THEM "them"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::of_expr,
            r#"any of ($a, $b) in (0..100)"#,
            r#"
 of_expr
 ├─ quantifier
 │  └─ k_ANY "any"
 ├─ k_OF "of"
 ├─ pattern_ident_tuple
 │  ├─ LPAREN "("
 │  ├─ pattern_ident_wildcarded "$a"
 │  ├─ COMMA ","
 │  ├─ pattern_ident_wildcarded "$b"
 │  └─ RPAREN ")"
 ├─ k_IN "in"
 └─ range
    ├─ LPAREN "("
    ├─ expr
    │  └─ term
    │     └─ primary_expr
    │        └─ integer_lit "0"
    ├─ DOT_DOT ".."
    ├─ expr
    │  └─ term
    │     └─ primary_expr
    │        └─ integer_lit "100"
    └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::for_expr,
            r#"for 3 x in iter : (true)"#,
            r#"
 for_expr
 ├─ k_FOR "for"
 ├─ quantifier
 │  └─ expr
 │     └─ term
 │        └─ primary_expr
 │           └─ integer_lit "3"
 ├─ ident "x"
 ├─ k_IN "in"
 ├─ iterable
 │  └─ expr
 │     └─ term
 │        └─ primary_expr
 │           └─ ident "iter"
 ├─ COLON ":"
 ├─ LPAREN "("
 ├─ boolean_expr
 │  └─ boolean_term
 │     └─ k_TRUE "true"
 └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::for_expr,
            r#"for all k,v in iter : (true)"#,
            r#"
 for_expr
 ├─ k_FOR "for"
 ├─ quantifier
 │  └─ k_ALL "all"
 ├─ ident "k"
 ├─ COMMA ","
 ├─ ident "v"
 ├─ k_IN "in"
 ├─ iterable
 │  └─ expr
 │     └─ term
 │        └─ primary_expr
 │           └─ ident "iter"
 ├─ COLON ":"
 ├─ LPAREN "("
 ├─ boolean_expr
 │  └─ boolean_term
 │     └─ k_TRUE "true"
 └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::for_expr,
            r#"for any i in (1,2,3) : (true)"#,
            r#"
 for_expr
 ├─ k_FOR "for"
 ├─ quantifier
 │  └─ k_ANY "any"
 ├─ ident "i"
 ├─ k_IN "in"
 ├─ iterable
 │  └─ expr_tuple
 │     ├─ LPAREN "("
 │     ├─ expr
 │     │  └─ term
 │     │     └─ primary_expr
 │     │        └─ integer_lit "1"
 │     ├─ COMMA ","
 │     ├─ expr
 │     │  └─ term
 │     │     └─ primary_expr
 │     │        └─ integer_lit "2"
 │     ├─ COMMA ","
 │     ├─ expr
 │     │  └─ term
 │     │     └─ primary_expr
 │     │        └─ integer_lit "3"
 │     └─ RPAREN ")"
 ├─ COLON ":"
 ├─ LPAREN "("
 ├─ boolean_expr
 │  └─ boolean_term
 │     └─ k_TRUE "true"
 └─ RPAREN ")"
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::term,
            r#"#a in (100..200)"#,
            r##"
 term
 └─ primary_expr
    ├─ pattern_count "#a"
    ├─ k_IN "in"
    └─ range
       ├─ LPAREN "("
       ├─ expr
       │  └─ term
       │     └─ primary_expr
       │        └─ integer_lit "100"
       ├─ DOT_DOT ".."
       ├─ expr
       │  └─ term
       │     └─ primary_expr
       │        └─ integer_lit "200"
       └─ RPAREN ")"
"##,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            GrammarRule::expr,
            r#"foo.bar[0].baz()"#,
            r#"
 expr
 ├─ term
 │  └─ indexing_expr
 │     ├─ primary_expr
 │     │  ├─ ident "foo"
 │     │  ├─ DOT "."
 │     │  └─ ident "bar"
 │     ├─ LBRACKET "["
 │     ├─ expr
 │     │  └─ term
 │     │     └─ primary_expr
 │     │        └─ integer_lit "0"
 │     └─ RBRACKET "]"
 ├─ DOT "."
 └─ term
    └─ func_call_expr
       ├─ primary_expr
       │  └─ ident "baz"
       ├─ LPAREN "("
       └─ RPAREN ")"
"#,
        ),
    ];

    for t in tests {
        let ascii_tree = match Parser::new().build_rule_cst(t.1, t.2) {
            Ok(mut cst) => cst.ascii_tree_string(),
            Err(err) => {
                panic!("error while parsing rule at line {}:\n{}\n", t.0, err)
            }
        };
        assert_eq!(t.3[1..], ascii_tree, "test at line {}", t.0);
    }
}
