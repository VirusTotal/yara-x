use pretty_assertions::assert_eq;
use std::mem;

use super::Token;
use crate::Span;

#[test]
fn keywords() {
    let mut lexer = super::Tokenizer::new("global rule".as_bytes());

    mem::discriminant(&Token::L_BRACE(Span(0..0)));

    assert_eq!(lexer.next_token(), Some(Token::GLOBAL_KW(Span(0..6))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(6..7))));
    assert_eq!(lexer.next_token(), Some(Token::RULE_KW(Span(7..11))));
    assert_eq!(lexer.next_token(), None);

    let mut lexer = super::Tokenizer::new("globalrule".as_bytes());

    assert_eq!(lexer.next_token(), Some(Token::IDENT(Span(0..10))));
    assert_eq!(lexer.next_token(), None);
}

#[test]
fn identifiers() {
    let mut lexer = super::Tokenizer::new("foo _bar baz0 qux_1".as_bytes());

    assert_eq!(lexer.next_token(), Some(Token::IDENT(Span(0..3))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(3..4))));
    assert_eq!(lexer.next_token(), Some(Token::IDENT(Span(4..8))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(8..9))));
    assert_eq!(lexer.next_token(), Some(Token::IDENT(Span(9..13))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(13..14))));
    assert_eq!(lexer.next_token(), Some(Token::IDENT(Span(14..19))));
    assert_eq!(lexer.next_token(), None);
}

#[test]
fn integer_literals() {
    let mut lexer = super::Tokenizer::new(r#"1 10 999"#.as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(0..1))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(1..2))));
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(2..4))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(4..5))));
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(5..8))));
    assert_eq!(lexer.next_token(), None);

    let mut lexer = super::Tokenizer::new(r#"0x10 0xAB 0xfc"#.as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(0..4))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(4..5))));
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(5..9))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(9..10))));
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(10..14))));
    assert_eq!(lexer.next_token(), None);

    let mut lexer = super::Tokenizer::new(r#"0o10 0o07 0x77"#.as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(0..4))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(4..5))));
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(5..9))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(9..10))));
    assert_eq!(lexer.next_token(), Some(Token::INTEGER_LIT(Span(10..14))));
    assert_eq!(lexer.next_token(), None);
}

#[test]
fn string_literals() {
    let mut lexer = super::Tokenizer::new(r#""foo \"bar\" baz""#.as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::STRING_LIT(Span(0..17))));
    assert_eq!(lexer.next_token(), None);

    let mut lexer = super::Tokenizer::new(r#""foo /*bar*/ baz""#.as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::STRING_LIT(Span(0..17))));
    assert_eq!(lexer.next_token(), None);

    let mut lexer = super::Tokenizer::new(r#""foo \\"""#.as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::STRING_LIT(Span(0..9))));
    assert_eq!(lexer.next_token(), None);

    let mut lexer = super::Tokenizer::new(r#""标识符""#.as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::STRING_LIT(Span(0..11))));
    assert_eq!(lexer.next_token(), None);
}

#[test]
fn errors() {
    let mut lexer = super::Tokenizer::new("标识符 标识符".as_bytes());
    assert_eq!(lexer.next_token(), Some(Token::UNKNOWN(Span(0..9))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(9..10))));
    assert_eq!(lexer.next_token(), Some(Token::UNKNOWN(Span(10..19))));

    let mut lexer = super::Tokenizer::new(b"\xC7\xA3\xFF\xFF");
    assert_eq!(lexer.next_token(), Some(Token::UNKNOWN(Span(0..2))));
    assert_eq!(lexer.next_token(), Some(Token::INVALID_UTF8(Span(2..3))));
    assert_eq!(lexer.next_token(), Some(Token::INVALID_UTF8(Span(3..4))));

    let mut lexer = super::Tokenizer::new(b"\xFF\xFF");
    assert_eq!(lexer.next_token(), Some(Token::INVALID_UTF8(Span(0..1))));

    let mut lexer = super::Tokenizer::new(b"foo \xFF\xFF");
    assert_eq!(lexer.next_token(), Some(Token::IDENT(Span(0..3))));
    assert_eq!(lexer.next_token(), Some(Token::WHITESPACE(Span(3..4))));
    assert_eq!(lexer.next_token(), Some(Token::INVALID_UTF8(Span(4..5))));
}
