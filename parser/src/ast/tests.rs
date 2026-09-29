use crate::ast::{AST, Item};
use crate::cst::CST;
use crate::{Parser, Span, ast};

#[test]
fn ast_from_cst() {
    let source = br#"
    global private rule test {
        meta:
            author = "test"
            version = 3.14
        strings:
            $a = "abc" ascii wide fullword
            $b = "cde" base64
            $c = { 01 02 [1-2] ?? }
            $d = /reg.*exp/i nocase
        condition:
            all of them and
            any of ($a*) and
            filesize > 100 and
            (1 << 2) + (8 >> 1) >= 4 and
            1 == 1 and
            2 != 3 and
            4 < 5 and
            6 <= 6 and
            7 > 2 and
            "foo" contains "f" and
            "bar" icontains "B" and
            "baz" startswith "b"
            and "qux" istartswith "Q" and
            "end" endswith "d" and
            "IEND" iendswith "D" and
            "eq" iequals "EQ" and
            "str" matches /str/ and
            not false and none of ($b*) and
            (1 & 2) | (3 ^ 4) != ~0 and
            5 % 2 == 1 and
            2 * 3 == 6 and
            1 - 1 == 0
    }
    "#;

    let parser = Parser::new(source);
    let cst = CST::try_from(parser).unwrap();
    let ast = AST::new(source, cst.iter());

    let rule = match ast.items.first().unwrap() {
        Item::Rule(rule) => rule,
        _ => panic!(),
    };

    assert!(ast.errors.is_empty());
    assert_eq!(rule.identifier.name, "test");

    let source = br#"foo"#;
    let parser = Parser::new(source);
    let cst = CST::try_from(parser).unwrap();
    let mut ast = AST::new(source, cst.iter());

    assert_eq!(
        ast.errors.pop().unwrap(),
        ast::Error::SyntaxError {
            message: String::from(
                "expecting import statement or rule definition"
            ),
            span: Span(0..3)
        }
    );
}

#[test]
fn ast_dfs() {
    use crate::ast::dfs::{DFSEvent, DFSIter};
    use crate::ast::*;

    let source = br#"
    rule test {
        strings:
            $a = "foo"
        condition:
            $a and foo.bar[0].baz == 1 and not (-(-1) == 1)
    }
    "#;
    let parser = Parser::new(source);
    let cst = CST::try_from(parser).unwrap();
    let ast = AST::new(source, cst.iter());

    let rule = match ast.items.first().unwrap() {
        Item::Rule(rule) => rule,
        _ => panic!(),
    };

    let iter = DFSIter::new(&rule.condition);
    let mut enter_count = 0;
    let mut leave_count = 0;

    for event in iter {
        match event {
            DFSEvent::Enter(_) => enter_count += 1,
            DFSEvent::Leave(_) => leave_count += 1,
        }
    }

    assert!(enter_count > 0);
    assert_eq!(enter_count, leave_count);
}
