use crate::ast::{AST, Item};
use crate::cst::CST;
use crate::{Parser, Span, ast};

#[test]
fn ast_from_cst() {
    let source = br#"rule test { condition: true }"#;
    let parser = Parser::new(source);
    let cst = CST::try_from(parser).unwrap();
    let ast = AST::new(source, cst.iter());

    let rule = match ast.items.first().unwrap() {
        Item::Rule(rule) => rule,
        _ => panic!(),
    };

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
