use crate::ast::{Item, AST};
use crate::cst::CST;
use crate::{ast, Parser, Span};

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
