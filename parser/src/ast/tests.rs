use crate::ast::{Item, AST};
use crate::cst::CST;
use crate::Parser;

#[test]
fn ast_from_cst() {
    let source = br#"rule test { condition: true }"#;
    let parser = Parser::new(source);
    let cst = CST::try_from(parser).unwrap();
    let ast = AST::new(source, cst.iter());

    let rule = match ast.items.get(0).unwrap() {
        Item::Rule(rule) => rule,
        _ => panic!(),
    };

    assert_eq!(rule.identifier.name, "test");
}
