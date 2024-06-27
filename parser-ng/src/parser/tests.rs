use crate::parser::cst::Event;
use crate::parser::cst::CST;
use crate::Parser;

#[test]
fn parser() {
    let cst: Vec<Event> = Parser::new(b"rule{{}").collect();

    println!("{:#?}", cst);
}

#[test]
fn parser2() {
    let cst = CST::from(Parser::new(
        r#"
        ff
private global rule foo {
    meta:
        foo = true
}
"#
        .as_bytes(),
    ));

    println!("{:#?}", cst);
}
