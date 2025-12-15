use crate::cst::{SyntaxKind, CST};
use crate::{Parser, Span};

#[test]
fn cst_1() {
    let cst: CST =
        Parser::new(b"rule test { condition: true }").try_into().unwrap();

    let source_file = cst.root();

    assert_eq!(source_file.kind(), SyntaxKind::SOURCE_FILE);

    // The root node has no parent.
    assert_eq!(source_file.parent(), None);

    // The root node has no siblings.
    assert_eq!(source_file.prev_sibling(), None);
    assert_eq!(source_file.next_sibling(), None);

    // The only child of the root node (which is a SOURCE_FILE),
    // is a RULE_DECL.
    let rule_decl = source_file.first_child();

    assert_eq!(source_file.last_child(), rule_decl);

    let mut children = source_file.children();
    assert_eq!(children.next(), rule_decl);
    assert_eq!(children.next(), None);

    let rule_decl = rule_decl.unwrap();

    // The parent of a RULE_DECL is the root node.
    assert_eq!(rule_decl.parent(), Some(source_file.clone()));

    // The only child of RULE_DECL is CONDITION_BLK.
    let condition_blk = rule_decl.first_child();
    assert_eq!(rule_decl.last_child(), condition_blk);

    let condition_blk = condition_blk.unwrap();
    assert_eq!(condition_blk.root(), source_file.clone());

    // Check the CONDITION_BLK's span.
    assert_eq!(condition_blk.span(), Span(12..27));

    // Make sure the ancestors of CONDITION_BLK are RULE_DECL
    // and SOURCE_FILE.
    let mut ancestors = condition_blk.ancestors();
    assert_eq!(ancestors.next(), Some(rule_decl.clone()));
    assert_eq!(ancestors.next(), Some(source_file.clone()));
    assert_eq!(ancestors.next(), None);

    let mut c = condition_blk.children_with_tokens();

    assert_eq!(c.next().map(|c| c.kind()), Some(SyntaxKind::CONDITION_KW));
    assert_eq!(c.next().map(|c| c.kind()), Some(SyntaxKind::COLON));
    assert_eq!(c.next().map(|c| c.kind()), Some(SyntaxKind::WHITESPACE));
    assert_eq!(c.next().map(|c| c.kind()), Some(SyntaxKind::BOOLEAN_EXPR));
    assert_eq!(c.next().map(|c| c.kind()), None);

    let mut t = condition_blk.first_token().unwrap();
    assert_eq!(t.kind(), SyntaxKind::CONDITION_KW);
    t = t.next_token().unwrap();
    assert_eq!(t.kind(), SyntaxKind::COLON);
    t = t.next_token().unwrap();
    assert_eq!(t.kind(), SyntaxKind::WHITESPACE);
    t = t.next_token().unwrap();
    assert_eq!(t.kind(), SyntaxKind::TRUE_KW);
    t = t.next_token().unwrap();
    assert_eq!(t.kind(), SyntaxKind::WHITESPACE);
    t = t.next_token().unwrap();
    assert_eq!(t.kind(), SyntaxKind::R_BRACE);
    assert_eq!(t.next_token(), None);

    // The ancestors for the R_BRACE token are RULE_DECL and
    // SOURCE_FILE.
    let mut ancestors = t.ancestors();
    assert_eq!(ancestors.next(), Some(rule_decl.clone()));
    assert_eq!(ancestors.next(), Some(source_file.clone()));
    assert_eq!(ancestors.next(), None);
}

#[test]
fn cst_2() {
    let cst: CST =
        Parser::new(b"rule test { condition: true }").try_into().unwrap();

    let mut c = cst.root().first_child().unwrap().children_with_tokens();

    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::RULE_KW));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::WHITESPACE));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::IDENT));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::WHITESPACE));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::L_BRACE));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::WHITESPACE));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::CONDITION_BLK));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::WHITESPACE));
    assert_eq!(c.next().map(|n| n.kind()), Some(SyntaxKind::R_BRACE));
    assert_eq!(c.next().map(|n| n.kind()), None);

    let c = cst.root().first_child().unwrap().first_child_or_token().unwrap();

    assert_eq!(c.parent().map(|n| n.kind()), Some(SyntaxKind::RULE_DECL));

    let mut a = c.ancestors();

    assert_eq!(a.next().map(|n| n.kind()), Some(SyntaxKind::RULE_DECL));
    assert_eq!(a.next().map(|n| n.kind()), Some(SyntaxKind::SOURCE_FILE));
    assert_eq!(a.next().map(|n| n.kind()), None);

    assert_eq!(
        c.next_sibling_or_token().map(|n| n.kind()),
        Some(SyntaxKind::WHITESPACE)
    );

    let c = cst.root().first_child().unwrap().last_child_or_token().unwrap();

    assert_eq!(
        c.prev_sibling_or_token().map(|n| n.kind()),
        Some(SyntaxKind::WHITESPACE)
    );
}

#[test]
fn cst_3() {
    let cst: CST =
        Parser::new(b"rule test { condition: true }").try_into().unwrap();

    let condition_blk =
        cst.root().first_child().unwrap().first_child().unwrap();

    let text = condition_blk.text();

    assert!(!text.is_empty());
    assert_eq!(text.len(), 15);

    let chunks = text
        .try_fold_chunks::<_, _, anyhow::Error>(Vec::new(), |mut acc, s| {
            acc.push(s.to_string());
            Ok(acc)
        })
        .unwrap();

    assert_eq!(chunks, ["condition", ":", " ", "true"]);

    let mut chunks = Vec::new();

    text.for_each_chunks(|s| {
        chunks.push(s.to_string());
    });

    assert_eq!(chunks, ["condition", ":", " ", "true"]);

    let result = text.try_for_each_chunks(|s| {
        if s == ":" {
            anyhow::bail!("colon found")
        } else {
            Ok(())
        }
    });

    assert!(result.is_err());
}

#[test]
fn cst_4() {
    let cst: CST =
        Parser::new(b"rule test { condition: true }").try_into().unwrap();

    let source_file = cst.root().into_mut();

    // Detach the first token, which is the `rule` keyword.
    source_file.first_token().unwrap().detach();

    // After detaching the `rule` keyword, the first token is the
    // whitespace that comes after the keyword.
    assert_eq!(
        source_file.first_token().map(|x| x.kind()),
        Some(SyntaxKind::WHITESPACE)
    );

    // Detach the last token, which is the closing }.
    source_file.last_token().unwrap().detach();

    // After detaching the closing }, the first token is the
    // whitespace that comes before.
    assert_eq!(
        source_file.last_token().map(|x| x.kind()),
        Some(SyntaxKind::WHITESPACE)
    );

    // Detach the first child of token of SOURCE_CODE, this node has a single
    // child that is the RULE_DECL node.
    source_file.first_child_or_token().unwrap().detach();

    // After detaching the RULE_DECL node, SOURCE_CODE is empty.
    assert_eq!(source_file.last_token().map(|x| x.kind()), None);
}

#[test]
fn cst_5() {
    let cst: CST = Parser::new(
        r#"rule test {
    /*
       Comment
    */
    condition:
        true or
        /* 😊 */ false
    }"#
        .as_bytes(),
    )
    .try_into()
    .unwrap();

    let mut c = cst.root().first_child().unwrap().children_with_tokens();

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::RULE_KW);
    assert_eq!(n.position(), (0, 0).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::WHITESPACE);
    assert_eq!(n.position(), (0, 4).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::IDENT);
    assert_eq!(n.position(), (0, 5).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::WHITESPACE);
    assert_eq!(n.position(), (0, 9).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::L_BRACE);
    assert_eq!(n.position(), (0, 10).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::NEWLINE);
    assert_eq!(n.position(), (0, 11).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::WHITESPACE);
    assert_eq!(n.position(), (1, 0).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::COMMENT);
    assert_eq!(n.position(), (1, 4).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::NEWLINE);
    assert_eq!(n.position(), (3, 6).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::WHITESPACE);
    assert_eq!(n.position(), (4, 0).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::CONDITION_BLK);
    assert_eq!(n.position(), (4, 4).into());

    let n1 = n.first_child_or_token().unwrap();
    assert_eq!(n1.kind(), SyntaxKind::CONDITION_KW);
    assert_eq!(n1.position(), (4, 4).into());

    let n1 = n1.next_sibling_or_token().unwrap();
    assert_eq!(n1.kind(), SyntaxKind::COLON);
    assert_eq!(n1.position(), (4, 13).into());

    let n1 = n1.next_sibling_or_token().unwrap();
    assert_eq!(n1.kind(), SyntaxKind::NEWLINE);
    assert_eq!(n1.position(), (4, 14).into());

    let n1 = n1.next_sibling_or_token().unwrap();
    assert_eq!(n1.kind(), SyntaxKind::WHITESPACE);
    assert_eq!(n1.position(), (5, 0).into());

    let n1 = n1.next_sibling_or_token().unwrap();
    assert_eq!(n1.kind(), SyntaxKind::BOOLEAN_EXPR);
    assert_eq!(n1.position(), (5, 8).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::NEWLINE);
    assert_eq!(n.position(), (6, 21).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::WHITESPACE);
    assert_eq!(n.position(), (7, 0).into());

    let n = c.next().unwrap();
    assert_eq!(n.kind(), SyntaxKind::R_BRACE);
    assert_eq!(n.position(), (7, 4).into());
}

#[test]
fn cst_6() {
    let cst: CST = Parser::new(
        r#"rule test {
    /*
       Comment
    */
    condition:
        true or
        /* 😊 */ false
    }"#
        .as_bytes(),
    )
    .try_into()
    .unwrap();

    let root_node = cst.root();

    // Token at line 0, column 0 is `SyntaxKind::RULE_KW`.
    assert_eq!(
        root_node.token_at_position((0, 0)).unwrap().kind(),
        SyntaxKind::RULE_KW
    );

    // Token at line 0, column 4 is `SyntaxKind::WHITESPACE`.
    assert_eq!(
        root_node.token_at_position((0, 4)).unwrap().kind(),
        SyntaxKind::WHITESPACE
    );

    // Token at line 0, column 11 is `SyntaxKind::NEWLINE`.
    assert_eq!(
        root_node.token_at_position((0, 11)).unwrap().kind(),
        SyntaxKind::NEWLINE
    );

    // There's no token at line 0, column 12.
    assert!(root_node.token_at_position((0, 12)).is_none());

    // Token at line 1, column 4 is `SyntaxKind::COMMENT`.
    assert_eq!(
        root_node.token_at_position((1, 4)).unwrap().kind(),
        SyntaxKind::COMMENT
    );

    // Token at line 2, column 8 is `SyntaxKind::COMMENT`.
    assert_eq!(
        root_node.token_at_position((2, 8)).unwrap().kind(),
        SyntaxKind::COMMENT
    );

    // Token at line 2, column 20 is `SyntaxKind::COMMENT`.
    assert_eq!(
        root_node.token_at_position((2, 20)).unwrap().kind(),
        SyntaxKind::COMMENT
    );

    // Token at line 3, column 5 is `SyntaxKind::COMMENT`.
    assert_eq!(
        root_node.token_at_position((3, 5)).unwrap().kind(),
        SyntaxKind::COMMENT
    );

    // Token at line 3, column 6 is `SyntaxKind::NEWLINE`.
    assert_eq!(
        root_node.token_at_position((3, 6)).unwrap().kind(),
        SyntaxKind::NEWLINE
    );

    // Token at line 4, column 4 is `SyntaxKind::CONDITION_KW`.
    assert_eq!(
        root_node.token_at_position((4, 4)).unwrap().kind(),
        SyntaxKind::CONDITION_KW
    );

    // There's no token at line 4, column 15.
    assert!(root_node.token_at_position((4, 15)).is_none());

    // Token at line 6, column 16 is `SyntaxKind::FALSE_KW`.
    assert_eq!(
        root_node.token_at_position((6, 16)).unwrap().kind(),
        SyntaxKind::FALSE_KW
    );
}
