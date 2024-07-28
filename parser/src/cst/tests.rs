use crate::cst::SyntaxKind;
use crate::{Parser, Span};

#[test]
fn cst_1() {
    let cst = Parser::new(b"rule test { condition: true }").into_cst();

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
    let cst = Parser::new(b"rule test { condition: true }").into_cst();

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
    let cst = Parser::new(b"rule test { condition: true }").into_cst();

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

    let result = text.try_for_each_chunks(|s| {
        if s == ":" {
            anyhow::bail!("colon found")
        } else {
            Ok(())
        }
    });

    assert!(result.is_err())
}
