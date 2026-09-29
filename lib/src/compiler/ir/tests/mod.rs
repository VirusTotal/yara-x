use std::mem::size_of;

use crate::compiler::{Expr, IR};
use crate::types::TypeValue;

#[test]
fn expr_size() {
    // Sentinel test for making sure the Expr doesn't grow in future
    // changes.
    #[cfg(target_pointer_width = "64")]
    assert_eq!(size_of::<Expr>(), 48);

    // Curiously enough, in 32-bits Windows the size is different from
    // 32-bits Linux.
    #[cfg(all(target_pointer_width = "32", target_family = "windows"))]
    assert_eq!(size_of::<Expr>(), 32);

    #[cfg(all(target_pointer_width = "32", target_family = "unix"))]
    assert_eq!(size_of::<Expr>(), 24);
}

#[test]
fn ancestors() {
    let mut ir = IR::new();

    let const_1 = ir.constant(TypeValue::const_integer_from(1));
    let const_2 = ir.constant(TypeValue::const_integer_from(2));
    let const_3 = ir.constant(TypeValue::const_integer_from(3));
    let add = ir.add(vec![const_2, const_3]).unwrap();
    let root = ir.add(vec![const_1, add]).unwrap();

    let mut ancestors = ir.ancestors(const_3);
    assert_eq!(ancestors.next(), Some(add));
    assert_eq!(ancestors.next(), Some(root));
    assert_eq!(ancestors.next(), None);

    let mut ancestors = ir.ancestors(const_1);
    assert_eq!(ancestors.next(), Some(root));
    assert_eq!(ancestors.next(), None);

    let mut ancestors = ir.ancestors(root);
    assert_eq!(ancestors.next(), None);
}

#[test]
fn children() {
    let mut ir = IR::new();

    let const_1 = ir.constant(TypeValue::const_integer_from(1));
    let const_2 = ir.constant(TypeValue::const_integer_from(2));
    let const_3 = ir.constant(TypeValue::const_integer_from(3));
    let add = ir.add(vec![const_2, const_3]).unwrap();
    let root = ir.add(vec![const_1, add]).unwrap();

    let mut children = ir.children(root);

    assert_eq!(children.next(), Some(const_1));
    assert_eq!(children.next(), Some(add));
    assert_eq!(children.next(), None);

    let mut children = ir.children(add);

    assert_eq!(children.next(), Some(const_2));
    assert_eq!(children.next(), Some(const_3));
    assert_eq!(children.next(), None);

    let mut children = ir.children(const_1);
    assert_eq!(children.next(), None);
}

// This test is run only in 64-bits systems because the IR tree shows the hash
// of each node, which will be either 32 or 64 bits long, depending on the
// system.
#[cfg(target_pointer_width = "64")]
#[test]
fn ir() {
    use std::fs;
    use std::io::BufWriter;

    use crate::Compiler;

    let files: Vec<_> = globwalk::glob("src/compiler/ir/tests/testdata/*.in")
        .unwrap()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    files.into_iter().for_each(|path| {
        println!("file: {path:?}");

        let mut mint = goldenfile::Mint::new(".");

        let output_path = if cfg!(feature = "constant-folding") {
            path.with_extension("ir")
        } else {
            path.with_extension("no-folding.ir")
        };

        let source = fs::read_to_string(path).unwrap();

        let output_file = mint.new_goldenfile(&output_path).unwrap();
        let mut compiler = Compiler::new();
        let w = BufWriter::new(output_file);

        compiler
            .hoisting(false)
            .set_ir_writer(w)
            .add_source(source.as_str())
            .unwrap();

        #[cfg(feature = "constant-folding")]
        {
            let cse_output = output_path.with_extension("cse.ir");
            let output_file = mint.new_goldenfile(&cse_output).unwrap();
            let mut compiler = Compiler::new();
            let w = BufWriter::new(output_file);

            compiler
                .hoisting(false)
                .set_ir_writer(w)
                .add_source(source.as_str())
                .unwrap();

            let hoisting_output = output_path.with_extension("hoisting.ir");
            let output_file = mint.new_goldenfile(&hoisting_output).unwrap();
            let mut compiler = Compiler::new();
            let w = BufWriter::new(output_file);

            compiler
                .hoisting(true)
                .set_ir_writer(w)
                .add_source(source.as_str())
                .unwrap();
        }
    });
}

#[test]
fn replace_child() {
    use super::{
        FieldAccess, ForIn, ForOf, ForVars, FuncCall, Iterable, Lookup,
        MatchAnchor, OfExprTuple, OfPatternSet, Quantifier, Range, With,
    };
    use crate::compiler::context::Var;
    use crate::compiler::{ExprId, PatternIdx, RegexSetId};
    use crate::types::{FuncSignature, MangledFnName, Type};

    let c1 = ExprId::from(1);
    let c2 = ExprId::from(2);
    let repl = ExprId::from(3);
    let dummy_var = Var::new(0, Type::Integer, 0);
    let make_for_vars = || ForVars {
        n: dummy_var,
        i: dummy_var,
        max_count: dummy_var,
        count: dummy_var,
        item: dummy_var,
    };

    // Expr::Const, Expr::Filesize, Expr::Symbol do nothing and do not panic
    let mut expr = Expr::Filesize;
    expr.replace_child(c1, repl);
    assert!(matches!(expr, Expr::Filesize));

    // Expr::Not, Expr::Minus, Expr::Defined, Expr::BitwiseNot
    let mut expr = Expr::Not { operand: c1 };
    expr.replace_child(c1, repl);
    assert!(matches!(expr, Expr::Not { operand } if operand == repl));

    let mut expr = Expr::Minus { operand: c1, is_float: false };
    expr.replace_child(c1, repl);
    assert!(matches!(expr, Expr::Minus { operand, .. } if operand == repl));

    let mut expr = Expr::Defined { operand: c1 };
    expr.replace_child(c1, repl);
    assert!(matches!(expr, Expr::Defined { operand } if operand == repl));

    let mut expr = Expr::BitwiseNot { operand: c1 };
    expr.replace_child(c1, repl);
    assert!(matches!(expr, Expr::BitwiseNot { operand } if operand == repl));

    // Expr::And, Expr::Or, Expr::Add, Expr::Sub, Expr::Mul, Expr::Div, Expr::Mod
    let mut expr = Expr::And { operands: vec![c1, c2] };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::And { operands } if operands == vec![repl, c2])
    );

    let mut expr = Expr::Or { operands: vec![c1, c2] };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::Or { operands } if operands == vec![repl, c2])
    );

    let mut expr = Expr::Add { operands: vec![c1, c2], is_float: false };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::Add { operands, .. } if operands == vec![repl, c2])
    );

    let mut expr = Expr::Sub { operands: vec![c1, c2], is_float: false };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::Sub { operands, .. } if operands == vec![repl, c2])
    );

    let mut expr = Expr::Mul { operands: vec![c1, c2], is_float: false };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::Mul { operands, .. } if operands == vec![repl, c2])
    );

    let mut expr = Expr::Div { operands: vec![c1, c2], is_float: false };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::Div { operands, .. } if operands == vec![repl, c2])
    );

    let mut expr = Expr::Mod { operands: vec![c1, c2] };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::Mod { operands, .. } if operands == vec![repl, c2])
    );

    // Binary Operators
    let mut expr = Expr::Eq { lhs: c1, rhs: c2 };
    expr.replace_child(c1, repl);
    assert!(matches!(expr, Expr::Eq { lhs, rhs } if lhs == repl && rhs == c2));

    let mut expr = Expr::Eq { lhs: c1, rhs: c2 };
    expr.replace_child(c2, repl);
    assert!(matches!(expr, Expr::Eq { lhs, rhs } if lhs == c1 && rhs == repl));

    // MatchesMany
    let mut expr =
        Expr::MatchesMany { lhs: c1, regex_set: RegexSetId::from(0) };
    expr.replace_child(c1, repl);
    assert!(matches!(expr, Expr::MatchesMany { lhs, .. } if lhs == repl));

    // PatternMatch (Anchor At/In)
    let mut expr = Expr::PatternMatch {
        pattern: PatternIdx::from(0),
        anchor: MatchAnchor::At(c1),
    };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::PatternMatch { anchor: MatchAnchor::At(expr), .. } if expr == repl)
    );

    let mut expr = Expr::PatternMatch {
        pattern: PatternIdx::from(0),
        anchor: MatchAnchor::In(Range { lower_bound: c1, upper_bound: c2 }),
    };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::PatternMatch { anchor: MatchAnchor::In(Range { lower_bound, upper_bound }), .. } if lower_bound == repl && upper_bound == c2)
    );

    let mut expr = Expr::PatternMatch {
        pattern: PatternIdx::from(0),
        anchor: MatchAnchor::In(Range { lower_bound: c1, upper_bound: c2 }),
    };
    expr.replace_child(c2, repl);
    assert!(
        matches!(expr, Expr::PatternMatch { anchor: MatchAnchor::In(Range { lower_bound, upper_bound }), .. } if lower_bound == c1 && upper_bound == repl)
    );

    // PatternCount
    let mut expr = Expr::PatternCount {
        pattern: PatternIdx::from(0),
        range: Some(Range { lower_bound: c1, upper_bound: c2 }),
    };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::PatternCount { range: Some(Range { lower_bound, upper_bound }), .. } if lower_bound == repl && upper_bound == c2)
    );

    let mut expr = Expr::PatternCount {
        pattern: PatternIdx::from(0),
        range: Some(Range { lower_bound: c1, upper_bound: c2 }),
    };
    expr.replace_child(c2, repl);
    assert!(
        matches!(expr, Expr::PatternCount { range: Some(Range { lower_bound, upper_bound }), .. } if lower_bound == c1 && upper_bound == repl)
    );

    // PatternOffset, PatternLength
    let mut expr =
        Expr::PatternOffset { pattern: PatternIdx::from(0), index: Some(c1) };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::PatternOffset { index: Some(idx), .. } if idx == repl)
    );

    let mut expr =
        Expr::PatternLength { pattern: PatternIdx::from(0), index: Some(c1) };
    expr.replace_child(c1, repl);
    assert!(
        matches!(expr, Expr::PatternLength { index: Some(idx), .. } if idx == repl)
    );

    // With
    let mut expr = Expr::With(Box::new(With {
        type_value: TypeValue::Unknown,
        declarations: vec![(dummy_var, c1)],
        body: c2,
    }));
    expr.replace_child(c1, repl);
    assert!(
        matches!(&expr, Expr::With(with) if with.declarations[0].1 == repl && with.body == c2)
    );

    let mut expr = Expr::With(Box::new(With {
        type_value: TypeValue::Unknown,
        declarations: vec![(dummy_var, c1)],
        body: c2,
    }));
    expr.replace_child(c2, repl);
    assert!(
        matches!(&expr, Expr::With(with) if with.declarations[0].1 == c1 && with.body == repl)
    );

    // FieldAccess
    let mut expr = Expr::FieldAccess(Box::new(FieldAccess {
        operands: vec![c1, c2],
        type_value: TypeValue::Unknown,
    }));
    expr.replace_child(c1, repl);
    assert!(
        matches!(&expr, Expr::FieldAccess(fa) if fa.operands == vec![repl, c2])
    );

    // FuncCall
    let mut expr = Expr::FuncCall(Box::new(FuncCall {
        object: Some(c1),
        args: vec![c2],
        signature: std::rc::Rc::new(FuncSignature {
            mangled_name: MangledFnName::from(""),
            args: vec![],
            result: TypeValue::Unknown,
            doc: None,
        }),
    }));
    expr.replace_child(c1, repl);
    assert!(
        matches!(&expr, Expr::FuncCall(fc) if fc.object == Some(repl) && fc.args == vec![c2])
    );

    let mut expr = Expr::FuncCall(Box::new(FuncCall {
        object: Some(c1),
        args: vec![c2],
        signature: std::rc::Rc::new(FuncSignature {
            mangled_name: MangledFnName::from(""),
            args: vec![],
            result: TypeValue::Unknown,
            doc: None,
        }),
    }));
    expr.replace_child(c2, repl);
    assert!(
        matches!(&expr, Expr::FuncCall(fc) if fc.object == Some(c1) && fc.args == vec![repl])
    );

    // OfExprTuple
    let mut expr = Expr::OfExprTuple(Box::new(OfExprTuple {
        quantifier: Quantifier::Percentage(c1),
        items: vec![c2],
        for_vars: make_for_vars(),
        anchor: MatchAnchor::At(c1),
    }));
    expr.replace_child(c1, repl);
    assert!(
        matches!(&expr, Expr::OfExprTuple(of) if matches!(of.anchor, MatchAnchor::At(a) if a == repl))
    );

    let mut expr = Expr::OfExprTuple(Box::new(OfExprTuple {
        quantifier: Quantifier::Percentage(c1),
        items: vec![c2],
        for_vars: make_for_vars(),
        anchor: MatchAnchor::At(c1),
    }));
    expr.replace_child(c2, repl);
    assert!(matches!(&expr, Expr::OfExprTuple(of) if of.items == vec![repl]));

    // OfPatternSet
    let mut expr = Expr::OfPatternSet(Box::new(OfPatternSet {
        quantifier: Quantifier::Percentage(c1),
        items: vec![],
        for_vars: make_for_vars(),
        anchor: MatchAnchor::At(c2),
    }));
    expr.replace_child(c2, repl);
    assert!(
        matches!(&expr, Expr::OfPatternSet(of) if matches!(of.anchor, MatchAnchor::At(a) if a == repl))
    );

    // ForOf
    let mut expr = Expr::ForOf(Box::new(ForOf {
        quantifier: Quantifier::Percentage(c1),
        for_vars: make_for_vars(),
        pattern_set: vec![],
        body: c2,
    }));
    expr.replace_child(c1, repl);
    assert!(
        matches!(&expr, Expr::ForOf(fo) if matches!(fo.quantifier, Quantifier::Percentage(q) if q == repl))
    );

    let mut expr = Expr::ForOf(Box::new(ForOf {
        quantifier: Quantifier::Percentage(c1),
        for_vars: make_for_vars(),
        pattern_set: vec![],
        body: c2,
    }));
    expr.replace_child(c2, repl);
    assert!(matches!(&expr, Expr::ForOf(fo) if fo.body == repl));

    // ForIn (iterable Range/ExprTuple/Expr)
    let mut expr = Expr::ForIn(Box::new(ForIn {
        quantifier: Quantifier::Percentage(c1),
        variables: vec![],
        for_vars: make_for_vars(),
        iterable: Iterable::Range(Range { lower_bound: c1, upper_bound: c2 }),
        body: c2,
    }));
    expr.replace_child(c1, repl);
    assert!(
        matches!(&expr, Expr::ForIn(fi) if matches!(fi.quantifier, Quantifier::Percentage(q) if q == repl))
    );

    let mut expr = Expr::ForIn(Box::new(ForIn {
        quantifier: Quantifier::Percentage(c1),
        variables: vec![],
        for_vars: make_for_vars(),
        iterable: Iterable::Range(Range { lower_bound: c1, upper_bound: c2 }),
        body: c2,
    }));
    expr.replace_child(c2, repl);
    assert!(matches!(&expr, Expr::ForIn(fi) if fi.body == repl));

    // Lookup
    let mut expr = Expr::Lookup(Box::new(Lookup {
        type_value: TypeValue::Unknown,
        primary: c1,
        index: c2,
    }));
    expr.replace_child(c1, repl);
    assert!(
        matches!(&expr, Expr::Lookup(l) if l.primary == repl && l.index == c2)
    );

    let mut expr = Expr::Lookup(Box::new(Lookup {
        type_value: TypeValue::Unknown,
        primary: c1,
        index: c2,
    }));
    expr.replace_child(c2, repl);
    assert!(
        matches!(&expr, Expr::Lookup(l) if l.primary == c1 && l.index == repl)
    );
}
