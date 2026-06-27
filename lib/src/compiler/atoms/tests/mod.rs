use pretty_assertions::assert_eq;

use crate::compiler::atoms::Atom;

#[test]
fn mask_combinations() {
    let atom = Atom::exact([0x11, 0x22, 0x33, 0x44]);
    let mut c = atom.mask_combinations(&[0xff, 0xf0, 0xff, 0xff]);

    assert_eq!(c.next(), Some(Atom::exact([0x11, 0x20, 0x33, 0x44])));
    assert_eq!(c.next(), Some(Atom::exact([0x11, 0x21, 0x33, 0x44])));
    assert_eq!(c.next(), Some(Atom::exact([0x11, 0x22, 0x33, 0x44])));

    let mut c = c.skip(10);

    assert_eq!(c.next(), Some(Atom::exact([0x11, 0x2d, 0x33, 0x44])));
    assert_eq!(c.next(), Some(Atom::exact([0x11, 0x2e, 0x33, 0x44])));
    assert_eq!(c.next(), Some(Atom::exact([0x11, 0x2f, 0x33, 0x44])));
    assert_eq!(c.next(), None);
}

#[test]
fn case_combinations() {
    let atom = Atom::exact(b"a1B2c");
    let mut c = atom.case_combinations();

    assert_eq!(c.next(), Some(Atom::exact(b"a1b2c")));
    assert_eq!(c.next(), Some(Atom::exact(b"a1b2C")));
    assert_eq!(c.next(), Some(Atom::exact(b"a1B2c")));
    assert_eq!(c.next(), Some(Atom::exact(b"a1B2C")));
    assert_eq!(c.next(), Some(Atom::exact(b"A1b2c")));
    assert_eq!(c.next(), Some(Atom::exact(b"A1b2C")));
    assert_eq!(c.next(), Some(Atom::exact(b"A1B2c")));
    assert_eq!(c.next(), Some(Atom::exact(b"A1B2C")));
    assert_eq!(c.next(), None);

    let mut atom = Atom::exact([0x00_u8, 0x01, 0x02]);
    atom.set_backtrack(2);

    let mut c = atom.clone().case_combinations();

    assert_eq!(c.next(), Some(atom));
    assert_eq!(c.next(), None);
}

#[test]
fn xor_combinations() {
    let atom = Atom::exact([0x00_u8, 0x01, 0x02]);
    let mut c = atom.xor_combinations(0..=1);

    assert_eq!(c.next(), Some(Atom::inexact([0x00, 0x01, 0x02])));
    assert_eq!(c.next(), Some(Atom::inexact([0x01, 0x00, 0x03])));
    assert_eq!(c.next(), None);
}

#[test]
fn make_wide() {
    let mut atom = Atom::exact([0x01_u8, 0x02, 0x03]);
    atom.set_backtrack(2);

    let atom = atom.make_wide();

    assert_eq!(atom.bytes.as_slice(), &[0x01, 0x00, 0x02, 0x00, 0x03, 0x00]);

    assert_eq!(atom.backtrack, 4);
}

fn check_atoms(pattern_src: &str, expected_atoms: &[&[u8]]) {
    let rule_src = format!(
        r#"
        rule test {{
            strings:
                $a = {}
            condition:
                $a
        }}
        "#,
        pattern_src
    );
    let rules = crate::compiler::compile(rule_src.as_str()).unwrap();
    let mut actual_atoms: Vec<Vec<u8>> =
        rules.atoms().iter().map(|atom| atom.as_slice().to_vec()).collect();

    let mut expected: Vec<Vec<u8>> =
        expected_atoms.iter().map(|slice| slice.to_vec()).collect();

    actual_atoms.sort();
    expected.sort();

    if actual_atoms != expected {
        println!("ACTUAL ATOMS FOR {}: {:?}", pattern_src, actual_atoms);
    }

    assert_eq!(actual_atoms, expected);
}

#[test]
fn atoms() {
    let mut expected_case1 = Vec::new();
    for b1 in 0x20..=0x2f {
        for b2 in 0xf0..=0xff {
            expected_case1.push(vec![b1, b2]);
        }
    }
    let expected_case1_refs: Vec<&[u8]> =
        expected_case1.iter().map(|v| v.as_slice()).collect();

    check_atoms(
        "{ 2? F? ?8 6? ?? 0? ?B ?B 3? ?? B? 2? ?7 5? }",
        &expected_case1_refs,
    );

    check_atoms(
        "{ 1? 2? 3? 44 55 66 77 8? 9? }",
        &[&[0x44, 0x55, 0x66, 0x77]],
    );

    check_atoms(
        "{ 11 22 33 44 [2-5] 55 66 77 88 }",
        &[&[0x11, 0x22, 0x33, 0x44]],
    );

    check_atoms(
        "{ ( 11 22 33 44 | 55 66 77 88 ) }",
        &[&[0x11, 0x22, 0x33, 0x44], &[0x55, 0x66, 0x77, 0x88]],
    );

    check_atoms("{ 11 22 33 }", &[&[0x11, 0x22, 0x33]]);

    check_atoms(
        "{ 1? 22 }",
        &[
            &[0x10, 0x22],
            &[0x11, 0x22],
            &[0x12, 0x22],
            &[0x13, 0x22],
            &[0x14, 0x22],
            &[0x15, 0x22],
            &[0x16, 0x22],
            &[0x17, 0x22],
            &[0x18, 0x22],
            &[0x19, 0x22],
            &[0x1a, 0x22],
            &[0x1b, 0x22],
            &[0x1c, 0x22],
            &[0x1d, 0x22],
            &[0x1e, 0x22],
            &[0x1f, 0x22],
        ],
    );
}
