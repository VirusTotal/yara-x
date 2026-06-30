use pretty_assertions::assert_eq;

use crate::compiler::atoms::{Atom, MaskedAtom};

#[test]
fn mask_combinations() {
    let masked_atom = MaskedAtom::from_slice_range(
        &[0x11, 0x22, 0x33, 0x44],
        &[0xff, 0xf0, 0xff, 0xff],
        ..,
    )
    .unwrap();
    let mut c = masked_atom.mask_combinations();

    assert_eq!(c.len(), 16);

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

fn check_atoms<I, T>(pattern_src: &str, expected_atoms: I)
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
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
    let actual_atoms = rules.atoms();

    let mut expected_iter = expected_atoms.into_iter();
    for actual in actual_atoms {
        let expected =
            expected_iter.next().expect("actual has more atoms than expected");
        assert_eq!(actual.as_slice(), expected.as_ref());
    }

    assert!(
        expected_iter.next().is_none(),
        "expected has more atoms than actual"
    );
}

#[test]
fn atoms() {
    check_atoms("{ 11 ?? ?? 22 }", [&[0x11]]);
    check_atoms("{ 11 22 33 }", [&[0x11, 0x22, 0x33]]);
    check_atoms("{ 1? 22 }", (0x10..=0x1f).map(|b| [b, 0x22]));

    check_atoms("{ 1? 2? 3? 44 55 66 77 8? 9? }", [&[0x44, 0x55, 0x66, 0x77]]);

    check_atoms(
        "{ 11 22 33 44 [2-5] 55 66 77 88 }",
        [&[0x11, 0x22, 0x33, 0x44]],
    );

    check_atoms(
        "{ 11 22 33 [2-5] 44 55 66 77 88 }",
        [&[0x55, 0x66, 0x77, 0x88]],
    );

    check_atoms(
        "{ ( 11 22 33 44 | 55 66 77 88 ) }",
        [&[0x11, 0x22, 0x33, 0x44], &[0x55, 0x66, 0x77, 0x88]],
    );

    check_atoms(
        "{ ( 11 22 | 33 44 55 | 66 77 88 99 ) }",
        [
            &[0x11_u8, 0x22].as_slice(),
            &[0x33_u8, 0x44, 0x55].as_slice(),
            &[0x66_u8, 0x77, 0x88, 0x99].as_slice(),
        ],
    );

    check_atoms(
        "{ ( 1? | 2? ) 33 }",
        (0x10..=0x1f)
            .map(|b| [b, 0x33])
            .chain((0x20..=0x2f).map(|b| [b, 0x33])),
    );

    check_atoms(
        "{ 2? F? ?8 6? ?? 0? ?B ?B 3? ?? B? 2? ?7 5? }",
        itertools::iproduct!(
            0x20..=0x2f,
            0xf0..=0xff,
            (0x08..=0xf8).step_by(0x10)
        )
        .map(|(b1, b2, b3)| [b1, b2, b3]),
    );

    check_atoms(
        "{ 11 2? 33 4? 55 }",
        itertools::iproduct!(0x20..=0x2f, 0x40..=0x4f)
            .map(|(b2, b4)| [0x11, b2, 0x33, b4]),
    );

    check_atoms(
        "{ 1? 2? 3? 44 }",
        itertools::iproduct!(0x10..=0x1f, 0x20..=0x2f, 0x30..=0x3f)
            .map(|(b1, b2, b3)| [b1, b2, b3, 0x44]),
    );

    check_atoms(
        "{ 11 ?? 1? 11 }",
        itertools::iproduct!(0x00..=0xff, 0x10..=0x1f)
            .map(|(b2, b3)| [0x11, b2, b3, 0x11]),
    );
}

#[test]
fn masked_atom_trim() {
    // Normal trim: removes last byte
    let mut masked_atom = MaskedAtom::from_slice_range(
        &[0x11, 0x22, 0x33, 0x44],
        &[0xff, 0xff, 0xff, 0xff],
        ..,
    )
    .unwrap();
    masked_atom.trim();
    assert_eq!(masked_atom.atom.as_ref(), &[0x11, 0x22, 0x33]);
    assert_eq!(masked_atom.mask.as_slice(), &[0xff, 0xff, 0xff]);
    assert!(!masked_atom.atom.is_exact());

    // Trim with ?? at the end of resulting atom: removes last byte and ??
    let mut masked_atom = MaskedAtom::from_slice_range(
        &[0x11, 0x22, 0x33, 0x44],
        &[0xff, 0xff, 0x00, 0xff],
        ..,
    )
    .unwrap();
    masked_atom.trim();
    // After trimming 0x44, it becomes [0x11, 0x22, 0x33] with mask [0xff, 0xff, 0x00].
    // Since the last byte (0x33) has mask 0x00, it's also trimmed.
    assert_eq!(masked_atom.atom.as_ref(), &[0x11, 0x22]);
    assert_eq!(masked_atom.mask.as_slice(), &[0xff, 0xff]);
    assert!(!masked_atom.atom.is_exact());

    // Trim with multiple ?? at the end
    let mut masked_atom = MaskedAtom::from_slice_range(
        &[0x11, 0x22, 0x33, 0x44],
        &[0xff, 0x00, 0x00, 0xff],
        ..,
    )
    .unwrap();
    masked_atom.trim();
    // After trimming 0x44, the two 0x00s are also trimmed.
    assert_eq!(masked_atom.atom.as_ref(), &[0x11]);
    assert_eq!(masked_atom.mask.as_slice(), &[0xff]);

    // Trim to empty
    let mut masked_atom = MaskedAtom::from_slice_range(
        &[0x11, 0x22, 0x33],
        &[0x00, 0x00, 0xff],
        ..,
    )
    .unwrap();
    masked_atom.trim();
    // Trim 0x33, then both 0x00s are trimmed, resulting in empty.
    assert!(masked_atom.atom.as_ref().is_empty());
    assert!(masked_atom.mask.is_empty());

    // Trim on empty
    let mut masked_atom = MaskedAtom::from_slice_range(&[], &[], ..).unwrap();
    masked_atom.trim();
    assert!(masked_atom.atom.as_ref().is_empty());
    assert!(masked_atom.mask.is_empty());
}

#[test]
fn from_slice_range_limits() {
    let bytes = [0x11, 0x22, 0x33, 0x44];
    let mask = [0xff, 0xff, 0xff, 0xff];

    // Out of bounds range
    assert!(Atom::from_slice_range(&bytes, 2..10).is_none());
    assert!(MaskedAtom::from_slice_range(&bytes, &mask, 2..10).is_none());

    // Backtrack overflow (start offset > u16::MAX)
    let large_bytes = vec![0; 70000];
    let large_mask = vec![0; 70000];
    assert!(Atom::from_slice_range(&large_bytes, 65536..65538).is_none());
    assert!(
        MaskedAtom::from_slice_range(&large_bytes, &large_mask, 65536..65538)
            .is_none()
    );

    // Valid bounds and backtrack
    let atom = Atom::from_slice_range(&large_bytes, 65535..65537);
    assert!(atom.is_some());
    assert_eq!(atom.unwrap().backtrack(), 65535);
}
