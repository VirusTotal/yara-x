use itertools::Itertools;
use pretty_assertions::assert_eq;

use crate::compiler::Atom;
use crate::re;
use crate::re::bitmapset::BitmapSet;
use crate::re::{BckCodeLoc, FwdCodeLoc};
use crate::types::Regexp;

use super::compiler::{CodeLoc, Compiler, RegexpAtom};
use super::pikevm::{epsilon_closure, EpsilonClosureState};

macro_rules! assert_re_code {
    ($re:expr, $fwd:expr, $bck:expr, $atoms:expr, $fwd_closure:expr, $bck_closure:expr) => {{
        let parser = re::parser::Parser::new();

        let (fwd_code, bck_code, atoms) = Compiler::new()
            .compile_internal(
                &parser.parse(&Regexp::new(format!("/{}/s", $re))).unwrap(),
            )
            .unwrap();

        assert_eq!($fwd, fwd_code.to_string());
        assert_eq!($bck, bck_code.to_string());
        assert_eq!($atoms, atoms);

        let mut fwd_closure = BitmapSet::<u32>::new();
        let mut cache = EpsilonClosureState::new();

        epsilon_closure(
            fwd_code.as_ref(),
            FwdCodeLoc::try_from(0_usize).unwrap(),
            0,
            None,
            None,
            &mut cache,
            &mut fwd_closure,
        );

        assert_eq!(
            $fwd_closure,
            fwd_closure.iter().map(|(ip, _)| *ip).collect::<Vec<_>>()
        );

        let mut bck_closure = BitmapSet::<u32>::new();
        epsilon_closure(
            bck_code.as_ref(),
            BckCodeLoc::try_from(0_usize).unwrap(),
            0,
            None,
            None,
            &mut cache,
            &mut bck_closure,
        );

        assert_eq!(
            $bck_closure,
            bck_closure.iter().map(|(ip, _)| *ip).collect::<Vec<_>>()
        );
    }};
}

macro_rules! assert_re_atoms_impl {
    ($re:expr) => {{
        let parser = re::parser::Parser::new();
        let (_, _, atoms) = Compiler::new()
            .compile_internal(
                &parser.parse(&Regexp::new(format!("/{}/s", $re))).unwrap(),
            )
            .unwrap();

        atoms
    }};
}

macro_rules! assert_re_atoms {
    ($re:expr, $atoms:expr) => {{
        let atoms = assert_re_atoms_impl!($re);
        let atoms: Vec<Atom> =
            atoms.into_iter().map(|re_atom| re_atom.atom).collect();
        assert_eq!($atoms, atoms);
    }};
}

macro_rules! assert_re_num_atoms {
    ($re:expr, $num_atoms:expr) => {{
        let atoms = assert_re_atoms_impl!($re);
        assert_eq!($num_atoms, atoms.len());
    }};
}

#[test]
fn re_code_1() {
    assert_re_code!(
        "(?s)abcd",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: LIT 0x64
00004: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x64
00001: LIT 0x63
00002: LIT 0x62
00003: LIT 0x61
00004: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::exact(vec![0x61, 0x62, 0x63, 0x64]),
            code_loc: CodeLoc { fwd: 0x00, bck: 0x04, bck_seq_id: 0 }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_2() {
    assert_re_code!(
        "(?s)abcde",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: LIT 0x64
00004: LIT 0x65
00005: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x65
00001: LIT 0x64
00002: LIT 0x63
00003: LIT 0x62
00004: LIT 0x61
00005: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
            code_loc: CodeLoc { fwd: 0x00, bck: 0x05, bck_seq_id: 0 }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_3() {
    assert_re_code!(
        "(?s)abc.",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: ANY_BYTE
00005: MATCH
"#,
        // Backward code
        r#"
00000: ANY_BYTE
00002: LIT 0x63
00003: LIT 0x62
00004: LIT 0x61
00005: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x62, 0x63]),
            code_loc: CodeLoc { fwd: 0x00, bck: 0x05, bck_seq_id: 0 }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_4() {
    assert_re_code!(
        r"(?s)a\xAAcde123",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0xaa
00003: LIT 0x63
00004: LIT 0x64
00005: LIT 0x65
00006: LIT 0x31
00007: LIT 0x32
00008: LIT 0x33
00009: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x33
00001: LIT 0x32
00002: LIT 0x31
00003: LIT 0x65
00004: LIT 0x64
00005: LIT 0x63
00006: LIT 0xaa
00008: LIT 0x61
00009: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x65, 0x31, 0x32, 0x33]),
            code_loc: CodeLoc { fwd: 0x05, bck: 0x04, bck_seq_id: 0 }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_5() {
    assert_re_code!(
        "(?s)ab|cd|ef",
        // Forward code
        r#"
00000: SPLIT_N(0) 00011 00019 00021
00011: LIT 0x61
00012: LIT 0x62
00013: JUMP 00023
00019: LIT 0x63
0001a: LIT 0x64
0001b: JUMP 00023
00021: LIT 0x65
00022: LIT 0x66
00023: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_N(0) 00011 00019 00021
00011: LIT 0x62
00012: LIT 0x61
00013: JUMP 00023
00019: LIT 0x64
0001a: LIT 0x63
0001b: JUMP 00023
00021: LIT 0x66
00022: LIT 0x65
00023: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x61, 0x62]),
                code_loc: CodeLoc { fwd: 0x00, bck: 0x23, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0x00, bck: 0x23, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x65, 0x66]),
                code_loc: CodeLoc { fwd: 0x00, bck: 0x23, bck_seq_id: 0 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x11, 0x19, 0x21],
        // Epsilon closure starting at backward code 0.
        vec![0x11, 0x19, 0x21]
    );
}

#[test]
fn re_code_6() {
    assert_re_code!(
        "(?s)1(ab|cd|ef)",
        // Forward code
        r#"
00000: LIT 0x31
00001: SPLIT_N(0) 00012 0001a 00022
00012: LIT 0x61
00013: LIT 0x62
00014: JUMP 00024
0001a: LIT 0x63
0001b: LIT 0x64
0001c: JUMP 00024
00022: LIT 0x65
00023: LIT 0x66
00024: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_N(0) 00011 00019 00021
00011: LIT 0x62
00012: LIT 0x61
00013: JUMP 00023
00019: LIT 0x64
0001a: LIT 0x63
0001b: JUMP 00023
00021: LIT 0x66
00022: LIT 0x65
00023: LIT 0x31
00024: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x31, 0x61, 0x62]),
                code_loc: CodeLoc { fwd: 0, bck: 0x24, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x31, 0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0, bck: 0x24, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x31, 0x65, 0x66]),
                code_loc: CodeLoc { fwd: 0, bck: 0x24, bck_seq_id: 0 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x11, 0x19, 0x21]
    );
}

#[test]
fn re_code_7() {
    assert_re_code!(
        "(?s)a(bcd.+e)*fg",
        // Forward code
        r#"
00000: LIT 0x61
00001: SPLIT_A(0) 0001d
00009: LIT 0x62
0000a: LIT 0x63
0000b: LIT 0x64
0000c: ANY_BYTE
0000e: SPLIT_B(1) 0000c
00016: LIT 0x65
00017: JUMP 00001
0001d: LIT 0x66
0001e: LIT 0x67
0001f: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x67
00001: LIT 0x66
00002: SPLIT_A(0) 0001e
0000a: LIT 0x65
0000b: ANY_BYTE
0000d: SPLIT_B(1) 0000b
00015: LIT 0x64
00016: LIT 0x63
00017: LIT 0x62
00018: JUMP 00002
0001e: LIT 0x61
0001f: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![97, 98, 99, 100]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x1f },
            },
            RegexpAtom {
                atom: Atom::exact(vec![97, 102, 103]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x1f },
            },
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_8() {
    assert_re_code!(
        "(?s)a(bcd.+?de)*?fg",
        // Forward code
        r#"
00000: LIT 0x61
00001: SPLIT_B(0) 0001e
00009: LIT 0x62
0000a: LIT 0x63
0000b: LIT 0x64
0000c: ANY_BYTE
0000e: SPLIT_A(1) 0000c
00016: LIT 0x64
00017: LIT 0x65
00018: JUMP 00001
0001e: LIT 0x66
0001f: LIT 0x67
00020: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x67
00001: LIT 0x66
00002: SPLIT_B(0) 0001f
0000a: LIT 0x65
0000b: LIT 0x64
0000c: ANY_BYTE
0000e: SPLIT_A(1) 0000c
00016: LIT 0x64
00017: LIT 0x63
00018: LIT 0x62
00019: JUMP 00002
0001f: LIT 0x61
00020: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x61, 0x66, 0x67]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x20 },
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x20 },
            },
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_9() {
    assert_re_code!(
        "(?s)abc[0-2x-y]def",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: CLASS_RANGES [0x30-0x32] [0x78-0x79]
0000a: LIT 0x64
0000b: LIT 0x65
0000c: LIT 0x66
0000d: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x66
00001: LIT 0x65
00002: LIT 0x64
00003: CLASS_RANGES [0x30-0x32] [0x78-0x79]
0000a: LIT 0x63
0000b: LIT 0x62
0000c: LIT 0x61
0000d: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x30]),
                code_loc: CodeLoc { bck: 0x0d, fwd: 0, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x31]),
                code_loc: CodeLoc { bck: 0x0d, fwd: 0, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x32]),
                code_loc: CodeLoc { bck: 0x0d, fwd: 0, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x78]),
                code_loc: CodeLoc { bck: 0x0d, fwd: 0, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x79]),
                code_loc: CodeLoc { bck: 0x0d, fwd: 0, bck_seq_id: 0 }
            },
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_10() {
    assert_re_code!(
        "(?s)abcd[acegikmoqsuwy024]ef",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: LIT 0x64
00004: CLASS_BITMAP 0x30 0x32 0x34 0x61 0x63 0x65 0x67 0x69 0x6b 0x6d 0x6f 0x71 0x73 0x75 0x77 0x79
00026: LIT 0x65
00027: LIT 0x66
00028: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x66
00001: LIT 0x65
00002: CLASS_BITMAP 0x30 0x32 0x34 0x61 0x63 0x65 0x67 0x69 0x6b 0x6d 0x6f 0x71 0x73 0x75 0x77 0x79
00024: LIT 0x64
00025: LIT 0x63
00026: LIT 0x62
00027: LIT 0x61
00028: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
            code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x28 },
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_11() {
    assert_re_code!(
        "(?s)(abc){2,}",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: SPLIT_B(0) 00000
0000b: LIT 0x61
0000c: LIT 0x62
0000d: LIT 0x63
0000e: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x63
00001: LIT 0x62
00002: LIT 0x61
00003: SPLIT_B(0) 00000
0000b: LIT 0x63
0000c: LIT 0x62
0000d: LIT 0x61
0000e: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x61]),
            code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x0e }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_12() {
    assert_re_code!(
        "(?s)(abc123){3,}",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: LIT 0x31
00004: LIT 0x32
00005: LIT 0x33
00006: LIT 0x61
00007: LIT 0x62
00008: LIT 0x63
00009: LIT 0x31
0000a: LIT 0x32
0000b: LIT 0x33
0000c: SPLIT_B(0) 00006
00014: LIT 0x61
00015: LIT 0x62
00016: LIT 0x63
00017: LIT 0x31
00018: LIT 0x32
00019: LIT 0x33
0001a: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x33
00001: LIT 0x32
00002: LIT 0x31
00003: LIT 0x63
00004: LIT 0x62
00005: LIT 0x61
00006: LIT 0x33
00007: LIT 0x32
00008: LIT 0x31
00009: LIT 0x63
0000a: LIT 0x62
0000b: LIT 0x61
0000c: SPLIT_B(0) 00006
00014: LIT 0x33
00015: LIT 0x32
00016: LIT 0x31
00017: LIT 0x63
00018: LIT 0x62
00019: LIT 0x61
0001a: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x63, 0x31, 0x32, 0x33]),
            code_loc: CodeLoc { fwd: 2, bck_seq_id: 0, bck: 0x18 }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_13() {
    assert_re_code!(
        "(?s)(abcdef|ghijkl){2,}",
        // Forward code
        r#"
00000: SPLIT_N(0) 0000d 00019
0000d: LIT 0x61
0000e: LIT 0x62
0000f: LIT 0x63
00010: LIT 0x64
00011: LIT 0x65
00012: LIT 0x66
00013: JUMP 0001f
00019: LIT 0x67
0001a: LIT 0x68
0001b: LIT 0x69
0001c: LIT 0x6a
0001d: LIT 0x6b
0001e: LIT 0x6c
0001f: SPLIT_B(1) 00000
00027: SPLIT_N(2) 00034 00040
00034: LIT 0x61
00035: LIT 0x62
00036: LIT 0x63
00037: LIT 0x64
00038: LIT 0x65
00039: LIT 0x66
0003a: JUMP 00046
00040: LIT 0x67
00041: LIT 0x68
00042: LIT 0x69
00043: LIT 0x6a
00044: LIT 0x6b
00045: LIT 0x6c
00046: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_N(0) 0000d 00019
0000d: LIT 0x66
0000e: LIT 0x65
0000f: LIT 0x64
00010: LIT 0x63
00011: LIT 0x62
00012: LIT 0x61
00013: JUMP 0001f
00019: LIT 0x6c
0001a: LIT 0x6b
0001b: LIT 0x6a
0001c: LIT 0x69
0001d: LIT 0x68
0001e: LIT 0x67
0001f: SPLIT_B(1) 00000
00027: SPLIT_N(2) 00034 00040
00034: LIT 0x66
00035: LIT 0x65
00036: LIT 0x64
00037: LIT 0x63
00038: LIT 0x62
00039: LIT 0x61
0003a: JUMP 00046
00040: LIT 0x6c
00041: LIT 0x6b
00042: LIT 0x6a
00043: LIT 0x69
00044: LIT 0x68
00045: LIT 0x67
00046: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0x0d, bck_seq_id: 0, bck: 0x3a }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x67, 0x68, 0x69, 0x6a]),
                code_loc: CodeLoc { fwd: 0x19, bck_seq_id: 0, bck: 0x46 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x0d, 0x19],
        // Epsilon closure starting at backward code 0.
        vec![0x0d, 0x19]
    );
}

#[test]
fn re_code_14() {
    assert_re_code!(
        "(?s)(abc){0,2}",
        // Forward code
        r#"
00000: SPLIT_A(0) 00016
00008: LIT 0x61
00009: LIT 0x62
0000a: LIT 0x63
0000b: SPLIT_A(1) 00016
00013: LIT 0x61
00014: LIT 0x62
00015: LIT 0x63
00016: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_A(0) 00016
00008: LIT 0x63
00009: LIT 0x62
0000a: LIT 0x61
0000b: SPLIT_A(1) 00016
00013: LIT 0x63
00014: LIT 0x62
00015: LIT 0x61
00016: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![]),
            code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x00 }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x08, 0x16],
        // Epsilon closure starting at backward code 0.
        vec![0x08, 0x16]
    );
}

#[test]
fn re_code_15() {
    assert_re_code!(
        "(?s)(a+|b)*",
        // Forward code
        r#"
00000: SPLIT_A(0) 0002b
00008: SPLIT_N(1) 00015 00024
00015: LIT 0x61
00016: SPLIT_B(2) 00015
0001e: JUMP 00025
00024: LIT 0x62
00025: JUMP 00000
0002b: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_A(0) 0002b
00008: SPLIT_N(1) 00015 00024
00015: LIT 0x61
00016: SPLIT_B(2) 00015
0001e: JUMP 00025
00024: LIT 0x62
00025: JUMP 00000
0002b: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![]),
            code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x00 }
        }],
        // Epsilon closure starting at forward code 0.
        vec![0x15, 0x24, 0x2b],
        // Epsilon closure starting at backward code 0.
        vec![0x15, 0x24, 0x2b]
    );
}

#[test]
fn re_code_16() {
    assert_re_code!(
        "(?s)(|abc)de",
        // Forward code
        r#"
00000: SPLIT_N(0) 0000d 00013
0000d: JUMP 00016
00013: LIT 0x61
00014: LIT 0x62
00015: LIT 0x63
00016: LIT 0x64
00017: LIT 0x65
00018: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x65
00001: LIT 0x64
00002: SPLIT_N(0) 0000f 00015
0000f: JUMP 00018
00015: LIT 0x63
00016: LIT 0x62
00017: LIT 0x61
00018: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x64, 0x65]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x18 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x18 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x16, 0x13],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_17() {
    assert_re_code!(
        "(?s)(|abc){3,}",
        // Forward code
        r#"
00000: SPLIT_N(0) 0000d 00013
0000d: JUMP 00016
00013: LIT 0x61
00014: LIT 0x62
00015: LIT 0x63
00016: SPLIT_N(1) 00023 00029
00023: JUMP 0002c
00029: LIT 0x61
0002a: LIT 0x62
0002b: LIT 0x63
0002c: SPLIT_B(2) 00016
00034: SPLIT_N(3) 00041 00047
00041: JUMP 0004a
00047: LIT 0x61
00048: LIT 0x62
00049: LIT 0x63
0004a: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_N(0) 0000d 00013
0000d: JUMP 00016
00013: LIT 0x63
00014: LIT 0x62
00015: LIT 0x61
00016: SPLIT_N(1) 00023 00029
00023: JUMP 0002c
00029: LIT 0x63
0002a: LIT 0x62
0002b: LIT 0x61
0002c: SPLIT_B(2) 00016
00034: SPLIT_N(3) 00041 00047
00041: JUMP 0004a
00047: LIT 0x63
00048: LIT 0x62
00049: LIT 0x61
0004a: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x4A },
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x4A },
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x61]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x4A },
            },
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x4a, 0x47, 0x29, 0x13],
        // Epsilon closure starting at backward code 0.
        vec![0x4a, 0x47, 0x29, 0x13]
    );
}

#[test]
fn re_code_18() {
    assert_re_code!(
        "(?s).b{2}",
        // Forward code
        r#"
00000: ANY_BYTE
00002: LIT 0x62
00003: LIT 0x62
00004: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x62
00001: LIT 0x62
00002: ANY_BYTE
00004: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x62, 0x62]),
            code_loc: CodeLoc { fwd: 0x02, bck_seq_id: 0, bck: 0x02 }
        },],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_19() {
    assert_re_code!(
        "(?s)a.(bc.){2}",
        // Forward code
        r#"
00000: LIT 0x61
00001: ANY_BYTE
00003: LIT 0x62
00004: LIT 0x63
00005: ANY_BYTE
00007: LIT 0x62
00008: LIT 0x63
00009: ANY_BYTE
0000b: MATCH
"#,
        // Backward code
        r#"
00000: ANY_BYTE
00002: LIT 0x63
00003: LIT 0x62
00004: ANY_BYTE
00006: LIT 0x63
00007: LIT 0x62
00008: ANY_BYTE
0000a: LIT 0x61
0000b: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x62, 0x63]),
            code_loc: CodeLoc { fwd: 0x03, bck_seq_id: 0, bck: 0x08 }
        },],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_20() {
    assert_re_code!(
        "(?is)a12",
        // Forward code
        r#"
00000: MASKED_BYTE 0x41 0xdf
00004: LIT 0x31
00005: LIT 0x32
00006: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x32
00001: LIT 0x31
00002: MASKED_BYTE 0x41 0xdf
00006: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x41, 0x31, 0x32]),
                code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x06 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x61, 0x31, 0x32]),
                code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x06 }
            },
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_21() {
    assert_re_code!(
        r#"(?is)[a-z]{1,2}ab"#,
        // Forward code
        r#"
00000: CLASS_RANGES [0x41-0x5a] [0x61-0x7a]
00007: SPLIT_A(0) 00016
0000f: CLASS_RANGES [0x41-0x5a] [0x61-0x7a]
00016: MASKED_BYTE 0x41 0xdf
0001a: MASKED_BYTE 0x42 0xdf
0001e: MATCH
"#,
        // Backward code
        r#"
00000: MASKED_BYTE 0x42 0xdf
00004: MASKED_BYTE 0x41 0xdf
00008: CLASS_RANGES [0x41-0x5a] [0x61-0x7a]
0000f: SPLIT_A(0) 0001e
00017: CLASS_RANGES [0x41-0x5a] [0x61-0x7a]
0001e: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![0x41, 0x42]),
                code_loc: CodeLoc { fwd: 0x16, bck_seq_id: 0, bck: 0x08 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x41, 0x62]),
                code_loc: CodeLoc { fwd: 0x16, bck_seq_id: 0, bck: 0x08 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x42]),
                code_loc: CodeLoc { fwd: 0x16, bck_seq_id: 0, bck: 0x08 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62]),
                code_loc: CodeLoc { fwd: 0x16, bck_seq_id: 0, bck: 0x08 }
            },
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_22() {
    assert_re_code!(
        r#"(0?F1?|2?f3?)abcd"#,
        // Forward code
        r#"
00000: SPLIT_N(0) 0000d 00026
0000d: SPLIT_A(1) 00016
00015: LIT 0x30
00016: LIT 0x46
00017: SPLIT_A(2) 00020
0001f: LIT 0x31
00020: JUMP 00039
00026: SPLIT_A(3) 0002f
0002e: LIT 0x32
0002f: LIT 0x66
00030: SPLIT_A(4) 00039
00038: LIT 0x33
00039: LIT 0x61
0003a: LIT 0x62
0003b: LIT 0x63
0003c: LIT 0x64
0003d: MATCH
"#, // Backward code
        r#"
00000: LIT 0x64
00001: LIT 0x63
00002: LIT 0x62
00003: LIT 0x61
00004: SPLIT_N(0) 00011 0002a
00011: SPLIT_A(2) 0001a
00019: LIT 0x31
0001a: LIT 0x46
0001b: SPLIT_A(1) 00024
00023: LIT 0x30
00024: JUMP 0003d
0002a: SPLIT_A(4) 00033
00032: LIT 0x33
00033: LIT 0x66
00034: SPLIT_A(3) 0003d
0003c: LIT 0x32
0003d: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
            code_loc: CodeLoc { fwd: 0x39, bck_seq_id: 0, bck: 0x04 }
        },],
        // Epsilon closure starting at forward code 0.
        vec![0x15, 0x16, 0x2e, 0x2f],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_23() {
    assert_re_code!(
        r#"(abc+d+){200}"#,
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: SPLIT_B(0) 00002
0000b: LIT 0x64
0000c: SPLIT_B(1) 0000b
00014: LIT 0x61
00015: LIT 0x62
00016: LIT 0x63
00017: SPLIT_B(2) 00016
0001f: LIT 0x64
00020: SPLIT_B(3) 0001f
00028: REPEAT_GREEDY 00014 199-199
00036: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x64
00001: SPLIT_B(2) 00000
00009: LIT 0x63
0000a: SPLIT_B(3) 00009
00012: LIT 0x62
00013: LIT 0x61
00014: REPEAT_GREEDY 00000 199-199
00022: LIT 0x64
00023: SPLIT_B(1) 00022
0002b: LIT 0x63
0002c: SPLIT_B(0) 0002b
00034: LIT 0x62
00035: LIT 0x61
00036: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x62, 0x63]),
            code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x36 }
        },],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_code_24() {
    assert_re_code!(
        r#"(a{2,3}?b){1,13}?"#,
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x61
00002: SPLIT_B(0) 0000b
0000a: LIT 0x61
0000b: LIT 0x62
0000c: SPLIT_B(1) 0002e
00014: LIT 0x61
00015: LIT 0x61
00016: SPLIT_B(2) 0001f
0001e: LIT 0x61
0001f: LIT 0x62
00020: REPEAT_NON_GREEDY 00014 0-12
0002e: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_B(1) 00022
00008: LIT 0x62
00009: LIT 0x61
0000a: LIT 0x61
0000b: SPLIT_B(2) 00014
00013: LIT 0x61
00014: REPEAT_NON_GREEDY 00008 0-12
00022: LIT 0x62
00023: LIT 0x61
00024: LIT 0x61
00025: SPLIT_B(0) 0002e
0002d: LIT 0x61
0002e: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x61]),
            code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x2e }
        },],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x22, 0x08]
    );
}

#[rustfmt::skip]
#[test]
fn re_atoms() {
    assert_re_atoms!(
        r#"abcd"#,
        vec![Atom::exact(b"abcd")]
    );

    assert_re_atoms!(
        r#"abcd1234"#,
        vec![Atom::inexact(b"1234")]
    );

    assert_re_atoms!(
        r#".abc"#,
        vec![Atom::inexact(b"abc")]
    );

    assert_re_atoms!(
        r#"abc."#,
        vec![Atom::inexact(b"abc")]
    );

    assert_re_atoms!(
        r#"a.bcd"#,
        vec![Atom::inexact(b"bcd")]
    );

    assert_re_atoms!(
        r#"abc.d"#,
        vec![Atom::inexact(b"abc")]
    );

    assert_re_atoms!(
        r#"ab.*cd"#,
        vec![
            Atom::inexact(b"ab"),
            Atom::exact("abcd"),
        ]
    );

    assert_re_atoms!(
        r#"ab{0,2}cd"#,
        vec![Atom::inexact(b"cd")]
    );

    assert_re_atoms!(
        r#"ab.*cde"#,
        vec![Atom::inexact(b"cde")]
    );

    assert_re_atoms!(
        r#"ab?c"#,
        vec![
            Atom::exact(b"abc"),
            Atom::exact(b"ac"),
        ]
    );

    assert_re_atoms!(
        r#"ab??c"#,
        vec![
            Atom::exact(b"ac"),
            Atom::exact(b"abc"),
        ]
    );

    assert_re_atoms!(
        r#"ab+"#,
        vec![Atom::inexact(b"ab")]
    );

    assert_re_atoms!(
        r#"a.."#,
        vec![Atom::inexact(b"a")]
    );

    assert_re_atoms!(
        r#"ab.."#,
        vec![Atom::inexact(b"ab")]
    );

    assert_re_atoms!(
        r#"(ab|cd)"#,
        vec![
            Atom::exact(b"ab"),
            Atom::exact(b"cd")
        ]
    );

    assert_re_atoms!(
        r#"ab|cd"#,
        vec![
            Atom::exact(b"ab"),
            Atom::exact(b"cd")
        ]);

    assert_re_atoms!(
        r#"a(b|c)d"#,
        vec![
            Atom::exact(b"abd"),
            Atom::exact(b"acd")
        ]
    );

    assert_re_atoms!(
        r#"ab(c|d|e|g).."#,
        vec![
            Atom::inexact(b"abc"),
            Atom::inexact(b"abd"),
            Atom::inexact(b"abe"),
            Atom::inexact(b"abg"),
        ]
    );

    assert_re_atoms!(
        r#"a[bc]d.e"#,
        vec![
            Atom::inexact(b"abd"),
            Atom::inexact(b"acd")
        ]
    );

    assert_re_atoms!(
        r#"a(bcd.*)*e"#,
        vec![
            Atom::inexact(b"abcd"),
            Atom::exact(b"ae"),
        ]
    );

    assert_re_atoms!(
        r#"a(bcd.*)*?e"#,
        vec![
            Atom::exact(b"ae"),
            Atom::inexact(b"abcd"),
        ]
    );

    assert_re_atoms!(
        r#"a(b.*)*c"#,
        vec![
            Atom::inexact(b"ab"),
            Atom::exact(b"ac"),
        ]
    );

    assert_re_atoms!(
        "\x00\x00\x00\x00.{2,3}abc",
        vec![Atom::inexact(b"abc")]
    );

    assert_re_atoms!(
        r#"(?i)ab"#,
        vec![
            Atom::exact(b"AB"),
            Atom::exact(b"Ab"),
            Atom::exact(b"aB"),
            Atom::exact(b"ab")
        ]
    );

    assert_re_atoms!(
        r#"(?i)abc.*123"#,
        vec![Atom::inexact(b"123")]
    );

    assert_re_atoms!(
        r#"(?i)a.bcd"#,
        vec![
            Atom::inexact(b"BCD"),
            Atom::inexact(b"BCd"),
            Atom::inexact(b"BcD"),
            Atom::inexact(b"Bcd"),
            Atom::inexact(b"bCD"),
            Atom::inexact(b"bCd"),
            Atom::inexact(b"bcD"),
            Atom::inexact(b"bcd"),
        ]
    );

    assert_re_atoms!(
        "(?s)a.\x00\x00\x00[A-Za-z0-9]{128,256}",
        [b'a'..=b'a', 0x00..=0xff, 0x00..=0x00, 0x00..=0x00]
            .into_iter()
            .multi_cartesian_product()
            .map(Atom::inexact)
            .collect::<Vec<Atom>>()
    );

    assert_re_atoms!(
        r#"(?s)a.b.c.d"#,
        [b'a'..=b'a', 0x00..=0xff, b'b'..=b'b',]
            .into_iter()
            .multi_cartesian_product()
            .map(Atom::inexact)
            .collect::<Vec<Atom>>()
    );

    assert_re_atoms!(r#"(?s)ab.?cd"#, {
        let mut v = [b'a'..=b'a', b'b'..=b'b', 0x00..=0xff, b'c'..=b'c']
            .into_iter()
            .multi_cartesian_product()
            .map(Atom::inexact)
            .collect::<Vec<Atom>>();
        v.push(Atom::exact(b"abcd"));
        v
    });

    assert_re_atoms!(r#"(?s)ab.??cd"#, {
        let mut v = vec![Atom::exact(b"abcd")];
        v.append(&mut [b'a'..=b'a', b'b'..=b'b', 0x00..=0xff, b'c'..=b'c']
            .into_iter()
            .multi_cartesian_product()
            .map(Atom::inexact)
            .collect::<Vec<Atom>>());
        v
    });

    assert_re_atoms!(
        r#"(?s)abc.d(((xy|xz)w.)|[a-c])(((xy|xz)w.)|[a-c])"#,
        vec![Atom::inexact(b"abc")]
    );

    assert_re_num_atoms!(
        r#"(?s)a(b.b|c.c|d.d|e.e|f.f|g.g|h.h|i.i|j.j|k.k|l.l|m.m|n.n|o.o|p.p|q.q|r.r)"#,
        4352
    );

    assert_re_num_atoms!(
        r#""\([0-9]([(-\\][0-9]){2,}[0-3]?([1-2][0-9]){2,}"#,
        530
    );

    assert_re_num_atoms!(
        r#"xy[0-9][a-e]{4,}([1-2][0-9]){4,}"#,
        50
    );
}
