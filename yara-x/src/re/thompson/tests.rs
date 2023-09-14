use indexmap::{indexset, IndexSet};
use itertools::Itertools;
use pretty_assertions::assert_eq;

use yara_x_parser::ast;

use crate::compiler::Atom;
use crate::re;
use crate::re::{BckCodeLoc, FwdCodeLoc};

use super::compiler::{CodeLoc, Compiler, RegexpAtom};
use super::pikevm::{epsilon_closure, EpsilonClosureState, ThreadSet};

macro_rules! assert_re_code {
    ($re:expr, $fwd:expr, $bck:expr, $atoms:expr, $fwd_closure:expr, $bck_closure:expr) => {{
        let parser = re::parser::Parser::new();

        let (fwd_code, bck_code, atoms) = Compiler::new()
            .compile_internal(
                &parser
                    .parse(&ast::Regexp {
                        literal: format!("/{}/", $re).as_str(),
                        src: $re,
                        case_insensitive: false,
                        dot_matches_new_line: true,
                        span: ast::Span::default(),
                    })
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(fwd_code.to_string(), $fwd);
        assert_eq!(bck_code.to_string(), $bck);
        assert_eq!(atoms, $atoms);

        let mut fwd_closure = ThreadSet::new();
        let mut cache = EpsilonClosureState::new();

        epsilon_closure(
            fwd_code.as_ref(),
            FwdCodeLoc::try_from(0_usize).unwrap(),
            None,
            None,
            &mut cache,
            &mut fwd_closure,
        );
        assert_eq!(fwd_closure.into_vec(), $fwd_closure);

        let mut bck_closure = ThreadSet::new();
        epsilon_closure(
            bck_code.as_ref(),
            BckCodeLoc::try_from(0_usize).unwrap(),
            None,
            None,
            &mut cache,
            &mut bck_closure,
        );
        assert_eq!(bck_closure.into_vec(), $bck_closure);
    }};
}

macro_rules! assert_re_atoms {
    ($re:expr, $atoms:expr) => {{
        let parser = re::parser::Parser::new();

        let (_, _, atoms) = Compiler::new()
            .compile_internal(
                &parser
                    .parse(&ast::Regexp {
                        literal: format!("/{}/", $re).as_str(),
                        src: $re,
                        case_insensitive: false,
                        dot_matches_new_line: true,
                        span: ast::Span::default(),
                    })
                    .unwrap(),
            )
            .unwrap();

        let atoms: Vec<Atom> =
            atoms.into_iter().map(|re_atom| re_atom.atom).collect();

        assert_eq!(atoms, $atoms);
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
00000: SPLIT_N(0) 00010 00018 00020
00010: LIT 0x61
00011: LIT 0x62
00012: JUMP 00022
00018: LIT 0x63
00019: LIT 0x64
0001a: JUMP 00022
00020: LIT 0x65
00021: LIT 0x66
00022: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_N(0) 00010 00018 00020
00010: LIT 0x62
00011: LIT 0x61
00012: JUMP 00022
00018: LIT 0x64
00019: LIT 0x63
0001a: JUMP 00022
00020: LIT 0x66
00021: LIT 0x65
00022: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x61, 0x62]),
                code_loc: CodeLoc { fwd: 0x00, bck: 0x22, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0x00, bck: 0x22, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x65, 0x66]),
                code_loc: CodeLoc { fwd: 0x00, bck: 0x22, bck_seq_id: 0 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x10, 0x18, 0x20],
        // Epsilon closure starting at backward code 0.
        vec![0x10, 0x18, 0x20]
    );
}

#[test]
fn re_code_6() {
    assert_re_code!(
        "(?s)1(ab|cd|ef)",
        // Forward code
        r#"
00000: LIT 0x31
00001: SPLIT_N(0) 00011 00019 00021
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
00000: SPLIT_N(0) 00010 00018 00020
00010: LIT 0x62
00011: LIT 0x61
00012: JUMP 00022
00018: LIT 0x64
00019: LIT 0x63
0001a: JUMP 00022
00020: LIT 0x66
00021: LIT 0x65
00022: LIT 0x31
00023: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x31, 0x61, 0x62]),
                code_loc: CodeLoc { fwd: 0, bck: 0x23, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x31, 0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0, bck: 0x23, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![0x31, 0x65, 0x66]),
                code_loc: CodeLoc { fwd: 0, bck: 0x23, bck_seq_id: 0 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x10, 0x18, 0x20]
    );
}

#[test]
fn re_code_7() {
    assert_re_code!(
        "(?s)a(bcd.+e)*fg",
        // Forward code
        r#"
00000: LIT 0x61
00001: SPLIT_A(0) 0001b
00008: LIT 0x62
00009: LIT 0x63
0000a: LIT 0x64
0000b: ANY_BYTE
0000d: SPLIT_B(1) 0000b
00014: LIT 0x65
00015: JUMP 00001
0001b: LIT 0x66
0001c: LIT 0x67
0001d: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x67
00001: LIT 0x66
00002: SPLIT_A(0) 0001c
00009: LIT 0x65
0000a: ANY_BYTE
0000c: SPLIT_B(1) 0000a
00013: LIT 0x64
00014: LIT 0x63
00015: LIT 0x62
00016: JUMP 00002
0001c: LIT 0x61
0001d: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![97, 98, 99, 100]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x1d },
            },
            RegexpAtom {
                atom: Atom::exact(vec![97, 102, 103]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x1d },
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
00001: SPLIT_B(0) 0001c
00008: LIT 0x62
00009: LIT 0x63
0000a: LIT 0x64
0000b: ANY_BYTE
0000d: SPLIT_A(1) 0000b
00014: LIT 0x64
00015: LIT 0x65
00016: JUMP 00001
0001c: LIT 0x66
0001d: LIT 0x67
0001e: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x67
00001: LIT 0x66
00002: SPLIT_B(0) 0001d
00009: LIT 0x65
0000a: LIT 0x64
0000b: ANY_BYTE
0000d: SPLIT_A(1) 0000b
00014: LIT 0x64
00015: LIT 0x63
00016: LIT 0x62
00017: JUMP 00002
0001d: LIT 0x61
0001e: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::exact(vec![0x61, 0x66, 0x67]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x1e },
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x1e },
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
0000a: LIT 0x61
0000b: LIT 0x62
0000c: LIT 0x63
0000d: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x63
00001: LIT 0x62
00002: LIT 0x61
00003: SPLIT_B(0) 00000
0000a: LIT 0x63
0000b: LIT 0x62
0000c: LIT 0x61
0000d: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x61]),
            code_loc: CodeLoc { fwd: 0, bck_seq_id: 0, bck: 0x0d }
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
00013: LIT 0x61
00014: LIT 0x62
00015: LIT 0x63
00016: LIT 0x31
00017: LIT 0x32
00018: LIT 0x33
00019: MATCH
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
00013: LIT 0x33
00014: LIT 0x32
00015: LIT 0x31
00016: LIT 0x63
00017: LIT 0x62
00018: LIT 0x61
00019: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x63, 0x31, 0x32, 0x33]),
            code_loc: CodeLoc { fwd: 2, bck_seq_id: 0, bck: 0x17 }
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
00000: SPLIT_N(0) 0000c 00018
0000c: LIT 0x61
0000d: LIT 0x62
0000e: LIT 0x63
0000f: LIT 0x64
00010: LIT 0x65
00011: LIT 0x66
00012: JUMP 0001e
00018: LIT 0x67
00019: LIT 0x68
0001a: LIT 0x69
0001b: LIT 0x6a
0001c: LIT 0x6b
0001d: LIT 0x6c
0001e: SPLIT_B(1) 00000
00025: SPLIT_N(2) 00031 0003d
00031: LIT 0x61
00032: LIT 0x62
00033: LIT 0x63
00034: LIT 0x64
00035: LIT 0x65
00036: LIT 0x66
00037: JUMP 00043
0003d: LIT 0x67
0003e: LIT 0x68
0003f: LIT 0x69
00040: LIT 0x6a
00041: LIT 0x6b
00042: LIT 0x6c
00043: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_N(0) 0000c 00018
0000c: LIT 0x66
0000d: LIT 0x65
0000e: LIT 0x64
0000f: LIT 0x63
00010: LIT 0x62
00011: LIT 0x61
00012: JUMP 0001e
00018: LIT 0x6c
00019: LIT 0x6b
0001a: LIT 0x6a
0001b: LIT 0x69
0001c: LIT 0x68
0001d: LIT 0x67
0001e: SPLIT_B(1) 00000
00025: SPLIT_N(2) 00031 0003d
00031: LIT 0x66
00032: LIT 0x65
00033: LIT 0x64
00034: LIT 0x63
00035: LIT 0x62
00036: LIT 0x61
00037: JUMP 00043
0003d: LIT 0x6c
0003e: LIT 0x6b
0003f: LIT 0x6a
00040: LIT 0x69
00041: LIT 0x68
00042: LIT 0x67
00043: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63, 0x64]),
                code_loc: CodeLoc { fwd: 0x0c, bck_seq_id: 0, bck: 0x37 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x67, 0x68, 0x69, 0x6a]),
                code_loc: CodeLoc { fwd: 0x18, bck_seq_id: 0, bck: 0x43 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x0c, 0x18],
        // Epsilon closure starting at backward code 0.
        vec![0x0c, 0x18]
    );
}

#[test]
fn re_code_14() {
    assert_re_code!(
        "(?s)(abc){0,2}",
        // Forward code
        r#"
00000: SPLIT_A(0) 00014
00007: LIT 0x61
00008: LIT 0x62
00009: LIT 0x63
0000a: SPLIT_A(1) 00014
00011: LIT 0x61
00012: LIT 0x62
00013: LIT 0x63
00014: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_A(0) 00014
00007: LIT 0x63
00008: LIT 0x62
00009: LIT 0x61
0000a: SPLIT_A(1) 00014
00011: LIT 0x63
00012: LIT 0x62
00013: LIT 0x61
00014: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62, 0x63]),
                code_loc: CodeLoc { fwd: 0x07, bck_seq_id: 0, bck: 0x14 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![]),
                code_loc: CodeLoc { fwd: 0x07, bck_seq_id: 0, bck: 0x14 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x07, 0x14],
        // Epsilon closure starting at backward code 0.
        vec![0x07, 0x14]
    );
}

#[test]
fn re_code_15() {
    assert_re_code!(
        "(?s)(a+|b)*",
        // Forward code
        r#"
00000: SPLIT_A(0) 00028
00007: SPLIT_N(1) 00013 00021
00013: LIT 0x61
00014: SPLIT_B(2) 00013
0001b: JUMP 00022
00021: LIT 0x62
00022: JUMP 00000
00028: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_A(0) 00028
00007: SPLIT_N(1) 00013 00021
00013: LIT 0x61
00014: SPLIT_B(2) 00013
0001b: JUMP 00022
00021: LIT 0x62
00022: JUMP 00000
00028: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![0x61]),
                code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x28 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x62]),
                code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x28 }
            },
            RegexpAtom {
                atom: Atom::exact(vec![]),
                code_loc: CodeLoc { fwd: 0x00, bck_seq_id: 0, bck: 0x28 }
            }
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x13, 0x21, 0x28],
        // Epsilon closure starting at backward code 0.
        vec![0x13, 0x21, 0x28]
    );
}

#[test]
fn re_code_16() {
    assert_re_code!(
        "(?s)(|abc)de",
        // Forward code
        r#"
00000: SPLIT_N(0) 0000c 00012
0000c: JUMP 00015
00012: LIT 0x61
00013: LIT 0x62
00014: LIT 0x63
00015: LIT 0x64
00016: LIT 0x65
00017: MATCH
"#,
        // Backward code
        r#"
00000: LIT 0x65
00001: LIT 0x64
00002: SPLIT_N(0) 0000e 00014
0000e: JUMP 00017
00014: LIT 0x63
00015: LIT 0x62
00016: LIT 0x61
00017: MATCH
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::inexact(vec![0x64, 0x65]),
            code_loc: CodeLoc { fwd: 0x15, bck_seq_id: 0, bck: 0x02 }
        },],
        // Epsilon closure starting at forward code 0.
        vec![0x15, 0x12],
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
00000: SPLIT_N(0) 0000c 00012
0000c: JUMP 00015
00012: LIT 0x61
00013: LIT 0x62
00014: LIT 0x63
00015: SPLIT_N(1) 00021 00027
00021: JUMP 0002a
00027: LIT 0x61
00028: LIT 0x62
00029: LIT 0x63
0002a: SPLIT_B(2) 00015
00031: SPLIT_N(3) 0003d 00043
0003d: JUMP 00046
00043: LIT 0x61
00044: LIT 0x62
00045: LIT 0x63
00046: MATCH
"#,
        // Backward code
        r#"
00000: SPLIT_N(0) 0000c 00012
0000c: JUMP 00015
00012: LIT 0x63
00013: LIT 0x62
00014: LIT 0x61
00015: SPLIT_N(1) 00021 00027
00021: JUMP 0002a
00027: LIT 0x63
00028: LIT 0x62
00029: LIT 0x61
0002a: SPLIT_B(2) 00015
00031: SPLIT_N(3) 0003d 00043
0003d: JUMP 00046
00043: LIT 0x63
00044: LIT 0x62
00045: LIT 0x61
00046: MATCH
"#,
        // Atoms
        vec![],
        // Epsilon closure starting at forward code 0.
        vec![0x46, 0x43, 0x27, 0x12],
        // Epsilon closure starting at backward code 0.
        vec![0x46, 0x43, 0x27, 0x12]
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
00007: SPLIT_A(0) 00015
0000e: CLASS_RANGES [0x41-0x5a] [0x61-0x7a] 
00015: MASKED_BYTE 0x41 0xdf
00019: MASKED_BYTE 0x42 0xdf
0001d: MATCH
"#,
        // Backward code
        r#"
00000: MASKED_BYTE 0x42 0xdf
00004: MASKED_BYTE 0x41 0xdf
00008: CLASS_RANGES [0x41-0x5a] [0x61-0x7a] 
0000f: SPLIT_A(0) 0001d
00016: CLASS_RANGES [0x41-0x5a] [0x61-0x7a] 
0001d: MATCH
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::inexact(vec![0x41, 0x42]),
                code_loc: CodeLoc { fwd: 0x15, bck_seq_id: 0, bck: 0x08 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x41, 0x62]),
                code_loc: CodeLoc { fwd: 0x15, bck_seq_id: 0, bck: 0x08 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x42]),
                code_loc: CodeLoc { fwd: 0x15, bck_seq_id: 0, bck: 0x08 }
            },
            RegexpAtom {
                atom: Atom::inexact(vec![0x61, 0x62]),
                code_loc: CodeLoc { fwd: 0x15, bck_seq_id: 0, bck: 0x08 }
            },
        ],
        // Epsilon closure starting at forward code 0.
        vec![0x00],
        // Epsilon closure starting at backward code 0.
        vec![0x00]
    );
}

#[test]
fn re_atoms() {
    assert_re_atoms!(r#"abcd"#, vec![Atom::exact(b"abcd")]);
    assert_re_atoms!(r#"abcd1234"#, vec![Atom::inexact(b"1234")]);
    assert_re_atoms!(r#".abc"#, vec![Atom::inexact(b"abc")]);
    assert_re_atoms!(r#"abc."#, vec![Atom::inexact(b"abc")]);
    assert_re_atoms!(r#"a.bcd"#, vec![Atom::inexact(b"bcd")]);
    assert_re_atoms!(r#"abc.d"#, vec![Atom::inexact(b"abc")]);

    assert_re_atoms!(
        r#"(ab|cd)"#,
        vec![Atom::exact(b"ab"), Atom::exact(b"cd")]
    );

    assert_re_atoms!(r#"ab|cd"#, vec![Atom::exact(b"ab"), Atom::exact(b"cd")]);

    assert_re_atoms!(
        r#"a(b|c)d"#,
        vec![Atom::exact(b"abd"), Atom::exact(b"acd")]
    );

    assert_re_atoms!(r#"ab.*cd"#, vec![Atom::inexact(b"ab")]);
    assert_re_atoms!(r#"ab.*cde"#, vec![Atom::inexact(b"cde")]);

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

    assert_re_atoms!(r#"(?i)abc.*123"#, vec![Atom::inexact(b"123")]);

    assert_re_atoms!("\x00\x00\x00\x00.{2,3}abc", vec![Atom::inexact(b"abc")]);

    assert_re_atoms!(
        r#"(?s)a.b.c.d"#,
        // Atoms a\x00b, a\x01b, a\x02b, .... up to a\xffb
        [(b'a'..=b'a'), (0x00..=0xff), (b'b'..=b'b'),]
            .into_iter()
            .multi_cartesian_product()
            .map(Atom::inexact)
            .collect::<Vec<Atom>>()
    );

    assert_re_atoms!(
        r#"(?s)a(b.b|c.c|d.d|e.e|f.f|g.g|h.h|i.i|j.j|k.k|l.l|m.m|n.n|o.o|p.p|q.q|r.r)"#,
        vec![Atom::inexact(b"a")]
    );
}
