use super::compiler::{Compiler, Location, RegexpAtom};
use crate::compiler::{hex_byte_to_class, Atom};
use pretty_assertions::assert_eq;
use regex_syntax::hir::{Class, Dot, Hir, Repetition};
use regex_syntax::parse;
use yara_x_parser::ast::HexByte;

macro_rules! assert_re_code {
    ($re:expr, $fwd:expr, $bck:expr, $atoms:expr) => {{
        let (forward_code, backward_code, atoms) =
            Compiler::new().compile(&parse($re).unwrap());

        assert_eq!(forward_code.to_string(), $fwd);
        assert_eq!(backward_code.to_string(), $bck);
        assert_eq!(atoms, $atoms);
    }};
}

#[test]
fn re_code_1() {
    assert_re_code!(
        "(?s)abcde",
        // Forward code
        r#"
00000: LIT 0x61
00001: LIT 0x62
00002: LIT 0x63
00003: LIT 0x64
00004: LIT 0x65
"#,
        // Backward code
        r#"
00000: LIT 0x65
00001: LIT 0x64
00002: LIT 0x63
00003: LIT 0x62
00004: LIT 0x61
"#,
        // Atoms
        vec![RegexpAtom {
            atom: Atom::from([0x61, 0x62, 0x63, 0x64]),
            code_loc: Location { fwd: 0x00, bck: 0x05, bck_seq_id: 0 }
        },]
    );
}

#[test]
fn re_code_2() {
    assert_re_code!(
        "(?s)ab|cd|ef",
        // Forward code
        r#"
00000: SPLIT_N 00009 0000f 00015
00009: LIT 0x61
0000a: LIT 0x62
0000b: JUMP 00017
0000f: LIT 0x63
00010: LIT 0x64
00011: JUMP 00017
00015: LIT 0x65
00016: LIT 0x66
"#,
        // Backward code
        r#"
00000: SPLIT_N 00009 0000f 00015
00009: LIT 0x62
0000a: LIT 0x61
0000b: JUMP 00017
0000f: LIT 0x64
00010: LIT 0x63
00011: JUMP 00017
00015: LIT 0x66
00016: LIT 0x65
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::from([0x61, 0x62]),
                code_loc: Location { fwd: 0x09, bck: 0x0b, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::from([0x63, 0x64]),
                code_loc: Location { fwd: 0x0f, bck: 0x11, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::from([0x65, 0x66]),
                code_loc: Location { fwd: 0x15, bck: 0x17, bck_seq_id: 0 }
            }
        ]
    );
}

#[test]
fn re_code_3() {
    assert_re_code!(
        "(?s)a(bc.+de)*fg",
        // Forward code
        r#"
00000: LIT 0x61
00001: SPLIT 00005, 00013
00005: LIT 0x62
00006: LIT 0x63
00007: ANY_BYTE
00009: SPLIT 00007, 0000d
0000d: LIT 0x64
0000e: LIT 0x65
0000f: JUMP 00001
00013: LIT 0x66
00014: LIT 0x67
"#,
        // Backward code
        r#"
00000: LIT 0x67
00001: LIT 0x66
00002: SPLIT 00006, 00014
00006: LIT 0x65
00007: LIT 0x64
00008: ANY_BYTE
0000a: SPLIT 00008, 0000e
0000e: LIT 0x63
0000f: LIT 0x62
00010: JUMP 00002
00014: LIT 0x61
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::from([0x61, 0x62, 0x63]),
                code_loc: Location { bck: 0, fwd: 0, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::from([0x61, 0x66, 0x67]),
                code_loc: Location { bck: 0, fwd: 0, bck_seq_id: 0 }
            }
        ]
    );
}

#[test]
fn re_code_4() {
    assert_re_code!(
        "(?s)a(bc.+?de)*?fg",
        // Forward code
        r#"
00000: LIT 0x61
00001: SPLIT 00013, 00005
00005: LIT 0x62
00006: LIT 0x63
00007: ANY_BYTE
00009: SPLIT 0000d, 00007
0000d: LIT 0x64
0000e: LIT 0x65
0000f: JUMP 00001
00013: LIT 0x66
00014: LIT 0x67
"#,
        // Backward code
        r#"
00000: LIT 0x67
00001: LIT 0x66
00002: SPLIT 00014, 00006
00006: LIT 0x65
00007: LIT 0x64
00008: ANY_BYTE
0000a: SPLIT 0000e, 00008
0000e: LIT 0x63
0000f: LIT 0x62
00010: JUMP 00002
00014: LIT 0x61
"#,
        // Atoms
        vec![
            RegexpAtom {
                atom: Atom::from([0x61, 0x66, 0x67]),
                code_loc: Location { bck: 0, fwd: 0, bck_seq_id: 0 }
            },
            RegexpAtom {
                atom: Atom::from([0x61, 0x62, 0x63]),
                code_loc: Location { bck: 0, fwd: 0, bck_seq_id: 0 }
            },
        ]
    );
}

#[test]
fn re_code_5() {
    let (forward_code, backward_code, atoms) =
        Compiler::new().compile(&Hir::concat(vec![
            Hir::literal([0x01, 0x02]),
            Hir::class(Class::Bytes(hex_byte_to_class(HexByte {
                value: 0x10,
                mask: 0xF0,
            }))),
            Hir::literal([0x03, 0x04]),
        ]));

    assert_eq!(
        r#"
00000: LIT 0x01
00001: LIT 0x02
00002: MASKED_BYTE 0x10 0xf0
00006: LIT 0x03
00007: LIT 0x04
"#,
        forward_code.to_string(),
    );

    assert_eq!(
        r#"
00000: LIT 0x04
00001: LIT 0x03
00002: MASKED_BYTE 0x10 0xf0
00006: LIT 0x02
00007: LIT 0x01
"#,
        backward_code.to_string(),
    );

    assert_eq!(
        atoms,
        vec![RegexpAtom {
            atom: Atom::from([0x01, 0x02]),
            code_loc: Location { fwd: 0x00, bck: 0x08, bck_seq_id: 0 }
        },]
    );
}

#[test]
fn re_code_6() {
    let (forward_code, backward_code, atoms) =
        Compiler::new().compile(&Hir::concat(vec![
            Hir::literal([0x01, 0x02]),
            Hir::class(Class::Bytes(hex_byte_to_class(HexByte {
                value: 0x10,
                mask: 0xF0,
            }))),
            Hir::literal([0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        ]));

    assert_eq!(
        r#"
00000: LIT 0x01
00001: LIT 0x02
00002: MASKED_BYTE 0x10 0xf0
00006: LIT 0x03
00007: LIT 0x04
00008: LIT 0x05
00009: LIT 0x06
0000a: LIT 0x07
0000b: LIT 0x08
"#,
        forward_code.to_string(),
    );

    assert_eq!(
        r#"
00000: LIT 0x08
00001: LIT 0x07
00002: LIT 0x06
00003: LIT 0x05
00004: LIT 0x04
00005: LIT 0x03
00006: MASKED_BYTE 0x10 0xf0
0000a: LIT 0x02
0000b: LIT 0x01
"#,
        backward_code.to_string(),
    );

    assert_eq!(
        atoms,
        vec![RegexpAtom {
            atom: Atom::from([0x03, 0x04, 0x05, 0x06]),
            code_loc: Location { fwd: 0x06, bck: 0x06, bck_seq_id: 0 }
        },]
    );
}
