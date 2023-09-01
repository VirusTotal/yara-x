use crate::re::fast::instr::Instr::{
    Jump, JumpRange, Literal, MaskedLiteral, Match,
};
use std::io::Cursor;
use std::io::Write;
use std::mem::size_of;
use std::ops::RangeInclusive;

/// Instructions supported by the Fast VM.
pub enum Instr<'a> {
    /// Match for the regexp has been found.
    Match,

    /// Match a literal string.
    Literal(&'a [u8]),

    /// Match a masked literal string. The first slice is the literal and
    /// the second one is the mask.
    MaskedLiteral(&'a [u8], &'a [u8]),

    /// Matches any string of a fixed length.
    Jump(u16),

    /// Matches any string with a length in a given range.
    JumpRange(RangeInclusive<u16>),
}

impl<'a> Instr<'a> {
    pub const MATCH: u8 = 0x00;
    pub const LITERAL: u8 = 0x01;
    pub const MASKED_LITERAL: u8 = 0x02;
    pub const JUMP: u8 = 0x03;
    pub const JUMP_RANGE: u8 = 0x04;
}

/// A sequence of instructions for the Fast VM.
#[derive(Default)]
pub struct InstrSeq {
    seq: Cursor<Vec<u8>>,
}

impl InstrSeq {
    /// Creates a new [`InstrSeq`].
    pub fn new() -> Self {
        Self { seq: Cursor::new(Vec::new()) }
    }

    /// Consumes the [`InstrSeq`] and returns the inner vector that contains
    /// the code.
    pub fn into_inner(self) -> Vec<u8> {
        self.seq.into_inner()
    }

    pub fn emit_match(&mut self) {
        self.seq.write_all(&[Instr::MATCH]).unwrap();
    }

    pub fn emit_literal(&mut self, literal: &[u8]) {
        assert!(literal.len() < u16::MAX as usize);

        let len = u16::to_le_bytes(literal.len().try_into().unwrap());

        self.seq.write_all(&[Instr::LITERAL]).unwrap();
        self.seq.write_all(len.as_slice()).unwrap();
        self.seq.write_all(literal).unwrap();
    }

    pub fn emit_masked_literal(&mut self, literal: &[u8], mask: &[u8]) {
        assert!(literal.len() < u16::MAX as usize);
        assert_eq!(literal.len(), mask.len());

        let len = u16::to_le_bytes(literal.len().try_into().unwrap());

        self.seq.write_all(&[Instr::MASKED_LITERAL]).unwrap();
        self.seq.write_all(len.as_slice()).unwrap();
        self.seq.write_all(literal).unwrap();
        self.seq.write_all(mask).unwrap();
    }

    pub fn emit_jump(&mut self, len: u16) {
        self.seq.write_all(&[Instr::JUMP]).unwrap();
        self.seq.write_all(len.to_le_bytes().as_slice()).unwrap();
    }

    pub fn emit_jump_range(&mut self, min: u16, max: u16) {
        self.seq.write_all(&[Instr::JUMP_RANGE]).unwrap();
        self.seq.write_all(min.to_le_bytes().as_slice()).unwrap();
        self.seq.write_all(max.to_le_bytes().as_slice()).unwrap();
    }
}

/// Parses a slice of bytes that contains Fast VM instructions, returning
/// individual instructions and their arguments.
pub struct InstrParser<'a> {
    code: &'a [u8],
    ip: usize,
}

impl<'a> InstrParser<'a> {
    pub fn new(code: &'a [u8]) -> Self {
        Self { code, ip: 0 }
    }

    pub fn ip(&self) -> usize {
        self.ip
    }

    pub fn next(&mut self) -> Instr {
        let (instr, size) = Self::decode_instr(&self.code[self.ip..]);
        self.ip += size;
        instr
    }

    #[inline(always)]
    pub(crate) fn decode_instr(code: &[u8]) -> (Instr, usize) {
        match code[..] {
            [Instr::LITERAL, ..] => {
                let literal_len = Self::decode_u16(&code[1..]) as usize;
                let literal_start = 1 + size_of::<u16>();
                (
                    Literal(&code[literal_start..literal_start + literal_len]),
                    1 + size_of::<u16>() + literal_len,
                )
            }
            [Instr::MASKED_LITERAL, ..] => {
                let literal_len = Self::decode_u16(&code[1..]) as usize;
                let literal_start = 1 + size_of::<u16>();
                let mask_start = literal_start + literal_len;
                (
                    MaskedLiteral(
                        &code[literal_start..literal_start + literal_len],
                        &code[mask_start..mask_start + literal_len],
                    ),
                    1 + size_of::<u16>() + 2 * literal_len,
                )
            }
            [Instr::JUMP, ..] => {
                let len = Self::decode_u16(&code[1..]);
                (Jump(len), 1 + size_of::<u16>())
            }
            [Instr::JUMP_RANGE, ..] => {
                let min = Self::decode_u16(&code[1..]);
                let max = Self::decode_u16(&code[1 + size_of::<u16>()..]);
                (JumpRange(min..=max), 1 + 2 * size_of::<u16>())
            }
            [Instr::MATCH, ..] => (Match, 1),
            [opcode, ..] => {
                unreachable!("unknown opcode for FastVM: {}", opcode)
            }
            _ => unreachable!(),
        }
    }

    fn decode_u16(slice: &[u8]) -> u16 {
        let bytes: &[u8; size_of::<u16>()] =
            unsafe { &*(slice.as_ptr() as *const [u8; size_of::<u16>()]) };

        u16::from_le_bytes(*bytes)
    }
}
