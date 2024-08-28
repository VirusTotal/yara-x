use std::mem::size_of;
use std::ops::{RangeFrom, RangeInclusive};

use crate::re::fast::instr::Instr::{
    Alternation, Jump, JumpExact, JumpExactNoNewline, JumpNoNewline,
    JumpNoNewlineUnbounded, JumpUnbounded, Literal, MaskedLiteral, Match,
};

/// Instructions supported by the Fast VM.
pub(crate) enum Instr<'a> {
    /// Match for the regexp has been found.
    Match,

    /// Match a literal string.
    Literal(&'a [u8]),

    /// Match a masked literal string. The first slice is the literal and
    /// the second one is the mask.
    MaskedLiteral(&'a [u8], &'a [u8]),

    /// Matches any of the alternative instructions returned by the the
    /// [`InstrParser`]. The instructions returned are either [`Literal`]
    /// or [`MaskedLiteral`], other types of instructions are not allowed
    /// as part of an alternation.
    Alternation(InstrParser<'a>),

    /// Matches all strings of a given length.
    JumpExact(u16),

    /// Matches all strings of a given length, but the string can't contain
    /// newline characters.
    JumpExactNoNewline(u16),

    /// Matches any string with a length in a given range.
    Jump(RangeInclusive<u16>),

    /// Like Jump, but the upper bound is infinite.
    JumpUnbounded(RangeFrom<u16>),

    /// Matches any string with a length in a given range, but the string can't
    /// contain newline characters. This is a non-greedy match, shorter strings
    /// are preferred.
    JumpNoNewline(RangeInclusive<u16>),

    /// Like JumpNoNewline, but the upper bound is infinite.
    JumpNoNewlineUnbounded(RangeFrom<u16>),
}

impl<'a> Instr<'a> {
    pub const MATCH: u8 = 0x00;
    pub const LITERAL: u8 = 0x01;
    pub const MASKED_LITERAL: u8 = 0x02;
    pub const JUMP_EXACT: u8 = 0x03;
    pub const JUMP: u8 = 0x04;
    pub const JUMP_EXACT_NO_NEWLINE: u8 = 0x05;
    pub const JUMP_NO_NEWLINE: u8 = 0x06;
    pub const ALTERNATION: u8 = 0x07;
}

/// Parses a slice of bytes that contains Fast VM instructions, returning
/// individual instructions and their arguments.
pub(crate) struct InstrParser<'a> {
    code: &'a [u8],
}

impl<'a> InstrParser<'a> {
    pub fn new(code: &'a [u8]) -> Self {
        Self { code }
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
            [Instr::ALTERNATION, ..] => {
                let len = Self::decode_u16(&code[1..]) as usize;
                let start = 1 + size_of::<u16>();
                (
                    Alternation(InstrParser::new(&code[start..start + len])),
                    1 + size_of::<u16>() + len,
                )
            }
            [Instr::JUMP_EXACT, ..] => {
                let len = Self::decode_u16(&code[1..]);
                (JumpExact(len), 1 + size_of::<u16>())
            }
            [Instr::JUMP, ..] => {
                let min = Self::decode_u16(&code[1..]);
                let max = Self::decode_u16(&code[1 + size_of::<u16>()..]);
                // When max is 0 it actually means unlimited max.
                if max == 0 {
                    (JumpUnbounded(min..), 1 + 2 * size_of::<u16>())
                } else {
                    (Jump(min..=max), 1 + 2 * size_of::<u16>())
                }
            }
            [Instr::JUMP_EXACT_NO_NEWLINE, ..] => {
                let len = Self::decode_u16(&code[1..]);
                (JumpExactNoNewline(len), 1 + size_of::<u16>())
            }
            [Instr::JUMP_NO_NEWLINE, ..] => {
                let min = Self::decode_u16(&code[1..]);
                let max = Self::decode_u16(&code[1 + size_of::<u16>()..]);
                // When max is 0 it actually means unlimited max.
                if max == 0 {
                    (JumpNoNewlineUnbounded(min..), 1 + 2 * size_of::<u16>())
                } else {
                    (JumpNoNewline(min..=max), 1 + 2 * size_of::<u16>())
                }
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

impl<'a> Iterator for InstrParser<'a> {
    type Item = Instr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.code.is_empty() {
            return None;
        }
        let (instr, size) = InstrParser::decode_instr(self.code);
        self.code = &self.code[size..];
        Some(instr)
    }
}
