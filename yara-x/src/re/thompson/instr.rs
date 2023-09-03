/*!
This module defines the instructions utilized by Pike's VM, along with various
types that aid in generating and executing sequences of VM instructions.

Instruction encoding format
---------------------------

For most regular expressions the VM code consists in long sequences of
instructions that match specific bytes. For instance, the regexp `/abc.def/` could
be represented by the following code:

```text
  match 'a'
  match 'b'
  match 'c'
  match any byte
  match 'd'
  match 'e'
  match 'f'
```

As observed, the majority of instructions in the code are meant to match
particular bytes, such as match 'a', match 'b', and so on. Instead of employing
a separate match opcode followed by the byte to be matched, which would be the
most common opcode, we can save space by excluding the match opcode entirely.
Instead, we directly include the byte to be matched in the instruction stream.
Consequently, the code predominantly consists of a sequence of bytes to be
matched. However, what about other operations like jumps or splits? How are
such operations encoded within the instruction stream? To address this, a
special marker is utilized to indicate that the subsequent byte should be
interpreted as an opcode, rather than a byte to be matched. This special marker
is defined by the [OPCODE_PREFIX] constant, which happens to be 0xAA due to its
distinctiveness and relative infrequency in real-life patterns (as opposed to
other potential candidates like 0x00 or 0xFF).

Whenever the VM encounters this marker, it recognizes that the byte(s) following
the marker correspond to an opcode that needs to be decoded and executed. While
some opcodes consist of a single byte, others span multiple bytes. Consequently,
the aforementioned example regexp would be encoded as follows:

```text
    0x61  0x62  0x63  0xAA     0x04     0x64   0x65  0x66
     a     b     c   marker  any byte    d       e     f
 ```

This raises the question of how to handle the situation when we need to match the
`0xAA` byte itself. In such cases, we represent it by including `0xAA` twice in the
instruction stream. Therefore, the sequence `0xAA 0xAA` signifies that the byte
`0xAA` must be matched once. Naturally, this implies that we cannot have an opcode
of `0xAA`. Stated differently, the opcode `0xAA` serves as a special case that
solely matches the `0xAA` byte.
 */

use std::mem::size_of;
use std::u8;

use bitvec::order::Lsb0;
use bitvec::slice::{BitSlice, IterOnes};

/// Marker that indicates the start of some VM opcode.
pub const OPCODE_PREFIX: u8 = 0xAA;

/// Number of alternatives in regular expressions (e.g: /foo|bar|baz/ have 3
/// alternatives)
pub type NumAlt = u8;

/// Offset for jump and split instructions. The offset is always relative to
/// the address where the instruction starts.
pub type Offset = i32;

/// Instructions supported by the Pike VM.
pub enum Instr<'a> {
    /// Match for the regexp has been found.
    Match,

    /// Matches any byte.
    AnyByte,

    /// Matches a specific byte.
    Byte(u8),

    /// Matches a case-insensitive character. The value of `u8` is in the
    /// range a-z.
    CaseInsensitiveChar(u8),

    /// Matches a masked byte. The opcode is followed by two `u8` operands:
    /// the byte and the mask.
    MaskedByte { byte: u8, mask: u8 },

    /// Matches a byte class. The class is represented by a 256-bits bitmap,
    /// one per byte. If the N-th bit is set, the byte N is part of the class
    /// and should match. This instruction is quite large, it takes 2 bytes
    /// for the opcode plus 32 bytes (256 bits) for the mask. For classes with
    /// a low number of non-adjacent byte ranges `ClassRanges` is preferred
    /// due to its more compact representation.
    ClassBitmap(ClassBitmap<'a>),

    /// Matches a byte class. The class is represented 1 or more byte ranges
    /// The first `u8` after the opcode indicates the number of ranges, then
    /// follows one pair `[u8, u8]` per range, indicating starting and ending
    /// bytes for the range, both inclusive. With 16 ranges this instruction
    /// takes 35 bytes (2 bytes for the opcode + 1 byte for the number of
    /// ranges + 32 bytes for the ranges), therefore it is used only when the
    /// number of ranges is <= 15. For a larger number of ranges `ClassBitmap`
    /// is preferred.
    ClassRanges(ClassRanges<'a>),

    /// Creates a new thread that starts at the current instruction pointer
    /// + offset while the current thread continues at the next instruction.
    /// The name comes from the fact that this instruction splits the execution
    /// flow in two.
    SplitA(Offset),

    /// Similar to SplitA, but the current thread continues at instruction
    /// pointer + offset while the new thread continues at the next instruction.
    /// This difference is important because the newly created thread has lower
    /// priority than the existing one, and priority affects the greediness of
    /// the regular expression.
    SplitB(Offset),

    /// Continues executing the code at N different locations. The current
    /// thread continues at the first location, and N-1 newly created threads
    /// continue at the remaining locations.
    SplitN(SplitN<'a>),

    /// Relative jump. The opcode is followed by an offset, the location
    /// of the target instruction is computed by adding this offset to the
    /// location of the jump opcode.
    Jump(Offset),

    /// Matches the start of the scanned data (^).
    Start,

    /// Matches the end of the scanned data ($).
    End,

    /// Matches a word boundary (i.e: characters that are not part of the
    /// \w class). Used for \b look-around assertions. This is a zero-length
    /// match.
    WordBoundary,

    /// The negation of WordBoundary. Used for \B look-around assertions. This
    /// is a zero-length match.
    WordBoundaryNeg,
}

impl<'a> Instr<'a> {
    pub const MATCH: u8 = 0x00;
    pub const SPLIT_A: u8 = 0x01;
    pub const SPLIT_B: u8 = 0x02;
    pub const SPLIT_N: u8 = 0x03;
    pub const JUMP: u8 = 0x04;
    pub const ANY_BYTE: u8 = 0x05;
    pub const MASKED_BYTE: u8 = 0x06;
    pub const CASE_INSENSITIVE_CHAR: u8 = 0x07;
    pub const CLASS_BITMAP: u8 = 0x08;
    pub const CLASS_RANGES: u8 = 0x09;
    pub const START: u8 = 0x0A;
    pub const END: u8 = 0x0B;
    pub const WORD_BOUNDARY: u8 = 0x0C;
    pub const WORD_BOUNDARY_NEG: u8 = 0x0D;
}

/// Parses a slice of bytes that contains Pike VM instructions, returning
/// individual instructions and their arguments.
pub(crate) struct InstrParser<'a> {
    code: &'a [u8],
}

impl<'a> InstrParser<'a> {
    pub fn new(code: &'a [u8]) -> Self {
        Self { code }
    }

    #[inline(always)]
    pub fn decode_instr(code: &[u8]) -> (Instr, usize) {
        match code[..] {
            [OPCODE_PREFIX, Instr::ANY_BYTE, ..] => (Instr::AnyByte, 2),
            [OPCODE_PREFIX, Instr::MASKED_BYTE, byte, mask, ..] => {
                (Instr::MaskedByte { byte, mask }, 4)
            }
            [OPCODE_PREFIX, Instr::CASE_INSENSITIVE_CHAR, byte, ..] => {
                (Instr::CaseInsensitiveChar(byte), 3)
            }
            [OPCODE_PREFIX, Instr::JUMP, ..] => {
                let offset = Self::decode_offset(&code[2..]);

                (Instr::Jump(offset), 2 + size_of::<Offset>())
            }
            [OPCODE_PREFIX, Instr::SPLIT_A, ..] => {
                let offset = Self::decode_offset(&code[2..]);

                (Instr::SplitA(offset), 2 + size_of::<Offset>())
            }
            [OPCODE_PREFIX, Instr::SPLIT_B, ..] => {
                let offset = Self::decode_offset(&code[2..]);

                (Instr::SplitB(offset), 2 + size_of::<Offset>())
            }
            [OPCODE_PREFIX, Instr::SPLIT_N, ..] => {
                let n = Self::decode_num_alt(&code[2..]);

                let offsets = &code[2 + size_of::<NumAlt>()
                    ..2 + size_of::<NumAlt>()
                        + size_of::<Offset>() * n as usize];

                (
                    Instr::SplitN(SplitN(offsets)),
                    2 + size_of::<NumAlt>() + size_of::<Offset>() * n as usize,
                )
            }
            [OPCODE_PREFIX, Instr::CLASS_RANGES, ..] => {
                let n = *unsafe { code.get_unchecked(2) } as usize;
                let ranges =
                    unsafe { code.get_unchecked(3..3 + size_of::<i16>() * n) };

                (
                    Instr::ClassRanges(ClassRanges(ranges)),
                    3 + size_of::<i16>() * n,
                )
            }
            [OPCODE_PREFIX, Instr::CLASS_BITMAP, ..] => {
                let bitmap = &code[2..2 + 32];
                (Instr::ClassBitmap(ClassBitmap(bitmap)), 2 + bitmap.len())
            }
            [OPCODE_PREFIX, Instr::START, ..] => (Instr::Start, 2),
            [OPCODE_PREFIX, Instr::END, ..] => (Instr::End, 2),
            [OPCODE_PREFIX, Instr::WORD_BOUNDARY, ..] => {
                (Instr::WordBoundary, 2)
            }
            [OPCODE_PREFIX, Instr::WORD_BOUNDARY_NEG, ..] => {
                (Instr::WordBoundaryNeg, 2)
            }
            [OPCODE_PREFIX, Instr::MATCH, ..] => (Instr::Match, 2),
            [OPCODE_PREFIX, OPCODE_PREFIX, ..] => {
                (Instr::Byte(OPCODE_PREFIX), 2)
            }
            [b, ..] => (Instr::Byte(b), 1),
            _ => unreachable!(),
        }
    }

    fn decode_offset(slice: &[u8]) -> Offset {
        let bytes: &[u8; size_of::<Offset>()] =
            unsafe { &*(slice.as_ptr() as *const [u8; size_of::<Offset>()]) };

        Offset::from_le_bytes(*bytes)
    }

    fn decode_num_alt(slice: &[u8]) -> NumAlt {
        let bytes: &[u8; size_of::<NumAlt>()] =
            unsafe { &*(slice.as_ptr() as *const [u8; size_of::<NumAlt>()]) };

        NumAlt::from_le_bytes(*bytes)
    }
}

impl<'a> Iterator for InstrParser<'a> {
    type Item = (Instr<'a>, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.code.is_empty() {
            return None;
        }
        let (instr, size) = InstrParser::decode_instr(self.code);
        self.code = &self.code[size..];
        Some((instr, size))
    }
}

pub struct SplitN<'a>(&'a [u8]);

impl<'a> SplitN<'a> {
    pub fn offsets(&self) -> SplitOffsets<'a> {
        SplitOffsets(self.0)
    }
}

pub struct SplitOffsets<'a>(&'a [u8]);

impl<'a> Iterator for SplitOffsets<'a> {
    type Item = Offset;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < size_of::<Offset>() {
            return None;
        }
        let next = Offset::from_le_bytes(
            (&self.0[..size_of::<Offset>()]).try_into().unwrap(),
        );
        self.0 = &self.0[size_of::<Offset>()..];
        Some(next)
    }
}

impl<'a> DoubleEndedIterator for SplitOffsets<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let len = self.0.len();
        if len < size_of::<Offset>() {
            return None;
        }
        let next = Offset::from_le_bytes(
            (&self.0[len - size_of::<Offset>()..len]).try_into().unwrap(),
        );
        self.0 = &self.0[..len - size_of::<Offset>()];
        Some(next)
    }
}

pub struct ClassRanges<'a>(&'a [u8]);

impl<'a> ClassRanges<'a> {
    /// Returns an iterator over the ranges of bytes contained in the class.
    pub fn ranges(&self) -> Ranges<'a> {
        Ranges(self.0)
    }

    /// Returns true if the class contains the given byte.
    pub fn contains(&self, byte: u8) -> bool {
        for range in self.ranges() {
            if (range.0..=range.1).contains(&byte) {
                return true;
            }
        }
        false
    }
}

pub struct Ranges<'a>(&'a [u8]);

impl<'a> Iterator for Ranges<'a> {
    type Item = (u8, u8);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 2 {
            return None;
        }
        let start = self.0[0];
        let end = self.0[1];
        self.0 = &self.0[2..];
        Some((start, end))
    }
}

pub struct ClassBitmap<'a>(&'a [u8]);

impl<'a> ClassBitmap<'a> {
    /// Returns an iterator over the bytes contained in the class.
    pub fn bytes(&self) -> IterOnes<'a, u8, Lsb0> {
        BitSlice::<_, Lsb0>::from_slice(self.0).iter_ones()
    }

    /// Returns true if the class contains the given byte.
    pub fn contains(&self, byte: u8) -> bool {
        unsafe {
            *BitSlice::<_, Lsb0>::from_slice(self.0)
                .get_unchecked(byte as usize)
        }
    }
}

/// Returns the length of the code emitted for the given literal.
///
/// Usually the code emitted for a literal has the same length than the literal
/// itself, because each byte in the literal corresponds to one byte in the
/// code. However, this is not true if the literal contains one or more bytes
/// equal to [`OPCODE_PREFIX`]. In such cases the code is longer than the
/// literal.
pub fn literal_code_length(literal: &[u8]) -> usize {
    let mut length = literal.len();
    for b in literal {
        if *b == OPCODE_PREFIX {
            length += 1;
        }
    }
    length
}
