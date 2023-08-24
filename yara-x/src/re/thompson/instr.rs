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

use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::num::NonZeroU32;
use std::u8;

use bitvec::array::BitArray;
use bitvec::order::Lsb0;
use bitvec::slice::{BitSlice, IterOnes};
use regex_syntax::hir::ClassBytes;
use serde::{Deserialize, Serialize};

use yara_x_parser::ast::HexByte;

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

    /// Relative jump. The opcode is followed by an `i16` offset, the location
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

    /// Not really an instruction, is just a marker that indicates the end
    /// of a instruction sequence.
    Eoi,
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

/// A sequence of instructions for the Pike VM.
#[derive(Default)]
pub struct InstrSeq {
    seq_id: u64,
    seq: Cursor<Vec<u8>>,
}

impl AsRef<[u8]> for InstrSeq {
    fn as_ref(&self) -> &[u8] {
        self.seq.get_ref().as_slice()
    }
}

impl InstrSeq {
    /// Creates a new [`InstrSeq`]  with the given ID. The caller must guarantee
    /// that each [`InstrSeq`] has a unique ID, not shared with other sequences
    /// from the same regular expression.
    pub fn new(seq_id: u64) -> Self {
        Self { seq_id, seq: Cursor::new(Vec::new()) }
    }

    /// Consumes the [`InstrSeq`] and returns the inner vector that contains
    /// the code.
    pub fn into_inner(self) -> Vec<u8> {
        self.seq.into_inner()
    }

    /// Appends another sequence to this one.
    pub fn append(&mut self, other: &Self) {
        self.seq.write_all(other.seq.get_ref().as_slice()).unwrap();
    }

    /// Returns the current location within the instruction sequence.
    ///
    /// The location is an offset relative to the sequence's starting point,
    /// the first instruction is at location 0. This function always returns
    /// the location where the next instruction will be put.
    #[inline]
    pub fn location(&self) -> usize {
        self.seq.position() as usize
    }

    /// Returns the unique ID associated to the instruction sequence.
    ///
    /// While emitting the backward code for regexp the compiler can create
    /// multiple [`InstrSeq`], but each of them has an unique ID that is
    /// returned by this function.
    #[inline]
    pub fn seq_id(&self) -> u64 {
        self.seq_id
    }

    /// Adds some instruction at the end of the sequence and returns the
    /// location where the newly added instruction resides.
    pub fn emit_instr(&mut self, instr: u8) -> usize {
        // Store the position where the instruction will be written, which will
        // the result for this function.
        let location = self.location();

        self.seq.write_all(&[OPCODE_PREFIX, instr]).unwrap();

        match instr {
            Instr::SPLIT_A | Instr::SPLIT_B | Instr::JUMP => {
                // Split and Jump instructions are followed by a 16-bits
                // offset that is relative to the start of the instruction.
                self.seq.write_all(&[0x00; size_of::<Offset>()]).unwrap();
            }
            _ => {}
        }

        location
    }

    /// Adds a [`Instr::SplitN`] instruction at the end of the sequence and
    /// returns the location where the newly added instruction resides.
    pub fn emit_split_n(&mut self, n: NumAlt) -> usize {
        let location = self.location();
        self.seq.write_all(&[OPCODE_PREFIX, Instr::SPLIT_N]).unwrap();
        self.seq.write_all(NumAlt::to_le_bytes(n).as_slice()).unwrap();
        for _ in 0..n {
            self.seq.write_all(&[0x00; size_of::<Offset>()]).unwrap();
        }
        location
    }

    /// Adds a [`Instr::MaskedByte`] instruction at the end of the sequence and
    /// returns the location where the newly added instruction resides.
    pub fn emit_masked_byte(&mut self, b: HexByte) -> usize {
        let location = self.location();
        self.seq
            .write_all(&[OPCODE_PREFIX, Instr::MASKED_BYTE, b.value, b.mask])
            .unwrap();
        location
    }

    /// Adds a [`Instr::ClassBitmap`] or [`Instr::ClassRanges`] instruction at
    /// the end of the sequence and returns the location where the newly added
    /// instruction resides.
    pub fn emit_class(&mut self, c: &ClassBytes) -> usize {
        let location = self.location();
        // When the number of ranges is <= 15 `Instr::ClassRanges` is
        // preferred over `Instr::ClassBitmap` because of its more compact
        // representation. With 16 ranges or more `Instr::ClassBitmap` becomes
        // more compact.
        if c.ranges().len() < 16 {
            self.seq
                .write_all(&[
                    OPCODE_PREFIX,
                    Instr::CLASS_RANGES,
                    c.ranges().len() as u8,
                ])
                .unwrap();
            for range in c.ranges() {
                self.seq.write_all(&[range.start(), range.end()]).unwrap();
            }
        } else {
            // Create a bitmap where the N-th bit is set if byte N is part of
            // any of the ranges in the class.
            let mut bitmap: BitArray<_, Lsb0> = BitArray::new([0_u8; 32]);
            for range in c.ranges() {
                let range = range.start() as usize..=range.end() as usize;
                bitmap[range].fill(true);
            }
            self.seq.write_all(&[OPCODE_PREFIX, Instr::CLASS_BITMAP]).unwrap();
            self.seq.write_all(&bitmap.data).unwrap();
        }

        location
    }

    /// Adds instructions for matching a literal at the end of the sequence.
    pub fn emit_literal<'a, I: IntoIterator<Item = &'a u8>>(
        &mut self,
        literal: I,
    ) -> usize {
        let location = self.location();
        for b in literal {
            // If the literal contains a byte that is equal to the opcode
            // prefix it is duplicated. This allows the VM to interpret this
            // byte as part of the literal, not as an instruction.
            if *b == OPCODE_PREFIX {
                self.seq.write_all(&[*b, *b]).unwrap();
            } else {
                self.seq.write_all(&[*b]).unwrap();
            }
        }
        location
    }

    /// Emits a clone of the code that goes from `start` to `end`, both
    /// inclusive.
    pub fn emit_clone(&mut self, start: usize, end: usize) -> usize {
        let location = self.location();
        self.seq.get_mut().extend_from_within(start..end);
        self.seq.seek(SeekFrom::Current(end as i64 - start as i64)).unwrap();
        location
    }

    /// Patches the offset of the instruction that starts at the given location.
    ///
    /// # Panics
    ///
    /// If the instruction at `location` is not one that have an offset as its
    /// argument, like [`Instr::Jump`], [`Instr::SplitA`] or [`Instr::SplitB`].
    pub fn patch_instr(&mut self, location: usize, offset: Offset) {
        // Save the current position for the forward code in order to restore
        // it later.
        let saved_loc = self.location();

        // Seek to the position indicated by `location`.
        self.seq.seek(SeekFrom::Start(location as u64)).unwrap();

        let mut buf = [0; 2];
        self.seq.read_exact(&mut buf).unwrap();

        // Make sure that we have some `split` or `jump` instruction at the
        // given location.
        assert_eq!(buf[0], OPCODE_PREFIX);
        assert!(
            buf[1] == Instr::JUMP
                || buf[1] == Instr::SPLIT_A
                || buf[1] == Instr::SPLIT_B
        );

        // Write the given offset after the instruction opcode. This will
        // overwrite any existing offsets, usually initialized with 0.
        self.seq.write_all(Offset::to_le_bytes(offset).as_slice()).unwrap();

        // Restore to the previous current position.
        self.seq.seek(SeekFrom::Start(saved_loc as u64)).unwrap();
    }

    /// Patches the offsets of the [`Instr::SplitN`] instruction at the given
    /// location.
    ///
    /// # Panics
    ///
    /// If the instruction at `location` [`Instr::SplitN`], or if the number
    /// of offsets provided are not the one that the instruction expects.
    pub fn patch_split_n<I: ExactSizeIterator<Item = Offset>>(
        &mut self,
        location: usize,
        mut offsets: I,
    ) {
        // Save the current location for the forward code in order to restore
        // it later.
        let saved_loc = self.location();

        // Seek to the position indicated by `location`.
        self.seq.seek(SeekFrom::Start(location as u64)).unwrap();

        let mut opcode = [0; 2];
        self.seq.read_exact(&mut opcode).unwrap();

        // Make sure that we have some `split` or `jump` instruction at the
        // given location.
        assert_eq!(opcode[0], OPCODE_PREFIX);
        assert_eq!(opcode[1], Instr::SPLIT_N);

        let read_num_alternatives = |c: &mut Cursor<Vec<u8>>| -> NumAlt {
            let mut buf = [0_u8; size_of::<NumAlt>()];
            c.read_exact(&mut buf).unwrap();
            NumAlt::from_le_bytes(buf)
        };

        let n = read_num_alternatives(&mut self.seq);

        // Make sure that the number of offsets passed to this function is
        // equal the number of alternatives.
        assert_eq!(n as usize, offsets.len());

        for _ in 0..n {
            self.seq
                .write_all(
                    Offset::to_le_bytes(offsets.next().unwrap()).as_slice(),
                )
                .unwrap();
        }

        // Restore to the previous current position.
        self.seq.seek(SeekFrom::Start(saved_loc as u64)).unwrap();
    }
}

impl Display for InstrSeq {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut instr = InstrParser::new(self.seq.get_ref().as_slice());
        writeln!(f)?;
        loop {
            let addr = instr.ip();
            match instr.next() {
                Instr::AnyByte => {
                    writeln!(f, "{:05x}: ANY_BYTE", addr)?;
                }
                Instr::Byte(byte) => {
                    writeln!(f, "{:05x}: LIT {:#04x}", addr, byte)?;
                }
                Instr::MaskedByte { byte, mask } => {
                    writeln!(
                        f,
                        "{:05x}: MASKED_BYTE {:#04x} {:#04x}",
                        addr, byte, mask
                    )?;
                }
                Instr::CaseInsensitiveChar(c) => {
                    writeln!(f, "{:05x}: CASE_INSENSITIVE {:#04x}", addr, c)?;
                }
                Instr::ClassRanges(class) => {
                    write!(f, "{:05x}: CLASS_RANGES ", addr)?;
                    for range in class.ranges() {
                        write!(f, "[{:#04x}-{:#04x}] ", range.0, range.1)?;
                    }
                    writeln!(f)?;
                }
                Instr::ClassBitmap(class) => {
                    write!(f, "{:05x}: CLASS_BITMAP ", addr)?;
                    for byte in class.bytes() {
                        write!(f, "{:#04x} ", byte)?;
                    }
                    writeln!(f)?;
                }
                Instr::Jump(offset) => {
                    writeln!(
                        f,
                        "{:05x}: JUMP {:05x}",
                        addr,
                        addr as isize + offset as isize,
                    )?;
                }
                Instr::SplitA(offset) => {
                    writeln!(
                        f,
                        "{:05x}: SPLIT_A {:05x}",
                        addr,
                        addr as isize + offset as isize,
                    )?;
                }
                Instr::SplitB(offset) => {
                    writeln!(
                        f,
                        "{:05x}: SPLIT_B {:05x}",
                        addr,
                        addr as isize + offset as isize,
                    )?;
                }
                Instr::SplitN(split) => {
                    write!(f, "{:05x}: SPLIT_N", addr)?;
                    for offset in split.offsets() {
                        write!(f, " {:05x}", addr as isize + offset as isize)?;
                    }
                    writeln!(f)?;
                }
                Instr::Start => {
                    writeln!(f, "{:05x}: START", addr)?;
                }
                Instr::End => {
                    writeln!(f, "{:05x}: END", addr)?;
                }
                Instr::WordBoundary => {
                    writeln!(f, "{:05x}: WORD_BOUNDARY", addr)?;
                }
                Instr::WordBoundaryNeg => {
                    writeln!(f, "{:05x}: WORD_BOUNDARY_NEG", addr)?;
                }
                Instr::Match => {
                    writeln!(f, "{:05x}: MATCH", addr)?;
                }
                Instr::Eoi => {
                    break;
                }
            };
        }

        Ok(())
    }
}

/// Parses a slice of bytes that contains Pike VM instructions, returning
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
        let (instr, size) = decode_instr(&self.code[self.ip..]);
        self.ip += size;
        instr
    }
}

/// Trait implementing by both [`FwdCodeLoc`] and [`BckCodeLoc`].
pub(crate) trait CodeLoc: From<usize> {
    fn location(&self) -> usize;
    fn backwards(&self) -> bool;
}

/// Represents a location within the forward code for a regexp.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub(crate) struct FwdCodeLoc(NonZeroU32);

impl From<usize> for FwdCodeLoc {
    fn from(value: usize) -> Self {
        let value: u32 = value.try_into().unwrap();
        Self(NonZeroU32::new(value + 1).unwrap())
    }
}

impl CodeLoc for FwdCodeLoc {
    #[inline]
    fn location(&self) -> usize {
        self.0.get() as usize - 1
    }

    #[inline]
    fn backwards(&self) -> bool {
        false
    }
}

/// Represents a location within the backward code for a regexp.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub(crate) struct BckCodeLoc(NonZeroU32);

impl From<usize> for BckCodeLoc {
    fn from(value: usize) -> Self {
        let value: u32 = value.try_into().unwrap();
        Self(NonZeroU32::new(value + 1).unwrap())
    }
}

impl CodeLoc for BckCodeLoc {
    #[inline]
    fn location(&self) -> usize {
        self.0.get() as usize - 1
    }

    #[inline]
    fn backwards(&self) -> bool {
        true
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

#[inline(always)]
pub(crate) fn decode_instr(code: &[u8]) -> (Instr, usize) {
    match code[..] {
        [OPCODE_PREFIX, Instr::ANY_BYTE, ..] => (Instr::AnyByte, 2),
        [OPCODE_PREFIX, Instr::MASKED_BYTE, byte, mask, ..] => {
            (Instr::MaskedByte { byte, mask }, 4)
        }
        [OPCODE_PREFIX, Instr::CASE_INSENSITIVE_CHAR, byte, ..] => {
            (Instr::CaseInsensitiveChar(byte), 3)
        }
        [OPCODE_PREFIX, Instr::JUMP, ..] => {
            let offset = decode_offset(&code[2..]);

            (Instr::Jump(offset), 2 + size_of::<Offset>())
        }
        [OPCODE_PREFIX, Instr::SPLIT_A, ..] => {
            let offset = decode_offset(&code[2..]);

            (Instr::SplitA(offset), 2 + size_of::<Offset>())
        }
        [OPCODE_PREFIX, Instr::SPLIT_B, ..] => {
            let offset = decode_offset(&code[2..]);

            (Instr::SplitB(offset), 2 + size_of::<Offset>())
        }
        [OPCODE_PREFIX, Instr::SPLIT_N, ..] => {
            let n = decode_num_alt(&code[2..]);

            let offsets = &code[2 + size_of::<NumAlt>()
                ..2 + size_of::<NumAlt>() + size_of::<Offset>() * n as usize];

            (
                Instr::SplitN(SplitN(offsets)),
                2 + size_of::<NumAlt>() + size_of::<Offset>() * n as usize,
            )
        }
        [OPCODE_PREFIX, Instr::CLASS_RANGES, ..] => {
            let n = code[2];

            let ranges = &code[3..3 + size_of::<i16>() * n as usize];

            (
                Instr::ClassRanges(ClassRanges(ranges)),
                3 + size_of::<i16>() * n as usize,
            )
        }
        [OPCODE_PREFIX, Instr::CLASS_BITMAP, ..] => {
            let bitmap = &code[2..2 + 32];
            (Instr::ClassBitmap(ClassBitmap(bitmap)), 2 + bitmap.len())
        }
        [OPCODE_PREFIX, Instr::START, ..] => (Instr::Start, 2),
        [OPCODE_PREFIX, Instr::END, ..] => (Instr::End, 2),
        [OPCODE_PREFIX, Instr::WORD_BOUNDARY, ..] => (Instr::WordBoundary, 2),
        [OPCODE_PREFIX, Instr::WORD_BOUNDARY_NEG, ..] => {
            (Instr::WordBoundaryNeg, 2)
        }
        [OPCODE_PREFIX, Instr::MATCH, ..] => (Instr::Match, 2),
        [OPCODE_PREFIX, OPCODE_PREFIX, ..] => (Instr::Byte(OPCODE_PREFIX), 2),
        [b, ..] => (Instr::Byte(b), 1),
        [] => (Instr::Eoi, 0),
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
