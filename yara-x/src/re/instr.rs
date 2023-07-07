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

use bitvec::array::BitArray;
use bitvec::order::Lsb0;
use bitvec::slice::{BitSlice, IterOnes};
use regex_syntax::hir::ClassBytes;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::u8;

use yara_x_parser::ast::HexByte;

/// Marker that indicates the start of some VM opcode.
const OPCODE_PREFIX: u8 = 0xAA;

/// Number of alternatives in regular expressions (e.g: /foo|bar|baz/ have 3
/// alternatives)
pub type NumAlt = u8;

/// Offset for jump and split instructions. The offset is always relative to
/// the address where the instruction starts.
pub type Offset = i16;

/// Instructions supported by the Pike VM.
pub enum Instr<'a> {
    /// Matches any byte.
    AnyByte,

    /// Matches a byte.
    Match(u8),

    /// Matches a masked byte. The opcode is followed by two `u8` operands:
    /// the byte and the mask.
    MaskedByte(u8, u8),

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

    /// Continues executing the code at two different locations. The current
    /// thread continues at the first location, and a newly created thread
    /// continues at the second location.
    SplitA(Offset),
    SplitB(Offset),

    /// Continues executing the code at N different locations. The current
    /// thread continues at the first location, and N-1 newly created threads
    /// continue at the remaining locations.
    SplitN(SplitN<'a>),

    /// Relative jump. The opcode is followed by an `i16` offset, the location
    /// of the target instruction is computed by adding this offset to the
    /// location of the jump opcode.
    Jump(Offset),

    End,
}

impl<'a> Instr<'a> {
    pub const SPLIT_A: u8 = 0x00;
    pub const SPLIT_B: u8 = 0x01;
    pub const SPLIT_N: u8 = 0x02;
    pub const JUMP: u8 = 0x03;
    pub const ANY_BYTE: u8 = 0x04;
    pub const MASKED_BYTE: u8 = 0x05;
    pub const CLASS_BITMAP: u8 = 0x06;
    pub const CLASS_RANGES: u8 = 0x07;
}

/// A sequence of instructions for the regexp VM.
#[derive(Default)]
pub struct InstrSeq {
    seq_id: u64,
    seq: Cursor<Vec<u8>>,
}

impl InstrSeq {
    pub fn new(seq_id: u64) -> Self {
        Self { seq_id, seq: Cursor::new(Vec::new()) }
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
    pub fn location(&self) -> u64 {
        self.seq.position()
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
    pub fn emit_instr(&mut self, instr: u8) -> u64 {
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
            Instr::ANY_BYTE => {}
            _ => unreachable!(),
        }

        location
    }

    /// Adds a [`Instr::SplitN`] instruction at the end of the sequence and
    /// returns the location where the newly added instruction resides.
    pub fn emit_split_n(&mut self, n: NumAlt) -> u64 {
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
    pub fn emit_masked_byte(&mut self, b: HexByte) -> u64 {
        let location = self.location();
        self.seq
            .write_all(&[OPCODE_PREFIX, Instr::MASKED_BYTE, b.value, b.mask])
            .unwrap();
        location
    }

    /// Adds a [`Instr::ClassBitmap`] or [`Instr::ClassRanges`] instruction at
    /// the end of the sequence and returns the location where the newly added
    /// instruction resides.
    pub fn emit_class(&mut self, c: &ClassBytes) -> u64 {
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
    ) -> u64 {
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

    /// Patches the offset of the instruction that starts at the given location.
    ///
    /// # Panics
    ///
    /// If the instruction at `location` is not one that have an offset as its
    /// argument, like [`Instr::Jump`], [`Instr::SplitA`] or [`Instr::SplitB`].
    pub fn patch_instr(&mut self, location: u64, offset: Offset) {
        // Save the current position for the forward code in order to restore
        // it later.
        let saved_loc = self.location();

        // Seek to the position indicated by `location`.
        self.seq.seek(SeekFrom::Start(location)).unwrap();

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
        self.seq.seek(SeekFrom::Start(saved_loc)).unwrap();
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
        location: u64,
        mut offsets: I,
    ) {
        // Save the current location for the forward code in order to restore
        // it later.
        let saved_loc = self.location();

        // Seek to the position indicated by `location`.
        self.seq.seek(SeekFrom::Start(location)).unwrap();

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
        self.seq.seek(SeekFrom::Start(saved_loc)).unwrap();
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
                Instr::MaskedByte(byte, mask) => {
                    writeln!(
                        f,
                        "{:05x}: MASKED_BYTE {:#04x} {:#04x}",
                        addr, byte, mask
                    )?;
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
                Instr::Match(byte) => {
                    writeln!(f, "{:05x}: LIT {:#04x}", addr, byte)?;
                }
                Instr::End => {
                    break;
                }
            };
        }

        Ok(())
    }
}

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
        match self.code[self.ip..] {
            [OPCODE_PREFIX, OPCODE_PREFIX, ..] => {
                self.ip += 2;
                Instr::Match(OPCODE_PREFIX)
            }
            [OPCODE_PREFIX, Instr::ANY_BYTE, ..] => {
                self.ip += 2;
                Instr::AnyByte
            }
            [OPCODE_PREFIX, Instr::MASKED_BYTE, byte, mask, ..] => {
                self.ip += 4;
                Instr::MaskedByte(byte, mask)
            }
            [OPCODE_PREFIX, Instr::JUMP, ..] => {
                self.ip += 2;
                let offset = Offset::from_le_bytes(
                    (&self.code[self.ip..self.ip + size_of::<Offset>()])
                        .try_into()
                        .unwrap(),
                );
                self.ip += size_of::<Offset>();
                Instr::Jump(offset)
            }
            [OPCODE_PREFIX, Instr::SPLIT_A, ..] => {
                self.ip += 2;
                let offset = Offset::from_le_bytes(
                    (&self.code[self.ip..self.ip + size_of::<Offset>()])
                        .try_into()
                        .unwrap(),
                );
                self.ip += size_of::<Offset>();
                Instr::SplitA(offset)
            }
            [OPCODE_PREFIX, Instr::SPLIT_B, ..] => {
                self.ip += 2;
                let offset = Offset::from_le_bytes(
                    (&self.code[self.ip..self.ip + size_of::<Offset>()])
                        .try_into()
                        .unwrap(),
                );
                self.ip += size_of::<Offset>();
                Instr::SplitB(offset)
            }
            [OPCODE_PREFIX, Instr::SPLIT_N, ..] => {
                self.ip += 2;

                let n = NumAlt::from_le_bytes(
                    (&self.code[self.ip..self.ip + size_of::<NumAlt>()])
                        .try_into()
                        .unwrap(),
                );

                self.ip += size_of::<NumAlt>();

                let offsets = &self.code
                    [self.ip..self.ip + size_of::<Offset>() * n as usize];

                self.ip += size_of::<Offset>() * n as usize;

                Instr::SplitN(SplitN(offsets))
            }
            [OPCODE_PREFIX, Instr::CLASS_RANGES, ..] => {
                let n = self.code[self.ip + 2];
                self.ip += 3;

                let ranges = &self.code
                    [self.ip..self.ip + size_of::<i16>() * n as usize];

                self.ip += size_of::<i16>() * n as usize;

                Instr::ClassRanges(ClassRanges(ranges))
            }
            [OPCODE_PREFIX, Instr::CLASS_BITMAP, ..] => {
                self.ip += 2;
                let bitmap = &self.code[self.ip..self.ip + 32];
                self.ip += bitmap.len();

                Instr::ClassBitmap(ClassBitmap(bitmap))
            }
            [b, ..] => {
                self.ip += 1;
                Instr::Match(b)
            }
            [] => Instr::End,
        }
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
        if self.0.len() < 2 {
            return None;
        }
        let next = Offset::from_le_bytes(
            (&self.0[..size_of::<Offset>()]).try_into().unwrap(),
        );
        self.0 = &self.0[size_of::<Offset>()..];
        Some(next)
    }
}

pub struct ClassRanges<'a>(&'a [u8]);

impl<'a> ClassRanges<'a> {
    pub fn ranges(&self) -> Ranges<'a> {
        Ranges(self.0)
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
    pub fn bytes(&self) -> IterOnes<'a, u8, Lsb0> {
        BitSlice::<_, Lsb0>::from_slice(self.0).iter_ones()
    }
}
