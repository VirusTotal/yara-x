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
is defined by the [OPCODE_MARKER] constant, which happens to be 0xAA due to its
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

use yara_x_parser::ast::HexByte;

/// Marker that indicates the start of some VM opcode.
const OPCODE_MARKER: u8 = 0xAA;

/// Instructions supported by the VM.
#[derive(Copy, Clone)]
#[repr(u8)]
pub enum Instr {
    SplitA = 0x00,
    SplitB = 0x01,
    SplitN = 0x02,
    Jump = 0x03,
    AnyByte = 0x04,
    MaskedByte = 0x05,
}

impl Instr {
    const SPLIT_A: u8 = Instr::SplitA as u8;
    const SPLIT_B: u8 = Instr::SplitB as u8;
    const SPLIT_N: u8 = Instr::SplitN as u8;
    const JUMP: u8 = Instr::Jump as u8;
    const ANY_BYTE: u8 = Instr::AnyByte as u8;
    const MASKED_BYTE: u8 = Instr::MaskedByte as u8;
}

pub type NumAlternatives = u8;
pub type Offset = i16;

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
    pub fn emit_instr(&mut self, instr: Instr) -> u64 {
        // Store the position where the instruction will be written, which will
        // the result for this function.
        let location = self.location();
        self.seq.write_all(&[OPCODE_MARKER, instr as u8]).unwrap();

        match instr {
            Instr::SplitA | Instr::SplitB | Instr::Jump => {
                // Split and Jump instructions are followed by a 16-bits
                // offset that is relative to the start of the instruction.
                self.seq.write_all(&[0x00; size_of::<Offset>()]).unwrap();
            }
            Instr::AnyByte => {}
            _ => unreachable!(),
        }

        location
    }

    /// Adds a [`Instr::SplitN`] instruction at the end of the sequence and
    /// returns the location where the newly added instruction resides.
    pub fn emit_split_n(&mut self, n: NumAlternatives) -> u64 {
        let location = self.location();
        self.seq.write_all(&[OPCODE_MARKER, Instr::SPLIT_N]).unwrap();
        self.seq
            .write_all(NumAlternatives::to_le_bytes(n).as_slice())
            .unwrap();
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
            .write_all(&[OPCODE_MARKER, Instr::MASKED_BYTE, b.value, b.mask])
            .unwrap();
        location
    }

    /// Adds instructions for matching a literal at the end of the sequence.
    pub fn emit_literal<'a, I: IntoIterator<Item = &'a u8>>(
        &mut self,
        literal: I,
    ) -> u64 {
        let location = self.location();
        for b in literal {
            // If the literal contains a byte that is equal to the instruction
            // marker it is duplicated. This allows the VM to interpret this
            // byte as part of the literal, not as an instruction.
            if *b == OPCODE_MARKER {
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
        assert_eq!(buf[0], OPCODE_MARKER);
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
        assert_eq!(opcode[0], OPCODE_MARKER);
        assert_eq!(opcode[1], Instr::SPLIT_N);

        let read_num_alternatives =
            |c: &mut Cursor<Vec<u8>>| -> NumAlternatives {
                let mut buf = [0_u8; size_of::<NumAlternatives>()];
                c.read_exact(&mut buf).unwrap();
                NumAlternatives::from_le_bytes(buf)
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
        let mut c = Cursor::new(self.seq.get_ref());

        let mut opcode: [u8; 1] = [0; 1];

        let read_num_alternatives =
            |c: &mut Cursor<&Vec<u8>>| -> NumAlternatives {
                let mut buf = [0_u8; size_of::<NumAlternatives>()];
                c.read_exact(&mut buf).unwrap();
                NumAlternatives::from_le_bytes(buf)
            };

        let read_offset = |c: &mut Cursor<&Vec<u8>>| -> Offset {
            let mut buf = [0_u8; size_of::<Offset>()];
            c.read_exact(&mut buf).unwrap();
            Offset::from_le_bytes(buf)
        };

        let read_masked_byte = |c: &mut Cursor<&Vec<u8>>| -> (u8, u8) {
            let mut buf = [0_u8; 2];
            c.read_exact(&mut buf).unwrap();
            (buf[0], buf[1])
        };

        writeln!(f)?;

        while c.read_exact(opcode.as_mut_slice()).is_ok() {
            let addr = c.position() - 1;
            match opcode[0] {
                OPCODE_MARKER => {
                    if c.read_exact(opcode.as_mut_slice()).is_ok() {
                        match opcode[0] {
                            OPCODE_MARKER => {
                                writeln!(
                                    f,
                                    "{:05x}: LIT {:#04x}",
                                    addr, opcode[0]
                                )?;
                            }
                            Instr::SPLIT_A => {
                                let offset = read_offset(&mut c);
                                writeln!(
                                    f,
                                    "{:05x}: SPLIT {:05x}, {:05x}",
                                    addr,
                                    c.position(),
                                    addr as Offset + offset,
                                )?;
                            }
                            Instr::SPLIT_B => {
                                let offset = read_offset(&mut c);
                                writeln!(
                                    f,
                                    "{:05x}: SPLIT {:05x}, {:05x}",
                                    addr,
                                    addr as Offset + offset,
                                    c.position(),
                                )?;
                            }
                            Instr::SPLIT_N => {
                                let n = read_num_alternatives(&mut c);
                                write!(f, "{:05x}: SPLIT_N", addr)?;
                                for _ in 0..n {
                                    let offset = read_offset(&mut c);
                                    write!(
                                        f,
                                        " {:05x}",
                                        addr as Offset + offset
                                    )?
                                }
                                writeln!(f)?;
                            }
                            Instr::JUMP => {
                                let offset = read_offset(&mut c);
                                writeln!(
                                    f,
                                    "{:05x}: JUMP {:05x}",
                                    addr,
                                    addr as Offset + offset,
                                )?;
                            }
                            Instr::ANY_BYTE => {
                                writeln!(f, "{:05x}: ANY_BYTE", addr)?;
                            }
                            Instr::MASKED_BYTE => {
                                let (byte, mask) = read_masked_byte(&mut c);
                                writeln!(
                                    f,
                                    "{:05x}: MASKED_BYTE {:#04x} {:#04x}",
                                    addr, byte, mask
                                )?;
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                _ => {
                    writeln!(f, "{:05x}: LIT {:#04x}", addr, opcode[0])?;
                }
            }
        }

        Ok(())
    }
}
