use std::io::{Cursor, Seek, SeekFrom, Write};
use std::mem;
use std::mem::size_of;

use bstr::ByteSlice;
use regex_syntax::hir::{visit, Class, Hir, HirKind, Visitor};

use crate::compiler::{best_range_in_bytes, best_range_in_masked_bytes, Atom};
use crate::re;
use crate::re::fast::instr::Instr;
use crate::re::{BckCodeLoc, Error, FwdCodeLoc, RegexpAtom, MAX_ALTERNATIVES};

/// A compiler that takes a [`re::hir::Hir`] and produces code for
/// [`re::fast::FastVM`].
pub(crate) struct Compiler {}

impl Compiler {
    /// Creates a new compiler.
    pub fn new() -> Self {
        Self {}
    }

    /// Compiles the regular expression represented by the given [`Hir`]
    /// and appends the produced code to a vector.
    pub fn compile(
        mut self,
        hir: &re::hir::Hir,
        code: &mut Vec<u8>,
    ) -> Result<Vec<RegexpAtom>, Error> {
        // Break the pattern into pieces. Each piece is a literal, masked
        // literal, or jump. The pattern `{ ?1 02 03 [3-4] 04 05 06 }` is
        // split in three pieces:
        //
        //   ?1 02 03     - masked literal
        //   [3-4]        - jump
        //   04 05 06     - literal
        //
        let pieces = visit(
            &hir.inner,
            PatternSplitter {
                bytes: Vec::new(),
                mask: Vec::new(),
                pieces: Vec::new(),
                alternatives: Vec::new(),
                in_alternation: false,
                in_repetition: false,
            },
        )?;

        let mut best_quality = i32::MIN;
        let mut best_piece = 0;
        let mut best_atoms = None;
        let mut piece_atoms = Vec::new();

        let find_best_atoms = |bytes, mask, atoms: &mut Vec<_>| {
            let (range, quality) = if let Some(mask) = mask {
                best_range_in_masked_bytes(bytes, mask)
            } else {
                best_range_in_bytes(bytes)
            };
            atoms.push((Some(bytes), mask, range, quality));
        };

        // Iterate the pieces, looking for the one that contains the best
        // possible atom. In `{ ?1 02 03 [3-4] 04 05 06 }` the piece with the
        // best atom is `04 05 06`.
        for (i, piece) in pieces.iter().enumerate() {
            piece_atoms.clear();

            match piece {
                PatternPiece::Pattern(Pattern::Literal(bytes)) => {
                    find_best_atoms(bytes.as_slice(), None, &mut piece_atoms);
                }
                PatternPiece::Pattern(Pattern::Masked(bytes, mask)) => {
                    find_best_atoms(
                        bytes.as_slice(),
                        Some(mask.as_slice()),
                        &mut piece_atoms,
                    );
                }
                PatternPiece::Alternation(alts) => {
                    for alt in alts {
                        match alt {
                            Pattern::Literal(bytes) => {
                                find_best_atoms(
                                    bytes.as_slice(),
                                    None,
                                    &mut piece_atoms,
                                );
                            }
                            Pattern::Masked(bytes, mask) => {
                                find_best_atoms(
                                    bytes.as_slice(),
                                    Some(mask.as_slice()),
                                    &mut piece_atoms,
                                );
                            }
                        }
                    }
                }
                PatternPiece::JumpExact(..) | PatternPiece::Jump(..) => {
                    piece_atoms.push((None, None, None, i32::MIN))
                }
            };

            // Find the quality of the worst piece.
            let quality =
                *piece_atoms.iter().map(|(_, _, _, q)| q).min().unwrap();

            // If the quality of the worst piece is higher than the current
            // best quality, replace the best atoms and best quality.
            if quality > best_quality {
                best_piece = i;
                best_quality = quality;
                best_atoms = Some(mem::take(&mut piece_atoms));
            }
        }

        // The pieces that are before the one that contains the best atom
        // will produce backward code. For example, the best atom in pattern
        // `{ ?1 02 03 [3-4] 04 05 06 }` is `04 05 06`. Pieces `?1 02 03` and
        // `[3-4]` are before piece `04 05 06`. When the atom ``04 05 06` is
        // found. The matching of the `?1 02 03 [3-4]` portion of the pattern
        // will be done backwards, starting at the offset where the atom was
        // found.
        //
        // Here we emit the backward code, but only if the piece that contains
        // the best atom is not the first one.
        let bck_code_start = if best_piece > 0 {
            let bck_code_start = code.len();
            let mut bck_code = InstrSeq::new();
            for piece in pieces[0..best_piece].iter().rev() {
                self.emit_piece(piece, &mut bck_code)?;
            }
            bck_code.emit_match();
            code.extend_from_slice(bck_code.into_inner().as_slice());
            Some(bck_code_start)
        } else {
            None
        };

        // The piece that contains the best atom, and any other piece that
        // appears after it, will produce forward code.
        let fwd_pieces = &pieces[best_piece..];

        // Position where the forward code starts.
        let fwd_code_start = code.len();

        let mut fwd_code = InstrSeq::new();

        for piece in fwd_pieces {
            self.emit_piece(piece, &mut fwd_code)?;
        }

        fwd_code.emit_match();
        code.extend_from_slice(fwd_code.into_inner().as_slice());

        let mut atoms = Vec::new();

        let best_atoms = match best_atoms {
            Some(best_atoms) => best_atoms,
            None => return Err(Error::FastIncompatible),
        };

        for (best_bytes, best_mask, best_range, _) in best_atoms {
            match (best_bytes, best_mask, best_range) {
                (Some(bytes), Some(mask), Some(range)) => {
                    let atom = Atom::from_slice_range(bytes, range.clone());
                    for atom in atom.mask_combinations(&mask[range]) {
                        atoms.push(RegexpAtom {
                            atom,
                            fwd_code: Some(FwdCodeLoc::from(fwd_code_start)),
                            bck_code: bck_code_start.map(BckCodeLoc::from),
                        })
                    }
                }
                (Some(bytes), None, Some(range)) => atoms.push(RegexpAtom {
                    atom: Atom::from_slice_range(bytes, range),
                    fwd_code: Some(FwdCodeLoc::from(fwd_code_start)),
                    bck_code: bck_code_start.map(BckCodeLoc::from),
                }),
                _ => unreachable!(),
            }
        }

        // If the pattern was decomposed into more than one piece its atoms can
        // not be exact. The atoms could be exact if the pattern was a single
        // piece, and it fits completely in the atom.
        if pieces.len() > 1 {
            for atom in atoms.iter_mut() {
                atom.set_exact(false);
            }
        }

        let min_atom_len =
            atoms.iter().map(|atom| atom.len()).min().unwrap_or(0);

        // If the minimum atom length is < 2, return Error::FastIncompatible
        // and force the use of the Thompson's compiler with this regexp. The
        // Thompson's compiler does a better a job at extracting longer atoms
        // from regexps, and in cases of extremely short atoms it's better to
        // give it a try than using FastVM with short atoms.
        if min_atom_len < 2 {
            return Err(Error::FastIncompatible);
        }

        Ok(atoms)
    }

    fn emit_piece(
        &mut self,
        piece: &PatternPiece,
        instr: &mut InstrSeq,
    ) -> Result<(), Error> {
        match piece {
            PatternPiece::Pattern(pattern) => instr.emit_pattern(pattern),
            PatternPiece::Alternation(alt) => {
                instr.emit_alternation(alt)?;
            }
            PatternPiece::JumpExact(len, accept_newlines) => {
                instr.emit_jump_exact(*len as u16, *accept_newlines)
            }
            PatternPiece::Jump(min, max, accept_newlines) => {
                instr.emit_jump(
                    *min as u16,
                    max.map(|max| max as u16),
                    *accept_newlines,
                );
            }
        }

        Ok(())
    }
}

/// Represents the pieces in which patterns are decomposed during compilation.
///
/// Patterns accepted by the Fast VM can be decomposed into a sequence of pieces
/// where each piece is either a literal, a masked literal, an alternation, or a
/// jump.
///
/// For instance, the pattern `{ 01 02 03 [0-2] 04 0? 06 }` is decomposed into:
///
/// ```text
/// Pattern(Literal([01, 02, 03]))
/// Jump(0,2, false)
/// Pattern(Masked([04, 00, 06], [FF, F0, FF]))
/// ```
///
/// The `bool` field in all jump variants mean whether the newline characters
/// are accepted in the data being skipped or not.
enum PatternPiece {
    Pattern(Pattern),
    Alternation(Vec<Pattern>),
    Jump(u32, Option<u32>, bool),
    JumpExact(u32, bool),
}

enum Pattern {
    Literal(Vec<u8>),
    Masked(Vec<u8>, Vec<u8>),
}

/// Given the [`Hir`] for a regexp pattern, decomposed it into
/// [`PatternPiece`]s.
struct PatternSplitter {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    pieces: Vec<PatternPiece>,
    alternatives: Vec<Pattern>,
    in_alternation: bool,
    in_repetition: bool,
}

impl PatternSplitter {
    fn finish_literal(&mut self) -> Option<Pattern> {
        // If the `bytes` is empty return `None` because empty literals are
        // ignored, except when we are inside an alternation, where empty
        // literals are accepted in cases like `(abc|)`.
        if !self.in_alternation && self.bytes.is_empty() {
            return None;
        }
        // If all bytes in the mask are 0xff the piece is a Literal and the
        // mask is not necessary, if not, the piece is a MaskedLiteral. In both
        // cases the mask and the bytes are reset to empty vectors.
        if self.mask.iter().all(|&b| b == 0xff) {
            self.mask.clear();
            Some(Pattern::Literal(mem::take(&mut self.bytes)))
        } else {
            Some(Pattern::Masked(
                mem::take(&mut self.bytes),
                mem::take(&mut self.mask),
            ))
        }
    }
}

impl Visitor for PatternSplitter {
    type Output = Vec<PatternPiece>;
    type Err = Error;

    fn finish(mut self) -> Result<Self::Output, Self::Err> {
        if let Some(pattern) = self.finish_literal() {
            self.pieces.push(PatternPiece::Pattern(pattern));
        }
        Ok(self.pieces)
    }

    fn visit_pre(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match hir.kind() {
            HirKind::Literal(literal) => {
                self.bytes.extend_from_slice(literal.0.as_bytes());
                self.mask.extend(itertools::repeat_n(0xff, literal.0.len()));
            }
            HirKind::Class(class) => {
                // A class found inside a repetition is ignored. The only
                // kind of classes allowed inside a repetition are those that
                // match all bytes, and those cases are handled while visiting
                // the repetition node itself.
                if self.in_repetition {
                    return Ok(());
                }
                match class {
                    Class::Bytes(class) => {
                        // Check if the class is representing a single masked
                        // byte, like `3?`.
                        if let Some(masked_byte) =
                            re::hir::class_to_masked_byte(class)
                        {
                            self.bytes.push(masked_byte.value);
                            self.mask.push(masked_byte.mask);
                            return Ok(());
                        }

                        // If already in an alternation there's nothing more we
                        // can do.
                        if self.in_alternation {
                            return Err(Error::FastIncompatible);
                        }

                        // Check if the class is representing an alternation of
                        // masked bytes, like `(1? | 2? | 3?)`. When the HIR for
                        // hex patterns is constructed, this kind of alternation
                        // is expressed as a `hir::Alternation` node where each
                        // alternative is a class representing a single masked
                        // byte. However, the `regex_syntax` crate can optimize
                        // the HIR by merging all the alternatives into a single
                        // class. For instance, Alt(Class(A-a), Class(B-b)) can
                        // become Class(A-a, B-b).
                        if let Some(masked_bytes) =
                            re::hir::class_to_masked_bytes_alternation(class)
                        {
                            if let Some(pattern) = self.finish_literal() {
                                self.pieces
                                    .push(PatternPiece::Pattern(pattern));
                            }
                            self.pieces.push(PatternPiece::Alternation(
                                masked_bytes
                                    .iter()
                                    .map(|b| {
                                        Pattern::Masked(
                                            vec![b.value],
                                            vec![b.mask],
                                        )
                                    })
                                    .collect(),
                            ));
                        } else {
                            return Err(Error::FastIncompatible);
                        }
                    }
                    // Even though the regexp HIR was generated without unicode
                    // support, the HIR can contain unicode classes due to a
                    // design issue in regex-syntax.
                    // https://github.com/rust-lang/regex/issues/1088
                    Class::Unicode(_) => return Err(Error::FastIncompatible),
                }
            }

            HirKind::Repetition(rep) => {
                // Repetitions are ok as long as they are not nested inside
                // another repetition or alternation and the pattern repeated
                // is any byte. Jumps in hex pattern (eg: [1], [10-20]) are
                // expressed as one of such repetitions. These jumps behave as
                // delimiters between pattern pieces.
                if self.in_repetition || self.in_alternation {
                    return Err(Error::FastIncompatible);
                }

                let any_byte = re::hir::any_byte(rep.sub.kind());
                let any_byte_except_newline =
                    re::hir::any_byte_except_newline(rep.sub.kind());

                if !any_byte && !any_byte_except_newline {
                    return Err(Error::FastIncompatible);
                }

                let accept_newlines = !any_byte_except_newline;

                match (rep.min, rep.max) {
                    // When the jump has a fixed size <= 8 and accept newlines
                    // treat it as a sequence of ?? wildcards. It's more
                    // efficient to treat short fixed size jumps as a sequence
                    // of wildcards than breaking the pattern into more pieces.
                    (min, Some(max))
                        if min == max && max <= 8 && accept_newlines =>
                    {
                        for _ in 0..max {
                            self.bytes.push(0);
                            self.mask.push(0);
                        }
                    }
                    (min, max) => {
                        if let Some(pattern) = self.finish_literal() {
                            self.pieces.push(PatternPiece::Pattern(pattern));
                        }
                        if Some(min) == max {
                            self.pieces.push(PatternPiece::JumpExact(
                                min,
                                accept_newlines,
                            ));
                        } else {
                            self.pieces.push(PatternPiece::Jump(
                                min,
                                max,
                                accept_newlines,
                            ));
                        }
                    }
                }
                self.in_repetition = true;
            }
            HirKind::Alternation(alternatives) => {
                if self.in_repetition || self.in_alternation {
                    return Err(Error::FastIncompatible);
                }
                if alternatives.len() > MAX_ALTERNATIVES.into() {
                    return Err(Error::TooManyAlternatives);
                }
                if let Some(pattern) = self.finish_literal() {
                    self.pieces.push(PatternPiece::Pattern(pattern));
                }
                self.in_alternation = true;
            }
            HirKind::Look(_) => return Err(Error::FastIncompatible),
            _ => {}
        }

        Ok(())
    }

    fn visit_post(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match hir.kind() {
            HirKind::Repetition(_) => {
                self.in_repetition = false;
            }
            HirKind::Alternation(_) => {
                if let Some(pattern) = self.finish_literal() {
                    self.alternatives.push(pattern);
                }
                let alternatives = mem::take(&mut self.alternatives);
                self.pieces.push(PatternPiece::Alternation(alternatives));
                self.in_alternation = false;
            }
            _ => {}
        }

        Ok(())
    }

    fn visit_alternation_in(&mut self) -> Result<(), Self::Err> {
        if let Some(pattern) = self.finish_literal() {
            self.alternatives.push(pattern);
        }
        Ok(())
    }
}

/// Helper type for emitting a sequence of instructions for
/// [`re::fast::fastvm::FastVM`].
#[derive(Default)]
struct InstrSeq {
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

    pub fn emit_jump_exact(&mut self, len: u16, accept_newlines: bool) {
        if accept_newlines {
            self.seq.write_all(&[Instr::JUMP_EXACT]).unwrap();
        } else {
            self.seq.write_all(&[Instr::JUMP_EXACT_NO_NEWLINE]).unwrap();
        }
        self.seq.write_all(len.to_le_bytes().as_slice()).unwrap();
    }

    pub fn emit_jump(
        &mut self,
        min: u16,
        max: Option<u16>,
        accept_newlines: bool,
    ) {
        if accept_newlines {
            self.seq.write_all(&[Instr::JUMP]).unwrap();
        } else {
            self.seq.write_all(&[Instr::JUMP_NO_NEWLINE]).unwrap();
        }
        self.seq.write_all(min.to_le_bytes().as_slice()).unwrap();
        // When `max` is `None` it is encoded as 0 in the opcode. This is ok
        // because jumps with an upper bound of 0 are not allowed.
        self.seq.write_all(max.unwrap_or(0).to_le_bytes().as_slice()).unwrap();
    }

    pub fn emit_pattern(&mut self, pattern: &Pattern) {
        match pattern {
            Pattern::Literal(literal) => {
                assert!(literal.len() < u16::MAX as usize);
                let len = u16::to_le_bytes(literal.len().try_into().unwrap());
                self.seq.write_all(&[Instr::LITERAL]).unwrap();
                self.seq.write_all(len.as_slice()).unwrap();
                self.seq.write_all(literal).unwrap();
            }
            Pattern::Masked(literal, mask) => {
                assert!(literal.len() < u16::MAX as usize);
                assert_eq!(literal.len(), mask.len());
                let len = u16::to_le_bytes(literal.len().try_into().unwrap());
                self.seq.write_all(&[Instr::MASKED_LITERAL]).unwrap();
                self.seq.write_all(len.as_slice()).unwrap();
                self.seq.write_all(literal).unwrap();
                self.seq.write_all(mask).unwrap();
            }
        }
    }

    pub fn emit_alternation(
        &mut self,
        alternatives: &Vec<Pattern>,
    ) -> Result<(), Error> {
        debug_assert!(alternatives.len() <= MAX_ALTERNATIVES.into());
        // Write the opcode. The opcode will be followed by an u16 with the
        // size of all the alternatives. The code for the alternatives comes
        // after the size.
        self.seq.write_all(&[Instr::ALTERNATION]).unwrap();
        // Store the location where the size of the alternatives will be put,
        // this location is needed for patching the size later.
        let len_location = self.seq.position();
        // The size is initially filled with zeroes.
        self.seq.write_all(&[0x00; size_of::<u16>()]).unwrap();
        // Store the location where the alternatives start, for computing the
        // size later.
        let alternatives_loc = self.seq.position();
        // Emit all alternatives.
        for pattern in alternatives {
            self.emit_pattern(pattern);
        }
        // Calculate the size of alternatives.
        let alternatives_len = self.seq.position() - alternatives_loc;
        // The size of alternatives should fit in a u16.
        let alternatives_len =
            alternatives_len.try_into().map_err(|_| Error::TooLarge)?;
        self.seq.seek(SeekFrom::Start(len_location)).unwrap();
        self.seq
            .write_all(u16::to_le_bytes(alternatives_len).as_slice())
            .unwrap();
        // Go back to the end of the code.
        self.seq.seek(SeekFrom::End(0)).unwrap();

        Ok(())
    }
}
