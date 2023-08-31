use crate::compiler::{best_range_in_bytes, best_range_in_masked_bytes, Atom};

use bstr::ByteSlice;
use regex_syntax::hir::{visit, Class, Hir, HirKind, Visitor};
use std::mem;

use crate::re;
use crate::re::fast::instr::InstrSeq;
use crate::re::{BckCodeLoc, Error, FwdCodeLoc, RegexpAtom};

/// A compiler that takes a [`re::hir::Hir`] and produces code for the
/// VM represented by [`re::fast::FastVM`].
///
/// This compiler accepts only a subset of the regular expressions.
///
pub(crate) struct Compiler {}

impl Compiler {
    pub fn new() -> Self {
        Self {}
    }

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
                rep_level: 0,
            },
        )?;

        let mut best_quality = i32::MIN;
        let mut best_bytes = None;
        let mut best_mask = None;
        let mut best_range = None;
        let mut best_piece = 0;

        // Iterate the pieces, looking for the one that contains the best
        // possible atom. In `{ ?1 02 03 [3-4] 04 05 06 }` the piece with the
        // best atom is `04 05 06`.
        for (i, piece) in pieces.iter().enumerate() {
            let (bytes, mask, range, quality) = match piece {
                PatternPiece::Literal(bytes) => {
                    let (range, quality) =
                        best_range_in_bytes(bytes.as_slice());

                    (Some(bytes.as_slice()), None, Some(range), quality)
                }
                PatternPiece::MaskedLiteral(bytes, mask) => {
                    let (range, quality) = best_range_in_masked_bytes(
                        bytes.as_slice(),
                        mask.as_slice(),
                    );
                    (
                        Some(bytes.as_slice()),
                        Some(mask.as_slice()),
                        Some(range),
                        quality,
                    )
                }
                PatternPiece::Jump(_) | PatternPiece::JumpRange(_, _) => {
                    (None, None, None, i32::MIN)
                }
            };
            if quality > best_quality {
                best_piece = i;
                best_quality = quality;
                best_bytes = bytes;
                best_mask = mask;
                best_range = range;
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
                self.emit_piece(piece, &mut bck_code);
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
            self.emit_piece(piece, &mut fwd_code);
        }

        fwd_code.emit_match();
        code.extend_from_slice(fwd_code.into_inner().as_slice());

        let mut atoms = Vec::new();

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

        // If the pattern was decomposed into more than one piece its atoms can
        // not be exact. The atoms could be exact if the pattern was is a single
        // piece and it fits completely in the atom.
        if pieces.len() > 1 {
            for atom in atoms.iter_mut() {
                atom.set_exact(false);
            }
        }

        Ok(atoms)
    }

    fn emit_piece(&mut self, piece: &PatternPiece, instr: &mut InstrSeq) {
        match piece {
            PatternPiece::Literal(bytes) => instr.emit_literal(bytes),
            PatternPiece::MaskedLiteral(bytes, mask) => {
                instr.emit_masked_literal(bytes, mask)
            }
            PatternPiece::Jump(len) => instr.emit_jump(*len),
            PatternPiece::JumpRange(min, max) => {
                instr.emit_jump_range(*min, *max)
            }
        }
    }
}

/// Represents the pieces in which patterns are decomposed during compilation.
///
/// Patterns accepted by the Fast VM can be decomposed into a sequence of
/// pieces where each piece is either a literal, a masked literal, or a jump.
/// For example, the pattern `{ 01 02 03 [0-2] 04 0? 06 }` is decomposed into
/// the sequence:
///
/// ```text
/// Literal([01, 02, 03])
/// Jump(0,2)
/// MaskedLiteral([04, 00, 06], [FF, F0, FF])
/// ```
enum PatternPiece {
    Literal(Vec<u8>),
    MaskedLiteral(Vec<u8>, Vec<u8>),
    JumpRange(u16, u16),
    Jump(u16),
}

/// Given the HIR for a regexp pattern, decomposed it in [`PatternPiece`]s.
struct PatternSplitter {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    pieces: Vec<PatternPiece>,
    rep_level: u32,
}

impl PatternSplitter {
    fn finish_literal(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        self.pieces.push(
            // If all bytes in the mask are 0xff the piece is a
            // Literal and the mask is not necessary, if not,
            // the piece is a MaskedLiteral. In both cases the mask
            // and the bytes are reset to empty vectors.
            if self.mask.iter().all(|&b| b == 0xff) {
                self.mask.clear();
                PatternPiece::Literal(mem::take(&mut self.bytes))
            } else {
                PatternPiece::MaskedLiteral(
                    mem::take(&mut self.bytes),
                    mem::take(&mut self.mask),
                )
            },
        );
    }
}

impl Visitor for PatternSplitter {
    type Output = Vec<PatternPiece>;
    type Err = Error;

    fn finish(mut self) -> Result<Self::Output, Self::Err> {
        self.finish_literal();
        Ok(self.pieces)
    }

    fn visit_pre(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match hir.kind() {
            // Repetitions are ok, as long as they are a non-greedy and
            // the pattern repeated is any byte. Jumps in hex patterns
            // (eg: [1], [10-20]) are expressed as one of such repetitions.
            // These jumps behave as delimiters between pattern pieces.
            HirKind::Repetition(rep) => {
                if !rep.greedy && re::hir::any_byte(rep.sub.kind()) {
                    self.rep_level += 1
                } else {
                    return Err(Error::FastIncompatible);
                }
            }
            HirKind::Capture(_)
            | HirKind::Look(_)
            | HirKind::Alternation(_) => return Err(Error::FastIncompatible),
            _ => {}
        }
        Ok(())
    }

    fn visit_post(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        if matches!(hir.kind(), HirKind::Repetition(_)) {
            self.rep_level -= 1;
        }
        if self.rep_level > 0 {
            return Ok(());
        }
        match hir.kind() {
            HirKind::Literal(literal) => {
                self.bytes.extend_from_slice(literal.0.as_bytes());
                self.mask.extend(itertools::repeat_n(0xff, literal.0.len()));
            }
            HirKind::Class(class) => match class {
                Class::Bytes(class) => {
                    if let Some(masked_byte) =
                        re::hir::class_to_masked_byte(class)
                    {
                        self.bytes.push(masked_byte.value);
                        self.mask.push(masked_byte.mask);
                    } else {
                        return Err(Error::FastIncompatible);
                    }
                }
                Class::Unicode(_) => {
                    return Err(Error::FastIncompatible);
                }
            },
            HirKind::Repetition(rep) => {
                // Repetitions are ok, as long as they are a non-greedy and
                // the pattern repeated is any byte. Jumps in hex patterns
                // (eg: [1], [10-20]) are expressed as one of such repetitions.
                // These jumps behave as delimiters between pattern pieces.
                match (rep.min, rep.max) {
                    // When the jump has a fixed size <= 8 treat it as a
                    // sequence of ?? wildcards. It's more efficient to
                    // treat short fixed size jumps as a sequence of
                    // wildcards than breaking the pattern into more
                    // pieces.
                    (min, Some(max)) if min == max && max <= 8 => {
                        for _ in 0..max {
                            self.bytes.push(0);
                            self.mask.push(0);
                        }
                    }
                    (min, Some(max)) => {
                        self.finish_literal();
                        if min == max {
                            self.pieces.push(PatternPiece::Jump(min as u16));
                        } else {
                            self.pieces.push(PatternPiece::JumpRange(
                                min as u16, max as u16,
                            ));
                        }
                    }
                        // This should not happen. Regexp patterns are split
                        // into multiple chained patterns by calling
                        // re::hir::Hir::split_at_large_gaps before being passed
                        // to this compiler. Therefore patterns should not
                        // contain unbounded jumps when are compiled.
                        (_, None) => {
                            unreachable!()
                        }
                }
            }
            HirKind::Empty => {}
            HirKind::Concat(_) => {}
            _ => unreachable!(),
        }

        Ok(())
    }
}
