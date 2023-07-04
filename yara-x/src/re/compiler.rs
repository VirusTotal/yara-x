/*!
This module provides a compiler that takes a regex's [`Hir`] and produces a
sequence of instructions for a Pike's VM similar to the one described in
https://swtch.com/~rsc/regexp/regexp2.html

More specifically, the compiler produces two instruction sequences, one that
matches the regexp left-to-right, and another one that matches right-to-left.
*/
use bstr::ByteSlice;
use regex_syntax::hir;
use regex_syntax::hir::{visit, Class, Hir, HirKind, Literal};
use std::cmp::min;
use std::collections::HashMap;
use yara_x_parser::ast::HexByte;

use crate::compiler::{any_byte, class_to_hex_byte, Atom, DESIRED_ATOM_SIZE};
use crate::re::instr::{Instr, InstrSeq, NumAlternatives};
use crate::{compiler, re};

#[derive(Eq, PartialEq, Clone, Copy, Debug, Default)]
pub(crate) struct Location {
    pub fwd: u64,
    pub bck_seq_id: u64,
    pub bck: u64,
}

impl Location {
    fn sub(&self, rhs: &Self) -> Offset {
        Offset {
            fwd: (self.fwd as i64 - rhs.fwd as i64)
                .try_into()
                .expect("regexp too large"),
            bck: (self.bck as i64 - rhs.bck as i64)
                .try_into()
                .expect("regexp too large"),
        }
    }
}

pub(crate) struct Offset {
    fwd: re::instr::Offset,
    bck: re::instr::Offset,
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) struct RegexpAtom {
    pub atom: Atom,
    pub code_loc: Location,
}

/// Compiles a regular expression.
#[derive(Default)]
pub(crate) struct Compiler {
    /// Code for the Pike VM that matches the regexp left-to-right.
    forward_code: InstrSeq,

    /// Code for the Pike VM that matches the regexp right-to-left.
    backward_code: InstrSeq,

    /// Stack that stores the locations that the compiler needs to remember.
    /// For example, when some instruction that jumps forward in the code is
    /// emitted, the destination address is not yet known. The compiler needs
    /// to save the jump's address in order to patch the instruction and adjust
    /// the destination address once its known.
    bookmarks: Vec<Location>,

    /// Best atoms found so far. This is a stack where each entry is a list of
    /// atoms. Each entry also has an `i32` that indicates the quality of the
    /// list of atoms, which corresponds to the quality of the lowest quality
    /// atom in the list.
    best_atoms: Vec<(i32, Vec<RegexpAtom>)>,

    /// When writing the backward code for a `HirKind::Concat` node we can't
    /// simply write the code directly to `backward_code` because the children
    /// of `Concat` are visited left-to-right, and we need them right-to-left.
    /// Instead, the code produced by each child of `Concat` is stored in a
    /// temporary [`InstrSeq`], and once all the children are processed the
    /// final code is written into `backward_code` by copying the temporary
    /// [`InstrSeq`]s one by one in reverse order. Each of these temporary
    /// [`InstrSeq`] is called a chunk, and they are stored in this stack of
    /// chunks.
    backward_code_chunks: Vec<InstrSeq>,

    /// Literal extractor.
    lit_extractor: hir::literal::Extractor,
}

impl Compiler {
    pub fn new() -> Self {
        let mut lit_extractor = hir::literal::Extractor::new();
        lit_extractor.limit_total(256);
        lit_extractor.limit_literal_len(DESIRED_ATOM_SIZE);

        Self {
            lit_extractor,
            forward_code: InstrSeq::new(0),
            backward_code: InstrSeq::new(0),
            backward_code_chunks: Vec::new(),
            bookmarks: Vec::new(),
            best_atoms: vec![(i32::MIN, Vec::new())],
        }
    }

    pub fn compile(
        mut self,
        hir: &Hir,
    ) -> (InstrSeq, InstrSeq, Vec<RegexpAtom>) {
        visit(hir, &mut self).unwrap();
        (
            self.forward_code,
            self.backward_code,
            self.best_atoms.pop().unwrap().1,
        )
    }
}

impl Compiler {
    #[inline]
    fn backward_code(&self) -> &InstrSeq {
        self.backward_code_chunks.last().unwrap_or(&self.backward_code)
    }

    #[inline]
    fn backward_code_mut(&mut self) -> &mut InstrSeq {
        self.backward_code_chunks.last_mut().unwrap_or(&mut self.backward_code)
    }

    fn location(&self) -> Location {
        Location {
            fwd: self.forward_code.location(),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code().location(),
        }
    }

    fn emit_instr(&mut self, instr: Instr) -> Location {
        Location {
            fwd: self.forward_code.emit_instr(instr),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_instr(instr),
        }
    }

    fn emit_split_n(&mut self, n: NumAlternatives) -> Location {
        Location {
            fwd: self.forward_code.emit_split_n(n),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_split_n(n),
        }
    }

    fn emit_masked_byte(&mut self, b: HexByte) -> Location {
        Location {
            fwd: self.forward_code.emit_masked_byte(b),
            bck_seq_id: self.backward_code.seq_id(),
            bck: self.backward_code_mut().emit_masked_byte(b),
        }
    }

    fn emit_literal(&mut self, literal: &Literal) -> Location {
        Location {
            fwd: self.forward_code.emit_literal(literal.0.iter()),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_literal(literal.0.iter().rev()),
        }
    }

    fn patch_instr(&mut self, location: &Location, offset: Offset) {
        self.forward_code.patch_instr(location.fwd, offset.fwd);
        self.backward_code_mut().patch_instr(location.bck, offset.bck);
    }

    fn patch_split_n<I: ExactSizeIterator<Item = Offset>>(
        &mut self,
        location: &Location,
        offsets: I,
    ) {
        let mut fwd = Vec::with_capacity(offsets.len());
        let mut bck = Vec::with_capacity(offsets.len());

        for o in offsets {
            fwd.push(o.fwd);
            bck.push(o.bck);
        }

        self.forward_code.patch_split_n(location.fwd, fwd.into_iter());
        self.backward_code_mut().patch_split_n(location.bck, bck.into_iter());
    }
}

impl hir::Visitor for &mut Compiler {
    type Output = ();
    type Err = std::io::Error;

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(())
    }

    fn visit_pre(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match hir.kind() {
            HirKind::Literal(_) => {}
            HirKind::Class(_) => {}
            HirKind::Capture(_) => {
                self.bookmarks.push(self.location());
            }
            HirKind::Concat(_) => {
                self.bookmarks.push(self.location());

                // A new child of a `Concat` node is about to be processed,
                // create the chunk that will receive the code for this child.
                self.backward_code_chunks
                    .push(InstrSeq::new(self.backward_code().seq_id() + 1));
            }
            HirKind::Alternation(alternatives) => {
                // e1|e2|....|eN
                //
                // l0: split_n l1,l2,l3
                // l1: ... code for e1 ...
                //     jump l4
                // l2: ... code for e2 ...
                //     jump l4
                //     ....
                // lN: ... code for eN ...
                // lEND:
                // TODO: make sure that the number of alternatives is 255 or
                // less. Maybe return an error from here.
                let l0 =
                    self.emit_split_n(alternatives.len().try_into().unwrap());

                self.bookmarks.push(l0);
                self.bookmarks.push(self.location());

                self.best_atoms.push((0, Vec::new()))
            }
            HirKind::Repetition(rep) => {
                match (rep.min, rep.max, rep.greedy) {
                    // e* and e*?
                    //
                    // l1: split l1,l3  ( l3,l1 for the non-greedy e*? )
                    //     ... code for e ...
                    // l2: jump l1
                    // l3:
                    (0, None, greedy) => {
                        let l1 = self.emit_instr(if greedy {
                            Instr::SplitA
                        } else {
                            Instr::SplitB
                        });
                        self.bookmarks.push(l1);
                    }
                    // e+ and e+?
                    //
                    // l1: ... code for e ...
                    // l2: split l1,l3  ( l3,l1 for the non-greedy e+? )
                    // l3:
                    (1, None, _) => {
                        let l1 = self.location();
                        self.bookmarks.push(l1);
                    }
                    _ => {}
                }
            }
            kind @ _ => unreachable!("{:?}", kind),
        }

        Ok(())
    }

    fn visit_post(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        let mut loc;

        match hir.kind() {
            HirKind::Capture(_) => {
                loc = self.bookmarks.pop().unwrap();
            }
            HirKind::Literal(literal) => {
                loc = self.emit_literal(literal);
                // TODO: replace with function that returns the length of the
                // code produced by literal, taking into account that 0xAA is
                // two bytes.
                loc.bck += literal.0.len() as u64;
            }
            hir_kind @ HirKind::Class(class) => {
                loc = self.location();
                if any_byte(hir_kind) {
                    self.emit_instr(Instr::AnyByte);
                } else {
                    match class {
                        Class::Bytes(class) => {
                            if let Some(byte) = class_to_hex_byte(class) {
                                self.emit_masked_byte(byte);
                            } else {
                                todo!()
                            }
                        }
                        Class::Unicode(_) => {}
                    }
                }
            }
            HirKind::Concat(exprs) => {
                loc = self.bookmarks.pop().unwrap();
                // We are here because all the children of a `Concat` node have
                // been processed. The last N chunks in `backward_code_chunks`
                // contain the code produced for each of the N children, but
                // the nodes where processed left-to-right, and we want the
                // chunks right-to-left, so these last N chunks must be
                // reversed while copied.
                let n = exprs.len();
                let len = self.backward_code_chunks.len();

                // Split `backward_code_chunks` in two halves, [0, len-n) and
                // [len-n, len). The first half stays in `backward_code_chunks`
                // while the second half is stored in `last_n_chunks`.
                let last_n_chunks =
                    self.backward_code_chunks.split_off(len - n);

                // Obtain a reference to the backward code, which can be either
                // the chunk at the top of the `backward_code_chunks` stack or
                // `self.backward_code` if the stack is empty.
                let backward_code = self
                    .backward_code_chunks
                    .last_mut()
                    .unwrap_or(&mut self.backward_code);

                let mut chunk_locations = HashMap::new();

                // All chunks in `last_n_chucks` will be appended to the
                // backward code in reverse order. The offset where each chunk
                // resides in the backward code is stored in map.
                for chunk in last_n_chunks.iter().rev() {
                    chunk_locations
                        .insert(chunk.seq_id(), backward_code.location());
                    backward_code.append(chunk);
                }

                let (_, atoms) = self.best_atoms.last_mut().unwrap();

                // Atoms may be pointing to some code located in one of
                // the chunks, the backward code location for those atoms need
                // to be adjusted accordingly.
                for atom in atoms {
                    if let Some(delta) =
                        chunk_locations.get(&atom.code_loc.bck_seq_id)
                    {
                        atom.code_loc.bck_seq_id = backward_code.seq_id();
                        atom.code_loc.bck += delta;
                    }
                }
            }
            HirKind::Alternation(exprs) => {
                // e1|e2|....|eN
                //
                //         split_n l1,l2,l3
                // l1    : ... code for e1 ...
                // l1_j  : jump l_end
                // l2    : ... code for e2 ...
                // l2_j  : jump l_end
                //
                // lN    : ... code for eN ...
                // l_end :
                let n = exprs.len();
                let l_end = self.location();

                let mut expr_locs = Vec::with_capacity(n);

                // Now that we know the ending location, patch the N - 1 jumps
                // between alternatives.
                for _ in 0..n - 1 {
                    expr_locs.push(self.bookmarks.pop().unwrap());
                    let ln_j = self.bookmarks.pop().unwrap();
                    self.patch_instr(&ln_j, l_end.sub(&ln_j));
                }

                expr_locs.push(self.bookmarks.pop().unwrap());

                let split_loc = self.bookmarks.pop().unwrap();
                loc = split_loc;

                let offsets =
                    expr_locs.into_iter().rev().map(|loc| loc.sub(&split_loc));

                self.patch_split_n(&split_loc, offsets);

                // Remove the last N items from best atoms and put them in
                // `last_n`. These last N items correspond to each of the N
                // alternatives.
                let last_n =
                    self.best_atoms.split_off(self.best_atoms.len() - n);

                // Join the atoms from all alternatives together. The quality
                // is the quality of the worst alternative.
                let alternative_atoms = last_n
                    .into_iter()
                    .reduce(|mut all, (quality, mut atoms)| {
                        all.1.append(&mut atoms);
                        (min(all.0, quality), all.1)
                    })
                    .unwrap();

                // Use the atoms extracted from the alternatives if they are
                // better than the best atoms so far.
                let best_atoms = self.best_atoms.last_mut().unwrap();

                if best_atoms.0 < alternative_atoms.0 {
                    *best_atoms = alternative_atoms;
                }
            }
            HirKind::Repetition(rep) => {
                match (rep.min, rep.max, rep.greedy) {
                    // e* and e*?
                    //
                    // l1: split l1,l3  ( l3,l1 for the non-greedy e*? )
                    //     ... code for e ...
                    // l2: jump l1
                    // l3:
                    (0, None, _) => {
                        let l1 = self.bookmarks.pop().unwrap();
                        let l2 = self.emit_instr(Instr::Jump);
                        let l3 = self.location();
                        self.patch_instr(&l1, l3.sub(&l1));
                        self.patch_instr(&l2, l1.sub(&l2));

                        loc = l1;
                    }
                    // e+ and e+?
                    //
                    // l1: ... code for e ...
                    // l2: split l1,l3  ( l3,l1 for the non-greedy e+? )
                    // l3:
                    (1, None, greedy) => {
                        let l1 = self.bookmarks.pop().unwrap();
                        let l2 = self.emit_instr(if greedy {
                            Instr::SplitB
                        } else {
                            Instr::SplitA
                        });
                        self.patch_instr(&l2, l1.sub(&l2));

                        loc = l1;
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }

        if let Some(literals) = self.lit_extractor.extract(hir).literals() {
            // Compute the minimum quality of all the literals
            let min_quality = literals
                .iter()
                .map(|l| compiler::atom_quality2(l.as_bytes()))
                .min();

            if let Some(quality) = min_quality {
                let (best_quality, best_atoms) =
                    self.best_atoms.last_mut().unwrap();

                if quality > *best_quality {
                    *best_quality = quality;
                    *best_atoms = literals
                        .iter()
                        .map(|l| RegexpAtom {
                            atom: Atom::from(l.as_bytes().bytes()),
                            code_loc: loc,
                        })
                        .collect();
                }
            }
        }

        Ok(())
    }

    fn visit_alternation_in(&mut self) -> Result<(), Self::Err> {
        // Emit the jump that appears between alternatives and jump to
        // the end.
        let l = self.emit_instr(Instr::Jump);
        // The jump's destination is not known yet, so save the jump's
        // address in order to patch the destination later.
        self.bookmarks.push(l);
        // Save the location of the current alternative. This is used for
        // patching the `split_n` instruction later.
        self.bookmarks.push(self.location());
        // The best atoms for this alternative are independent from the
        // other alternatives.
        self.best_atoms.push((0, Vec::new()));
        Ok(())
    }

    fn visit_concat_in(&mut self) -> Result<(), Self::Err> {
        // A new child of a `Concat` node is about to be processed,
        // create the chunk that will receive the code for this child.
        self.backward_code_chunks
            .push(InstrSeq::new(self.backward_code().seq_id() + 1));

        Ok(())
    }
}
