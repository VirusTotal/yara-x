/*!
This module provides a compiler that takes a regex's [`Hir`] and produces a
sequence of instructions for the Pike's VM.

More specifically, the compiler produces two instruction sequences, one that
matches the regexp left-to-right, and another one that matches right-to-left.
*/

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::iter::zip;
use std::mem::{size_of, size_of_val};
use std::slice::IterMut;

use bitvec::array::BitArray;
use bitvec::order::Lsb0;

use regex_syntax::hir;
use regex_syntax::hir::literal::Seq;
use regex_syntax::hir::{
    visit, Class, ClassBytes, Hir, HirKind, Literal, Look, Repetition, Visitor,
};

use super::instr;
use super::instr::{literal_code_length, Instr, NumAlt, OPCODE_PREFIX};

use crate::compiler::{
    best_atom_in_bytes, Atom, AtomsQuality, DESIRED_ATOM_SIZE,
    MAX_ATOMS_PER_REGEXP,
};

use crate::re;
use crate::re::hir::HexByte;
use crate::re::thompson::instr::{InstrParser, SplitId};
use crate::re::{BckCodeLoc, Error, FwdCodeLoc, MAX_ALTERNATIVES};

#[derive(Eq, PartialEq, Clone, Copy, Debug, Default)]
pub(crate) struct CodeLoc {
    pub fwd: usize,
    pub bck_seq_id: u64,
    pub bck: usize,
}

impl CodeLoc {
    fn sub(&self, rhs: &Self) -> Result<CodeLocOffset, Error> {
        Ok(CodeLocOffset {
            fwd: (self.fwd as isize - rhs.fwd as isize)
                .try_into()
                .map_err(|_| Error::TooLarge)?,
            bck: (self.bck as isize - rhs.bck as isize)
                .try_into()
                .map_err(|_| Error::TooLarge)?,
        })
    }
}

struct CodeLocOffset {
    fwd: instr::Offset,
    bck: instr::Offset,
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) struct RegexpAtom {
    pub atom: Atom,
    pub code_loc: CodeLoc,
}

/// Compiles a regular expression.
///
/// Compiling a regexp consists in performing a DFS traversal of the HIR tree
/// while emitting code for the Pike VM and extracting the atoms that will be
/// passed to the Aho-Corasick algorithm.
///
/// Atoms are short literals (the length is controlled by [`DESIRED_ATOM_SIZE`])
/// that are extracted from the regexp and must present in any matching
/// string. Idealistically, the compiler will extract a single, long-enough
/// atom from the regexp, but in those cases where extracting a single atom is
/// not possible (or would be too short), the compiler can extract multiple
/// atoms from the regexp. When any of the atom is found in the scanned data
/// by the Aho-Corasick algorithm, the scanner proceeds to verify if the regexp
/// matches by executing the Pike VM code.
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
    bookmarks: Vec<CodeLoc>,

    /// Best atoms found so far. This is a stack where each entry is a list of
    /// atoms, represented by [`RegexpAtoms`].
    best_atoms_stack: Vec<RegexpAtoms>,

    /// When writing the backward code for a `HirKind::Concat` node we can't
    /// simply write the code directly to `backward_code` because the children
    /// of `Concat` are visited left-to-right, and we need them right-to-left.
    /// Instead, the code produced by each child of `Concat` is stored in a
    /// temporary [`InstrSeq`], and once all the children are processed the
    /// final code is written into `backward_code` by copying the temporary
    /// [`InstrSeq`]s in reverse order. Each of these temporary [`InstrSeq`]
    /// is called a chunk, and they are stored in this stack.
    backward_code_chunks: Vec<InstrSeq>,

    /// Literal extractor.
    lit_extractor: hir::literal::Extractor,

    /// How deep in the HIR we currently are. The top-level node has `depth` 1.
    depth: u32,

    /// Similar to `depth`, but indicates the number of possibly zero length
    /// `Repetition` nodes from the current node to the top-level node. For
    /// instance, in `/a(b(cd)*e)*f/` the `cd` literal is inside a repetition
    /// that could be zero-length, and the same happens with `b(cd)e`. The
    /// value of  `zero_rep_depth` when visiting `cd` is 2.
    ///
    /// This used for determining whether to extract atoms from certain nodes
    /// in the HIR or not. Extracting atoms from a subtree under a zero-length
    /// repetition doesn't make sense, atoms must be extracted from portions of
    /// the pattern that are required to be present in any matching string.
    zero_rep_depth: u32,
}

impl Compiler {
    /// Creates a new regexp compiler.
    pub fn new() -> Self {
        let mut lit_extractor = hir::literal::Extractor::new();

        // Maximum number of atoms extracted for a character class.
        lit_extractor.limit_class(256);

        // Maximum number of atoms extracted from each pattern. The literal
        // extractor will try to keep the number of atoms per pattern below
        // this limit, but if it fails to do so it will result in a 0-length
        // atom used for that pattern, with a significant negative effect on
        // performance. For very complex patterns this number may be too low
        // to accommodate all the atoms the literal extractor will produce,
        // but an explosion in the number of atoms is not desirable neither,
        // so this is a tradeoff. Perhaps this could be configurable, so that
        // users can increase the number if they start getting warnings due
        // to 0-length atoms, but for the time being let's use a number that
        // seems to work fine in most cases.
        lit_extractor.limit_total(MAX_ATOMS_PER_REGEXP);

        lit_extractor.limit_literal_len(DESIRED_ATOM_SIZE);
        lit_extractor.limit_repeat(DESIRED_ATOM_SIZE);

        Self {
            lit_extractor,
            forward_code: InstrSeq::new(),
            backward_code: InstrSeq::new(),
            backward_code_chunks: Vec::new(),
            bookmarks: Vec::new(),
            best_atoms_stack: vec![RegexpAtoms::empty()],
            depth: 0,
            zero_rep_depth: 0,
        }
    }

    /// Given the high-level intermediate representation (HIR) of a regular
    /// expression, produces code for the PikeVM that matches the regular
    /// expression and returns a set of atoms extracted from it.
    ///
    /// The code for the PikeVM is appended to the `code` vector, and the
    /// returned atoms contain the location within the code where the PikeVM
    /// should start the execution when the atom is found.
    pub fn compile(
        self,
        hir: &re::hir::Hir,
        code: &mut Vec<u8>,
    ) -> Result<Vec<re::RegexpAtom>, Error> {
        let (fwd_code, bck_code, atoms) = self.compile_internal(hir)?;

        // `fwd_code_start` will contain the offset within the `code` vector
        // where the forward code resides.
        let fwd_code_start = code.len();
        code.append(&mut fwd_code.into_inner());

        // `bck_code_start` will contain the offset within the `code` vector
        // where the backward code resides.
        let bck_code_start = code.len();
        code.append(&mut bck_code.into_inner());

        let atoms = atoms
            .into_iter()
            .map(|a| re::RegexpAtom {
                atom: a.atom,
                fwd_code: Some(FwdCodeLoc::from(
                    a.code_loc.fwd + fwd_code_start,
                )),
                bck_code: Some(BckCodeLoc::from(
                    a.code_loc.bck + bck_code_start,
                )),
            })
            .collect();

        Ok(atoms)
    }
}

impl Compiler {
    pub(super) fn compile_internal(
        self,
        hir: &re::hir::Hir,
    ) -> Result<(InstrSeq, InstrSeq, Vec<RegexpAtom>), Error> {
        let start_loc = self.location();

        let (mut backward_code, mut forward_code, mut atoms) =
            visit(&hir.inner, self)?;

        forward_code.emit_instr(Instr::MATCH)?;
        backward_code.emit_instr(Instr::MATCH)?;

        if atoms.is_empty() {
            atoms.push(RegexpAtom {
                atom: Atom::inexact([]),
                code_loc: start_loc,
            })
        }

        assert!(atoms.len() <= MAX_ATOMS_PER_REGEXP);

        Ok((forward_code, backward_code, atoms))
    }

    #[inline]
    fn forward_code(&self) -> &InstrSeq {
        &self.forward_code
    }

    #[inline]
    fn forward_code_mut(&mut self) -> &mut InstrSeq {
        &mut self.forward_code
    }

    #[inline]
    fn backward_code(&self) -> &InstrSeq {
        self.backward_code_chunks.last().unwrap_or(&self.backward_code)
    }

    #[inline]
    fn backward_code_mut(&mut self) -> &mut InstrSeq {
        self.backward_code_chunks.last_mut().unwrap_or(&mut self.backward_code)
    }

    fn location(&self) -> CodeLoc {
        CodeLoc {
            fwd: self.forward_code().location(),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code().location(),
        }
    }

    fn emit_instr(&mut self, instr: u8) -> Result<CodeLoc, Error> {
        Ok(CodeLoc {
            fwd: self.forward_code_mut().emit_instr(instr)?,
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_instr(instr)?,
        })
    }

    fn emit_split_n(&mut self, n: NumAlt) -> Result<CodeLoc, Error> {
        Ok(CodeLoc {
            fwd: self.forward_code_mut().emit_split_n(n)?,
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_split_n(n)?,
        })
    }

    fn emit_masked_byte(&mut self, b: HexByte) -> CodeLoc {
        CodeLoc {
            fwd: self.forward_code_mut().emit_masked_byte(b),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_masked_byte(b),
        }
    }

    fn emit_class(&mut self, c: &ClassBytes) -> CodeLoc {
        CodeLoc {
            fwd: self.forward_code_mut().emit_class(c),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_class(c),
        }
    }

    fn emit_literal(&mut self, literal: &Literal) -> CodeLoc {
        CodeLoc {
            fwd: self.forward_code_mut().emit_literal(literal.0.iter()),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_literal(literal.0.iter().rev()),
        }
    }

    fn emit_clone(
        &mut self,
        start: CodeLoc,
        end: CodeLoc,
    ) -> Result<CodeLoc, Error> {
        Ok(CodeLoc {
            fwd: self.forward_code_mut().emit_clone(start.fwd, end.fwd)?,
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_clone(start.bck, end.bck)?,
        })
    }

    fn patch_instr(&mut self, location: &CodeLoc, offset: CodeLocOffset) {
        self.forward_code_mut().patch_instr(location.fwd, offset.fwd);
        self.backward_code_mut().patch_instr(location.bck, offset.bck);
    }

    fn patch_split_n<I: ExactSizeIterator<Item = CodeLocOffset>>(
        &mut self,
        location: &CodeLoc,
        offsets: I,
    ) {
        let mut fwd = Vec::with_capacity(offsets.len());
        let mut bck = Vec::with_capacity(offsets.len());

        for o in offsets {
            fwd.push(o.fwd);
            bck.push(o.bck);
        }

        self.forward_code_mut().patch_split_n(location.fwd, fwd.into_iter());
        self.backward_code_mut().patch_split_n(location.bck, bck.into_iter());
    }

    fn visit_post_class(&mut self, class: &Class) -> Result<CodeLoc, Error> {
        match class {
            Class::Bytes(class) => {
                if let Some(byte) = re::hir::class_to_masked_byte(class) {
                    Ok(self.emit_masked_byte(byte))
                } else {
                    Ok(self.emit_class(class))
                }
            }
            Class::Unicode(class) => {
                // Unicode classes can appear even on regexps that were compiled
                // without unicode support. This a well-known issue with the
                // `regex-syntax` crate, and we should be able to handle it.
                // See: https://github.com/rust-lang/regex/issues/1088
                //
                // The first thing we do is trying to covert the unicode class
                // into a byte class. If that's not possible, the alternative
                // is converting the unicode class to an alternation of literals,
                // where each literal is the UTF-8 encoding of one character in
                // the class.
                if let Some(class) = class.to_byte_class() {
                    Ok(self.emit_class(&class))
                } else {
                    let mut lits = Vec::new();
                    for range in class.ranges() {
                        for unicode_char in range.start()..=range.end() {
                            let mut buf: [u8; 4] = [0; 4];
                            lits.push(Hir::literal(
                                unicode_char.encode_utf8(&mut buf).as_bytes(),
                            ));
                        }
                    }
                    // Using `Hir::alternation` for creating a HIR for the
                    // alternation of literals is not possible, because during
                    // the construction the HIR will be converted into a
                    // unicode class. Therefore, we don't try to create a HIR
                    // node for the alternation, and instead visit the literal
                    // nodes as if they were part of an alternation.
                    self.visit_pre_alternation(&lits)?;
                    for (i, lit) in lits.iter().enumerate() {
                        self.visit_pre(lit)?;
                        self.visit_post(lit)?;
                        if i < lits.len() - 1 {
                            self.visit_alternation_in()?;
                        }
                    }
                    self.visit_post_alternation(&lits)
                }
            }
        }
    }

    fn visit_post_look(&mut self, look: &Look) -> Result<CodeLoc, Error> {
        Ok(match look {
            Look::Start => self.emit_instr(Instr::START)?,
            Look::End => self.emit_instr(Instr::END)?,
            Look::WordAscii => self.emit_instr(Instr::WORD_BOUNDARY)?,
            Look::WordAsciiNegate => {
                self.emit_instr(Instr::WORD_BOUNDARY_NEG)?
            }
            Look::WordStartAscii => self.emit_instr(Instr::WORD_START)?,
            Look::WordEndAscii => self.emit_instr(Instr::WORD_END)?,
            _ => unreachable!("{:?}", look),
        })
    }

    fn visit_pre_concat(&mut self) {
        self.bookmarks.push(self.location());
        // A new child of a `Concat` node is about to be processed,
        // create the chunk that will receive the code for this child.
        self.backward_code_chunks.push(self.backward_code().next());
    }

    fn visit_post_concat(&mut self, expressions: &[Hir]) -> Vec<CodeLoc> {
        // We are here because all the children of a `Concat` node have been
        // processed. The last N chunks in `backward_code_chunks` contain the
        // code produced for each of the N children, but the nodes where
        // processed left-to-right, and we want the chunks right-to-left, so
        // these last N chunks will be copied into backward code in reverse
        // order.
        let n = expressions.len();

        // Split `backward_code_chunks` in two halves, [0, len-n) and
        // [len-n, len). The first half stays in `backward_code_chunks` while
        // the second half is stored in `last_n_chunks`.
        let last_n_chunks = self
            .backward_code_chunks
            .split_off(self.backward_code_chunks.len() - n);

        // Obtain a reference to the backward code corresponding to the `Concat`
        // node. It would be better to use `self.backward_code_mut()`, but it
        // causes a mutable borrow on `self`, while the code below borrows
        // `self.backward_code_chunks` or `self.backward_code` but not `self.
        let backward_code = self
            .backward_code_chunks
            .last_mut()
            .unwrap_or(&mut self.backward_code);

        // Update the split ID for the `Concat` node. If any of the children
        // emitted a split instruction, and therefore incremented its split_id,
        // this increment must be reflected in the parent node (`Concat`), so
        // that any other node emitted after the parent doesn't reuse an already
        // existing split ID.
        if let Some(last_chunks) = last_n_chunks.last() {
            backward_code.split_id = last_chunks.split_id;
        }

        // The top N bookmarks corresponds to the beginning of the code for
        // each expression in the concatenation.
        let mut locations = self.bookmarks.split_off(self.bookmarks.len() - n);

        // Both `locations` and `last_n_chunks` have the same length N.
        debug_assert_eq!(locations.len(), last_n_chunks.len());

        // All chunks in `last_n_chucks` will be appended to the backward code
        // in reverse order. The offset where each chunk resides in the backward
        // code is stored in the hash map.
        let mut chunk_locations = HashMap::new();

        for (location, chunk) in
            zip(locations.iter_mut(), last_n_chunks.iter()).rev()
        {
            chunk_locations.insert(chunk.seq_id(), backward_code.location());
            backward_code.append(chunk);

            location.bck_seq_id = backward_code.seq_id();
            location.bck = backward_code.location();
        }

        // Atoms may be pointing to some code located in one of the chunks that
        // were written to backward code in a different order, the backward code
        // location for those atoms needs to be adjusted accordingly.
        let best_atoms = self.best_atoms_stack.last_mut().unwrap();

        for atom in best_atoms.iter_mut() {
            if let Some(adjustment) =
                chunk_locations.get(&atom.code_loc.bck_seq_id)
            {
                atom.code_loc.bck_seq_id = backward_code.seq_id();
                atom.code_loc.bck += adjustment;
            }
        }

        locations
    }

    fn visit_pre_alternation(
        &mut self,
        alternatives: &[Hir],
    ) -> Result<(), Error> {
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
        debug_assert!(alternatives.len() < 256);

        let l0 = self.emit_split_n(alternatives.len().try_into().unwrap())?;

        self.bookmarks.push(l0);
        self.bookmarks.push(self.location());

        self.best_atoms_stack.push(RegexpAtoms::empty());

        Ok(())
    }

    fn visit_post_alternation(
        &mut self,
        expressions: &[Hir],
    ) -> Result<CodeLoc, Error> {
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
        let n = expressions.len();
        let l_end = self.location();

        let mut expr_locs = Vec::with_capacity(n);

        // Now that we know the ending location, patch the N - 1 jumps
        // between alternatives.
        for _ in 0..n - 1 {
            expr_locs.push(self.bookmarks.pop().unwrap());
            let ln_j = self.bookmarks.pop().unwrap();
            self.patch_instr(&ln_j, l_end.sub(&ln_j)?);
        }

        expr_locs.push(self.bookmarks.pop().unwrap());

        let split_loc = self.bookmarks.pop().unwrap();

        let offsets: Vec<CodeLocOffset> = expr_locs
            .into_iter()
            .rev()
            .map(|loc| loc.sub(&split_loc))
            .collect::<Result<Vec<CodeLocOffset>, Error>>()?;

        self.patch_split_n(&split_loc, offsets.into_iter());

        // Remove the last N items from the best atoms and put them in
        // `last_n`. These last N items correspond to each of the N
        // alternatives.
        let last_n =
            self.best_atoms_stack.split_off(self.best_atoms_stack.len() - n);

        // Join the atoms from all alternatives together.
        let alternative_atoms = last_n
            .into_iter()
            .reduce(|mut all, atoms| {
                all.append(atoms);
                all
            })
            .unwrap();

        let best_atoms = self.best_atoms_stack.last_mut().unwrap();

        // Use the atoms extracted from the alternatives if they are
        // better than the best atoms found so far, and less than
        // MAX_ATOMS_PER_REGEXP.
        if alternative_atoms.len() <= MAX_ATOMS_PER_REGEXP
            && best_atoms.quality < alternative_atoms.quality
        {
            *best_atoms = alternative_atoms;
        }

        Ok(split_loc)
    }

    fn visit_pre_repetition(&mut self, rep: &Repetition) -> Result<(), Error> {
        match (rep.min, rep.max, rep.greedy) {
            // e* and e*?
            //
            // l1: split_a l3  ( split_b for the non-greedy e*? )
            //     ... code for e ...
            // l2: jump l1
            // l3:
            (0, None, greedy) => {
                let l1 = self.emit_instr(if greedy {
                    Instr::SPLIT_A
                } else {
                    Instr::SPLIT_B
                })?;
                self.bookmarks.push(l1);
                self.zero_rep_depth += 1;
            }
            // e+ and e+?
            //
            // l1: ... code for e ...
            // l2: split_b l1  ( split_a for the non-greedy e+? )
            // l3:
            (1, None, _) => {
                let l1 = self.location();
                self.bookmarks.push(l1);
            }
            // e{min,}   min > 1
            //
            // ... code for e repeated min times
            //
            (_, None, _) => {
                self.bookmarks.push(self.location());
            }
            // e{min,max}
            //
            //     ... code for e ... -+
            //     ... code for e ...  |  min times
            //     ... code for e ... -+
            //     split end          -+
            //     ... code for e ...  |  max-min times
            //     split end           |
            //     ... code for e ... -+
            // end:
            //
            (min, Some(_), greedy) => {
                if min == 0 {
                    let split = self.emit_instr(if greedy {
                        Instr::SPLIT_A
                    } else {
                        Instr::SPLIT_B
                    })?;
                    self.bookmarks.push(split);
                    self.zero_rep_depth += 1;
                }
                self.bookmarks.push(self.location());
            }
        }

        Ok(())
    }

    fn visit_post_repetition(
        &mut self,
        rep: &Repetition,
    ) -> Result<CodeLoc, Error> {
        match (rep.min, rep.max, rep.greedy) {
            // e* and e*?
            //
            // l1: split_a l3  ( split_b for the non-greedy e*? )
            //     ... code for e ...
            // l2: jump l1
            // l3:
            (0, None, _) => {
                let l1 = self.bookmarks.pop().unwrap();
                let l2 = self.emit_instr(Instr::JUMP)?;
                let l3 = self.location();
                self.patch_instr(&l1, l3.sub(&l1)?);
                self.patch_instr(&l2, l1.sub(&l2)?);
                self.zero_rep_depth -= 1;

                Ok(l1)
            }
            // e+ and e+?
            //
            // l1: ... code for e ...
            // l2: split_b l1  ( split_a for the non-greedy e+? )
            // l3:
            (1, None, greedy) => {
                let l1 = self.bookmarks.pop().unwrap();
                let l2 = self.emit_instr(if greedy {
                    Instr::SPLIT_B
                } else {
                    Instr::SPLIT_A
                })?;
                self.patch_instr(&l2, l1.sub(&l2)?);

                Ok(l1)
            }
            // e{min,}   min > 1
            //
            //     ... code for e repeated min - 2 times
            // l1: ... code for e ...
            // l2: split_b l1 ( split_a for the non-greedy e{min,}? )
            //     ... code for e
            (min, None, greedy) => {
                assert!(min >= 2); // min == 0 and min == 1 handled above.

                // `start` and `end` are the locations where the code for `e`
                // starts and ends.
                let start = self.bookmarks.pop().unwrap();
                let end = self.location();

                // The first copy of `e` was already emitted when the children
                // of the repetition node was visited. Clone the code for `e`
                // n - 3 times, which result in n - 2 copies.
                for _ in 0..min.saturating_sub(3) {
                    self.emit_clone(start, end)?;
                }

                let l1 =
                    if min > 2 { self.emit_clone(start, end)? } else { start };

                let l2 = self.emit_instr(if greedy {
                    Instr::SPLIT_B
                } else {
                    Instr::SPLIT_A
                })?;

                self.patch_instr(&l2, l1.sub(&l2)?);
                self.emit_clone(start, end)?;

                // If the best atoms were extracted from the expression inside
                // the repetition, the backward code location for those atoms
                // must be adjusted taking into account the code that has been
                // added after the atoms were extracted. For instance, in the
                // regexp /abcd{2}/, the atom 'abcd' is generated while
                // the 'abcd' literal is processed, and the backward code points
                // to the point right after the final 'd'. However, when the
                // repetition node is handled, the code becomes 'abcdabcd', but
                // the atom's backward code still points to the second 'a', and
                // it should point after the second 'd'.
                //
                // The adjustment is the size of the code generated for the
                // expression `e` multiplied by min - 1, plus the size of the
                // split instruction.
                let adjustment = (min - 1) as usize * (end.bck - start.bck)
                    + size_of_val(&OPCODE_PREFIX)
                    + size_of_val(&Instr::SPLIT_A)
                    + size_of::<SplitId>()
                    + size_of::<instr::Offset>();

                let best_atoms = self.best_atoms_stack.last_mut().unwrap();

                for atom in best_atoms.iter_mut() {
                    if atom.code_loc.bck_seq_id == start.bck_seq_id
                        && atom.code_loc.bck >= start.bck
                    {
                        atom.code_loc.bck += adjustment;
                    }
                }

                Ok(start)
            }
            // e{min,max}
            //
            //     ... code for e ... -+
            //     ... code for e ...  |  min times
            //     ... code for e ... -+
            //     split end          -+
            //     ... code for e ...  |  max-min times
            //     split end           |
            //     ... code for e ... -+
            // end:
            //
            (min, Some(max), greedy) => {
                debug_assert!(min <= max);

                // `start` and `end` are the locations where the code for `e`
                // starts and ends.
                let start = self.bookmarks.pop().unwrap();
                let end = self.location();

                // The first copy of `e` has already been emitted while
                // visiting the child nodes. Make min - 1 clones of `e`.
                for _ in 0..min.saturating_sub(1) {
                    self.emit_clone(start, end)?;
                }

                // If min == 0 the first split and `e` are already emitted (the
                // split was emitted during the call to `visit_post_repetition`
                // and `e` was emitted while visiting the child node. In such
                // case the loop goes only to max - 1. If min > 0, we need to
                // emit max - min splits.
                for _ in 0..if min == 0 { max - 1 } else { max - min } {
                    let split = self.emit_instr(if greedy {
                        Instr::SPLIT_A
                    } else {
                        Instr::SPLIT_B
                    })?;
                    self.bookmarks.push(split);
                    self.emit_clone(start, end)?;
                }

                if min > 1 {
                    let adjustment =
                        (min - 1) as usize * (end.bck - start.bck);

                    let best_atoms = self.best_atoms_stack.last_mut().unwrap();

                    for atom in best_atoms.iter_mut() {
                        if atom.code_loc.bck_seq_id == start.bck_seq_id
                            && atom.code_loc.bck >= start.bck
                        {
                            atom.code_loc.bck += adjustment;
                        }
                    }
                }

                let end = self.location();

                for _ in 0..max - min {
                    let split = self.bookmarks.pop().unwrap();
                    self.patch_instr(&split, end.sub(&split)?);
                }

                if min == 0 {
                    self.zero_rep_depth -= 1;
                }

                Ok(start)
            }
        }
    }
}

impl hir::Visitor for Compiler {
    type Output = (InstrSeq, InstrSeq, Vec<RegexpAtom>);
    type Err = Error;

    fn finish(mut self) -> Result<Self::Output, Self::Err> {
        Ok((
            self.backward_code,
            self.forward_code,
            self.best_atoms_stack.pop().unwrap().atoms,
        ))
    }

    fn visit_pre(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match hir.kind() {
            HirKind::Empty => {}
            HirKind::Literal(_) => {}
            HirKind::Class(_) => {}
            HirKind::Look(_) => {}
            HirKind::Capture(_) => {
                self.bookmarks.push(self.location());
            }
            HirKind::Concat(_) => {
                self.visit_pre_concat();
            }
            HirKind::Alternation(alternatives) => {
                if alternatives.len() > MAX_ALTERNATIVES.into() {
                    return Err(Error::TooManyAlternatives);
                }
                self.visit_pre_alternation(alternatives)?;
            }
            HirKind::Repetition(rep) => {
                self.visit_pre_repetition(rep)?;
            }
        }

        // We are about to start processing the children of the current node,
        // let's increment `depth` indicating that we are one level down the
        // tree.
        self.depth += 1;

        Ok(())
    }

    fn visit_post(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        // We just finished visiting the children of the current node, let's
        // decrement `depth` indicating that we are one level up the tree.
        self.depth -= 1;

        let (atoms, code_loc) = match hir.kind() {
            HirKind::Empty => {
                // If `zero_rep_depth` > 0 we are currently at a HIR node that is
                // contained in a `HirKind::Repetition` node that could repeat zero
                // times. Extracting atoms from this node doesn't make sense, atoms
                // must be extracted from portions of the pattern that are required
                // to be in the matching data.
                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                (Some(vec![Atom::exact([])]), self.location())
            }
            HirKind::Literal(literal) => {
                let mut code_loc = self.emit_literal(literal);

                code_loc.bck_seq_id = self.backward_code().seq_id();
                code_loc.bck = self.backward_code().location();

                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                let literal = literal.0.as_ref();

                // Try to extract atoms from the HIR node. When the node is
                // a literal we don't use the literal extractor provided by
                // `regex_syntax` as it always returns the first bytes in the
                // literal. Sometimes the best atom is not at the very start of
                // the literal, our own logic implemented in `best_atom_from_slice`
                // takes into account a few things, like penalizing common bytes
                // and prioritizing digits over letters.
                let mut best_atom = best_atom_in_bytes(literal);

                // If the atom extracted from the literal is not at the
                // start of the literal it's `backtrack` value will be
                // non-zero and the locations where forward and backward
                // code start must be adjusted accordingly.
                let adjustment = literal_code_length(
                    &literal[0..best_atom.backtrack() as usize],
                );

                code_loc.fwd += adjustment;
                code_loc.bck -= adjustment;
                best_atom.set_backtrack(0);

                (Some(vec![best_atom]), code_loc)
            }
            HirKind::Capture(_) => {
                let mut code_loc = self.bookmarks.pop().unwrap();

                code_loc.bck_seq_id = self.backward_code().seq_id();
                code_loc.bck = self.backward_code().location();

                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                let best_atoms = seq_to_atoms(self.lit_extractor.extract(hir));

                (best_atoms, code_loc)
            }
            HirKind::Look(look) => {
                let mut code_loc = self.visit_post_look(look)?;

                code_loc.bck_seq_id = self.backward_code().seq_id();
                code_loc.bck = self.backward_code().location();

                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                let best_atoms = seq_to_atoms(self.lit_extractor.extract(hir));

                (best_atoms, code_loc)
            }
            hir_kind @ HirKind::Class(class) => {
                let mut code_loc = if re::hir::any_byte(hir_kind) {
                    self.emit_instr(Instr::ANY_BYTE)?
                } else {
                    self.visit_post_class(class)?
                };

                code_loc.bck_seq_id = self.backward_code().seq_id();
                code_loc.bck = self.backward_code().location();

                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                let best_atoms = seq_to_atoms(self.lit_extractor.extract(hir));

                (best_atoms, code_loc)
            }
            HirKind::Concat(expressions) => {
                //
                // fwd code:     expr1 expr2 expr3
                //                           ^->
                // bck code:     expr3 expr2 expr1
                //                     ^->
                //
                let locations = self.visit_post_concat(expressions);

                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                let mut best_atoms = None;
                let mut best_quality = AtomsQuality::min();
                let mut code_loc = CodeLoc::default();

                let seqs: Vec<_> = expressions
                    .iter()
                    .map(|expr| self.lit_extractor.extract(expr))
                    .collect();

                for i in 0..seqs.len() {
                    if let Some(mut seq) = concat_seq(&seqs[i..]) {
                        // If this sequence doesn't start at the first
                        // expression in the concatenation it must be
                        // marked as inexact.
                        if i > 0 {
                            seq.make_inexact()
                        }
                        let quality = AtomsQuality::from_seq(&seq);
                        if quality > best_quality {
                            best_quality = quality;
                            best_atoms = seq_to_atoms(seq);
                            code_loc = locations[i]
                        }
                    }
                }

                (best_atoms, code_loc)
            }
            HirKind::Alternation(expressions) => {
                let mut code_loc = self.visit_post_alternation(expressions)?;

                code_loc.bck_seq_id = self.backward_code().seq_id();
                code_loc.bck = self.backward_code().location();

                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                let best_atoms = seq_to_atoms(self.lit_extractor.extract(hir));

                (best_atoms, code_loc)
            }
            HirKind::Repetition(repeated) => {
                let mut code_loc = self.visit_post_repetition(repeated)?;

                code_loc.bck_seq_id = self.backward_code().seq_id();
                code_loc.bck = self.backward_code().location();

                if self.zero_rep_depth > 0 {
                    return Ok(());
                }

                let best_atoms = seq_to_atoms(self.lit_extractor.extract(hir));

                (best_atoms, code_loc)
            }
        };

        // If no atoms where found, nothing more to do.
        let mut atoms = match atoms {
            None => return Ok(()),
            Some(atoms) if atoms.is_empty() => return Ok(()),
            Some(atoms) => atoms,
        };

        // An atom is "exact" when it covers the whole pattern, which means
        // that finding the atom during a scan is enough to guarantee that
        // the pattern matches. Atoms extracted from children of the current
        // HIR node may be flagged as "exact" because they cover a whole HIR
        // subtree. They are "exact" with respect to some sub-pattern, but
        // not necessarily with respect to the whole pattern. So, atoms that
        // are flagged as "exact" are converted to "inexact" unless they
        // were extracted from the top-level HIR node.
        //
        // Also, atoms extracted from HIR nodes that contain look-around
        // assertions are also considered "inexact", regardless of whether
        // they are flagged as "exact", because the atom extractor can
        // produce "exact" atoms that can't be trusted, this what the
        // documentation says:
        //
        // "Literal extraction treats all look-around assertions as-if they
        // match every empty string. So for example, the regex \bquux\b will
        // yield a sequence containing a single exact literal quux. However,
        // not all occurrences of quux correspond to a match of the regex.
        // For example, \bquux\b does not match ZquuxZ anywhere because quux
        // does not fall on a word boundary.
        //
        // In effect, if your regex contains look-around assertions, then a
        // match of an exact literal does not necessarily mean the regex
        // overall matches. So you may still need to run the regex engine
        // in such cases to confirm the match." (end of quote)
        let can_be_exact =
            self.depth == 0 && hir.properties().look_set().is_empty();

        if !can_be_exact {
            for atom in atoms.iter_mut() {
                atom.make_inexact();
            }
        }

        let best_atoms = self.best_atoms_stack.last_mut().unwrap();
        let quality = AtomsQuality::from_atoms(atoms.iter());

        if quality > best_atoms.quality {
            *best_atoms = RegexpAtoms {
                quality,
                atoms: atoms
                    .into_iter()
                    .map(|atom| RegexpAtom { atom, code_loc })
                    .collect(),
            };
        }

        Ok(())
    }

    fn visit_alternation_in(&mut self) -> Result<(), Self::Err> {
        // Emit the jump that appears between alternatives and jump to
        // the end.
        let l = self.emit_instr(Instr::JUMP)?;
        // The jump's destination is not known yet, so save the jump's
        // address in order to patch the destination later.
        self.bookmarks.push(l);
        // Save the location of the current alternative. This is used for
        // patching the `split_n` instruction later.
        self.bookmarks.push(self.location());
        // The best atoms for this alternative are independent of the
        // other alternatives.
        self.best_atoms_stack.push(RegexpAtoms::empty());

        Ok(())
    }

    fn visit_concat_in(&mut self) -> Result<(), Self::Err> {
        self.bookmarks.push(self.location());
        // A new child of a `Concat` node is about to be processed,
        // create the chunk that will receive the code for this child.
        self.backward_code_chunks.push(self.backward_code().next());

        Ok(())
    }
}

/// A sequence of instructions for the PikeVM.
///
/// This type is used by the compiler while emitting code for PikeVM. It is
/// simply a buffer with a set of specialized functions for adding PikeVM
/// instructions at the end of the buffer. It also provides functions for
/// getting the location where the next instruction will be added, and for
/// setting the offset of instructions that point to other places within
/// the code.
///
/// Each `InstrSeq` has an ID, that distinguish them from other sequences.
#[derive(Default)]
pub(crate) struct InstrSeq {
    /// The unique ID that identifies this sequence of instructions.
    seq_id: u64,
    /// A vector that contains the PikeVM code.
    seq: Cursor<Vec<u8>>,
    /// The ID that will identify the next split instruction emitted in this
    /// sequence.
    split_id: SplitId,
}

impl AsRef<[u8]> for InstrSeq {
    fn as_ref(&self) -> &[u8] {
        self.seq.get_ref().as_slice()
    }
}

impl InstrSeq {
    /// Creates a new [`InstrSeq`].
    pub fn new() -> Self {
        Self {
            seq_id: 0,
            seq: Cursor::new(Vec::new()),
            split_id: SplitId::default(),
        }
    }

    /// Creates a new [`InstrSeq`] with an ID that is `self.seq_id() + 1`.
    pub fn next(&self) -> Self {
        Self {
            seq_id: self.seq_id + 1,
            seq: Cursor::new(Vec::new()),
            split_id: self.split_id,
        }
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
    pub fn emit_instr(&mut self, instr: u8) -> Result<usize, Error> {
        // Store the position where the instruction will be written, which will
        // the result for this function.
        let location = self.location();

        self.seq.write_all(&[OPCODE_PREFIX, instr]).unwrap();

        match instr {
            Instr::SPLIT_A | Instr::SPLIT_B => {
                // Split instructions are followed by a value that identifies
                // the split. Each split in the same regexp have a unique
                // value.
                self.seq
                    .write_all(self.split_id.to_le_bytes().as_slice())
                    .unwrap();
                // Increment the split ID, so that the next split has a
                // different ID.
                if let Some(incremented) = self.split_id.add(1) {
                    self.split_id = incremented
                } else {
                    return Err(Error::TooLarge);
                }
                // The split ID is  followed by a 16-bits offset that is
                // relative to the start of the instruction.
                self.seq
                    .write_all(&[0x00; size_of::<instr::Offset>()])
                    .unwrap();
            }
            Instr::JUMP => {
                // Jump instructions are followed by a 16-bits offset that is
                // relative to the start of the instruction.
                self.seq
                    .write_all(&[0x00; size_of::<instr::Offset>()])
                    .unwrap();
            }
            _ => {}
        }

        Ok(location)
    }

    /// Adds a [`Instr::SplitN`] instruction at the end of the sequence and
    /// returns the location where the newly added instruction resides.
    pub fn emit_split_n(&mut self, n: NumAlt) -> Result<usize, Error> {
        let location = self.location();

        self.seq.write_all(&[OPCODE_PREFIX, Instr::SPLIT_N]).unwrap();
        self.seq.write_all(self.split_id.to_le_bytes().as_slice()).unwrap();

        if let Some(incremented) = self.split_id.add(1) {
            self.split_id = incremented
        } else {
            return Err(Error::TooLarge);
        }

        self.seq.write_all(NumAlt::to_le_bytes(n).as_slice()).unwrap();

        for _ in 0..n {
            self.seq.write_all(&[0x00; size_of::<instr::Offset>()]).unwrap();
        }

        Ok(location)
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
    ///
    /// The new code is identically to existing code, except of the IDs
    /// associated to split instructions, which are updated in order to keep
    /// the guarantee that every split instruction in a regexp has its own
    /// unique ID.
    pub fn emit_clone(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<usize, Error> {
        let location = self.location();

        // Extend the code by cloning the ranges that go from `start` to `end`.
        self.seq.get_mut().extend_from_within(start..end);

        // Create two slices, one that covers all the previously existing code
        // and another that covers the newly cloned code.
        let (original_code, cloned_code) =
            self.seq.get_mut().as_mut_slice().split_at_mut(location);

        // Every split instruction has an ID, we don't want the split
        // instructions in the cloned code to have the same IDs than
        // in the original code, those IDs need to be updated.
        for (instr, offset) in InstrParser::new(&original_code[start..end]) {
            match instr {
                Instr::SplitA(_, _)
                | Instr::SplitB(_, _)
                | Instr::SplitN(_) => {
                    debug_assert_eq!(
                        cloned_code[offset],
                        original_code[start + offset]
                    );
                    debug_assert_eq!(
                        cloned_code[offset + 1],
                        original_code[start + offset + 1]
                    );
                    // Update the split ID, which is at `offset + 2` because
                    // `offset` is the offset where the opcode starts, and the
                    // first two bytes are the prefix and the opcode itself.
                    cloned_code[offset + 2..offset + 2 + size_of::<SplitId>()]
                        .copy_from_slice(
                            self.split_id.to_le_bytes().as_slice(),
                        );

                    if let Some(incremented) = self.split_id.add(1) {
                        self.split_id = incremented
                    } else {
                        return Err(Error::TooLarge);
                    }
                }
                _ => {}
            }
        }

        self.seq.seek(SeekFrom::Current(end as i64 - start as i64)).unwrap();

        Ok(location)
    }

    /// Patches the offset of the instruction that starts at the given location.
    ///
    /// # Panics
    ///
    /// If the instruction at `location` is not one that have an offset as its
    /// argument, like [`Instr::Jump`], [`Instr::SplitA`] or [`Instr::SplitB`].
    pub fn patch_instr(&mut self, location: usize, offset: instr::Offset) {
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

        match buf[1] {
            Instr::JUMP => {}
            Instr::SPLIT_A | Instr::SPLIT_B => {
                // Skip the split ID.
                self.seq
                    .seek(SeekFrom::Current(size_of::<SplitId>() as i64))
                    .unwrap();
            }
            _ => {
                unreachable!()
            }
        }

        // Write the given offset after the instruction opcode. This will
        // overwrite any existing offsets, usually initialized with 0.
        self.seq
            .write_all(instr::Offset::to_le_bytes(offset).as_slice())
            .unwrap();

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
    pub fn patch_split_n<I: ExactSizeIterator<Item = instr::Offset>>(
        &mut self,
        location: usize,
        mut offsets: I,
    ) {
        // Save the current location for the forward code in order to restore
        // it later.
        let saved_loc = self.location();

        // Seek to the position indicated by `location`.
        self.seq.seek(SeekFrom::Start(location as u64)).unwrap();

        // Read the first few bytes in the opcode, corresponding to the prefix,
        // the opcode itself, and the split id respectively.
        let mut opcode = [0; 2 + size_of::<SplitId>()];
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
                    instr::Offset::to_le_bytes(offsets.next().unwrap())
                        .as_slice(),
                )
                .unwrap();
        }

        // Restore to the previous current position.
        self.seq.seek(SeekFrom::Start(saved_loc as u64)).unwrap();
    }
}

impl Display for InstrSeq {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;

        for (instr, addr) in InstrParser::new(self.seq.get_ref().as_slice()) {
            match instr {
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
                Instr::SplitA(id, offset) => {
                    writeln!(
                        f,
                        "{:05x}: SPLIT_A({}) {:05x}",
                        addr,
                        id,
                        addr as isize + offset as isize,
                    )?;
                }
                Instr::SplitB(id, offset) => {
                    writeln!(
                        f,
                        "{:05x}: SPLIT_B({}) {:05x}",
                        addr,
                        id,
                        addr as isize + offset as isize,
                    )?;
                }
                Instr::SplitN(split) => {
                    write!(f, "{:05x}: SPLIT_N({})", addr, split.id())?;
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
                Instr::WordStart => {
                    writeln!(f, "{:05x}: WORD_START", addr)?;
                }
                Instr::WordEnd => {
                    writeln!(f, "{:05x}: WORD_END", addr)?;
                }
                Instr::Match => {
                    writeln!(f, "{:05x}: MATCH", addr)?;
                    break;
                }
            };
        }

        Ok(())
    }
}

/// Given a slice of [`Seq`] (sequence of literals), produce another [`Seq`]
/// that is the concatenation of the first N sequences in the slice.
///
/// How large is N depends on the sequences being concatenated. This function
/// will try to produce a sequence where the minimum literal size is the largest
/// possible, without exceeding [`DESIRED_ATOM_SIZE`], while also making sure
/// that the number of literals in the resulting sequence doesn't exceed
/// [`MAX_ATOMS_PER_REGEXP`].
///
/// This function also tries to obtain a good balance between the number of
/// literals in the resulting sequence and their lengths. Sometimes the number
/// of literals can be reduced at the expense of trimming the final bytes of
/// each literal. For instance, the sequences composed by literals `01 02 XX`,
/// where XX are all possible bytes, contains 256 literals, each of them 3
/// bytes long. This sequence can be reduced to a sequence with a single
/// `01 02` literal.
///
/// In some cases the function also returns [`None`]. Particularly,
///
/// * when the input slice is empty.
/// * when the first sequence in the slice has 256 single byte literals.
///
fn concat_seq(seqs: &[Seq]) -> Option<Seq> {
    let first_seq = match seqs.first() {
        Some(seq) => seq,
        None => return None,
    };

    match first_seq.len() {
        // Return None if the first sequence contains 256 possible literals
        // while the maximum literal length is 1. This means the first sequence
        // is ??.
        Some(256) => {
            if matches!(first_seq.max_literal_len(), Some(1) | None) {
                return None;
            }
        }
        // Return `None` if the first sequence is infinite.
        None => return None,
        _ => {}
    }

    let mut seqs_added = 0;
    let mut total_min_literal_len = 0;
    let mut result = Seq::singleton(hir::literal::Literal::exact(vec![]));

    for seq in seqs.iter() {
        match seq.min_literal_len() {
            Some(min_literal_len) => {
                // If the cross product of `result` with `seq` produces too many
                // literals, stop trying to add more sequences to the result and
                // return what we have so far.
                match result.max_cross_len(seq) {
                    None => break,
                    Some(len) if len > MAX_ATOMS_PER_REGEXP => break,
                    _ => {}
                }

                result.cross_forward(&mut seq.clone());
                seqs_added += 1;
                total_min_literal_len += min_literal_len;

                // The desired atom length as been reached, don't process
                // more sequences.
                if total_min_literal_len >= DESIRED_ATOM_SIZE {
                    break;
                }

                // If every element in the sequence is inexact, then a cross
                // product will always be a no-op. Thus, there is nothing else we
                // can add to it and can quit early. Note that this also includes
                // infinite sequences.
                if result.is_inexact() {
                    break;
                }
            }
            None => break,
        }
    }

    // If there are sequences that were not added to the result, the result
    // is inexact.
    if seqs_added < seqs.len() {
        result.make_inexact();
    }

    result.keep_first_bytes(DESIRED_ATOM_SIZE);

    optimize_seq(result)
}

/// Optimizes a [`Seq`] (sequence of literals) by removing duplicate literals
/// and reducing the number of literals at the expense of literal length.
///
/// For instance, if the sequence have literals `01 02 XX`, where `XX` means
/// every possible byte value, those 256 different literals can be replaced
/// by the single literal `01 02`. This literal is shorter, but it's better
/// to have a shorter literal than 256 literals that only differ in the last
/// byte.
fn optimize_seq(mut seq: Seq) -> Option<Seq> {
    let literals = seq.literals()?;

    // The sequence has a single literal, nothing to be optimized.
    if literals.len() == 1 {
        return Some(seq);
    }

    // Hash map where keys are literal prefixes (all bytes in the literal
    // except for the last one), and values are 256-bits bitmaps. Each bit in
    // the bitmap tells if the corresponding byte was seen at the end of the
    // literal. For instance, if the sequence contains literals `01 02 03` and
    // `01 02 04`, the key `01 02` will contain a bitmap where bits 3 and 4
    // are set, while the rest of the bits are unset.
    let mut map = HashMap::new();

    for lit in literals {
        // `prefix` contains all bytes in the literal except the last one.
        // The literal is not empty, so it's length is >= 1.
        if let Some((last_byte, prefix)) = lit.as_bytes().split_last() {
            map.entry(prefix)
                .or_insert_with(|| BitArray::<[u8; 32], Lsb0>::new([0_u8; 32]))
                .set(*last_byte as usize, true);
        }
    }

    // Keep the entries where the bitmap has 256 bits set to one. This means
    // that the corresponding prefix has been seen together with all possible
    // combinations for the last byte. The remaining entries correspond to
    // literals that can be shortened by truncating the last byte.
    map.retain(|_, bitmap| bitmap.count_ones() == 256);

    // Nothing to optimize, except literal de-duplication.
    if map.is_empty() {
        seq.dedup();
        return Some(seq);
    }

    for (_, bitmap) in map.iter_mut() {
        bitmap.set(0, true);
    }

    let mut result = Seq::empty();

    for lit in literals {
        if let Some((_, prefix)) = lit.as_bytes().split_last() {
            match map.entry(prefix) {
                Entry::Occupied(mut entry) => {
                    let bitmap = entry.get_mut();
                    if *bitmap.get(0).unwrap() {
                        bitmap.set(0, false);
                        result.push(hir::literal::Literal::inexact(prefix));
                    }
                }
                Entry::Vacant(_) => result.push(lit.clone()),
            }
        } else {
            // The literal is empty, copy it as is.
            result.push(lit.clone());
        }
    }

    result.dedup();
    Some(result)
}

fn seq_to_atoms(seq: Seq) -> Option<Vec<Atom>> {
    optimize_seq(seq)?
        .literals()
        .map(|literals| literals.iter().map(Atom::from).collect())
}

/// A list of [`RegexpAtom`] that contains additional information, like the
/// quality of the atoms.
struct RegexpAtoms {
    atoms: Vec<RegexpAtom>,
    /// Quality of the atoms.
    quality: AtomsQuality,
}

impl RegexpAtoms {
    /// Create a new empty list of atoms.
    fn empty() -> Self {
        Self { atoms: Vec::new(), quality: AtomsQuality::min() }
    }

    /// Appends another [`RegexpAtoms`] to this one.
    fn append(&mut self, atoms: RegexpAtoms) {
        self.quality.merge(atoms.quality);
        let mut atoms = atoms.atoms;
        self.atoms.append(&mut atoms);
    }

    #[inline]
    fn len(&self) -> usize {
        self.atoms.len()
    }

    #[inline]
    fn iter_mut(&mut self) -> IterMut<'_, RegexpAtom> {
        self.atoms.iter_mut()
    }
}
