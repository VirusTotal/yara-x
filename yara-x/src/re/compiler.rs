/*!
This module provides a compiler that takes a regex's [`Hir`] and produces a
sequence of instructions for a Pike's VM similar to the one described in
https://swtch.com/~rsc/regexp/regexp2.html

More specifically, the compiler produces two instruction sequences, one that
matches the regexp left-to-right, and another one that matches right-to-left.
*/

use std::cmp::min;
use std::collections::HashMap;
use std::mem::{size_of, size_of_val};

use regex_syntax::hir;
use regex_syntax::hir::{
    visit, Class, ClassBytes, Hir, HirKind, Literal, Look, Repetition,
};

use yara_x_parser::ast::HexByte;

use crate::compiler::{best_atom_from_slice, Atom, DESIRED_ATOM_SIZE};
use crate::re;
use crate::re::hir::class_to_hex_byte;
use crate::re::instr::{
    literal_code_length, Instr, InstrSeq, NumAlt, OPCODE_PREFIX,
};

#[derive(Eq, PartialEq, Clone, Copy, Debug, Default)]
pub(crate) struct Location {
    pub fwd: usize,
    pub bck_seq_id: u64,
    pub bck: usize,
}

impl Location {
    fn sub(&self, rhs: &Self) -> Offset {
        Offset {
            fwd: (self.fwd as isize - rhs.fwd as isize)
                .try_into()
                .expect("regexp too large"),
            bck: (self.bck as isize - rhs.bck as isize)
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
///
/// Compiling a regexp consists in performing DFS traversal of the HIR tree
/// while emitting code for the Pike VM and extracting the atoms that will be
/// passed to the Aho-Corasick algorithm.
///
/// Atoms are short literals (the length is controlled by [`DESIRED_ATOM_SIZE`])
/// that are are extracted from the regexp and must present in any matching
/// string. Idealistically, the compiler will extract a single, long-enough
/// atom from the regexp, but in those cases where extracting a single atom is
/// is not possible (or would be too short), the compiler can extract multiple
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
    /// in the HIR or not. Extracting atoms from a sub-tree under a zero-length
    /// repetition doesn't make sense, atoms must be extracted from portions of
    /// the pattern that are required to be present any matching string.
    zero_rep_depth: u32,
}

impl Compiler {
    pub fn new() -> Self {
        let mut lit_extractor = hir::literal::Extractor::new();

        lit_extractor.limit_class(256);
        lit_extractor.limit_total(512);
        lit_extractor.limit_literal_len(DESIRED_ATOM_SIZE);
        lit_extractor.limit_repeat(256);

        Self {
            lit_extractor,
            forward_code: InstrSeq::new(0),
            backward_code: InstrSeq::new(0),
            backward_code_chunks: Vec::new(),
            bookmarks: Vec::new(),
            best_atoms: vec![(i32::MIN, Vec::new())],
            depth: 0,
            zero_rep_depth: 0,
        }
    }

    pub fn compile(
        mut self,
        hir: &re::hir::Hir,
    ) -> (InstrSeq, InstrSeq, Vec<RegexpAtom>) {
        visit(&hir.inner, &mut self).unwrap();

        self.forward_code.emit_instr(Instr::MATCH);
        self.backward_code.emit_instr(Instr::MATCH);

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

    fn emit_instr(&mut self, instr: u8) -> Location {
        Location {
            fwd: self.forward_code.emit_instr(instr),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_instr(instr),
        }
    }

    fn emit_split_n(&mut self, n: NumAlt) -> Location {
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

    fn emit_class(&mut self, c: &ClassBytes) -> Location {
        Location {
            fwd: self.forward_code.emit_class(c),
            bck_seq_id: self.backward_code.seq_id(),
            bck: self.backward_code_mut().emit_class(c),
        }
    }

    fn emit_literal(&mut self, literal: &Literal) -> Location {
        Location {
            fwd: self.forward_code.emit_literal(literal.0.iter()),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_literal(literal.0.iter().rev()),
        }
    }

    fn emit_clone(&mut self, start: Location, end: Location) -> Location {
        Location {
            fwd: self.forward_code.emit_clone(start.fwd, end.fwd),
            bck_seq_id: self.backward_code().seq_id(),
            bck: self.backward_code_mut().emit_clone(start.bck, end.bck),
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

    fn extract_atoms_from_hir(&self, hir: &Hir) -> Option<Vec<Atom>> {
        let seq = self.lit_extractor.extract(hir);

        // If the literal extractor produced exactly 256 atoms, and those atoms
        // have a common prefix that is one byte shorter than the longest atom,
        // we are in the case where we have 256 atoms that differ only in the
        // last byte. It doesn't make sense to have 256 atoms of length N, when
        // we can have 1 atom of length N-1 by discarding the last byte.
        if let Some(256) = seq.len() {
            if let Some(max_len) = seq.max_literal_len() {
                if max_len > 1 {
                    if let Some(longest_prefix) = seq.longest_common_prefix() {
                        if longest_prefix.len() == max_len - 1 {
                            return Some(vec![Atom::inexact(longest_prefix)]);
                        }
                    }
                }
            }
        }

        seq.literals()
            .map(|literals| literals.iter().map(Atom::from).collect())
    }

    fn visit_post_class(&mut self, class: &Class) -> Location {
        match class {
            Class::Bytes(class) => {
                if let Some(byte) = class_to_hex_byte(class) {
                    self.emit_masked_byte(byte)
                } else {
                    self.emit_class(class)
                }
            }
            Class::Unicode(class) => {
                if let Some(class) = class.to_byte_class() {
                    self.emit_class(&class)
                } else {
                    // TODO: properly handle this
                    panic!("unicode classes not supported")
                }
            }
        }
    }

    fn visit_post_look(&mut self, look: &Look) -> Location {
        match look {
            Look::Start => self.emit_instr(Instr::START),
            Look::End => self.emit_instr(Instr::END),
            Look::WordAscii => self.emit_instr(Instr::WORD_BOUNDARY),
            Look::WordAsciiNegate => self.emit_instr(Instr::WORD_BOUNDARY_NEG),
            _ => unreachable!(),
        }
    }

    fn visit_pre_concat(&mut self) {
        self.bookmarks.push(self.location());
        // A new child of a `Concat` node is about to be processed,
        // create the chunk that will receive the code for this child.
        self.backward_code_chunks
            .push(InstrSeq::new(self.backward_code().seq_id() + 1));
    }

    fn visit_post_concat(&mut self, expressions: &Vec<Hir>) -> Location {
        // We are here because all the children of a `Concat` node have
        // been processed. The last N chunks in `backward_code_chunks`
        // contain the code produced for each of the N children, but
        // the nodes where processed left-to-right, and we want the
        // chunks right-to-left, so these last N chunks must be copied
        // into backward code in reverse order.
        let n = expressions.len();
        let len = self.backward_code_chunks.len();

        // Split `backward_code_chunks` in two halves, [0, len-n) and
        // [len-n, len). The first half stays in `backward_code_chunks`
        // while the second half is stored in `last_n_chunks`.
        let last_n_chunks = self.backward_code_chunks.split_off(len - n);

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
        // resides in the backward code is stored in the hash map.
        for chunk in last_n_chunks.iter().rev() {
            chunk_locations.insert(chunk.seq_id(), backward_code.location());
            backward_code.append(chunk);
        }

        let (_, atoms) = self.best_atoms.last_mut().unwrap();

        // Atoms may be pointing to some code located in one of the
        // chunks that were written to backward code in a different
        // order, the backward code location for those atoms needs to
        // be adjusted accordingly.
        for atom in atoms {
            if let Some(adjustment) =
                chunk_locations.get(&atom.code_loc.bck_seq_id)
            {
                atom.code_loc.bck_seq_id = backward_code.seq_id();
                atom.code_loc.bck += adjustment;
            }
        }

        self.bookmarks.pop().unwrap()
    }

    fn visit_pre_alternation(&mut self, alternatives: &Vec<Hir>) {
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
        let l0 = self.emit_split_n(alternatives.len().try_into().unwrap());

        self.bookmarks.push(l0);
        self.bookmarks.push(self.location());

        self.best_atoms.push((i32::MIN, Vec::new()));
    }

    fn visit_post_alternation(&mut self, expressions: &Vec<Hir>) -> Location {
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
            self.patch_instr(&ln_j, l_end.sub(&ln_j));
        }

        expr_locs.push(self.bookmarks.pop().unwrap());

        let split_loc = self.bookmarks.pop().unwrap();

        let offsets =
            expr_locs.into_iter().rev().map(|loc| loc.sub(&split_loc));

        self.patch_split_n(&split_loc, offsets);

        // Remove the last N items from best atoms and put them in
        // `last_n`. These last N items correspond to each of the N
        // alternatives.
        let last_n = self.best_atoms.split_off(self.best_atoms.len() - n);

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

        split_loc
    }

    fn visit_pre_repetition(&mut self, rep: &Repetition) {
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
                });
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
                    });
                    self.bookmarks.push(split);
                    self.zero_rep_depth += 1;
                }
                self.bookmarks.push(self.location());
            }
        }
    }

    fn visit_post_repetition(&mut self, rep: &Repetition) -> Location {
        match (rep.min, rep.max, rep.greedy) {
            // e* and e*?
            //
            // l1: split_a l3  ( split_b for the non-greedy e*? )
            //     ... code for e ...
            // l2: jump l1
            // l3:
            (0, None, _) => {
                let l1 = self.bookmarks.pop().unwrap();
                let l2 = self.emit_instr(Instr::JUMP);
                let l3 = self.location();
                self.patch_instr(&l1, l3.sub(&l1));
                self.patch_instr(&l2, l1.sub(&l2));
                self.zero_rep_depth -= 1;
                l1
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
                });
                self.patch_instr(&l2, l1.sub(&l2));

                l1
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
                    self.emit_clone(start, end);
                }

                let l1;
                if min > 2 {
                    l1 = self.location();
                    self.emit_clone(start, end);
                } else {
                    l1 = start;
                };

                let l2 = self.emit_instr(if greedy {
                    Instr::SPLIT_B
                } else {
                    Instr::SPLIT_A
                });

                self.patch_instr(&l2, l1.sub(&l2));
                self.emit_clone(start, end);

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
                    + size_of::<re::instr::Offset>();

                let (_, atoms) = self.best_atoms.last_mut().unwrap();

                for atom in atoms.iter_mut() {
                    if atom.code_loc.bck_seq_id == start.bck_seq_id
                        && atom.code_loc.bck >= start.bck
                    {
                        atom.code_loc.bck += adjustment;
                    }
                }

                start
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
                // `start` and `end` are the locations where the code for `e`
                // starts and ends.
                let start = self.bookmarks.pop().unwrap();
                let end = self.location();

                // The first copy of `e` has already been emitted while
                // visiting the child nodes. Make min - 1 clones of `e`.
                for _ in 0..min.saturating_sub(1) {
                    self.emit_clone(start, end);
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
                    });
                    self.bookmarks.push(split);
                    self.emit_clone(start, end);
                }

                if min > 1 {
                    let adjustment =
                        (min - 1) as usize * (end.bck - start.bck);

                    let (_, atoms) = self.best_atoms.last_mut().unwrap();

                    for atom in atoms.iter_mut() {
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
                    self.patch_instr(&split, end.sub(&split));
                }

                if min == 0 {
                    self.zero_rep_depth -= 1;
                }

                start
            }
        }
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
                self.visit_pre_alternation(alternatives);
            }
            HirKind::Repetition(rep) => {
                self.visit_pre_repetition(rep);
            }
        }

        self.depth += 1;

        Ok(())
    }

    fn visit_post(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        let mut code_loc = match hir.kind() {
            HirKind::Empty => self.location(),
            HirKind::Literal(literal) => self.emit_literal(literal),
            HirKind::Capture(_) => self.bookmarks.pop().unwrap(),
            HirKind::Look(look) => self.visit_post_look(look),
            hir_kind @ HirKind::Class(class) => {
                if re::hir::any_byte(hir_kind) {
                    self.emit_instr(Instr::ANY_BYTE)
                } else {
                    self.visit_post_class(class)
                }
            }
            HirKind::Concat(expressions) => {
                self.visit_post_concat(expressions)
            }
            HirKind::Alternation(expressions) => {
                self.visit_post_alternation(expressions)
            }
            HirKind::Repetition(repeated) => {
                self.visit_post_repetition(repeated)
            }
        };

        // If `zero_rep_depth` > 0 we are currently at a HIR node that is
        // contained in a `HirKind::Repetition` node that could repeat zero
        // times. Extracting atoms from this node doesn't make sense, atoms
        // must be extracted from portions of the pattern that are required
        // to be in the matching data.
        if self.zero_rep_depth == 0 {
            code_loc.bck_seq_id = self.backward_code().seq_id();
            code_loc.bck = self.backward_code().location();

            // Try to extract atoms from the HIR node. When the node is a
            // a literal we don't use the literal extractor provided by
            // `regex_syntax` as it always returns the first bytes in the
            // literal. Sometimes the best atom is not at the very start of
            // the literal, our own logic implemented in `best_atom_from_slice`
            // takes into account a few things, like penalizing common bytes
            // and prioritizing digits over letters.
            let atoms = match hir.kind() {
                HirKind::Literal(literal) => {
                    let literal = literal.0.as_ref();
                    let mut best_atom =
                        best_atom_from_slice(literal, DESIRED_ATOM_SIZE);

                    // If the atom extracted from the literal is not at the
                    // start of the literal it's `backtrack` value will be
                    // non zero and the locations where forward and backward
                    // code start must be adjusted accordingly.
                    let adjustment = literal_code_length(
                        &literal[0..best_atom.backtrack() as usize],
                    );

                    code_loc.fwd += adjustment;
                    code_loc.bck -= adjustment;
                    best_atom.set_backtrack(0);

                    Some(vec![best_atom])
                }
                _ => self.extract_atoms_from_hir(hir),
            };

            if let Some(atoms) = atoms {
                let min_quality = atoms.iter().map(|a| a.quality()).min();

                if let Some(quality) = min_quality {
                    let (best_quality, best_atoms) =
                        self.best_atoms.last_mut().unwrap();

                    if quality > *best_quality {
                        // An atom is "exact" when it covers the whole pattern,
                        // which means that finding the atom during a scan is
                        // enough to guarantee that the pattern matches. Atoms
                        // extracted from children of the current HIR node may
                        // be flagged as "exact" because they cover a whole HIR
                        // sub-tree. They are "exact" with respect to some sub-
                        // pattern, but not necessarily with respect to the
                        // whole pattern. So, atoms that are flagged as "exact"
                        // are converted to "inexact" unless they were extracted
                        // from the top-level HIR node.
                        //
                        // Also, atoms extracted from HIR nodes that contain
                        // look-around assertions are also considered "inexact",
                        // regardless of whether they are flagged as "exact",
                        // because the atom extractor can produce "exact" atoms
                        // that can't be trusted, this what the documentation
                        // says:
                        //
                        // "Literal extraction treats all look-around assertions
                        // as-if they match every empty string. So for example,
                        // the regex \bquux\b will yield a sequence containing
                        // a single exact literal quux. However, not all
                        // occurrences of quux correspond to a match a of the
                        // regex. For example, \bquux\b does not match ZquuxZ
                        // anywhere because quux does not fall on a word
                        // boundary.
                        //
                        // In effect, if your regex contains look-around
                        // assertions, then a match of an exact literal does not
                        // necessarily mean the regex overall matches. So you
                        // may still need to run the regex engine in such cases
                        // to confirm the match." (end of quote)
                        //
                        let can_be_exact = self.depth == 1
                            && hir.properties().look_set().is_empty();

                        *best_quality = quality;
                        *best_atoms = atoms
                            .into_iter()
                            .map(|atom| RegexpAtom {
                                atom: if !can_be_exact {
                                    atom.make_inexact()
                                } else {
                                    atom
                                },
                                code_loc,
                            })
                            .collect();
                    }
                }
            }
        }

        self.depth -= 1;

        Ok(())
    }

    fn visit_alternation_in(&mut self) -> Result<(), Self::Err> {
        // Emit the jump that appears between alternatives and jump to
        // the end.
        let l = self.emit_instr(Instr::JUMP);
        // The jump's destination is not known yet, so save the jump's
        // address in order to patch the destination later.
        self.bookmarks.push(l);
        // Save the location of the current alternative. This is used for
        // patching the `split_n` instruction later.
        self.bookmarks.push(self.location());
        // The best atoms for this alternative are independent from the
        // other alternatives.
        self.best_atoms.push((i32::MIN, Vec::new()));
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
