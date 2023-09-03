use indexmap::IndexSet;
use std::ops::RangeInclusive;
use std::{cmp, mem};

use itertools::izip;
use memx::memeq;

use crate::re::fast::instr::{Instr, InstrParser};
use crate::re::{Action, CodeLoc, DEFAULT_SCAN_LIMIT};

/// A faster but less general alternative to [PikeVM].
///
/// `FastVM` is a virtual machine that executes bytecode that evaluates
/// regular expressions, similarly to [PikeVM]. `FastVM` is faster, but
/// only supports a subset of the regular expressions supported by [PikeVM]
/// (see the more details in the [`crate::re::fast`] module's documentation).
///
/// [PikeVM]: crate::re::thompson::pikevm::PikeVM
pub(crate) struct FastVM<'r> {
    /// The code for the VM. Produced by [`crate::re::fast::Compiler`].
    code: &'r [u8],
    /// Maximum number of bytes to scan. The VM will abort after ingesting
    /// this number of bytes from the input.
    scan_limit: usize,
    /// A set with all the positions within the data that are matching so
    /// far. `IndexSet` is used instead of `HashSet` because insertion order
    /// needs to be maintained while iterating the positions and `HashSet`
    /// doesn't make any guarantees about iteration order.
    positions: IndexSet<usize>,
}

impl<'r> FastVM<'r> {
    /// Creates a new [`FastVM`].
    pub fn new(code: &'r [u8]) -> Self {
        Self {
            code,
            positions: IndexSet::new(),
            scan_limit: DEFAULT_SCAN_LIMIT,
        }
    }

    /// Specifies the maximum number of bytes that will be scanned by the
    /// VM before aborting.
    ///
    /// This sets a limit on the number of bytes that the VM will read from the
    /// input while trying find a match. Without a limit, the VM will can incur
    /// in excessive execution time for regular expressions that are unbounded,
    /// like `foo.*bar`. For inputs that starts with `foo`, this regexp will
    /// try to scan the whole input, and that would take a long time if the
    /// input is excessively large.
    ///
    /// The default limit is 4096 bytes.
    #[allow(dead_code)]
    pub fn scan_limit(mut self, limit: usize) -> Self {
        self.scan_limit = limit;
        self
    }

    pub fn try_match<C>(
        &mut self,
        start: C,
        input: &[u8],
        mut f: impl FnMut(usize) -> Action,
    ) where
        C: CodeLoc,
    {
        let backwards = start.backwards();
        let mut ip = start.location();

        let input = if backwards {
            &input[input.len().saturating_sub(self.scan_limit)..]
        } else {
            &input[..cmp::min(input.len(), self.scan_limit)]
        };

        let mut next_positions = IndexSet::new();

        self.positions.clear();
        self.positions.insert(0);

        while !self.positions.is_empty() {
            let (instr, instr_size) =
                InstrParser::decode_instr(&self.code[ip..]);

            ip += instr_size;

            match instr {
                Instr::Match => {
                    for position in &self.positions {
                        match f(*position) {
                            Action::Stop => {
                                return;
                            }
                            Action::Continue => {}
                        }
                    }
                }
                Instr::Literal(literal) => {
                    for position in &self.positions {
                        if *position >= input.len() {
                            continue;
                        }
                        let is_match = if backwards {
                            self.try_match_literal_bck(
                                &input[..input.len() - position],
                                literal,
                            )
                        } else {
                            self.try_match_literal_fwd(
                                &input[*position..],
                                literal,
                            )
                        };
                        if is_match {
                            next_positions.insert(position + literal.len());
                        }
                    }
                }
                Instr::MaskedLiteral(literal, mask) => {
                    for position in &self.positions {
                        if *position >= input.len() {
                            continue;
                        }
                        let is_match = if backwards {
                            self.try_match_masked_literal_bck(
                                &input[..input.len() - position],
                                literal,
                                mask,
                            )
                        } else {
                            self.try_match_masked_literal_fwd(
                                &input[*position..],
                                literal,
                                mask,
                            )
                        };
                        if is_match {
                            next_positions.insert(position + literal.len());
                        }
                    }
                }
                Instr::Alternation(alternatives) => {
                    for alt in alternatives {
                        for position in &self.positions {
                            if *position >= input.len() {
                                continue;
                            }
                            match alt {
                                Instr::Literal(literal) => {
                                    let is_match = if backwards {
                                        self.try_match_literal_bck(
                                            &input[..input.len() - position],
                                            literal,
                                        )
                                    } else {
                                        self.try_match_literal_fwd(
                                            &input[*position..],
                                            literal,
                                        )
                                    };
                                    if is_match {
                                        next_positions
                                            .insert(position + literal.len());
                                    }
                                }
                                Instr::MaskedLiteral(literal, mask) => {
                                    let is_match = if backwards {
                                        self.try_match_masked_literal_bck(
                                            &input[..input.len() - position],
                                            literal,
                                            mask,
                                        )
                                    } else {
                                        self.try_match_masked_literal_fwd(
                                            &input[*position..],
                                            literal,
                                            mask,
                                        )
                                    };
                                    if is_match {
                                        next_positions
                                            .insert(position + literal.len());
                                    }
                                }
                                // The only valid instructions in alternatives
                                // are literals.
                                Instr::Match
                                | Instr::Alternation(_)
                                | Instr::Jump(_)
                                | Instr::JumpRange(_) => {
                                    unreachable!()
                                }
                            }
                        }
                    }
                }
                Instr::Jump(jump) => {
                    for position in &self.positions {
                        next_positions.insert(position + jump as usize);
                    }
                }
                Instr::JumpRange(range) => {
                    match InstrParser::decode_instr(&self.code[ip..]) {
                        (Instr::Literal(literal), _) if backwards => {
                            for position in &self.positions {
                                if *position >= input.len() {
                                    continue;
                                }
                                self.jump_bck(
                                    &input[..input.len() - position],
                                    literal,
                                    &range,
                                    *position,
                                    &mut next_positions,
                                );
                            }
                        }
                        (Instr::Literal(literal), _) if !backwards => {
                            for position in &self.positions {
                                if *position >= input.len() {
                                    continue;
                                }
                                self.jump_fwd(
                                    &input[*position..],
                                    literal,
                                    &range,
                                    *position,
                                    &mut next_positions,
                                )
                            }
                        }
                        (Instr::MaskedLiteral(literal, mask), _)
                            if backwards && mask.last() == Some(&0xff) =>
                        {
                            for position in &self.positions {
                                if *position >= input.len() {
                                    continue;
                                }
                                self.jump_bck(
                                    &input[..input.len() - position],
                                    literal,
                                    &range,
                                    *position,
                                    &mut next_positions,
                                );
                            }
                        }
                        (Instr::MaskedLiteral(literal, mask), _)
                            if !backwards && mask.first() == Some(&0xff) =>
                        {
                            for position in &self.positions {
                                if *position >= input.len() {
                                    continue;
                                }
                                self.jump_fwd(
                                    &input[*position..],
                                    literal,
                                    &range,
                                    *position,
                                    &mut next_positions,
                                );
                            }
                        }
                        _ => {
                            for position in mem::take(&mut self.positions) {
                                for i in range.clone() {
                                    next_positions
                                        .insert(position + i as usize);
                                }
                            }
                        }
                    }
                }
            }

            next_positions = mem::replace(&mut self.positions, next_positions);
            next_positions.clear();
        }
    }
}

impl FastVM<'_> {
    #[inline]
    fn try_match_literal_fwd(&self, input: &[u8], literal: &[u8]) -> bool {
        if input.len() < literal.len() {
            return false;
        }
        memeq(&input[..literal.len()], literal)
    }

    #[inline]
    fn try_match_literal_bck(&self, input: &[u8], literal: &[u8]) -> bool {
        if input.len() < literal.len() {
            return false;
        }
        memeq(&input[input.len() - literal.len()..], literal)
    }

    #[inline]
    fn try_match_masked_literal_fwd(
        &self,
        input: &[u8],
        literal: &[u8],
        mask: &[u8],
    ) -> bool {
        debug_assert_eq!(literal.len(), mask.len());

        if input.len() < literal.len() {
            return false;
        }

        for (input, byte, mask) in izip!(input, literal, mask) {
            if *input & *mask != *byte & *mask {
                return false;
            }
        }

        true
    }

    #[inline]
    fn try_match_masked_literal_bck(
        &self,
        input: &[u8],
        literal: &[u8],
        mask: &[u8],
    ) -> bool {
        debug_assert_eq!(literal.len(), mask.len());

        if input.len() < literal.len() {
            return false;
        }

        for (input, byte, mask) in
            izip!(input.iter().rev(), literal.iter().rev(), mask.iter().rev())
        {
            if *input & *mask != *byte & *mask {
                return false;
            }
        }

        true
    }

    #[inline]
    fn jump_fwd(
        &self,
        input: &[u8],
        literal: &[u8],
        range: &RangeInclusive<u16>,
        position: usize,
        next_positions: &mut IndexSet<usize>,
    ) {
        let jmp_min = *range.start() as usize;
        let jmp_max = cmp::min(input.len(), *range.end() as usize + 1);
        let jmp_range = jmp_min..jmp_max;

        if jmp_range.start >= jmp_range.end {
            return;
        }

        if let Some(jmp_range) = input.get(jmp_range) {
            let lit = *literal.first().unwrap();
            for offset in memchr::memchr_iter(lit, jmp_range) {
                next_positions.insert(position + jmp_min + offset);
            }
        }
    }

    #[inline]
    fn jump_bck(
        &self,
        input: &[u8],
        literal: &[u8],
        range: &RangeInclusive<u16>,
        position: usize,
        next_positions: &mut IndexSet<usize>,
    ) {
        let jmp_range = input.len().saturating_sub(*range.end() as usize + 1)
            ..input.len().saturating_sub(*range.start() as usize);

        if jmp_range.start >= jmp_range.end {
            return;
        }

        if let Some(jmp_range) = input.get(jmp_range) {
            let lit = *literal.last().unwrap();
            for offset in memchr::memrchr_iter(lit, jmp_range) {
                next_positions.insert(position + jmp_range.len() - offset - 1);
            }
        }
    }
}
