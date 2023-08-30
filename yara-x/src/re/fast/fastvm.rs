use crate::re::fast::instr::{Instr, InstrParser};
use crate::re::{Action, CodeLoc};
use memx::memeq;
use std::ops::RangeInclusive;

/// Represents a faster alternative to [crate::re::thompson::pikevm::PikeVM]
///
/// A FastVM is similar to a PikeVM, but it is limited to a subset of the
/// regular expressions.
///
/// TODO: finish
pub(crate) struct FastVM<'r> {
    /// The code for the VM. Produced by [`crate::re::fast::Compiler`].
    code: &'r [u8],
    /// The list of currently active positions.
    threads: Vec<(usize, usize)>,
}

impl<'r> FastVM<'r> {
    /// Creates a new [`FastVM`].
    pub fn new(code: &'r [u8]) -> Self {
        Self { code, threads: Vec::new() }
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
        self.threads.push((start.location(), 0));

        while let Some((mut ip, mut position)) = self.threads.pop() {
            while position <= input.len() {
                let (instr, instr_size) =
                    InstrParser::decode_instr(&self.code[ip..]);

                ip += instr_size;

                match instr {
                    Instr::Match => match f(position) {
                        Action::Stop => {
                            self.threads.clear();
                            return;
                        }
                        Action::Continue => break,
                    },
                    Instr::Literal(literal) => {
                        let is_match = if backwards {
                            self.try_match_literal_bck(
                                &input[..input.len() - position],
                                literal,
                            )
                        } else {
                            self.try_match_literal_fwd(
                                &input[position..],
                                literal,
                            )
                        };
                        if !is_match {
                            break;
                        }
                        position += literal.len();
                    }
                    Instr::MaskedLiteral(literal, mask) => {
                        debug_assert_eq!(literal.len(), mask.len());
                        position += literal.len();
                    }
                    Instr::Jump(jump) => {
                        position += jump as usize;
                    }
                    Instr::JumpRange(range) => {
                        match InstrParser::decode_instr(&self.code[ip..]) {
                            (Instr::Literal(literal), _) if backwards => {
                                if let Some(new_position) = self.jump_bck(
                                    &input[..input.len() - position],
                                    *literal.last().unwrap(),
                                    range,
                                    ip,
                                    position,
                                ) {
                                    position = new_position;
                                } else {
                                    break;
                                }
                            }
                            (Instr::Literal(literal), _) if !backwards => {
                                if let Some(new_position) = self.jump_fwd(
                                    &input[position..],
                                    *literal.first().unwrap(),
                                    range,
                                    ip,
                                    position,
                                ) {
                                    position = new_position;
                                } else {
                                    break;
                                }
                            }
                            (Instr::MaskedLiteral(literal, mask), _)
                                if backwards && mask.last() == Some(&0xff) =>
                            {
                                if let Some(new_position) = self.jump_bck(
                                    &input[..input.len() - position],
                                    *literal.last().unwrap(),
                                    range,
                                    ip,
                                    position,
                                ) {
                                    position = new_position;
                                } else {
                                    break;
                                }
                            }
                            (Instr::MaskedLiteral(literal, mask), _)
                                if !backwards
                                    && mask.first() == Some(&0xff) =>
                            {
                                if let Some(new_position) = self.jump_fwd(
                                    &input[position..],
                                    *literal.first().unwrap(),
                                    range,
                                    ip,
                                    position,
                                ) {
                                    position = new_position;
                                } else {
                                    break;
                                }
                            }
                            _ => {
                                let min = *range.start() as usize;
                                for i in range.skip(1).rev() {
                                    self.threads
                                        .push((ip, position + i as usize))
                                }
                                position += min;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl FastVM<'_> {
    #[inline]
    fn try_match_literal_fwd(&mut self, input: &[u8], literal: &[u8]) -> bool {
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
    fn jump_fwd(
        &mut self,
        input: &[u8],
        lit: u8,
        range: RangeInclusive<u16>,
        ip: usize,
        mut position: usize,
    ) -> Option<usize> {
        let jmp_min = *range.start() as usize;
        let jmp_max = std::cmp::min(input.len(), *range.end() as usize + 1);
        let jmp_range = jmp_min..jmp_max;

        if jmp_range.start >= jmp_range.end {
            return None;
        }

        let mut offsets = memchr::memrchr_iter(lit, input.get(jmp_range)?);

        let last = offsets.next_back();
        for offset in offsets {
            self.threads.push((ip, position + jmp_min + offset))
        }

        if let Some(offset) = last {
            position += jmp_min + offset;
        } else {
            return None;
        }

        Some(position)
    }

    #[inline]
    fn jump_bck(
        &mut self,
        input: &[u8],
        lit: u8,
        range: RangeInclusive<u16>,
        ip: usize,
        mut position: usize,
    ) -> Option<usize> {
        let jump_range = input.len().saturating_sub(*range.end() as usize + 1)
            ..input.len().saturating_sub(*range.start() as usize);

        if jump_range.start >= jump_range.end {
            return None;
        }

        let jump_range = input.get(jump_range)?;
        let mut offsets = memchr::memchr_iter(lit, jump_range);

        let last = offsets.next_back();
        for offset in offsets {
            self.threads.push((ip, position + jump_range.len() - offset - 1))
        }

        if let Some(offset) = last {
            position += jump_range.len() - offset - 1;
        } else {
            return None;
        }

        Some(position)
    }
}
