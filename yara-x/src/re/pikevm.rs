use crate::re::instr::{decode_instr, epsilon_closure, Cache, Instr};
use std::mem;

pub struct PikeVM {
    fibers: Vec<usize>,
    next_fibers: Vec<usize>,
    cache: Cache,
}

impl PikeVM {
    /// Creates a new [`PikeVM`].
    pub fn new() -> Self {
        Self {
            fibers: Vec::new(),
            next_fibers: Vec::new(),
            cache: Cache::new(),
        }
    }

    /// Returns `None` the [`PikeVM`] can't match the given data or
    /// the length of the matched data. Notice the length can be zero
    /// if the regexp matches the empty string.
    pub fn try_match<'a, F, B>(
        &mut self,
        code: &[u8],
        start: usize,
        backwards: bool,
        mut fwd_data: F,
        mut bck_data: B,
    ) -> Option<usize>
    where
        F: Iterator<Item = &'a u8>,
        B: Iterator<Item = &'a u8>,
    {
        let step = 1;
        let mut matched_bytes = 0;
        let mut result = None;
        let mut byte = fwd_data.next();

        epsilon_closure(
            code,
            start,
            backwards,
            byte,
            bck_data.next(),
            &mut self.cache,
            &mut self.fibers,
        );

        while !self.fibers.is_empty() {
            let next_byte = fwd_data.next();

            for fiber in self.fibers.iter() {
                let (instr, size) = decode_instr(&code[*fiber..]);
                let next_instr = *fiber + size;

                let is_match = match instr {
                    Instr::AnyByte => byte.is_some(),
                    Instr::Byte(expected) => {
                        matches!(byte, Some(byte) if *byte == expected)
                    }
                    Instr::MaskedByte(expected, mask) => {
                        matches!(byte, Some(byte) if *byte & mask == expected)
                    }
                    Instr::ClassBitmap(class) => {
                        matches!(byte, Some(byte) if class.contains(*byte))
                    }
                    Instr::ClassRanges(class) => {
                        matches!(byte, Some(byte) if class.contains(*byte))
                    }
                    Instr::Match => {
                        result = Some(matched_bytes);
                        // if non-greedy break
                        break;
                    }
                    Instr::Eoi => {
                        // TODO: is this correct?
                        break;
                    }
                    _ => unreachable!(),
                };

                if is_match {
                    epsilon_closure(
                        code,
                        next_instr,
                        backwards,
                        next_byte,
                        byte,
                        &mut self.cache,
                        &mut self.next_fibers,
                    );
                }
            }

            byte = next_byte;
            matched_bytes += step;
            mem::swap(&mut self.fibers, &mut self.next_fibers);
            self.next_fibers.clear();
        }

        result
    }
}
