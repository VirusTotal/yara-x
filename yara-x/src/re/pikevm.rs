use crate::re::instr::{decode_instr, epsilon_closure, Instr};
use std::mem;

///
pub struct PikeVM {
    fibers: Vec<usize>,
    next_fibers: Vec<usize>,
}

impl PikeVM {
    /// Creates a new [`PikeVM`].
    pub fn new() -> Self {
        Self { fibers: Vec::new(), next_fibers: Vec::new() }
    }

    /// Returns `None` the [`PikeVM`] can't match the given data or
    /// the length of the matched data. Notice the length can be zero
    /// if the regexp matches the empty string.
    pub fn try_match<'a, T>(
        &mut self,
        code: &[u8],
        start: usize,
        mut data: T,
    ) -> Option<usize>
    where
        T: Iterator<Item = &'a u8>,
    {
        let step = 1;
        let mut at = 0;
        let mut result = None;
        let mut byte = None;

        epsilon_closure(code, start, &mut self.fibers);

        while !self.fibers.is_empty() {
            byte = data.next();

            for fiber in self.fibers.iter() {
                let (instr, size) = decode_instr(&code[*fiber..]);
                let next_instr = *fiber + size;
                match instr {
                    Instr::AnyByte => {
                        if byte.is_some() {
                            epsilon_closure(
                                code,
                                next_instr,
                                &mut self.next_fibers,
                            );
                        }
                    }
                    Instr::Byte(expected) => {
                        if let Some(byte) = byte {
                            if *byte == expected {
                                epsilon_closure(
                                    code,
                                    next_instr,
                                    &mut self.next_fibers,
                                );
                            }
                        }
                    }
                    Instr::MaskedByte(expected, mask) => {
                        if let Some(byte) = byte {
                            if byte & mask == expected {
                                epsilon_closure(
                                    code,
                                    next_instr,
                                    &mut self.next_fibers,
                                );
                            }
                        }
                    }
                    Instr::ClassBitmap(class) => {
                        if let Some(byte) = byte {
                            if class.contains(*byte) {
                                epsilon_closure(
                                    code,
                                    next_instr,
                                    &mut self.next_fibers,
                                );
                            }
                        }
                    }
                    Instr::ClassRanges(class) => {
                        if let Some(byte) = byte {
                            if class.contains(*byte) {
                                epsilon_closure(
                                    code,
                                    next_instr,
                                    &mut self.next_fibers,
                                );
                            }
                        }
                    }
                    Instr::Match => {
                        result = Some(at);
                        break;
                    }
                    Instr::EOI => {
                        // TODO: is this correct?
                        break;
                    }
                    _ => unreachable!(),
                }
            }

            at += step;
            mem::swap(&mut self.fibers, &mut self.next_fibers);
            self.next_fibers.clear();
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use crate::re::compiler::Compiler;
    use crate::re::pikevm::PikeVM;

    #[test]
    fn pike_vm_1() {
        let mut parser = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build();

        let (forward_code, backward_code, atoms) =
            Compiler::new().compile(&parser.parse("(?s)a*?").unwrap());

        let forward_code = forward_code.into_inner();
        let mut pike_vm = PikeVM::new();

        assert_eq!(
            pike_vm.try_match(forward_code.as_slice(), 0, b"aaa".iter()),
            Some(0)
        );
    }
}
