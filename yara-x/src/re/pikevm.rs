use std::mem;

use crate::re::instr::{
    decode_instr, epsilon_closure, CodeLoc, EpsilonClosureState, Instr,
};

pub(crate) enum Match {
    Continue,
    Stop,
}

/// Represents a [Pike's VM](https://swtch.com/~rsc/regexp/regexp2.html) that
/// executes VM code produced by the [compiler][`crate::re::compiler::Compiler`].
pub(crate) struct PikeVM<'r> {
    /// The code for the VM. Produced by [`crate::re::compiler::Compiler`].
    code: &'r [u8],
    /// The list of currently active threads. Each item in this list is a
    /// position within the VM code, pointing to some VM instruction. Each item
    /// in the list is unique, the VM guarantees that there aren't two active
    /// threads at the same VM instruction.
    threads: Vec<usize>,
    /// The list of threads that will become the active threads when the next
    /// byte is read from the input.
    next_threads: Vec<usize>,
    /// Maximum number of bytes to scan. The VM will abort after ingesting
    /// this number of bytes from the input.
    scan_limit: usize,
    /// State for the [`epsilon_closure`] function.
    cache: EpsilonClosureState,
}

impl<'r> PikeVM<'r> {
    pub const DEFAULT_SCAN_LIMIT: usize = 4096;

    /// Creates a new [`PikeVM`].
    pub fn new(code: &'r [u8]) -> Self {
        Self {
            code,
            threads: Vec::new(),
            next_threads: Vec::new(),
            cache: EpsilonClosureState::new(),
            scan_limit: Self::DEFAULT_SCAN_LIMIT,
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
    pub fn scan_limit(mut self, limit: usize) -> Self {
        self.scan_limit = limit;
        self
    }

    /// Executes VM code starting at the `start` location and calls `f` for
    /// each match found. Input bytes are read from the `fwd_input` iterator
    /// until no more bytes are available or the scan limit is reached. When
    /// a match is found `f` is called with the number of bytes that matched.
    /// The number of matching bytes can be zero, as some regexps can match
    /// a zero-length string.
    ///
    /// The `f` function must return either [`Match::Continue`] or
    /// [`Match::Stop`], the former will cause the VM to keep trying to find
    /// longer matches, while the latter will stop the scanning.
    ///
    /// `bck_input` is an iterator that returns the bytes that are before
    /// the starting point of `fwd_input`, in reverse order. For instance,
    /// suppose we have the string `a b c e f g h i`, and `fwd_input` starts
    /// at the `f` character and returns `f`, `g`, `h` and `i` in that order.
    /// In such case `bck_input` will return `e`, `c`, `b` and `a`.
    ///
    /// ```text
    ///       a  b  c  e  f   g   h   i
    ///                   |
    ///      <- bck_input | fwd_input ->
    /// ```
    ///
    /// The purpose of `bck_input` is allowing the function to access the bytes
    /// that appear right before the start of `fwd_input` for matching some
    /// look-around assertions that need information about the surrounding
    /// bytes.
    pub(crate) fn try_match<'a, C, F, B>(
        &mut self,
        start: C,
        mut fwd_input: F,
        mut bck_input: B,
        mut f: impl FnMut(usize) -> Match,
    ) where
        C: CodeLoc,
        F: Iterator<Item = &'a u8>,
        B: Iterator<Item = &'a u8>,
    {
        let step = 1;
        let mut current_pos = 0;
        let mut curr_byte = fwd_input.next();

        // Make sure that the list of threads is empty when this function is
        // called.
        debug_assert!(self.threads.is_empty());

        epsilon_closure(
            self.code,
            start,
            curr_byte,
            bck_input.next(),
            &mut self.cache,
            &mut self.threads,
        );

        while !self.threads.is_empty() {
            let next_byte = fwd_input.next();

            for ip in self.threads.iter() {
                let (instr, size) = decode_instr(&self.code[*ip..]);

                let is_match = match instr {
                    Instr::AnyByte => {
                        matches!(curr_byte, Some(_))
                    }
                    Instr::Byte(byte) => {
                        matches!(curr_byte, Some(b) if *b == byte)
                    }
                    Instr::MaskedByte { byte, mask } => {
                        matches!(curr_byte, Some(b) if *b & mask == byte)
                    }
                    Instr::CaseInsensitiveChar(byte) => {
                        matches!(curr_byte, Some(b) if b.to_ascii_lowercase() == byte)
                    }
                    Instr::ClassBitmap(class) => {
                        matches!(curr_byte, Some(b) if class.contains(*b))
                    }
                    Instr::ClassRanges(class) => {
                        matches!(curr_byte, Some(b) if class.contains(*b))
                    }
                    Instr::Match => match f(current_pos) {
                        Match::Stop => break,
                        Match::Continue => false,
                    },
                    Instr::Eoi => {
                        // TODO: is this correct?
                        break;
                    }
                    _ => unreachable!(),
                };

                if is_match {
                    epsilon_closure(
                        self.code,
                        C::from(*ip + size),
                        next_byte,
                        curr_byte,
                        &mut self.cache,
                        &mut self.next_threads,
                    );
                }
            }

            curr_byte = next_byte;
            current_pos += step;

            mem::swap(&mut self.threads, &mut self.next_threads);
            self.next_threads.clear();

            if current_pos >= self.scan_limit {
                self.threads.clear();
                break;
            }
        }
    }
}
