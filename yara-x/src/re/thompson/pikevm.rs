use bitvec::array::BitArray;
use bitvec::vec::BitVec;

use super::instr::{Instr, InstrParser};
use crate::re::thompson::instr::SplitId;
use crate::re::{Action, CodeLoc, DEFAULT_SCAN_LIMIT};

/// Represents a [Pike's VM](https://swtch.com/~rsc/regexp/regexp2.html) that
/// executes VM code produced by the [compiler][`crate::re::compiler::Compiler`].
pub(crate) struct PikeVM<'r> {
    /// The code for the VM. Produced by [`crate::re::compiler::Compiler`].
    code: &'r [u8],
    /// The list of currently active threads. Each item in this list is a
    /// position within the VM code, pointing to some VM instruction. Each item
    /// in the list is unique, the VM guarantees that there aren't two active
    /// threads at the same VM instruction.
    threads: ThreadSet,
    /// The list of threads that will become the active threads when the next
    /// byte is read from the input.
    next_threads: ThreadSet,
    /// Maximum number of bytes to scan. The VM will abort after ingesting
    /// this number of bytes from the input.
    scan_limit: u16,
    /// State for the [`epsilon_closure`] function.
    cache: EpsilonClosureState,
}

impl<'r> PikeVM<'r> {
    /// Creates a new [`PikeVM`].
    pub fn new(code: &'r [u8]) -> Self {
        Self {
            code,
            threads: ThreadSet::new(),
            next_threads: ThreadSet::new(),
            cache: EpsilonClosureState::new(),
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
    pub fn scan_limit(mut self, limit: u16) -> Self {
        self.scan_limit = limit;
        self
    }

    /// Executes VM code starting at the `start` location and calls `f` for
    /// each match found. The `right` slice contains the bytes at the right
    /// of the starting point (i.e: from the starting point until the end of
    /// the input), while the `right` slice contains the bytes at the left of
    /// the starting point (i.e: from the start of the input until the starting
    /// point.
    ///
    /// ```text
    ///     <-- left --> | <-- right -->
    ///      a b c d e f | g h i j k l k
    ///                  |
    ///                   starting point
    /// ```
    ///
    /// The `f` function must return either [`Action::Continue`] or
    /// [`Action::Stop`], the former will cause the VM to keep trying to find
    /// longer matches, while the latter will stop the scanning.
    #[inline]
    pub(crate) fn try_match<C>(
        &mut self,
        start: C,
        right: &[u8],
        left: &[u8],
        wide: bool,
        mut f: impl FnMut(usize) -> Action,
    ) where
        C: CodeLoc,
    {
        match (start.backwards(), wide) {
            // Going forward, not wide.
            (false, false) => {
                self.try_match_impl(start, right.iter(), left.iter().rev(), f)
            }
            // Going forward, wide.
            (false, true) => self.try_match_impl(
                start,
                right.iter().step_by(2),
                left.iter().rev().skip(1).step_by(2),
                |match_len| f(match_len * 2),
            ),
            // Going backward, not wide.
            (true, false) => {
                self.try_match_impl(start, left.iter().rev(), right.iter(), f)
            }
            // Going backward, wide.
            (true, true) => self.try_match_impl(
                start,
                left.iter().rev().skip(1).step_by(2),
                right.iter().step_by(2),
                |match_len| f(match_len * 2),
            ),
        }
    }

    /// Executes VM code starting at the `start` location and calls `f` for
    /// each match found. Input bytes are read from the `fwd_input` iterator
    /// until no more bytes are available or the scan limit is reached. When
    /// a match is found `f` is called with the number of bytes that matched.
    /// The number of matching bytes can be zero, as some regexps can match
    /// a zero-length string.
    ///
    /// The `f` function must return either [`Action::Continue`] or
    /// [`Action::Stop`], the former will cause the VM to keep trying to find
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
    fn try_match_impl<'a, C, F, B>(
        &mut self,
        start: C,
        mut fwd_input: F,
        mut bck_input: B,
        mut f: impl FnMut(usize) -> Action,
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
                let (instr, size) = InstrParser::decode_instr(unsafe {
                    self.code.get_unchecked(*ip..)
                });

                let is_match = match instr {
                    Instr::AnyByte => curr_byte.is_some(),
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
                        Action::Stop => break,
                        Action::Continue => false,
                    },
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

            if current_pos >= self.scan_limit.into() {
                self.threads.clear();
                break;
            }
        }
    }
}

/// Structure used by the [`epsilon_closure`] function for maintaining
/// its state during the computation of an epsilon closure. See the
/// documentation of [`epsilon_closure`] for details.
pub struct EpsilonClosureState {
    threads: Vec<usize>,
    executed_splits: BitArray<[u64; 4]>,
}

impl EpsilonClosureState {
    pub fn new() -> Self {
        Self { threads: Vec::new(), executed_splits: Default::default() }
    }

    #[inline(always)]
    pub fn executed(&mut self, split_id: SplitId) -> bool {
        unsafe {
            let executed =
                *self.executed_splits.get_unchecked(split_id as usize);
            if !executed {
                self.executed_splits.set_unchecked(split_id as usize, true)
            }
            executed
        }
    }
}

/// Computes the epsilon closure derived from executing the code starting at
/// a given position.
///
/// In a NFA, the epsilon closure of some state `S`, is the set containing all
/// the states that can be reached from `S` by following epsilon transitions
/// (i.e: transitions that don't consume any input symbol). The Pike's VM code
/// produced for a regexp is simply another way of representing a NFA where
/// each instruction is a state. The NFA jumps from one state to the other by
/// following the instruction flow. Instructions like `jump` and `split`, which
/// jump from one state to another (or others) unconditionally, without
/// consuming a byte from the input, are epsilon transitions in this context.
///
/// This function starts at the instruction in the `start` location, and from
/// there explore all the possible transitions that don't depend on the next
/// value from the input. When some instruction that depends on the next
/// input is found (a non-epsilon transition) the location of that instruction
/// is added to the closure.
///
/// This function expects a mutable reference to a [`EpsilonClosureState`],
/// which is the structure used for keeping track of the current state while
/// computing the epsilon closure. Instead of creating a new instance of
/// [`EpsilonClosureState`] on each call to [`epsilon_closure`], the same
/// instance should be reused in order to prevent unnecessary allocations.
/// The function guarantees that the state is empty before returning, and
/// therefore it can be re-used safely.
#[inline(always)]
pub(crate) fn epsilon_closure<C: CodeLoc>(
    code: &[u8],
    start: C,
    curr_byte: Option<&u8>,
    prev_byte: Option<&u8>,
    state: &mut EpsilonClosureState,
    closure: &mut ThreadSet,
) {
    state.threads.push(start.location());
    state.executed_splits.fill(false);

    while let Some(ip) = state.threads.pop() {
        let (instr, size) =
            InstrParser::decode_instr(unsafe { code.get_unchecked(ip..) });
        let next = ip + size;
        match instr {
            Instr::AnyByte
            | Instr::Byte(_)
            | Instr::MaskedByte { .. }
            | Instr::CaseInsensitiveChar(_)
            | Instr::ClassBitmap(_)
            | Instr::ClassRanges(_)
            | Instr::Match => {
                closure.insert(ip);
            }
            Instr::SplitA(id, offset) => {
                if !state.executed(id) {
                    state
                        .threads
                        .push((ip as i64 + offset as i64).try_into().unwrap());
                    state.threads.push(next);
                }
            }
            Instr::SplitB(id, offset) => {
                if !state.executed(id) {
                    state.threads.push(next);
                    state
                        .threads
                        .push((ip as i64 + offset as i64).try_into().unwrap());
                }
            }
            Instr::SplitN(split) => {
                if !state.executed(split.id()) {
                    for offset in split.offsets().rev() {
                        state.threads.push(
                            (ip as i64 + offset as i64).try_into().unwrap(),
                        );
                    }
                }
            }
            Instr::Jump(offset) => {
                state
                    .threads
                    .push((ip as i64 + offset as i64).try_into().unwrap());
            }
            Instr::Start => {
                if start.backwards() {
                    if curr_byte.is_none() {
                        state.threads.push(next);
                    }
                } else if prev_byte.is_none() {
                    state.threads.push(next);
                }
            }
            Instr::End => {
                if start.backwards() {
                    if prev_byte.is_none() {
                        state.threads.push(next);
                    }
                } else if curr_byte.is_none() {
                    state.threads.push(next);
                }
            }
            Instr::WordBoundary | Instr::WordBoundaryNeg => {
                let mut is_match = match (prev_byte, curr_byte) {
                    (Some(p), Some(c)) => {
                        p.is_ascii_alphanumeric() != c.is_ascii_alphanumeric()
                    }
                    (None, Some(b)) | (Some(b), None) => {
                        b.is_ascii_alphanumeric()
                    }
                    _ => false,
                };

                if matches!(instr, Instr::WordBoundaryNeg) {
                    is_match = !is_match;
                }

                if is_match {
                    state.threads.push(next)
                }
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct ThreadSet {
    threads: Vec<usize>,
    base: usize,
    p_bitmap: BitVec<usize>,
    n_bitmap: BitVec<usize>,
}

impl ThreadSet {
    pub fn new() -> Self {
        Self {
            threads: Vec::new(),
            base: 0,
            p_bitmap: BitVec::repeat(false, 1024),
            n_bitmap: BitVec::repeat(false, 1024),
        }
    }

    #[inline]
    pub fn insert(&mut self, value: usize) -> bool {
        if self.threads.is_empty() {
            self.base = value;
            self.threads.push(value);
            return true;
        }
        if self.base == value {
            return false;
        }

        let offset = value as isize - self.base as isize;

        match offset {
            offset if offset > 0 => {
                let offset = offset as usize;
                if self.p_bitmap.len() <= offset {
                    self.p_bitmap.resize(offset + 1, false);
                    self.p_bitmap.set(offset, true);
                    self.threads.push(value);
                    true
                } else if !*self.p_bitmap.get(offset).unwrap() {
                    self.p_bitmap.set(offset, true);
                    self.threads.push(value);
                    true
                } else {
                    false
                }
            }
            offset if offset < 0 => {
                let offset = -offset as usize;
                if self.n_bitmap.len() <= offset {
                    self.n_bitmap.resize(offset + 1, false);
                    self.n_bitmap.set(offset, true);
                    self.threads.push(value);
                    true
                } else if !*self.n_bitmap.get(offset).unwrap() {
                    self.n_bitmap.set(offset, true);
                    self.threads.push(value);
                    true
                } else {
                    false
                }
            }
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    #[inline]
    pub fn clear(&mut self) {
        for thread in self.threads.iter() {
            let offset = *thread as isize - self.base as isize;
            if offset >= 0 {
                self.p_bitmap.set(offset as usize, false);
            } else {
                self.n_bitmap.set((-offset) as usize, false);
            }
        }

        self.threads.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &usize> {
        self.threads.iter()
    }

    pub fn into_vec(self) -> Vec<usize> {
        self.threads
    }
}

#[cfg(test)]
mod tests {
    use crate::re::thompson::pikevm::ThreadSet;

    #[test]
    fn thread_set() {
        let mut s = ThreadSet::new();

        assert!(s.insert(4));
        assert!(s.insert(2));
        assert!(s.insert(10));
        assert!(s.insert(0));
        assert!(s.insert(2000));

        assert!(!s.insert(4));
        assert!(!s.insert(2));
        assert!(!s.insert(10));
        assert!(!s.insert(0));
        assert!(!s.insert(2000));

        assert_eq!(s.threads, vec![4, 2, 10, 0, 2000]);

        s.clear();

        assert!(s.insert(200));
        assert!(s.insert(2));
        assert!(s.insert(10));
        assert!(s.insert(300));
        assert!(s.insert(250));

        assert_eq!(s.threads, vec![200, 2, 10, 300, 250]);
    }
}
