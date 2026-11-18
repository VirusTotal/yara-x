use std::ops::{ControlFlow, RangeInclusive};
use std::{cmp, mem};

use bitflags::bitflags;
use itertools::izip;

use crate::re::fast::instr::{Instr, InstrParser};
use crate::re::position_set::PositionSet;
use crate::re::{CodeLoc, DEFAULT_SCAN_LIMIT, InputByte, WideIter};

/// A faster but less general alternative to [PikeVM].
///
/// `FastVM` is a virtual machine that executes bytecode that evaluates
/// regular expressions, similarly to [PikeVM]. `FastVM` is faster, but
/// only supports a subset of the regular expressions supported by [PikeVM]
/// (see the more details in the [`crate::re::fast`] module's documentation).
///
/// [PikeVM]: crate::re::thompson::PikeVM
pub(crate) struct FastVM<'r> {
    /// The code for the VM. Produced by [`crate::re::fast::Compiler`].
    code: &'r [u8],
    /// Maximum number of bytes to scan. The VM will abort after ingesting
    /// this number of bytes from the input.
    scan_limit: u32,
    /// A set with all the positions within the data that are matching so
    /// far. `PositionSet` is used instead of `HashSet` because insertion order
    /// needs to be maintained while iterating the positions and `HashSet`
    /// doesn't make any guarantees about iteration order. Also, `PositionSet`
    /// avoids hashing overhead by indexing a flat bitmap directly.
    positions: PositionSet,
    /// The set that will replace `positions` in the next iteration of the
    /// VM loop.
    next_positions: PositionSet,
}

impl<'r> FastVM<'r> {
    /// Creates a new [`FastVM`].
    pub fn new(code: &'r [u8]) -> Self {
        Self {
            code,
            positions: PositionSet::new(),
            next_positions: PositionSet::new(),
            scan_limit: DEFAULT_SCAN_LIMIT,
        }
    }

    /// Specifies the maximum number of bytes that will be scanned by the
    /// VM before aborting.
    ///
    /// This sets a limit on the number of bytes that the VM will read from the
    /// input while trying to find a match. Without a limit, the VM can incur
    /// in excessive execution time for regular expressions that are unbounded,
    /// like `foo.*bar`. For inputs that starts with `foo`, this regexp will
    /// try to scan the whole input, and that would take a long time if the
    /// input is excessively large.
    ///
    /// The default limit is 4096 bytes.
    #[allow(dead_code)]
    pub fn scan_limit(mut self, limit: u32) -> Self {
        self.scan_limit = limit;
        self
    }

    /// Returns the maximum number of bytes scanned by the VM before aborting.
    #[inline]
    pub fn get_scan_limit(&self) -> u32 {
        self.scan_limit
    }

    /// Executes VM code starting at `start` against `input`, calling `f` with
    /// the length in bytes of each match found.
    ///
    /// How `input` is interpreted depends on the execution direction encoded in
    /// `start`:
    ///
    /// * **Forward**: `input` starts at the anchor point
    ///   (typically the start of the atom) and extends toward the end of the
    ///   haystack. Matching advances left-to-right from `input[0]`, scanning at
    ///   most `self.scan_limit` bytes.
    /// * **Backward** (`start.backwards()`: `input` contains the bytes before
    ///   the anchor point (`&haystack[..atom_pos]`). Matching advances
    ///   right-to-left from `input[input.len()]`, scanning at most the last
    ///   `self.scan_limit` bytes of `input`.
    ///
    /// ```text
    ///     <-- backward input --> | <-- forward input -->
    ///          a b c d e f       |     g h i j k l
    ///                            ^
    ///                       starting point
    /// ```
    ///
    /// When `wide` is `true`, each pattern byte is expected to be followed by an
    /// interleaved `0x00` byte (UTF-16LE ASCII), so step sizes and reported
    /// match lengths are doubled in bytes.
    ///
    /// Returning [`ControlFlow::Continue`] from `f` instructs the VM to keep
    /// searching for additional matches, whereas [`ControlFlow::Break`] aborts
    /// execution immediately.
    pub fn try_match<C>(
        &mut self,
        start: C,
        input: &[u8],
        wide: bool,
        mut f: impl FnMut(usize) -> ControlFlow<()>,
    ) where
        C: CodeLoc,
    {
        let backwards = start.backwards();
        let mut ip = start.location();

        let input = if backwards {
            &input[input.len().saturating_sub(self.scan_limit as usize)..]
        } else {
            &input[..cmp::min(input.len(), self.scan_limit as usize)]
        };

        let step = if wide { 2 } else { 1 };

        self.positions.insert(0);

        let mut flags = JumpFlags::empty();

        if wide {
            flags.insert(JumpFlags::Wide);
        }

        while !self.positions.is_empty() {
            let (instr, instr_size) =
                InstrParser::decode_instr(&self.code[ip..]);

            ip += instr_size;

            match instr {
                Instr::Match => {
                    let mut stop = false;
                    for &position in self.positions.iter() {
                        // If the pattern is wide, make sure that the matching
                        // string contains the corresponding interleaved zeroes.
                        if wide {
                            let interleaved_zeroes_found = if backwards {
                                input
                                    .iter()
                                    .rev()
                                    .take(position)
                                    .step_by(2)
                                    .all(|b| *b == 0)
                            } else {
                                input
                                    .iter()
                                    .take(position)
                                    .skip(1)
                                    .step_by(2)
                                    .all(|b| *b == 0)
                            };
                            if !interleaved_zeroes_found {
                                continue;
                            }
                        }
                        match f(position) {
                            ControlFlow::Break(_) => {
                                stop = true;
                                break;
                            }
                            ControlFlow::Continue(_) => {}
                        }
                    }
                    if stop {
                        self.positions.clear();
                        return;
                    }
                }
                Instr::Literal(_) | Instr::MaskedLiteral(_, _) => {
                    self.advance_pattern(&instr, input, backwards, wide);
                }
                Instr::Alternation(alternatives) => {
                    for alt in alternatives {
                        self.advance_pattern(&alt, input, backwards, wide);
                    }
                }
                Instr::JumpExact(jump) => {
                    if let Some(jump_bytes) = (jump as usize).checked_mul(step)
                    {
                        for &position in self.positions.iter() {
                            if let Some(next_pos) =
                                position.checked_add(jump_bytes)
                                && next_pos <= input.len()
                            {
                                self.next_positions.insert(next_pos);
                            }
                        }
                    }
                }
                Instr::JumpExactNoNewline(jump) => {
                    if let Some(jump_bytes) = (jump as usize).checked_mul(step)
                    {
                        for &position in self.positions.iter() {
                            if let Some(next_pos) =
                                position.checked_add(jump_bytes)
                                && let Some(jump_range) =
                                    input.get(position..next_pos)
                                && memchr::memchr(0x0A, jump_range).is_none()
                            {
                                self.next_positions.insert(next_pos);
                            }
                        }
                    }
                }
                Instr::Jump(..)
                | Instr::JumpUnbounded(..)
                | Instr::JumpNoNewline(..)
                | Instr::JumpNoNewlineUnbounded(..) => {
                    let mut flags = flags;

                    let range = match instr {
                        Instr::Jump(range) => {
                            flags.insert(JumpFlags::AcceptNewlines);
                            range
                        }
                        Instr::JumpNoNewline(range) => range,
                        Instr::JumpUnbounded(range) => {
                            flags.insert(JumpFlags::AcceptNewlines);
                            range.start..=self.scan_limit
                        }
                        Instr::JumpNoNewlineUnbounded(range) => {
                            range.start..=self.scan_limit
                        }
                        _ => unreachable!(),
                    };

                    let expected_byte =
                        match InstrParser::decode_instr(&self.code[ip..]).0 {
                            Instr::Literal(literal) => {
                                if backwards {
                                    literal.last().copied()
                                } else {
                                    literal.first().copied()
                                }
                            }
                            Instr::MaskedLiteral(literal, mask) => {
                                if backwards && mask.last() == Some(&0xff) {
                                    literal.last().copied()
                                } else if !backwards
                                    && mask.first() == Some(&0xff)
                                {
                                    literal.first().copied()
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };

                    for &position in self.positions.iter() {
                        if position >= input.len() {
                            continue;
                        }
                        if backwards {
                            Self::jump_bck(
                                &input[..input.len() - position],
                                expected_byte,
                                flags,
                                &range,
                                position,
                                &mut self.next_positions,
                            );
                        } else {
                            Self::jump_fwd(
                                &input[position..],
                                expected_byte,
                                flags,
                                &range,
                                position,
                                &mut self.next_positions,
                            );
                        }
                    }
                }
            }

            mem::swap(&mut self.positions, &mut self.next_positions);
            self.next_positions.clear();
        }
    }
}

impl FastVM<'_> {
    /// Returns the `len`-byte slice in `input` to test at `position`, always
    /// oriented in left-to-right haystack order, or `None` if fewer than `len`
    /// bytes remain in the scan direction.
    ///
    /// * In forward mode, `position` is measured from the start of `input`,
    ///   returning `&input[position..position + len]`.
    /// * In backward mode, `position` is measured leftward from `input.len()`,
    ///   returning `&input[end - len..end]` where `end = input.len() - position`.
    #[inline(always)]
    fn candidate_window(
        input: &[u8],
        position: usize,
        len: usize,
        backwards: bool,
    ) -> Option<&[u8]> {
        if backwards {
            let end = input.len().checked_sub(position)?;
            input.get(end.checked_sub(len)?..end)
        } else {
            input.get(position..position.checked_add(len)?)
        }
    }

    /// Advances all currently active offsets in `self.positions` across `instr`
    /// ([`Instr::Literal`] or [`Instr::MaskedLiteral`]), inserting
    /// `position + byte_len` into `self.next_positions` for each offset whose
    /// candidate window matches.
    ///
    /// Used both for top-level literal instructions and for each branch inside
    /// an [`Instr::Alternation`].
    #[inline]
    fn advance_pattern(
        &mut self,
        instr: &Instr<'_>,
        input: &[u8],
        backwards: bool,
        wide: bool,
    ) {
        let step = if wide { 2 } else { 1 };

        match *instr {
            Instr::Literal(literal) => {
                let byte_len = step * literal.len();
                for &position in self.positions.iter() {
                    if let Some(window) = Self::candidate_window(
                        input, position, byte_len, backwards,
                    ) && Self::match_literal(window, literal, wide)
                    {
                        self.next_positions.insert(position + byte_len);
                    }
                }
            }
            Instr::MaskedLiteral(literal, mask) => {
                let byte_len = step * literal.len();
                for &position in self.positions.iter() {
                    if let Some(window) = Self::candidate_window(
                        input, position, byte_len, backwards,
                    ) && Self::match_masked_literal(
                        window, literal, mask, wide,
                    ) {
                        self.next_positions.insert(position + byte_len);
                    }
                }
            }
            // The only valid instructions here (including inside Alternation)
            // are Literal and MaskedLiteral.
            _ => unreachable!(),
        }
    }

    /// Returns `true` if `window` matches `literal` exactly.
    ///
    /// `window` must have length `literal.len()` (or `literal.len() * 2` when
    /// `wide` is `true`, in which case odd-indexed bytes must all be `0x00`).
    #[inline]
    fn match_literal(window: &[u8], literal: &[u8], wide: bool) -> bool {
        if wide {
            debug_assert_eq!(window.len(), literal.len() * 2);
            // Iterate the window in chunks of two bytes, where the first one
            // must match a byte in the literal, and the second one is the
            // interleaved zero.
            let (chunks, _) = window.as_chunks::<2>();
            for (chunk, byte) in izip!(chunks, literal.iter()) {
                if chunk[0] != *byte || chunk[1] != 0 {
                    return false;
                }
            }
            true
        } else {
            window == literal
        }
    }

    /// Returns `true` if `window` matches `literal` after applying `mask`
    /// (`(input_byte & mask_byte) == (literal_byte & mask_byte)`).
    ///
    /// `window` must have length `literal.len()` (or `literal.len() * 2` when
    /// `wide` is `true`, in which case odd-indexed bytes must all be `0x00`).
    #[inline]
    fn match_masked_literal(
        window: &[u8],
        literal: &[u8],
        mask: &[u8],
        wide: bool,
    ) -> bool {
        debug_assert_eq!(literal.len(), mask.len());

        if wide {
            debug_assert_eq!(window.len(), literal.len() * 2);
            // Iterate the window in chunks of two bytes, where the first one
            // must match a byte in the literal, and the second one is the
            // interleaved zero.
            let input = WideIter::non_zero_first(window.iter());

            for (input, byte, mask) in izip!(input, literal, mask) {
                match input {
                    InputByte::Valid(b) if b & *mask == *byte & *mask => {}
                    _ => return false,
                }
            }
        } else {
            debug_assert_eq!(window.len(), literal.len());
            for (input, byte, mask) in izip!(window, literal, mask) {
                if *input & *mask != *byte & *mask {
                    return false;
                }
            }
        }

        true
    }

    /// Advances a single forward `position` across a variable-length jump
    /// `range` (`[min..=max]` steps, scaled by 2 when [`JumpFlags::Wide`] is
    /// set), inserting reachable target offsets into `next_positions`.
    ///
    /// `input` is the remaining slice starting at `position`
    /// (`&full_input[position..]`). When `byte_after_jmp` is `Some(b)` (the
    /// known leading byte of the instruction immediately following the jump),
    /// SIMD `memchr` / `memchr2` is used to record only offsets within the jump
    /// window where `b` actually occurs; when [`JumpFlags::AcceptNewlines`] is
    /// not set, any `0x0A` byte in the mandatory prefix or jump window halts
    /// further expansion from `position`.
    #[inline]
    fn jump_fwd(
        input: &[u8],
        byte_after_jmp: Option<u8>,
        flags: JumpFlags,
        range: &RangeInclusive<u32>,
        position: usize,
        next_positions: &mut PositionSet,
    ) {
        let step = if flags.contains(JumpFlags::Wide) { 2 } else { 1 };

        let n = (*range.start() as usize).saturating_mul(step);
        let m = (*range.end() as usize).saturating_mul(step);

        let range_min = n;
        let range_max = cmp::min(input.len(), m.saturating_add(step));

        if range_min >= range_max {
            return;
        }

        // If newlines are not accepted in the data being skipped by the jump
        // lets make sure that the ranges that goes from the current position
        // to position + n doesn't contain any newlines.
        if !flags.contains(JumpFlags::AcceptNewlines)
            && memchr::memchr(0x0A, &input[..range_min]).is_some()
        {
            return;
        }

        let jmp_range = &input[range_min..range_max];

        let mut on_match_found = |offset| {
            next_positions.insert(position + range_min + offset);
        };

        let accept_newlines = flags.contains(JumpFlags::AcceptNewlines);

        match byte_after_jmp {
            Some(b) if !accept_newlines => {
                // Search for the literal byte and the newline at the same
                // time. Any offset found before the newline is a position
                // that needs to be verified, but once the newline is found
                // no more positions will match and we can return.
                //
                // There's an edge case when the literal byte is also a
                // newline, in such cases any newline found most also be
                // verified.
                for offset in memchr::memchr2_iter(b, 0x0A, jmp_range) {
                    if b != 0x0A && jmp_range[offset] == 0x0A {
                        return;
                    }
                    on_match_found(offset)
                }
            }
            Some(b) if accept_newlines => {
                // If newlines are accepted, we can search for the literal
                // byte alone. There are potential matches only at the
                // positions where the byte is found.
                for offset in memchr::memchr_iter(b, jmp_range) {
                    on_match_found(offset)
                }
            }
            _ => {
                for (offset, byte) in jmp_range.iter().enumerate() {
                    if !accept_newlines && *byte == 0x0A {
                        return;
                    }
                    on_match_found(offset)
                }
            }
        }
    }

    /// Advances a single backward `position` leftward across a variable-length
    /// jump `range` (`[min..=max]` steps, scaled by 2 when [`JumpFlags::Wide`]
    /// is set), inserting reachable target distances into `next_positions`.
    ///
    /// `input` is the prefix preceding `position`
    /// (`&full_input[..full_input.len() - position]`). When
    /// `expected_after_jump` is `Some(b)` (the known trailing byte of the
    /// preceding sub-pattern in backward execution), reverse SIMD `memrchr` /
    /// `memrchr2` scans right-to-left so only candidate positions preceded by
    /// `b` are inserted, stopping at the first `0x0A` when
    /// [`JumpFlags::AcceptNewlines`] is not set.
    #[inline]
    fn jump_bck(
        input: &[u8],
        expected_after_jump: Option<u8>,
        flags: JumpFlags,
        range: &RangeInclusive<u32>,
        position: usize,
        next_positions: &mut PositionSet,
    ) {
        let step = if flags.contains(JumpFlags::Wide) { 2 } else { 1 };

        let n = (*range.start() as usize).saturating_mul(step);
        let m = (*range.end() as usize).saturating_mul(step);

        //  Let's explain what this function does using the following pattern
        //  as an example:
        //
        //    { 01 02 03 [n-m] 04 05 06 07 }
        //
        //  The scheme below resumes what's happening. The atom found by
        //  Aho-Corasick is `04 05 06 07`, and this function is about to
        //  process the jump [n-m]. The input received is the data that ends
        //  where the atom starts. What we want to do is scanning the range
        // `range_min..range_max` from right to left looking for all instances
        //  of `03`, which are positions where `01 02 03` could match while
        //  scanning backwards.
        //
        //  |--------------- input ---------------|
        //  |              |--------- M ----------|
        //  |              |          |---- N ----|
        //  | ... 01 02 03 | .................... | 04 05 06 07
        //             ^              ^
        //             range_min      range_max
        //
        let range_min = input.len().saturating_sub(m.saturating_add(step));
        let range_max = input.len().saturating_sub(n);

        if range_min >= range_max {
            return;
        }

        // If newlines are not accepted in the data being skipped by the jump
        // lets make sure that the ranges that goes from the current position
        // to position + n doesn't contain any newlines.
        if !flags.contains(JumpFlags::AcceptNewlines)
            && memchr::memchr(0x0A, &input[range_max..]).is_some()
        {
            return;
        }

        let jmp_range = &input[range_min..range_max];

        let mut on_match_found = |offset| {
            if let Some(jump) = jmp_range.len().checked_sub(offset + step) {
                next_positions.insert(position + n + jump);
            }
        };

        let accept_newlines = flags.contains(JumpFlags::AcceptNewlines);

        match expected_after_jump {
            Some(b) if !accept_newlines => {
                // Search for the literal byte and the newline at the same
                // time. Any offset found before the newline is a position
                // that needs to be verified, but once the newline is found
                // no more positions will match and we can return.
                //
                // There's an edge case when the literal byte is also a
                // newline, in such cases any newline found most also be
                // verified.
                for offset in memchr::memrchr2_iter(b, 0x0A, jmp_range) {
                    if b != 0x0A && jmp_range[offset] == 0x0A {
                        return;
                    }
                    on_match_found(offset)
                }
            }
            Some(b) if accept_newlines => {
                // If newlines are accepted, we can search for the literal
                // byte alone. There are potential matches only at the
                // positions where the byte is found.
                for offset in memchr::memrchr_iter(b, jmp_range) {
                    on_match_found(offset)
                }
            }
            _ => {
                for (offset, byte) in jmp_range.iter().enumerate().rev() {
                    if !accept_newlines && *byte == 0x0A {
                        return;
                    }
                    on_match_found(offset)
                }
            }
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct JumpFlags: u8  {
        const AcceptNewlines = 0x01;
        const Wide           = 0x02;
    }
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use crate::re::fast::{Compiler, FastVM};
    use crate::re::hir::Hir;

    #[test]
    fn large_jumps_with_u32_scan_limit() {
        for (min, max) in
            [(70_000, Some(70_000)), (65_536, Some(70_000)), (65_536, None)]
        {
            // Forward jump > u16::MAX: `{ 01 02 [min-max] 03 }`.
            let hir = Hir::concat(vec![
                Hir::literal([0x01, 0x02]),
                Hir::any_byte_repetition(min, max, false),
                Hir::literal([0x03]),
            ]);
            let mut code = Vec::new();
            let atoms = Compiler::new().compile(&hir, &mut code).unwrap();
            assert_eq!(atoms.len(), 1);
            assert!(atoms[0].bck_code.is_none());

            let mut input = vec![0x01, 0x02];
            input.extend(std::iter::repeat_n(0xff, 70_000));
            input.push(0x03);

            let mut matched_len = None;
            let mut vm = FastVM::new(&code).scan_limit(100_000);
            vm.try_match(atoms[0].fwd_code.unwrap(), &input, false, |len| {
                matched_len = Some(len);
                ControlFlow::Break(())
            });
            assert_eq!(matched_len, Some(input.len()));

            // Backward jump > u16::MAX: `{ 01 [min-max] 02 03 }`.
            let hir = Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::any_byte_repetition(min, max, false),
                Hir::literal([0x02, 0x03]),
            ]);
            let mut code = Vec::new();
            let atoms = Compiler::new().compile(&hir, &mut code).unwrap();
            assert_eq!(atoms.len(), 1);
            assert!(atoms[0].bck_code.is_some());

            let mut prefix = vec![0x01];
            prefix.extend(std::iter::repeat_n(0xff, 70_000));

            let mut matched_bck_len = None;
            let mut vm = FastVM::new(&code).scan_limit(100_000);
            vm.try_match(atoms[0].bck_code.unwrap(), &prefix, false, |len| {
                matched_bck_len = Some(len);
                ControlFlow::Break(())
            });
            assert_eq!(matched_bck_len, Some(prefix.len()));
        }
    }

    #[test]
    fn overlapping_jumps_and_large_scan_limit() {
        // `{ 01 02 [0-10] 03 [0-600000] 04 }` exercises duplicate frontier
        // insertions across overlapping jumps and positions > 512 KiB.
        let hir = Hir::concat(vec![
            Hir::literal([0x01, 0x02]),
            Hir::any_byte_repetition(0, Some(10), false),
            Hir::literal([0x03]),
            Hir::any_byte_repetition(0, Some(600_000), false),
            Hir::literal([0x04]),
        ]);
        let mut code = Vec::new();
        let atoms = Compiler::new().compile(&hir, &mut code).unwrap();

        let mut input = vec![0x01, 0x02, 0x03, 0x03, 0x03];
        input.extend(std::iter::repeat_n(0xaa, 550_000));
        input.push(0x04);

        let mut matched_len = None;
        let mut vm = FastVM::new(&code).scan_limit(600_000);
        vm.try_match(atoms[0].fwd_code.unwrap(), &input, false, |len| {
            matched_len = Some(len);
            ControlFlow::Break(())
        });
        assert_eq!(matched_len, Some(input.len()));
    }
}
