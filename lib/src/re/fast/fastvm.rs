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
    /// When `greedy` is `true`, variable-length jumps try longer jumps before
    /// shorter ones; otherwise they try shorter jumps first.
    ///
    /// Returning [`ControlFlow::Continue`] from `f` instructs the VM to keep
    /// searching for additional matches, whereas [`ControlFlow::Break`] aborts
    /// execution immediately.
    pub fn try_match<C>(
        &mut self,
        start: C,
        input: &[u8],
        wide: bool,
        greedy: bool,
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

        if greedy {
            flags.insert(JumpFlags::Greedy);
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
                    for &position in self.positions.iter() {
                        if let Some(next_pos) = Self::match_literal_instr(
                            &instr, input, position, backwards, wide,
                        ) {
                            self.next_positions.insert(next_pos);
                        }
                    }
                }
                Instr::Alternation(alternatives) => {
                    // Iterate positions in the outer loop and alternatives in
                    // the inner loop so `next_positions` preserves match
                    // priority order: any branch reachable from a
                    // higher-priority position precedes branches from
                    // lower-priority positions, and earlier alternatives
                    // precede later ones at the same position.
                    for &position in self.positions.iter() {
                        for alt in alternatives {
                            if let Some(next_pos) = Self::match_literal_instr(
                                &alt, input, position, backwards, wide,
                            ) {
                                self.next_positions.insert(next_pos);
                            }
                        }
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
                                    Self::candidate_window(
                                        input, position, jump_bytes, backwards,
                                    )
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
                        // `position == input.len()` means the input is
                        // exhausted. That is not a dead end: a jump whose
                        // minimum is zero can still consume nothing.
                        if position > input.len() {
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

    /// Matches a literal instruction ([`Instr::Literal`] or
    /// [`Instr::MaskedLiteral`]) against `input` at `position`, returning the
    /// next position (`position + byte_len`) if it matches.
    ///
    /// Used both for top-level literal instructions and for each branch inside
    /// an [`Instr::Alternation`].
    #[inline(always)]
    fn match_literal_instr(
        instr: &Instr<'_>,
        input: &[u8],
        position: usize,
        backwards: bool,
        wide: bool,
    ) -> Option<usize> {
        let step = if wide { 2 } else { 1 };

        match *instr {
            Instr::Literal(literal) => {
                let byte_len = step * literal.len();
                let window = Self::candidate_window(
                    input, position, byte_len, backwards,
                )?;
                Self::match_literal(window, literal, wide)
                    .then_some(position + byte_len)
            }
            Instr::MaskedLiteral(literal, mask) => {
                let byte_len = step * literal.len();
                let window = Self::candidate_window(
                    input, position, byte_len, backwards,
                )?;
                Self::match_masked_literal(window, literal, mask, wide)
                    .then_some(position + byte_len)
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

    /// Executes a forward variable-length jump from `position`, inserting all
    /// reachable landing offsets into `next_positions`.
    ///
    /// `input` is the unscanned slice starting at `position`. If the next
    /// instruction starts with a known byte (`byte_after_jmp`), only positions
    /// where that byte appears are added; otherwise every valid offset in
    /// `range` is added.
    ///
    /// Positions are inserted longest-jump-first when [`JumpFlags::Greedy`] is
    /// set and shortest-jump-first otherwise. When [`JumpFlags::AcceptNewlines`]
    /// is unset, the jump stops before any `0x0A` byte.
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
        let accept_newlines = flags.contains(JumpFlags::AcceptNewlines);
        let greedy = flags.contains(JumpFlags::Greedy);

        let n = (*range.start() as usize).saturating_mul(step);
        let m = (*range.end() as usize).saturating_mul(step);

        // When no fixed byte follows the jump (e.g. the jump is the last
        // instruction in the pattern, or is followed by an alternation or
        // masked literal without a fixed leading byte), we cannot search for a
        // sentinel byte after the jump — and unlike the `Some(b)` path below,
        // the jump is allowed to consume up to `input.len()` itself.
        let Some(b) = byte_after_jmp else {
            let mut max = cmp::min(m, input.len());
            // When newlines are disallowed, stop before the first 0x0A so no
            // jump length consumes it. If 0x0A falls within the mandatory
            // prefix `0..n`, `max` becomes `< n` and the range below is empty.
            if !accept_newlines
                && let Some(nl) = memchr::memchr(0x0A, &input[..max])
            {
                max = nl;
            }
            if greedy {
                for len in (n..max + 1).step_by(step).rev() {
                    next_positions.insert(position + len);
                }
            } else {
                for len in (n..=max).step_by(step) {
                    next_positions.insert(position + len);
                }
            }
            return;
        };

        let range_min = n;
        let range_max = cmp::min(input.len(), m.saturating_add(step));

        if range_min >= range_max {
            return;
        }

        // If newlines are not accepted in the data being skipped by the jump
        // lets make sure that the ranges that goes from the current position
        // to position + n doesn't contain any newlines.
        if !accept_newlines
            && memchr::memchr(0x0A, &input[..range_min]).is_some()
        {
            return;
        }

        let mut jmp_range = &input[range_min..range_max];

        let mut on_match_found = |offset: usize| {
            // In wide mode every character of the pattern consumes two bytes,
            // so a jump can only consume an even number of them. `memchr`
            // also finds `b` at odd offsets, where it is not the first byte of
            // a character but the zero padding of the previous one; jumping
            // there would match the rest of the pattern one byte off.
            if (range_min + offset).is_multiple_of(step) {
                next_positions.insert(position + range_min + offset);
            }
        };

        if !accept_newlines {
            if greedy {
                // When newlines are disallowed, the jump cannot cross the
                // first 0x0A in `jmp_range`. Truncate before scanning in
                // reverse (longest-jump-first). If `b == 0x0A`, the first
                // newline itself is a valid target position for the literal
                // byte after the jump, so include it in the slice.
                if let Some(nl) = memchr::memchr(0x0A, jmp_range) {
                    let end = if b == 0x0A { nl + 1 } else { nl };
                    jmp_range = &jmp_range[..end];
                }
                for offset in memchr::memrchr_iter(b, jmp_range) {
                    on_match_found(offset);
                }
            } else {
                // Search for the literal byte and the newline at the same
                // time. Any offset found before the newline is a position
                // that needs to be verified, but once the newline is found
                // no more positions will match and we can return.
                //
                // There's an edge case when the literal byte is also a
                // newline: the first newline itself is a valid position for
                // the literal, but the jump still cannot cross it, so we
                // must return immediately after recording it.
                for offset in memchr::memchr2_iter(b, 0x0A, jmp_range) {
                    if jmp_range[offset] == b {
                        on_match_found(offset);
                    }
                    if jmp_range[offset] == 0x0A {
                        return;
                    }
                }
            }
        } else if greedy {
            for offset in memchr::memrchr_iter(b, jmp_range) {
                on_match_found(offset);
            }
        } else {
            for offset in memchr::memchr_iter(b, jmp_range) {
                on_match_found(offset);
            }
        }
    }

    /// Executes a backward variable-length jump from `position`, inserting all
    /// reachable landing distances into `next_positions`.
    ///
    /// `input` is the unscanned prefix ending at `position`. If the preceding
    /// instruction ends with a known byte (`expected_after_jump`), only
    /// positions immediately preceded by that byte are added; otherwise every
    /// valid offset in `range` is added.
    ///
    /// Positions are inserted longest-jump-first when [`JumpFlags::Greedy`] is
    /// set and shortest-jump-first otherwise. When [`JumpFlags::AcceptNewlines`]
    /// is unset, the jump stops before any `0x0A` byte.
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
        let accept_newlines = flags.contains(JumpFlags::AcceptNewlines);
        let greedy = flags.contains(JumpFlags::Greedy);

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
        // When no fixed byte precedes the jump (e.g. the jump is the first
        // instruction in the pattern, or is preceded by an alternation or
        // masked literal without a fixed trailing byte), we cannot search for
        // a sentinel byte before the jump — and unlike the `Some(b)` path
        // below, the jump is allowed to consume all of `input` back to offset
        // 0.
        let Some(b) = expected_after_jump else {
            let mut max = cmp::min(m, input.len());
            // When newlines are disallowed, stop before the rightmost 0x0A in
            // the candidate suffix `input[input.len() - max..]` so no jump
            // length consumes it. `nl` is the index within that suffix, so at
            // most `max - nl - 1` bytes lie to its right; if that is `< n`
            // (0x0A inside the mandatory prefix), the range below is empty.
            if !accept_newlines
                && let Some(nl) =
                    memchr::memrchr(0x0A, &input[input.len() - max..])
            {
                max = max - nl - 1;
            }
            if greedy {
                for len in (n..max + 1).step_by(step).rev() {
                    next_positions.insert(position + len);
                }
            } else {
                for len in (n..=max).step_by(step) {
                    next_positions.insert(position + len);
                }
            }
            return;
        };

        let range_min = input.len().saturating_sub(m.saturating_add(step));
        let range_max = input.len().saturating_sub(n);

        if range_min >= range_max {
            return;
        }

        // If newlines are not accepted in the data being skipped by the jump
        // lets make sure that the ranges that goes from the current position
        // to position + n doesn't contain any newlines.
        if !accept_newlines
            && memchr::memchr(0x0A, &input[range_max..]).is_some()
        {
            return;
        }

        let mut jmp_range = &input[range_min..range_max];

        let mut on_match_found = |jmp_range_len: usize, offset: usize| {
            // As in `jump_fwd`, a jump in wide mode can only consume an even
            // number of bytes, and `memrchr` / `memchr` also finds `b` at the
            // zero padding of a character. The test is on `jump` rather than on
            // `offset` because `range_min` saturates at 0 when `input` is
            // shorter than the jump, which leaves `jmp_range` with a length
            // that is not a multiple of `step`.
            if let Some(jump) = jmp_range_len.checked_sub(offset + step)
                && jump.is_multiple_of(step)
            {
                next_positions.insert(position + n + jump);
            }
        };

        if !accept_newlines {
            if greedy {
                // When newlines are disallowed, the backward jump cannot cross
                // the rightmost 0x0A in `jmp_range`. Trim everything to its
                // left before scanning left-to-right (longest-jump-first). If
                // `b == 0x0A`, the rightmost newline itself is a valid target
                // position for the literal byte preceding the jump, so keep it.
                if let Some(nl) = memchr::memrchr(0x0A, jmp_range) {
                    let start = if b == 0x0A { nl } else { nl + 1 };
                    jmp_range = &jmp_range[start..];
                }
                for offset in memchr::memchr_iter(b, jmp_range) {
                    on_match_found(jmp_range.len(), offset);
                }
            } else {
                // Search for the literal byte and the newline at the same
                // time. Any offset found before the newline is a position
                // that needs to be verified, but once the newline is found
                // no more positions will match and we can return.
                //
                // There's an edge case when the literal byte is also a
                // newline: the first newline itself is a valid position for
                // the literal, but the jump still cannot cross it, so we
                // must return immediately after recording it.
                for offset in memchr::memrchr2_iter(b, 0x0A, jmp_range) {
                    if jmp_range[offset] == b {
                        on_match_found(jmp_range.len(), offset);
                    }
                    if jmp_range[offset] == 0x0A {
                        return;
                    }
                }
            }
        } else {
            if greedy {
                for offset in memchr::memchr_iter(b, jmp_range) {
                    on_match_found(jmp_range.len(), offset);
                }
            } else {
                for offset in memchr::memrchr_iter(b, jmp_range) {
                    on_match_found(jmp_range.len(), offset);
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
        const Greedy         = 0x04;
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
            vm.try_match(
                atoms[0].fwd_code.unwrap(),
                &input,
                false,
                false,
                |len| {
                    matched_len = Some(len);
                    ControlFlow::Break(())
                },
            );
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
            vm.try_match(
                atoms[0].bck_code.unwrap(),
                &prefix,
                false,
                false,
                |len| {
                    matched_bck_len = Some(len);
                    ControlFlow::Break(())
                },
            );
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
        vm.try_match(
            atoms[0].fwd_code.unwrap(),
            &input,
            false,
            false,
            |len| {
                matched_len = Some(len);
                ControlFlow::Break(())
            },
        );
        assert_eq!(matched_len, Some(input.len()));
    }
}
