use std::hash::BuildHasherDefault;
use std::ops::RangeInclusive;
use std::{cmp, mem};

use itertools::izip;
use memx::memeq;
use rustc_hash::FxHasher;

use crate::re::fast::instr::{Instr, InstrParser};
use crate::re::{Action, CodeLoc, DEFAULT_SCAN_LIMIT};

type IndexSet = indexmap::IndexSet<usize, BuildHasherDefault<FxHasher>>;

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
    positions: IndexSet,
}

impl<'r> FastVM<'r> {
    /// Creates a new [`FastVM`].
    pub fn new(code: &'r [u8]) -> Self {
        Self {
            code,
            positions: IndexSet::default(),
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
        wide: bool,
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

        let step = if wide { 2 } else { 1 };
        let mut next_positions = IndexSet::default();

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
                                self.positions.clear();
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
                                wide,
                            )
                        } else {
                            self.try_match_literal_fwd(
                                &input[*position..],
                                literal,
                                wide,
                            )
                        };
                        if is_match {
                            next_positions
                                .insert(position + step * literal.len());
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
                                wide,
                            )
                        } else {
                            self.try_match_masked_literal_fwd(
                                &input[*position..],
                                literal,
                                mask,
                                wide,
                            )
                        };
                        if is_match {
                            next_positions
                                .insert(position + step * literal.len());
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
                                            wide,
                                        )
                                    } else {
                                        self.try_match_literal_fwd(
                                            &input[*position..],
                                            literal,
                                            wide,
                                        )
                                    };
                                    if is_match {
                                        next_positions.insert(
                                            position + step * literal.len(),
                                        );
                                    }
                                }
                                Instr::MaskedLiteral(literal, mask) => {
                                    let is_match = if backwards {
                                        self.try_match_masked_literal_bck(
                                            &input[..input.len() - position],
                                            literal,
                                            mask,
                                            wide,
                                        )
                                    } else {
                                        self.try_match_masked_literal_fwd(
                                            &input[*position..],
                                            literal,
                                            mask,
                                            wide,
                                        )
                                    };
                                    if is_match {
                                        next_positions.insert(
                                            position + step * literal.len(),
                                        );
                                    }
                                }
                                // The only valid instructions in alternatives
                                // are literals.
                                _ => {
                                    unreachable!()
                                }
                            }
                        }
                    }
                }
                Instr::JumpExact(jump) => {
                    for position in &self.positions {
                        next_positions.insert(position + step * jump as usize);
                    }
                }
                Instr::JumpExactNoNewline(jump) => {
                    for position in &self.positions {
                        let jump_range =
                            *position..*position + step * jump as usize;
                        if memchr::memchr(0x0A, &input[jump_range]).is_none() {
                            next_positions
                                .insert(position + step * jump as usize);
                        }
                    }
                }
                Instr::Jump(ref range)
                | Instr::JumpGreedy(ref range)
                | Instr::JumpNoNewline(ref range)
                | Instr::JumpGreedyNoNewline(ref range) => {
                    let greedy = matches!(
                        instr,
                        Instr::JumpGreedy(_) | Instr::JumpGreedyNoNewline(_)
                    );

                    let accept_newlines = !matches!(
                        instr,
                        Instr::JumpNoNewline(_)
                            | Instr::JumpGreedyNoNewline(_)
                    );

                    match InstrParser::decode_instr(&self.code[ip..]) {
                        (Instr::Literal(literal), _) if backwards => {
                            for position in &self.positions {
                                if *position >= input.len() {
                                    continue;
                                }
                                self.jump_bck(
                                    &input[..input.len() - position],
                                    literal,
                                    wide,
                                    greedy,
                                    accept_newlines,
                                    range,
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
                                    wide,
                                    greedy,
                                    accept_newlines,
                                    range,
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
                                    wide,
                                    greedy,
                                    accept_newlines,
                                    range,
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
                                    wide,
                                    greedy,
                                    accept_newlines,
                                    range,
                                    *position,
                                    &mut next_positions,
                                );
                            }
                        }
                        _ => {
                            for position in mem::take(&mut self.positions) {
                                if accept_newlines {
                                    let jmp_min_range = position
                                        ..position + *range.start() as usize;
                                    match input.get(jmp_min_range) {
                                        Some(r) => {
                                            if memchr::memchr(0x0A, r)
                                                .is_some()
                                            {
                                                continue;
                                            }
                                        }
                                        None => continue,
                                    }
                                }
                                for i in range.clone() {
                                    if accept_newlines {
                                        match input
                                            .get(position + step * i as usize)
                                        {
                                            Some(0x0A) | None => continue,
                                            _ => {}
                                        }
                                    }
                                    next_positions
                                        .insert(position + step * i as usize);
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
    fn try_match_literal_fwd(
        &self,
        input: &[u8],
        literal: &[u8],
        wide: bool,
    ) -> bool {
        if wide {
            if input.len() < literal.len() * 2 {
                return false;
            }
            input.iter().step_by(2).eq(literal.iter())
        } else {
            if input.len() < literal.len() {
                return false;
            }
            memeq(&input[..literal.len()], literal)
        }
    }

    #[inline]
    fn try_match_literal_bck(
        &self,
        input: &[u8],
        literal: &[u8],
        wide: bool,
    ) -> bool {
        if wide {
            if input.len() < literal.len() * 2 {
                return false;
            }
            input
                .iter() // iterate input
                .rev() // in reverse order
                .skip(1) // skipping the last byte that should be 0
                .step_by(2) // two bytes at a time
                .eq(literal.iter().rev())
        } else {
            if input.len() < literal.len() {
                return false;
            }
            memeq(&input[input.len() - literal.len()..], literal)
        }
    }

    #[inline]
    fn try_match_masked_literal_fwd(
        &self,
        input: &[u8],
        literal: &[u8],
        mask: &[u8],
        wide: bool,
    ) -> bool {
        debug_assert_eq!(literal.len(), mask.len());

        if wide {
            if input.len() < literal.len() * 2 {
                return false;
            }
            for (input, byte, mask) in
                izip!(input.iter().step_by(2), literal, mask)
            {
                if *input & *mask != *byte & *mask {
                    return false;
                }
            }
        } else {
            if input.len() < literal.len() {
                return false;
            }
            for (input, byte, mask) in izip!(input, literal, mask) {
                if *input & *mask != *byte & *mask {
                    return false;
                }
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
        wide: bool,
    ) -> bool {
        debug_assert_eq!(literal.len(), mask.len());

        if wide {
            if input.len() < literal.len() * 2 {
                return false;
            }
            for (input, byte, mask) in izip!(
                input.iter().rev().step_by(2),
                literal.iter().rev(),
                mask.iter().rev()
            ) {
                if *input & *mask != *byte & *mask {
                    return false;
                }
            }
        } else {
            if input.len() < literal.len() {
                return false;
            }
            for (input, byte, mask) in izip!(
                input.iter().rev(),
                literal.iter().rev(),
                mask.iter().rev()
            ) {
                if *input & *mask != *byte & *mask {
                    return false;
                }
            }
        }

        true
    }

    #[inline]
    fn jump_fwd(
        &self,
        input: &[u8],
        literal: &[u8],
        wide: bool,
        greedy: bool,
        accept_newlines: bool,
        range: &RangeInclusive<u16>,
        position: usize,
        next_positions: &mut IndexSet,
    ) {
        let step = if wide { 2 } else { 1 };

        let n = *range.start() as usize * step;
        let m = *range.end() as usize * step;

        let range_min = n;
        let range_max = cmp::min(input.len(), m + step);

        if range_min >= range_max {
            return;
        }

        // If newlines are not accepted in the data being skipped by the jump
        // lets make sure that the ranges that goes from the current position
        // to position + n doesn't contain any newlines.
        if !accept_newlines && memchr::memchr(0x0A, &input[..n]).is_some() {
            return;
        }

        if let Some(jmp_range) = input.get(range_min..range_max) {
            let lit = *literal.first().unwrap();
            let mut on_match_found = |offset| {
                if wide {
                    // In wide mode we are only interested in bytes found
                    // at even offsets. At odd offsets the input should
                    // have only zeroes and they are not potential matches.
                    if offset % 2 == 0 {
                        next_positions.insert(position + n + offset);
                    }
                } else {
                    next_positions.insert(position + n + offset);
                }
            };
            match (greedy, accept_newlines) {
                // Non-greedy, newlines accepted.
                (false, true) => {
                    for offset in memchr::memchr_iter(lit, jmp_range) {
                        on_match_found(offset)
                    }
                }
                // Non-greedy, newlines not accepted.
                (false, false) => {
                    // Search for the literal byte and the newline at the same
                    // time. Any offset found before the newline is a position
                    // that needs to be verified, but once the newline if found
                    // no more positions will match and we can return.
                    for offset in memchr::memchr2_iter(lit, 0x0A, jmp_range) {
                        if jmp_range[offset] == 0x0A {
                            return;
                        }
                        on_match_found(offset)
                    }
                }
                // Greedy, newlines accepted.
                (true, true) => {
                    for offset in memchr::memrchr_iter(lit, jmp_range) {
                        on_match_found(offset)
                    }
                }
                // Greedy, newlines not accepted.
                (true, false) => {
                    // Search for the newline character in the range covered by
                    // the jump. If found, truncate the range at the point where
                    // the newline was found.
                    let jmp_range = if let Some(newline) =
                        memchr::memchr(0x0A, jmp_range)
                    {
                        &jmp_range[..newline]
                    } else {
                        jmp_range
                    };
                    // Now search for the literal byte from right to left (in
                    // opposite direction to the forward jump). As this is a
                    // greedy jump we want the higher offsets to be inserted
                    // in `next_positions` first.
                    for offset in memchr::memrchr_iter(lit, jmp_range) {
                        on_match_found(offset)
                    }
                }
            }
        }
    }

    #[inline]
    fn jump_bck(
        &self,
        input: &[u8],
        literal: &[u8],
        wide: bool,
        greedy: bool,
        accept_newlines: bool,
        range: &RangeInclusive<u16>,
        position: usize,
        next_positions: &mut IndexSet,
    ) {
        let step = if wide { 2 } else { 1 };

        let n = *range.start() as usize * step;
        let m = *range.end() as usize * step;

        //  Let's explain the what this function does using the following
        //  pattern as an example:
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
        let range_min = input.len().saturating_sub(m + step);
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

        if let Some(jmp_range) = input.get(range_min..range_max) {
            let lit = *literal.last().unwrap();
            let mut on_match_found = |offset| {
                if wide {
                    // In wide mode we are only interested in bytes found
                    // at even offsets. At odd offsets the input should
                    // have only zeroes and they are not potential matches.
                    if offset % 2 == 0 {
                        next_positions.insert(
                            position + n + jmp_range.len() - offset - step,
                        );
                    }
                } else {
                    next_positions.insert(
                        position + n + jmp_range.len() - offset - step,
                    );
                }
            };
            match (greedy, accept_newlines) {
                // Non-greedy, newlines accepted.
                (false, true) => {
                    for offset in memchr::memrchr_iter(lit, jmp_range) {
                        on_match_found(offset)
                    }
                }
                // Non-greedy, newlines not accepted.
                (false, false) => {
                    for offset in memchr::memrchr2_iter(lit, 0x0A, jmp_range) {
                        if jmp_range[offset] == 0x0A {
                            return;
                        }
                        on_match_found(offset)
                    }
                }
                // Greedy, newlines accepted.
                (true, true) => {
                    for offset in memchr::memchr_iter(lit, jmp_range) {
                        on_match_found(offset)
                    }
                }
                // Greedy, newlines not accepted.
                (true, false) => {
                    // Search for the newline character in the range covered by
                    // the jump. If found, truncate the range at the point where
                    // the newline was found.
                    let jmp_range = if let Some(newline) =
                        memchr::memchr(0x0A, jmp_range)
                    {
                        &jmp_range[newline + 1..]
                    } else {
                        jmp_range
                    };
                    // Now search for the literal byte from left to right (in
                    // the opposite direction to the backward jump). As this a
                    // a greedy jump we want the lower offsets to be inserted
                    // in `next_positions` first.
                    for offset in memchr::memchr_iter(lit, jmp_range) {
                        on_match_found(offset)
                    }
                }
            }
        }
    }
}
