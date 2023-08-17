use std::cell::RefCell;
use std::collections::VecDeque;
use std::ops::{Range, RangeInclusive};
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::Ordering;

#[cfg(feature = "logging")]
use log::*;
#[cfg(feature = "logging")]
use std::time::Instant;

use base64::Engine;
use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;
use bstr::ByteSlice;
use protobuf::{MessageDyn, MessageFull};
use regex::bytes::Regex;
use rustc_hash::FxHashMap;
use wasmtime::Store;

use crate::compiler::{
    NamespaceId, PatternId, RegexpId, RuleId, Rules, SubPattern,
    SubPatternAtom, SubPatternFlagSet, SubPatternFlags, SubPatternId,
};
use crate::re::pikevm;
use crate::re::pikevm::PikeVM;
use crate::scanner::matches::{Match, MatchList, UnconfirmedMatch};
use crate::scanner::{RuntimeStringId, HEARTBEAT_COUNTER};
use crate::string_pool::BStringPool;
use crate::types::{Struct, TypeValue};
use crate::wasm::MATCHING_RULES_BITMAP_BASE;
use crate::ScanError;

/// Structure that holds information about the current scan.
pub(crate) struct ScanContext<'r> {
    /// Pointer to the WASM store.
    pub wasm_store: NonNull<Store<ScanContext<'r>>>,
    /// Pointer to the data being scanned.
    pub scanned_data: *const u8,
    /// Length of data being scanned.
    pub scanned_data_len: usize,
    /// Vector containing the IDs of the non-private rules that matched,
    /// including both global and non-global ones. Global rules are initially
    /// added to `global_matching_rules`, and once all the rules in the
    /// namespace are evaluated, the global rules that matched are moved
    /// to this vector.
    pub non_private_matching_rules: Vec<RuleId>,
    /// Vector containing the IDs of the private rules that matched, including
    /// both global and non-global ones.
    pub private_matching_rules: Vec<RuleId>,
    /// Map containing the IDs of the global rules that matched.
    pub global_matching_rules: FxHashMap<NamespaceId, Vec<RuleId>>,
    /// Compiled rules for this scan.
    pub compiled_rules: &'r Rules,
    /// Structure that contains top-level symbols, like module names
    /// and external variables. Symbols are normally looked up in this
    /// structure, except if `current_struct` is set to some other
    /// structure that overrides `root_struct`.
    pub root_struct: Struct,
    /// Currently active structure that overrides the `root_struct` if
    /// set.
    pub current_struct: Option<Rc<Struct>>,
    /// String pool where the strings produced at runtime are stored. This
    /// for example stores the strings returned by YARA modules.
    pub string_pool: BStringPool<RuntimeStringId>,
    /// Module's main memory.
    pub main_memory: Option<wasmtime::Memory>,
    /// The host-side stack of local variables.
    ///
    /// See [`crate::compiler::Context::new_var`] for a more detailed
    /// description of what is this, and what "host-side" means in this
    /// case.
    pub vars_stack: Vec<TypeValue>,
    /// Hash map that contains the protobuf messages returned by YARA modules.
    /// Keys are the fully qualified protobuf message name, and values are
    /// the message returned by the corresponding module.
    pub module_outputs: FxHashMap<String, Box<dyn MessageDyn>>,
    /// Hash map that tracks the matches occurred during a scan. The keys
    /// are the PatternId of the matching pattern, and values are a list
    /// of matches.
    pub pattern_matches: FxHashMap<PatternId, MatchList>,
    /// Hash map that tracks the unconfirmed matches for chained patterns. When
    /// a pattern is split into multiple chained pieces, each piece is handled
    /// as an individual pattern, but the match of one of the pieces doesn't
    /// imply that the whole pattern matches. This partial matches are stored
    /// here until they can be confirmed or discarded.
    pub unconfirmed_matches:
        FxHashMap<SubPatternId, VecDeque<UnconfirmedMatch>>,
    /// Bit vector that contains one bit per pattern. The N-th bit is set if
    /// pattern with PatternId = N has reached the maximum number of matches
    /// indicated by `max_matches_per_pattern`.
    pub limit_reached: BitVec,
    /// Maximum number of matches per pattern.
    pub max_matches_per_pattern: usize,
    /// When [`HEARTBEAT_COUNTER`] is larger than this value, the scan is
    /// aborted due to a timeout.
    pub deadline: u64,
    /// Hash map that serves as a cache for regexps used in expressions like
    /// `some_var matches /foobar/`. Compiling a regexp is a expensive
    /// operation. Instead of compiling the regexp each time the expression
    /// is evaluated, it is compiled the first time and stored in this hash
    /// map.
    pub regexp_cache: RefCell<FxHashMap<RegexpId, Regex>>,
}

impl ScanContext<'_> {
    /// Returns a slice with the data being scanned.
    pub(crate) fn scanned_data<'a>(&self) -> &'a [u8] {
        unsafe {
            std::slice::from_raw_parts::<u8>(
                self.scanned_data,
                self.scanned_data_len,
            )
        }
    }

    /// Returns true of the regexp identified by the given [`RegexpId`]
    /// matches `haystack`.
    pub(crate) fn regexp_matches(
        &self,
        regexp_id: RegexpId,
        haystack: &[u8],
    ) -> bool {
        self.regexp_cache
            .borrow_mut()
            .entry(regexp_id)
            .or_insert_with(|| self.compiled_rules.get_regexp(regexp_id))
            .is_match(haystack)
    }

    /// Returns the protobuf struct produced by a module.
    ///
    /// The main function of a module returns a protobuf message with data
    /// produced by the module for the current scan. Accessing this data
    /// from some other function exported by the module is useful in certain
    /// cases, and that's the purpose of this function.
    ///
    /// This function is generic over `T`, where `T` is some protobuf message
    /// type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::modules::protos::my_module::MyModuleProto;
    /// let module_data: MyModuleProto = ctx.module_data::<MyModuleProto>()
    /// ```
    pub(crate) fn module_output<T: MessageFull>(&self) -> Option<&T> {
        let m = self.module_outputs.get(T::descriptor().full_name())?.as_ref();
        <dyn MessageDyn>::downcast_ref(m)
    }

    /// Called during the scan process when a global rule didn't match.
    ///
    /// When this happen any other global rule in the same namespace that
    /// matched previously is reset to a non-matching state.
    pub(crate) fn track_global_rule_no_match(&mut self, rule_id: RuleId) {
        let wasm_store = unsafe { self.wasm_store.as_mut() };
        let main_mem = self.main_memory.unwrap().data_mut(wasm_store);

        let base = MATCHING_RULES_BITMAP_BASE as usize;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(&mut main_mem[base..]);

        let rule = self.compiled_rules.get(rule_id);

        // This function must be called only for global rules.
        debug_assert!(rule.is_global);

        // All the global rules that matched previously, and are in the same
        // namespace than the non-matching rule, must be removed from the
        // `global_matching_rules` map. Also, their corresponding bits in
        // the matching rules bitmap must be cleared.
        if let Some(rules) =
            self.global_matching_rules.get_mut(&rule.namespace_id)
        {
            for rule_id in rules.iter() {
                bits.set((*rule_id).into(), false);
            }

            rules.clear()
        }
    }

    /// Called during the scan process when a rule has matched for tracking
    /// the matching rules.
    pub(crate) fn track_rule_match(&mut self, rule_id: RuleId) {
        let rule = self.compiled_rules.get(rule_id);

        if rule.is_global {
            self.global_matching_rules
                .entry(rule.namespace_id)
                .or_default()
                .push(rule_id);
        } else if rule.is_private {
            self.private_matching_rules.push(rule_id);
        } else {
            self.non_private_matching_rules.push(rule_id);
        }

        let wasm_store = unsafe { self.wasm_store.as_mut() };
        let main_mem = self.main_memory.unwrap().data_mut(wasm_store);

        let base = MATCHING_RULES_BITMAP_BASE as usize;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(&mut main_mem[base..]);

        // The RuleId-th bit in the `rule_matches` bit vector is set to 1.
        bits.set(rule_id.into(), true);
    }

    /// Called during the scan process when a pattern has matched for tracking
    /// the matching patterns.
    pub(crate) fn track_pattern_match(
        &mut self,
        pattern_id: PatternId,
        match_: Match,
        replace: bool,
    ) {
        let wasm_store = unsafe { self.wasm_store.as_mut() };
        let main_mem = self.main_memory.unwrap().data_mut(wasm_store);
        let num_rules = self.compiled_rules.rules().len();

        let base = MATCHING_RULES_BITMAP_BASE as usize + num_rules / 8 + 1;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(&mut main_mem[base..]);

        bits.set(pattern_id.into(), true);

        let matches_list = self.pattern_matches.entry(pattern_id).or_default();

        if matches_list.len() < self.max_matches_per_pattern {
            matches_list.add(match_, replace)
        } else {
            self.limit_reached.set(pattern_id.into(), true);
        }
    }

    /// Search for patterns in the data.
    ///
    /// The pattern search phase is when YARA scans the data looking for the
    /// patterns declared in rules. All the patterns are searched simultaneously
    /// using the Aho-Corasick algorithm. This phase is triggered lazily during
    /// the evaluation of the rule conditions, when some of the conditions need
    /// to know if a pattern matched or not.
    ///
    /// This function won't be called if the conditions can be fully evaluated
    /// without looking for any of the patterns. If it must be called, it will be
    /// called only once.
    pub(crate) fn search_for_patterns(&mut self) -> Result<(), ScanError> {
        let scanned_data = self.scanned_data();

        self.verify_patterns_anchored_at_0();

        let ac = self.compiled_rules.ac_automaton();

        let mut pike_vm = PikeVM::new(self.compiled_rules.re_code())
            .scan_limit(PikeVM::DEFAULT_SCAN_LIMIT);

        let atoms = self.compiled_rules.atoms();

        #[cfg(feature = "logging")]
        let start = Instant::now();

        #[cfg(feature = "logging")]
        let mut atom_matches = 0_usize;

        for ac_match in ac.find_overlapping_iter(scanned_data) {
            #[cfg(feature = "logging")]
            {
                atom_matches += 1;
            }

            if HEARTBEAT_COUNTER.load(Ordering::Relaxed) >= self.deadline {
                #[cfg(feature = "logging")]
                info!("Scan timeout after: {:?}", Instant::elapsed(&start));
                return Err(ScanError::Timeout);
            }

            let atom =
                unsafe { atoms.get_unchecked(ac_match.pattern().as_usize()) };

            // Subtract the backtrack value from the offset where the atom
            // matched. If the result is negative the atom can't be inside
            // the scanned data and therefore is not a possible match.
            let (atom_pos, overflow) =
                ac_match.start().overflowing_sub(atom.backtrack());

            if overflow {
                continue;
            }

            // Each atom belongs to a sub-pattern.
            let sub_pattern_id = atom.sub_pattern_id();

            // Each sub-pattern belongs to a pattern.
            let (pattern_id, sub_pattern) =
                &self.compiled_rules.get_sub_pattern(sub_pattern_id);

            // Check if the potentially matching pattern has reached the
            // maximum number of allowed matches. In that case continue without
            // verifying the match. `get_unchecked` is used for performance
            // reasons, the number of bits in the bit vector is guaranteed to
            // to be the number of patterns.
            if unsafe {
                *self
                    .limit_reached
                    .get_unchecked::<usize>((*pattern_id).into())
            } {
                continue;
            }

            // If the atom is exact no further verification is needed, except
            // for making sure that the fullword requirements are met. An exact
            // atom is enough to guarantee that the whole sub-pattern matched.
            if atom.is_exact() {
                let flags = match sub_pattern {
                    SubPattern::Literal { flags, .. }
                    | SubPattern::LiteralChainHead { flags, .. }
                    | SubPattern::LiteralChainTail { flags, .. }
                    | SubPattern::Regexp { flags, .. }
                    | SubPattern::RegexpChainHead { flags, .. }
                    | SubPattern::RegexpChainTail { flags, .. } => flags,
                    _ => unreachable!(),
                };

                let match_range = atom_pos..atom_pos + atom.len();

                if verify_full_word(scanned_data, &match_range, *flags, None) {
                    self.handle_sub_pattern_match(
                        sub_pattern_id,
                        sub_pattern,
                        *pattern_id,
                        Match { range: match_range, xor_key: None },
                    );
                }

                continue;
            }

            match sub_pattern {
                SubPattern::Literal { pattern, flags, .. }
                | SubPattern::LiteralChainHead { pattern, flags, .. }
                | SubPattern::LiteralChainTail { pattern, flags, .. } => {
                    if let Some(match_) = verify_literal_match(
                        self.compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap(),
                        scanned_data,
                        atom_pos,
                        *flags,
                    ) {
                        self.handle_sub_pattern_match(
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            match_,
                        );
                    }
                }
                SubPattern::Regexp { flags, .. }
                | SubPattern::RegexpChainHead { flags, .. }
                | SubPattern::RegexpChainTail { flags, .. } => {
                    verify_regexp_match(
                        &mut pike_vm,
                        scanned_data,
                        atom_pos,
                        atom,
                        *flags,
                        |match_| {
                            self.handle_sub_pattern_match(
                                sub_pattern_id,
                                sub_pattern,
                                *pattern_id,
                                match_,
                            );
                        },
                    )
                }

                SubPattern::Xor { pattern, flags } => {
                    if let Some(match_) = verify_xor_match(
                        self.compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap(),
                        scanned_data,
                        atom_pos,
                        atom,
                        *flags,
                    ) {
                        self.handle_sub_pattern_match(
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            match_,
                        );
                    }
                }

                SubPattern::Base64 { pattern, padding }
                | SubPattern::Base64Wide { pattern, padding } => {
                    if let Some(match_) = verify_base64_match(
                        self.compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap(),
                        scanned_data,
                        (*padding).into(),
                        atom_pos,
                        None,
                        matches!(sub_pattern, SubPattern::Base64Wide { .. }),
                    ) {
                        self.handle_sub_pattern_match(
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            match_,
                        );
                    }
                }

                SubPattern::CustomBase64 { pattern, alphabet, padding }
                | SubPattern::CustomBase64Wide {
                    pattern,
                    alphabet,
                    padding,
                } => {
                    let alphabet = self
                        .compiled_rules
                        .lit_pool()
                        .get_str(*alphabet)
                        .map(|alphabet| {
                            // `Alphabet::new` validates the string again. This
                            // is not really necessary as we already know that
                            // the string represents a valid alphabet, it would
                            // be better if could use the private function
                            // `Alphabet::from_str_unchecked`
                            base64::alphabet::Alphabet::new(alphabet).unwrap()
                        });

                    assert!(alphabet.is_some());

                    if let Some(match_) = verify_base64_match(
                        self.compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap(),
                        scanned_data,
                        (*padding).into(),
                        atom_pos,
                        alphabet,
                        matches!(
                            sub_pattern,
                            SubPattern::CustomBase64Wide { .. }
                        ),
                    ) {
                        self.handle_sub_pattern_match(
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            match_,
                        );
                    }
                }
            };
        }

        #[cfg(feature = "logging")]
        {
            info!("Scan time: {:?}", Instant::elapsed(&start));
            info!("Atom matches: {}", atom_matches);
        }
        Ok(())
    }

    fn verify_patterns_anchored_at_0(&mut self) {
        for (sub_pattern_id, (pattern_id, sub_pattern)) in self
            .compiled_rules
            .sub_patterns_anchored_at_0()
            .iter()
            .map(|id| (id, self.compiled_rules.get_sub_pattern(*id)))
        {
            match sub_pattern {
                SubPattern::Literal { pattern, flags, .. } => {
                    if let Some(match_) = verify_literal_match(
                        self.compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap(),
                        self.scanned_data(),
                        0,
                        *flags,
                    ) {
                        self.handle_sub_pattern_match(
                            *sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            match_,
                        );
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    fn handle_sub_pattern_match(
        &mut self,
        sub_pattern_id: SubPatternId,
        sub_pattern: &SubPattern,
        pattern_id: PatternId,
        match_: Match,
    ) {
        match sub_pattern {
            SubPattern::Literal { .. }
            | SubPattern::Xor { .. }
            | SubPattern::Base64 { .. }
            | SubPattern::Base64Wide { .. }
            | SubPattern::CustomBase64 { .. }
            | SubPattern::CustomBase64Wide { .. } => {
                self.track_pattern_match(pattern_id, match_, false);
            }
            SubPattern::Regexp { flags, .. } => {
                self.track_pattern_match(
                    pattern_id,
                    match_,
                    flags.contains(SubPatternFlags::Greedy),
                );
            }
            SubPattern::LiteralChainHead { .. }
            | SubPattern::RegexpChainHead { .. } => {
                // This is the head of a set of chained sub-patterns.
                // Verifying that the head matches doesn't mean that
                // the whole sub-pattern matches, the rest of the chain
                // must be found as well. For the time being this is
                // just an unconfirmed match.
                self.unconfirmed_matches
                    .entry(sub_pattern_id)
                    .or_default()
                    .push_back(UnconfirmedMatch {
                        range: match_.range,
                        chain_length: 0,
                    })
            }
            SubPattern::LiteralChainTail {
                chained_to, gap, flags, ..
            }
            | SubPattern::RegexpChainTail { chained_to, gap, flags, .. } => {
                if self.within_valid_distance(
                    sub_pattern_id,
                    *chained_to,
                    match_.range.start,
                    gap,
                ) {
                    if flags.contains(SubPatternFlags::LastInChain) {
                        // This sub-pattern is the last one in the
                        // chain. We can proceed to verify the whole
                        // chain and determine if it matched or not.
                        self.verify_chain_of_matches(
                            pattern_id,
                            sub_pattern_id,
                            match_.range,
                        );
                    } else {
                        // This sub-pattern is in the middle of the
                        // chain. We need to find the sub-patterns that
                        // follow, so for the time being this only an
                        // unconfirmed match.
                        self.unconfirmed_matches
                            .entry(sub_pattern_id)
                            .or_default()
                            .push_back(UnconfirmedMatch {
                                range: match_.range,
                                chain_length: 0,
                            });
                    }
                }
            }
        }
    }

    fn within_valid_distance(
        &mut self,
        sub_pattern_id: SubPatternId,
        chained_to: SubPatternId,
        match_start: usize,
        gap: &RangeInclusive<u32>,
    ) -> bool {
        // The lowest possible offset where the current sub-pattern can match
        // is the offset of the first unconfirmed match, or the offset of the
        // current match if no previous unconfirmed match exists.
        let lowest_offset = self
            .unconfirmed_matches
            .get(&sub_pattern_id)
            .and_then(|unconfirmed_matches| unconfirmed_matches.front())
            .map_or(match_start, |first_match| first_match.range.start);

        if let Some(unconfirmed_matches) =
            self.unconfirmed_matches.get_mut(&chained_to)
        {
            let min_gap = *gap.start() as usize;
            let max_gap = *gap.end() as usize;

            // Retain the unconfirmed matches that can possibly match, but
            // discard those that are so far away from the current match that
            // there's no possibility for them to match.
            unconfirmed_matches
                .retain(|m| m.range.end + max_gap >= lowest_offset);

            for m in unconfirmed_matches {
                let valid_range =
                    m.range.end + min_gap..=m.range.end + max_gap;
                if valid_range.contains(&match_start) {
                    return true;
                }
            }
        }

        false
    }

    /// Given the [`SubPatternId`] associated to the last sub-pattern in a
    /// chain, and a range where this sub-pattern matched, verifies that the
    /// whole chain actually matches.
    ///
    /// The `tail_sub_pattern_id` argument must identify the last sub-pattern
    /// in a chain. For example, if the chain is `S1 <- S2 <- S3`, this function
    /// must receive the [`SubPatternId`] for `S3`, and a range where `S3`
    /// matched. Then the function traverses the chain from the tail to the
    /// head, making sure that each intermediate sub-pattern has unconfirmed
    /// matches that has the correct distance between them, so that the whole
    /// chain matches from head to tail.
    ///
    /// If the whole chain matches, the corresponding match is added to the
    /// list of confirmed matches for pattern identified by `pattern_id`.
    fn verify_chain_of_matches(
        &mut self,
        pattern_id: PatternId,
        tail_sub_pattern_id: SubPatternId,
        tail_match_range: Range<usize>,
    ) {
        let mut queue = VecDeque::new();

        queue.push_back((tail_sub_pattern_id, tail_match_range, 1));

        let mut tail_match_range: Option<Range<usize>> = None;

        while let Some((id, match_range, chain_length)) = queue.pop_front() {
            match &self.compiled_rules.get_sub_pattern(id).1 {
                SubPattern::LiteralChainHead { flags, .. }
                | SubPattern::RegexpChainHead { flags, .. } => {
                    // The chain head is reached and we know the range where
                    // the tail matches. This indicates that the whole chain is
                    // valid and we have a full match.
                    if let Some(tail_match_range) = &tail_match_range {
                        self.track_pattern_match(
                            pattern_id,
                            Match {
                                range: match_range.start..tail_match_range.end,
                                xor_key: None,
                            },
                            flags.contains(SubPatternFlags::Greedy),
                        );
                    }
                }
                SubPattern::LiteralChainTail {
                    chained_to,
                    gap,
                    flags,
                    ..
                }
                | SubPattern::RegexpChainTail {
                    chained_to, gap, flags, ..
                } => {
                    // Iterate over the list of unconfirmed matches of the
                    // sub-pattern that comes before in the chain. For example,
                    // if the chain is P1 <- P2 and we just found a match for
                    // P2, iterate over the unconfirmed matches for P1.
                    if let Some(unconfirmed_matches) =
                        self.unconfirmed_matches.get_mut(chained_to)
                    {
                        let min_gap = *gap.start() as usize;
                        let max_gap = *gap.end() as usize;

                        // Check whether the current match is at a correct
                        // distance from each of the unconfirmed matches.
                        for m in unconfirmed_matches {
                            let valid_range =
                                m.range.end + min_gap..=m.range.end + max_gap;

                            if valid_range.contains(&match_range.start)
                                && m.chain_length <= chain_length
                            {
                                m.chain_length = chain_length + 1;
                                queue.push_back((
                                    *chained_to,
                                    m.range.clone(),
                                    m.chain_length,
                                ));
                            }
                        }
                    }

                    if flags.contains(SubPatternFlags::LastInChain) {
                        // Take note of the range where the tail matched. This
                        // is reached only when this function is called with a
                        // sub-pattern ID that corresponds to chain tail.
                        tail_match_range = Some(match_range.clone());
                    }
                }
                _ => unreachable!(),
            };
        }
    }
}

/// Verifies if a literal `pattern` matches at `atom_pos` in `scanned_data`.
///
/// Returns a [`Match`] if the match was confirmed or [`None`] if otherwise.
fn verify_literal_match(
    pattern: &[u8],
    scanned_data: &[u8],
    atom_pos: usize,
    flags: SubPatternFlagSet,
) -> Option<Match> {
    // Offset where the match should end (exclusive).
    let match_end = atom_pos + pattern.len();

    // The match can not end past the end of the scanned data.
    if match_end > scanned_data.len() {
        return None;
    }

    if flags.intersects(
        SubPatternFlags::FullwordLeft | SubPatternFlags::FullwordRight,
    ) && !verify_full_word(
        scanned_data,
        &(atom_pos..match_end),
        flags,
        None,
    ) {
        return None;
    }

    let match_found = if flags.contains(SubPatternFlags::Nocase) {
        pattern.eq_ignore_ascii_case(&scanned_data[atom_pos..match_end])
    } else {
        memx::memeq(&scanned_data[atom_pos..match_end], pattern.as_bytes())
    };

    if match_found {
        Some(Match {
            // The end of the range is exclusive.
            range: atom_pos..match_end,
            xor_key: None,
        })
    } else {
        None
    }
}

/// Returns true if the match delimited by `match_range` is a full word match.
/// This means that the bytes before the range's start and after the range's
/// end are both non-alphanumeric.
fn verify_full_word(
    scanned_data: &[u8],
    match_range: &Range<usize>,
    flags: SubPatternFlagSet,
    xor_key: Option<u8>,
) -> bool {
    let xor_key = xor_key.unwrap_or(0);

    if flags.contains(SubPatternFlags::Wide) {
        if flags.contains(SubPatternFlags::FullwordLeft)
            && match_range.start >= 2
            && (scanned_data[match_range.start - 1] ^ xor_key) == 0
            && (scanned_data[match_range.start - 2] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
        if flags.contains(SubPatternFlags::FullwordRight)
            && match_range.end + 1 < scanned_data.len()
            && (scanned_data[match_range.end + 1] ^ xor_key) == 0
            && (scanned_data[match_range.end] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
    } else {
        if flags.contains(SubPatternFlags::FullwordLeft)
            && match_range.start >= 1
            && (scanned_data[match_range.start - 1] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
        if flags.contains(SubPatternFlags::FullwordRight)
            && match_range.end < scanned_data.len()
            && (scanned_data[match_range.end] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
    }

    true
}

/// When some `atom` belonging to a regexp is found at `atom_pos`, verify
/// that the regexp actually matches.
///
/// This function can produce multiple matches, `f` is called for every
/// match found.
fn verify_regexp_match(
    pike_vm: &mut PikeVM,
    scanned_data: &[u8],
    atom_pos: usize,
    atom: &SubPatternAtom,
    flags: SubPatternFlagSet,
    mut f: impl FnMut(Match),
) {
    // Try matching from the point where the atom was found
    // going forward (left-to-right).
    let mut fwd_match_len = None;

    if flags.contains(SubPatternFlags::Wide) {
        pike_vm.try_match(
            atom.fwd_code(),
            scanned_data[atom_pos..].iter().step_by(2),
            scanned_data[..atom_pos].iter().rev().skip(1).step_by(2),
            |match_len| {
                fwd_match_len = Some(match_len * 2);
                pikevm::Match::Stop
            },
        );
    } else {
        pike_vm.try_match(
            atom.fwd_code(),
            scanned_data[atom_pos..].iter(),
            scanned_data[..atom_pos].iter().rev(),
            |match_len| {
                fwd_match_len = Some(match_len);
                pikevm::Match::Stop
            },
        );
    }

    let fwd_match_len = match fwd_match_len {
        Some(len) => len,
        None => return,
    };

    if flags.contains(SubPatternFlags::Wide) {
        pike_vm.try_match(
            atom.bck_code(),
            scanned_data[..atom_pos].iter().rev().skip(1).step_by(2),
            scanned_data[atom_pos..].iter().step_by(2),
            |bck_match_len| {
                let range =
                    atom_pos - bck_match_len * 2..atom_pos + fwd_match_len;
                if verify_full_word(scanned_data, &range, flags, None) {
                    f(Match { range, xor_key: None });
                }
                pikevm::Match::Continue
            },
        );
    } else {
        pike_vm.try_match(
            atom.bck_code(),
            scanned_data[..atom_pos].iter().rev(),
            scanned_data[atom_pos..].iter(),
            |bck_match_len| {
                let range = atom_pos - bck_match_len..atom_pos + fwd_match_len;
                if verify_full_word(scanned_data, &range, flags, None) {
                    f(Match { range, xor_key: None });
                }
                pikevm::Match::Continue
            },
        );
    }
}

/// Verifies that a literal sub-pattern actually matches in XORed form
/// at the position where an atom was found.
///
/// Returns a [`Match`] if the match was confirmed or [`None`] if otherwise.
fn verify_xor_match(
    pattern: &[u8],
    scanned_data: &[u8],
    atom_pos: usize,
    atom: &SubPatternAtom,
    flags: SubPatternFlagSet,
) -> Option<Match> {
    // Offset where the match should end (exclusive).
    let match_end = atom_pos + pattern.len();

    // The match can not end past the end of the scanned data.
    if match_end > scanned_data.len() {
        return None;
    }

    let mut pattern = pattern.to_owned();

    // The atom that matched is the result of XORing the pattern with some
    // key. The key can be obtained by XORing some byte in the atom with
    // the corresponding byte in the pattern.
    let key = atom.as_slice()[0] ^ pattern[atom.backtrack()];

    let match_range = atom_pos..match_end;

    if !verify_full_word(scanned_data, &match_range, flags, Some(key)) {
        return None;
    }

    // Now we can XOR the whole pattern with the obtained key and make sure
    // that it matches the data. This only makes sense if the key is not
    // zero.
    if key != 0 {
        for byte in &mut pattern {
            *byte ^= key;
        }
    }

    if memx::memeq(&scanned_data[match_range.clone()], pattern.as_bytes()) {
        Some(Match { range: match_range, xor_key: Some(key) })
    } else {
        None
    }
}

/// Verifies that a literal sub-pattern actually matches in base64 form at
/// the offset where some atom.
///
/// Returns a [`Match`] if the match was confirmed or [`None`] if otherwise.
fn verify_base64_match(
    pattern: &[u8],
    scanned_data: &[u8],
    padding: usize,
    atom_pos: usize,
    alphabet: Option<base64::alphabet::Alphabet>,
    wide: bool,
) -> Option<Match> {
    // The pattern is passed to this function in its original form, before
    // being encoded as base64. Compute the size of the pattern once it is
    // encoded as base64.
    let len = base64::encoded_len(pattern.len(), false).unwrap();

    // A portion of the pattern in base64 form was found at `atom_pos`,
    // but decoding the base64 string starting at that offset is not ok
    // because some characters may have been removed from both the left
    // and the right sides of the base64 string that has been found. For
    // example, for the pattern "foobar" one of the base64 patterns that
    // are searched for is "Zvb2Jhc", but once this pattern is found in
    // the scanned data we can't simply decode that string and expect
    // to find "foobar" in the decoded data.
    //
    // What we must do is use two more characters from the left, and one
    // more from the right of "Zvb2Jhc", like for example "eGZvb2Jhcg",
    // which is decoded as "xfoobar". The actual number of additional
    // characters that must be used from the left and right of the pattern
    // found depends on the padding and the rest of dividing the pattern's
    // length by 4. The table below covers all possible cases using the
    // plain text patterns "foobar", "fooba" and "foob".
    //
    // padding          base64                      len (mod 4)
    //    0   foobar    Zm9vYmFy    len(b64(foobar))  8 (0)  [Zm9vYmFy]
    //    0   fooba     Zm9vYmE     len(b64(fooba))   7 (3)  [Zm9vYm]E
    //    0   foob      Zm9vYg      len(b64(foob))    6 (2)  [Zm9vY]g
    //
    //    1   xfoobar   eGZvb2Jhcg  len(b64(foobar))  8 (0)  eG[Zvb2Jhc]g
    //    1   xfooba    eGZvb2Jh    len(b64(fooba))   7 (3)  eG[Zvb2Jh]
    //    1   xfoob     eGZvb2I     len(b64(foob))    6 (2)  eG[Zvb2]I
    //
    //    2   xxfoobar  eHhmb29iYXI len(b64(foobar))  8 (0)  eHh[mb29iYX]I
    //    2   xxfooba   eHhmb29iYQ  len(b64(fooba))   7 (3)  eHh[mb29iY]Q
    //    2   xxfoob    eHhmb29i    len(b64(foob))    6 (2)  eHh[mb29i]
    //
    // In the rightmost column the portion of the base64 pattern that is
    // searched using the Aho-Corasick algorithm is enclosed in [].
    let (mut decode_start_delta, mut decode_len, mut match_len) = match padding
    {
        0 => match len % 4 {
            0 => (0, len, len),
            2 => (0, len + 2, len - 1),
            3 => (0, len + 1, len - 1),
            _ => unreachable!(),
        },
        1 => match len % 4 {
            0 => (2, len + 4, len - 1),
            2 => (2, len + 2, len - 2),
            3 => (2, len + 1, len - 1),
            _ => unreachable!(),
        },
        2 => match len % 4 {
            0 => (3, len + 4, len - 1),
            2 => (3, len + 2, len - 1),
            3 => (3, len + 5, len - 1),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };

    // In wide mode each base64 character is two bytes long, adjust
    // decode_start_delta and lengths accordingly.
    if wide {
        decode_start_delta *= 2;
        decode_len *= 2;
        match_len *= 2;
    }

    // decode_range is the range within the scanned data that we are going
    // to decode as base64. It starts at atom_pos - decode_start_delta,
    // but if atom_pos < decode_start_delta this is not a real match.
    let mut decode_range = if let (decode_start, false) =
        atom_pos.overflowing_sub(decode_start_delta)
    {
        decode_start..decode_start + decode_len
    } else {
        return None;
    };

    // If the end of decode_range is past the end of the scanned data
    // truncate it to scanned_data_len.
    if decode_range.end > scanned_data.len() {
        decode_range.end = scanned_data.len();
    }

    let base64_engine = base64::engine::GeneralPurpose::new(
        alphabet.as_ref().unwrap_or(&base64::alphabet::STANDARD),
        base64::engine::general_purpose::NO_PAD,
    );

    let decoded = if wide {
        // Collect the ASCII characters at even positions and make sure
        // that bytes at odd positions are zeroes.
        let mut ascii = Vec::with_capacity(decode_range.len() / 2);
        for (i, b) in scanned_data[decode_range].iter().enumerate() {
            if i % 2 == 0 {
                ascii.push(*b)
            } else if *b != 0 {
                return None;
            }
        }
        base64_engine.decode(ascii.as_slice())
    } else {
        base64_engine.decode(&scanned_data[decode_range])
    };

    if let Ok(decoded) = decoded {
        // If the decoding was successful, ignore the padding and compare
        // to the pattern.
        let decoded = &decoded[padding..];
        if decoded.len() >= pattern.len()
            && pattern.eq(&decoded[0..pattern.len()])
        {
            Some(Match {
                range: atom_pos..atom_pos + match_len,
                xor_key: None,
            })
        } else {
            None
        }
    } else {
        None
    }
}
