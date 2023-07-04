use std::collections::VecDeque;
use std::ops::{Range, RangeInclusive};
use std::ptr::NonNull;
use std::rc::Rc;

use base64::Engine;
use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use bstr::ByteSlice;
use protobuf::{MessageDyn, MessageFull};
use regex::bytes::Regex;
use rustc_hash::FxHashMap;
use wasmtime::Store;

use crate::compiler::{
    AtomInfo, LiteralId, NamespaceId, PatternId, RegexpId, RuleId, Rules,
    SubPattern, SubPatternFlagSet, SubPatternFlags, SubPatternId,
};
use crate::scanner::matches::{Match, MatchList, UnconfirmedMatch};
use crate::scanner::RuntimeStringId;
use crate::string_pool::BStringPool;
use crate::types::{Struct, TypeValue};
use crate::wasm::MATCHING_RULES_BITMAP_BASE;

/// Structure that holds information about the current scan.
pub(crate) struct ScanContext<'r> {
    /// Pointer to the WASM store.
    pub wasm_store: NonNull<Store<ScanContext<'r>>>,
    /// Pointer to the data being scanned.
    pub scanned_data: *const u8,
    /// Length of data being scanned.
    pub scanned_data_len: usize,
    /// Vector containing the IDs of the non-global rules that matched. Global
    /// rules are added to the `global_rules_matching` map instead.
    pub rules_matching: Vec<RuleId>,
    /// Map containing the IDs of the global rules that matched.
    pub global_rules_matching: FxHashMap<NamespaceId, Vec<RuleId>>,
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

    /// Returns a regular expression given its [`RegexpId`].
    pub(crate) fn get_regexp(&self, regexp_id: RegexpId) -> Regex {
        // TODO: put the regular expressions in a cache and call
        // `compiled_rules.get_regexp` only if not found in the cache.
        self.compiled_rules.get_regexp(regexp_id)
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
        // `global_rules_matching` map. Also, their corresponding bits in
        // the matching rules bitmap must be cleared.
        if let Some(rules) =
            self.global_rules_matching.get_mut(&rule.namespace_id)
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
            self.global_rules_matching
                .entry(rule.namespace_id)
                .or_default()
                .push(rule_id);
        } else {
            self.rules_matching.push(rule_id);
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
    ) {
        let wasm_store = unsafe { self.wasm_store.as_mut() };
        let main_mem = self.main_memory.unwrap().data_mut(wasm_store);
        let num_rules = self.compiled_rules.rules().len();

        let base = MATCHING_RULES_BITMAP_BASE as usize + num_rules / 8 + 1;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(&mut main_mem[base..]);

        bits.set(pattern_id.into(), true);

        self.pattern_matches.entry(pattern_id).or_default().add(match_)
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
    pub(crate) fn search_for_patterns(&mut self) {
        let ac = self.compiled_rules.aho_corasick();

        for atom_match in ac.find_overlapping_iter(self.scanned_data()) {
            let matched_atom =
                &self.compiled_rules.atoms()[atom_match.pattern()];

            // Subtract the backtrack value from the offset where the atom
            // matched. If the result is negative the atom can't be inside
            // the scanned data and therefore is not a possible match.
            let (match_start, overflow) = atom_match
                .start()
                .overflowing_sub(matched_atom.atom.backtrack as usize);

            if overflow {
                continue;
            }

            let (pattern_id, sub_pattern) = &self
                .compiled_rules
                .get_sub_pattern(matched_atom.sub_pattern_id);

            match sub_pattern {
                SubPattern::Literal { pattern, flags } => {
                    if let Some(verified_match) = self.verify_literal_match(
                        match_start,
                        *pattern,
                        *flags,
                    ) {
                        self.track_pattern_match(*pattern_id, verified_match);
                    };
                }

                SubPattern::LiteralChainHead { pattern, flags, .. } => {
                    if let Some(m) = self.verify_literal_match(
                        match_start,
                        *pattern,
                        *flags,
                    ) {
                        // This is the head of a set of chained sub-patterns.
                        // Verifying that the head matches doesn't mean that
                        // the whole sub-pattern matches, the rest of the chain
                        // must be found as well. For the time being this is
                        // just an unconfirmed match.
                        self.unconfirmed_matches
                            .entry(matched_atom.sub_pattern_id)
                            .or_default()
                            .push_back(UnconfirmedMatch {
                                range: m.range.clone(),
                                chain_length: 0,
                            })
                    }
                }

                SubPattern::LiteralChainTail {
                    pattern,
                    chained_to,
                    gap,
                    flags,
                } => {
                    if let Some(m) = self.verify_literal_match(
                        match_start,
                        *pattern,
                        *flags,
                    ) {
                        if self.within_valid_distance(
                            matched_atom.sub_pattern_id,
                            *chained_to,
                            m.range.start,
                            gap,
                        ) {
                            if flags.contains(SubPatternFlags::LastInChain) {
                                // This sub-pattern is the last one in the
                                // chain. We can proceed to verify the whole
                                // chain and determine if it matched or not.
                                self.verify_chain_of_matches(
                                    *pattern_id,
                                    matched_atom.sub_pattern_id,
                                    m.range,
                                );
                            } else {
                                // This sub-pattern in in the middle of the
                                // chain. We need to find the sub-patterns that
                                // follow, so for the time being this only an
                                // unconfirmed match.
                                self.unconfirmed_matches
                                    .entry(matched_atom.sub_pattern_id)
                                    .or_default()
                                    .push_back(UnconfirmedMatch {
                                        range: m.range.clone(),
                                        chain_length: 0,
                                    });
                            }
                        }
                    }
                }

                SubPattern::Xor { pattern, flags } => {
                    if let Some(m) = self.verify_xor_match(
                        match_start,
                        matched_atom,
                        *pattern,
                        *flags,
                    ) {
                        self.track_pattern_match(*pattern_id, m);
                    }
                }

                SubPattern::Base64 { pattern, padding }
                | SubPattern::Base64Wide { pattern, padding } => {
                    if let Some(m) = self.verify_base64_match(
                        (*padding).into(),
                        match_start,
                        *pattern,
                        None,
                        matches!(sub_pattern, SubPattern::Base64Wide { .. }),
                    ) {
                        self.track_pattern_match(*pattern_id, m);
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

                    if let Some(m) = self.verify_base64_match(
                        (*padding).into(),
                        match_start,
                        *pattern,
                        alphabet,
                        matches!(
                            sub_pattern,
                            SubPattern::CustomBase64Wide { .. }
                        ),
                    ) {
                        self.track_pattern_match(*pattern_id, m);
                    }
                }
            };
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

    fn verify_full_word(
        &self,
        match_range: Range<usize>,
        flags: SubPatternFlagSet,
        xor_key: Option<u8>,
    ) -> bool {
        let data = self.scanned_data();
        let xor_key = xor_key.unwrap_or(0);

        if flags.contains(SubPatternFlags::Wide) {
            if flags.contains(SubPatternFlags::FullwordLeft)
                && match_range.start >= 2
                && (data[match_range.start - 1] ^ xor_key) == 0
                && (data[match_range.start - 2] ^ xor_key)
                    .is_ascii_alphanumeric()
            {
                return false;
            }
            if flags.contains(SubPatternFlags::FullwordRight)
                && match_range.end + 1 < data.len()
                && (data[match_range.end + 1] ^ xor_key) == 0
                && (data[match_range.end] ^ xor_key).is_ascii_alphanumeric()
            {
                return false;
            }
        } else {
            if flags.contains(SubPatternFlags::FullwordLeft)
                && match_range.start >= 1
                && (data[match_range.start - 1] ^ xor_key)
                    .is_ascii_alphanumeric()
            {
                return false;
            }
            if flags.contains(SubPatternFlags::FullwordRight)
                && match_range.end < data.len()
                && (data[match_range.end] ^ xor_key).is_ascii_alphanumeric()
            {
                return false;
            }
        }

        true
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
                SubPattern::LiteralChainHead { .. } => {
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
                        );
                    }
                }
                SubPattern::LiteralChainTail {
                    chained_to,
                    gap,
                    flags,
                    ..
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

    /// Verifies that a literal sub-pattern actually matches at `match_start`.
    ///
    /// Returns a [`Match`] if the match was confirmed or [`None`] if otherwise.
    fn verify_literal_match(
        &self,
        match_start: usize,
        pattern_id: LiteralId,
        flags: SubPatternFlagSet,
    ) -> Option<Match> {
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();
        let data = self.scanned_data();

        // Offset where the match should end (exclusive).
        let match_end = match_start + pattern.len();

        // The match can not end past the end of the scanned data.
        if match_end > data.len() {
            return None;
        }

        if !self.verify_full_word(match_start..match_end, flags, None) {
            return None;
        }

        let match_found = if flags.contains(SubPatternFlags::Nocase) {
            pattern.eq_ignore_ascii_case(&data[match_start..match_end])
        } else {
            memx::memeq(&data[match_start..match_end], pattern.as_bytes())
        };

        if match_found {
            Some(Match {
                // The end of the range is exclusive.
                range: match_start..match_end,
                xor_key: None,
            })
        } else {
            None
        }
    }

    /// Verifies that a literal sub-pattern actually matches at `match_start`
    /// in XORed form.
    ///
    /// Returns a [`Match`] if the match was confirmed or [`None`] if otherwise.
    fn verify_xor_match(
        &self,
        match_start: usize,
        matched_atom: &AtomInfo,
        pattern_id: LiteralId,
        flags: SubPatternFlagSet,
    ) -> Option<Match> {
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();
        let data = self.scanned_data();

        // Offset where the match should end (exclusive).
        let match_end = match_start + pattern.len();

        // The match can not end past the end of the scanned data.
        if match_end > data.len() {
            return None;
        }

        let mut pattern = pattern.to_owned();

        // The atom that matched is the result of XORing the pattern with some
        // key. The key can be obtained by XORing some byte in the atom with
        // the corresponding byte in the pattern.
        let key = matched_atom.atom.as_slice()[0]
            ^ pattern[matched_atom.atom.backtrack as usize];

        if !self.verify_full_word(match_start..match_end, flags, Some(key)) {
            return None;
        }

        // Now we can XOR the whole pattern with the obtained key and make sure
        // that it matches the data. This only makes sense if the key is not
        // zero.
        if key != 0 {
            for i in 0..pattern.len() {
                pattern[i] ^= key;
            }
        }

        if memx::memeq(&data[match_start..match_end], pattern.as_bytes()) {
            Some(Match { range: match_start..match_end, xor_key: Some(key) })
        } else {
            None
        }
    }

    /// Verifies that a literal sub-pattern actually matches at `match_start`
    /// in base64 form.
    ///
    /// Returns a [`Match`] if the match was confirmed or [`None`] if otherwise.
    fn verify_base64_match(
        &self,
        padding: usize,
        match_start: usize,
        pattern_id: LiteralId,
        alphabet: Option<base64::alphabet::Alphabet>,
        wide: bool,
    ) -> Option<Match> {
        // Get the pattern in its original form, not encoded as base64.
        let pattern = self.compiled_rules.lit_pool().get(pattern_id).unwrap();

        // Compute the size of the pattern once it is encoded as base64.
        let len = base64::encoded_len(pattern.len(), false).unwrap();

        // A portion of the pattern in base64 form was found at match_start,
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
        let (mut decode_start_delta, mut decode_len, mut match_len) =
            match padding {
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
        // to decode as base64. It starts at match_start - decode_start_delta,
        // but if match_start < decode_start_delta this is not a real match.
        let mut decode_range = if let (decode_start, false) =
            match_start.overflowing_sub(decode_start_delta)
        {
            decode_start..decode_start + decode_len
        } else {
            return None;
        };

        // If the end of decode_range is past the end of the scanned data
        // truncate it to scanned_data_len.
        if decode_range.end > self.scanned_data_len {
            decode_range.end = self.scanned_data_len;
        }

        let base64_engine = base64::engine::GeneralPurpose::new(
            alphabet.as_ref().unwrap_or(&base64::alphabet::STANDARD),
            base64::engine::general_purpose::NO_PAD,
        );

        let decoded = if wide {
            // Collect the ASCII characters at even positions and make sure
            // that bytes at odd positions are zeroes.
            let mut ascii = Vec::with_capacity(decode_range.len() / 2);
            for (i, b) in self.scanned_data()[decode_range].iter().enumerate()
            {
                if i % 2 == 0 {
                    ascii.push(*b)
                } else if *b != 0 {
                    return None;
                }
            }
            base64_engine.decode(ascii.as_slice())
        } else {
            base64_engine.decode(&self.scanned_data()[decode_range])
        };

        if let Ok(decoded) = decoded {
            // If the decoding was successful, ignore the padding and compare
            // to the pattern.
            let decoded = &decoded[padding..];
            if decoded.len() >= pattern.len()
                && pattern.eq(&decoded[0..pattern.len()])
            {
                Some(Match {
                    range: match_start..match_start + match_len,
                    xor_key: None,
                })
            } else {
                None
            }
        } else {
            None
        }
    }
}
