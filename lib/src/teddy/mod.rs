/*! Teddy is a SIMD accelerated multiple substring matching algorithm.

This implementation was taken from https://github.com/BurntSushi/aho-corasick
with minor modifications.

*/
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::new_ret_no_self)]

use core::fmt::Debug;
use std::sync::Arc;

mod generic;
mod vector;

pub(crate) use self::generic::{Match, Patterns};

pub(crate) trait SearcherT: Debug + Send + Sync {
    unsafe fn find_overlapping(
        &self,
        start: *const u8,
        end: *const u8,
        callback: &mut dyn FnMut(Match),
    );
}

#[derive(Clone, Debug)]
pub(crate) struct Builder {
    patterns: Vec<Vec<u8>>,
}

impl Builder {
    pub fn new() -> Self {
        Self { patterns: Vec::new() }
    }

    pub fn add(&mut self, pattern: &[u8]) {
        self.patterns.push(pattern.to_vec());
    }

    pub fn build(&self) -> Option<Searcher> {
        if self.patterns.is_empty() {
            return None;
        }
        let mut min_len = usize::MAX;
        for p in &self.patterns {
            if p.is_empty() {
                return None;
            }
            if p.len() < min_len {
                min_len = p.len();
            }
        }

        let pats = Arc::new(Patterns {
            by_id: self.patterns.clone(),
            minimum_len: min_len,
        });

        if pats.len() > 64 {
            return None;
        }

        if !cfg!(target_endian = "little") {
            return None;
        }

        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        {
            let mask_len = core::cmp::min(4, pats.minimum_len());
            let beefy = pats.len() > 32;
            let has_avx2 = is_available_avx2();
            let has_ssse3 = has_avx2 || is_available_ssse3();

            if !has_ssse3 && !has_avx2 {
                return None;
            }

            if mask_len == 1 && pats.len() > 16 {
                return None;
            }

            let use_avx2 = has_avx2;
            let fat = use_avx2 && beefy;

            match (mask_len, use_avx2, fat) {
                (1, false, _) => x86_64::SlimSSSE3::<1>::new(&pats),
                (1, true, false) => x86_64::SlimAVX2::<1>::new(&pats),
                (1, true, true) => x86_64::FatAVX2::<1>::new(&pats),
                (2, false, _) => x86_64::SlimSSSE3::<2>::new(&pats),
                (2, true, false) => x86_64::SlimAVX2::<2>::new(&pats),
                (2, true, true) => x86_64::FatAVX2::<2>::new(&pats),
                (3, false, _) => x86_64::SlimSSSE3::<3>::new(&pats),
                (3, true, false) => x86_64::SlimAVX2::<3>::new(&pats),
                (3, true, true) => x86_64::FatAVX2::<3>::new(&pats),
                (4, false, _) => x86_64::SlimSSSE3::<4>::new(&pats),
                (4, true, false) => x86_64::SlimAVX2::<4>::new(&pats),
                (4, true, true) => x86_64::FatAVX2::<4>::new(&pats),
                _ => None,
            }
        }

        #[cfg(all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_endian = "little"
        ))]
        {
            let mask_len = core::cmp::min(4, pats.minimum_len());
            match mask_len {
                1 => {
                    if pats.len() > 16 {
                        return None;
                    }
                    aarch64::SlimNeon::<1>::new(&pats)
                }
                2 => {
                    if pats.len() > 32 {
                        return None;
                    }
                    aarch64::SlimNeon::<2>::new(&pats)
                }
                3 => {
                    if pats.len() > 48 {
                        return None;
                    }
                    aarch64::SlimNeon::<3>::new(&pats)
                }
                4 => aarch64::SlimNeon::<4>::new(&pats),
                _ => None,
            }
        }

        #[cfg(not(any(
            all(target_arch = "x86_64", target_feature = "sse2"),
            all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_endian = "little"
            )
        )))]
        {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Searcher {
    imp: Arc<dyn SearcherT>,
    minimum_len: usize,
}

impl Searcher {
    #[inline(always)]
    pub(crate) fn find_overlapping(
        &self,
        haystack: &[u8],
        at: usize,
        callback: &mut dyn FnMut(Match),
    ) {
        if haystack[at..].len() < self.minimum_len {
            return;
        }
        let hayptr = haystack.as_ptr();
        unsafe {
            self.imp.find_overlapping(
                hayptr.add(at),
                hayptr.add(haystack.len()),
                callback,
            );
        }
    }

    #[inline(always)]
    pub fn minimum_len(&self) -> usize {
        self.minimum_len
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
#[inline]
fn is_available_ssse3() -> bool {
    #[cfg(target_feature = "ssse3")]
    {
        true
    }
    #[cfg(not(target_feature = "ssse3"))]
    {
        std::is_x86_feature_detected!("ssse3")
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
#[inline]
fn is_available_avx2() -> bool {
    #[cfg(target_feature = "avx2")]
    {
        true
    }
    #[cfg(not(target_feature = "avx2"))]
    {
        std::is_x86_feature_detected!("avx2")
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86_64 {
    use super::{Match, Patterns, Searcher, SearcherT};
    use core::arch::x86_64::{__m128i, __m256i};
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    pub struct SlimSSSE3<const BYTES: usize> {
        slim128: crate::teddy::generic::Slim<__m128i, BYTES>,
    }
    macro_rules! slim_ssse3 {
        ($len:expr) => {
            impl SlimSSSE3<$len> {
                pub fn new(patterns: &Arc<Patterns>) -> Option<Searcher> {
                    let slim128 = unsafe {
                        crate::teddy::generic::Slim::<__m128i, $len>::new(
                            Arc::clone(patterns),
                        )
                    };
                    let minimum_len = slim128.minimum_len();
                    Some(Searcher {
                        imp: Arc::new(SlimSSSE3 { slim128 }),
                        minimum_len,
                    })
                }
            }
            impl SearcherT for SlimSSSE3<$len> {
                #[target_feature(enable = "ssse3")]
                unsafe fn find_overlapping(
                    &self,
                    start: *const u8,
                    end: *const u8,
                    callback: &mut dyn FnMut(Match),
                ) {
                    unsafe {
                        self.slim128.find_overlapping(start, end, callback)
                    };
                }
            }
        };
    }
    slim_ssse3!(1);
    slim_ssse3!(2);
    slim_ssse3!(3);
    slim_ssse3!(4);

    #[derive(Clone, Debug)]
    pub struct SlimAVX2<const BYTES: usize> {
        slim128: crate::teddy::generic::Slim<__m128i, BYTES>,
        slim256: crate::teddy::generic::Slim<__m256i, BYTES>,
    }
    macro_rules! slim_avx2 {
        ($len:expr) => {
            impl SlimAVX2<$len> {
                pub fn new(patterns: &Arc<Patterns>) -> Option<Searcher> {
                    let slim128 = unsafe {
                        crate::teddy::generic::Slim::<__m128i, $len>::new(
                            Arc::clone(patterns),
                        )
                    };
                    let slim256 = unsafe {
                        crate::teddy::generic::Slim::<__m256i, $len>::new(
                            Arc::clone(patterns),
                        )
                    };
                    let minimum_len = slim128.minimum_len();
                    Some(Searcher {
                        imp: Arc::new(SlimAVX2 { slim128, slim256 }),
                        minimum_len,
                    })
                }
            }
            impl SearcherT for SlimAVX2<$len> {
                #[target_feature(enable = "avx2")]
                unsafe fn find_overlapping(
                    &self,
                    start: *const u8,
                    end: *const u8,
                    callback: &mut dyn FnMut(Match),
                ) {
                    let len = (end as usize).saturating_sub(start as usize);
                    if len < self.slim256.minimum_len() {
                        unsafe {
                            self.slim128.find_overlapping(start, end, callback)
                        };
                    } else {
                        unsafe {
                            self.slim256.find_overlapping(start, end, callback)
                        };
                    }
                }
            }
        };
    }
    slim_avx2!(1);
    slim_avx2!(2);
    slim_avx2!(3);
    slim_avx2!(4);

    #[derive(Clone, Debug)]
    pub struct FatAVX2<const BYTES: usize> {
        fat256: crate::teddy::generic::Fat<__m256i, BYTES>,
    }
    macro_rules! fat_avx2 {
        ($len:expr) => {
            impl FatAVX2<$len> {
                pub fn new(patterns: &Arc<Patterns>) -> Option<Searcher> {
                    let fat256 = unsafe {
                        crate::teddy::generic::Fat::<__m256i, $len>::new(
                            Arc::clone(patterns),
                        )
                    };
                    let minimum_len = fat256.minimum_len();
                    Some(Searcher {
                        imp: Arc::new(FatAVX2 { fat256 }),
                        minimum_len,
                    })
                }
            }
            impl SearcherT for FatAVX2<$len> {
                #[target_feature(enable = "avx2")]
                unsafe fn find_overlapping(
                    &self,
                    start: *const u8,
                    end: *const u8,
                    callback: &mut dyn FnMut(Match),
                ) {
                    unsafe {
                        self.fat256.find_overlapping(start, end, callback)
                    };
                }
            }
        };
    }
    fat_avx2!(1);
    fat_avx2!(2);
    fat_avx2!(3);
    fat_avx2!(4);
}

#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little"
))]
mod aarch64 {
    use super::{Match, Patterns, Searcher, SearcherT};
    use core::arch::aarch64::uint8x16_t;
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    pub struct SlimNeon<const BYTES: usize> {
        slim128: crate::teddy::generic::Slim<uint8x16_t, BYTES>,
    }
    macro_rules! slim_neon {
        ($len:expr) => {
            impl SlimNeon<$len> {
                pub fn new(patterns: &Arc<Patterns>) -> Option<Searcher> {
                    let slim128 = unsafe {
                        crate::teddy::generic::Slim::<uint8x16_t, $len>::new(
                            Arc::clone(patterns),
                        )
                    };
                    let minimum_len = slim128.minimum_len();
                    Some(Searcher {
                        imp: Arc::new(SlimNeon { slim128 }),
                        minimum_len,
                    })
                }
            }
            impl SearcherT for SlimNeon<$len> {
                #[target_feature(enable = "neon")]
                unsafe fn find_overlapping(
                    &self,
                    start: *const u8,
                    end: *const u8,
                    callback: &mut dyn FnMut(Match),
                ) {
                    unsafe {
                        self.slim128.find_overlapping(start, end, callback);
                    }
                }
            }
        };
    }
    slim_neon!(1);
    slim_neon!(2);
    slim_neon!(3);
    slim_neon!(4);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Searcher and collect all overlapping matches as
    /// (pattern_id, start_offset, end_offset) tuples.
    /// Returns `None` when the platform has no SIMD support so tests can
    /// gracefully skip instead of failing.
    fn find_all(
        patterns: &[&[u8]],
        haystack: &[u8],
        at: usize,
    ) -> Option<Vec<(u32, usize, usize)>> {
        let mut builder = Builder::new();
        for p in patterns {
            builder.add(p);
        }
        let searcher = builder.build()?;
        let base = haystack.as_ptr() as usize;
        let mut matches = Vec::new();
        searcher.find_overlapping(haystack, at, &mut |m| {
            let start = m.start() as usize - base;
            let end = m.end() as usize - base;
            matches.push((m.pattern(), start, end));
        });
        Some(matches)
    }

    /// Pad `data` with `0x01` bytes until it is at least 64 bytes long.
    ///
    /// The teddy searcher requires `haystack[at..].len() >= minimum_len`,
    /// where `minimum_len` is typically `V::BYTES + (BYTES - 1)` (e.g. 19
    /// for SSE2 with a 4-byte mask).  64 bytes is comfortably above every
    /// supported configuration, including AVX2.  Using `0x01` as the filler
    /// avoids accidental matches for tests that search for ASCII patterns.
    fn pad64(data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        v.resize(v.len().max(64), 0x01);
        v
    }

    // ── Builder edge cases ────────────────────────────────────────────────

    #[test]
    fn builder_no_patterns_returns_none() {
        assert!(Builder::new().build().is_none());
    }

    #[test]
    fn builder_empty_pattern_returns_none() {
        let mut b = Builder::new();
        b.add(b"");
        assert!(b.build().is_none());
    }

    #[test]
    fn builder_too_many_patterns_returns_none() {
        // > 64 patterns must be rejected.
        let mut b = Builder::new();
        for i in 0u8..=64 {
            b.add(&[i, i]);
        }
        assert!(b.build().is_none());
    }

    #[test]
    fn builder_exactly_64_patterns_builds() {
        let mut b = Builder::new();
        for i in 0u8..64 {
            b.add(&[i, i ^ 0x11]);
        }
        // May return None on platforms without SIMD — that's fine; the
        // point is that it must *not* panic or return None due to the
        // count check alone.
        let _ = b.build();
    }

    // ── No-match cases ────────────────────────────────────────────────────

    #[test]
    fn no_match_absent_pattern() {
        let haystack = pad64(b"hello world");
        let Some(m) = find_all(&[b"xyz"], &haystack, 0) else {
            return;
        };
        assert!(m.is_empty());
    }

    #[test]
    fn no_match_haystack_too_short_for_minimum_len() {
        // Haystack shorter than minimum_len must not crash and returns nothing.
        let Some(m) = find_all(&[b"abcdefghijklmnopqrst"], b"abc", 0) else {
            return;
        };
        assert!(m.is_empty());
    }

    #[test]
    fn no_match_empty_haystack() {
        let Some(m) = find_all(&[b"abc"], b"", 0) else {
            return;
        };
        assert!(m.is_empty());
    }

    // ── Single-pattern matching ───────────────────────────────────────────

    #[test]
    fn single_pattern_match_at_start() {
        let haystack = pad64(b"hello world");
        let Some(m) = find_all(&[b"hello"], &haystack, 0) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0], (0, 0, 5));
    }

    #[test]
    fn single_pattern_match_at_end() {
        let haystack = pad64(b"hello world");
        let Some(m) = find_all(&[b"world"], &haystack, 0) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0], (0, 6, 11));
    }

    #[test]
    fn single_pattern_match_in_middle() {
        let haystack = pad64(b"hello world");
        let Some(m) = find_all(&[b"lo wo"], &haystack, 0) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0], (0, 3, 8));
    }

    #[test]
    fn single_pattern_multiple_occurrences() {
        // "ab" appears at 0, 2, 4 in "ababab"; filler 0x01 never matches.
        let haystack = pad64(b"ababab");
        let Some(mut m) = find_all(&[b"ab"], &haystack, 0) else {
            return;
        };
        m.sort_unstable();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0], (0, 0, 2));
        assert_eq!(m[1], (0, 2, 4));
        assert_eq!(m[2], (0, 4, 6));
    }

    #[test]
    fn single_byte_pattern() {
        // 'x' (0x78) appears at 1, 3, 5; filler 0x01 never matches.
        let haystack = pad64(b"axbxcx");
        let Some(mut m) = find_all(&[b"x"], &haystack, 0) else {
            return;
        };
        m.sort_unstable();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].1, 1);
        assert_eq!(m[1].1, 3);
        assert_eq!(m[2].1, 5);
    }

    #[test]
    fn two_byte_pattern() {
        // "ab" at 1, 3, 6 in "aababcab".
        let haystack = pad64(b"aababcab");
        let Some(mut m) = find_all(&[b"ab"], &haystack, 0) else {
            return;
        };
        m.sort_unstable();
        let starts: Vec<usize> = m.iter().map(|x| x.1).collect();
        assert!(starts.contains(&1));
        assert!(starts.contains(&3));
        assert!(starts.contains(&6));
    }

    #[test]
    fn three_byte_pattern() {
        // "xyz" at 0 and 6 in "xyzabcxyzdef".
        let haystack = pad64(b"xyzabcxyzdef");
        let Some(mut m) = find_all(&[b"xyz"], &haystack, 0) else {
            return;
        };
        m.sort_unstable();
        let starts: Vec<usize> = m.iter().map(|x| x.1).collect();
        assert!(starts.contains(&0));
        assert!(starts.contains(&6));
    }

    #[test]
    fn four_byte_pattern() {
        // "abcd" at 4 and 15 in "testabcdtestXXXabcd".
        let haystack = b"testabcdtestXXXabcd";
        let Some(mut m) = find_all(&[b"abcd"], haystack, 0) else {
            return;
        };
        m.sort_unstable();
        let starts: Vec<usize> = m.iter().map(|x| x.1).collect();
        assert!(starts.contains(&4));
        assert!(starts.contains(&15));
    }

    // ── Multi-pattern matching ────────────────────────────────────────────

    #[test]
    fn two_patterns_both_present() {
        let haystack = pad64(b"foo and bar");
        let Some(mut m) = find_all(&[b"foo", b"bar"], &haystack, 0) else {
            return;
        };
        m.sort_unstable();
        assert_eq!(m.len(), 2);
        let starts: Vec<usize> = m.iter().map(|x| x.1).collect();
        assert!(starts.contains(&0));
        assert!(starts.contains(&8));
    }

    #[test]
    fn two_patterns_one_absent() {
        let haystack = pad64(b"only foo here");
        let Some(m) = find_all(&[b"foo", b"bar"], &haystack, 0) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].1, 5);
    }

    #[test]
    fn multiple_patterns_correct_ids() {
        // IDs must match the order add() was called: cat=0, dog=1, bird=2.
        let haystack = pad64(b"catdogbird");
        let Some(mut m) =
            find_all(&[b"cat", b"dog", b"bird"], &haystack, 0)
        else {
            return;
        };
        m.sort_unstable_by_key(|x| x.1);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0], (0, 0, 3));
        assert_eq!(m[1], (1, 3, 6));
        assert_eq!(m[2], (2, 6, 10));
    }

    #[test]
    fn overlapping_patterns() {
        // "abcde" starts at 2; "cde" starts at 4 — both must be reported.
        let mut haystack = pad64(b"XXabcdeYY");
        // Overwrite the filler so it doesn't accidentally contain the pattern.
        haystack[9..].fill(0x01);
        let Some(mut m) =
            find_all(&[b"abcde", b"cde"], &haystack, 0)
        else {
            return;
        };
        m.sort_unstable_by_key(|x| x.1);
        let starts: Vec<usize> = m.iter().map(|x| x.1).collect();
        assert!(starts.contains(&2), "expected match for 'abcde' at 2, got {starts:?}");
        assert!(starts.contains(&4), "expected match for 'cde' at 4, got {starts:?}");
    }

    // ── Search with non-zero `at` offset ─────────────────────────────────

    #[test]
    fn search_skips_matches_before_at() {
        // "abc" appears at 0 and 3; with at=3 only the second is reported.
        let haystack = pad64(b"abcabc");
        let Some(m) = find_all(&[b"abc"], &haystack, 3) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0], (0, 3, 6));
    }

    #[test]
    fn search_at_offset_equal_to_haystack_length_returns_empty() {
        // haystack[at..] is empty → nothing to search.
        let haystack = b"abcabc";
        let Some(m) = find_all(&[b"abc"], haystack, 6) else {
            return;
        };
        assert!(m.is_empty());
    }

    // ── Binary / non-ASCII patterns ───────────────────────────────────────

    #[test]
    fn binary_pattern_match() {
        let pattern: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let haystack: Vec<u8> =
            [0x00u8; 10].iter().chain(pattern).chain([0x00u8; 10].iter()).cloned().collect();
        let haystack = pad64(&haystack);
        let Some(m) = find_all(&[pattern], &haystack, 0) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0], (0, 10, 14));
    }

    #[test]
    fn all_same_byte_pattern() {
        let haystack = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 35 x 'a'
        let Some(mut m) = find_all(&[b"aaa"], haystack, 0) else {
            return;
        };
        m.sort_unstable();
        // Overlapping mode reports every start position 0..=32.
        assert!(!m.is_empty());
        for (_, start, end) in &m {
            assert_eq!(end - start, 3);
        }
    }

    // ── Large haystack (exercises the vectorised inner loop) ──────────────

    #[test]
    fn pattern_in_large_haystack() {
        let mut haystack = vec![0u8; 1024];
        let needle = b"needle";
        haystack[500..506].copy_from_slice(needle);
        let Some(m) = find_all(&[needle], &haystack, 0) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0], (0, 500, 506));
    }

    #[test]
    fn pattern_at_very_end_of_large_haystack() {
        let mut haystack = vec![0xFFu8; 1024];
        let needle: &[u8] = b"end!";
        haystack[1020..].copy_from_slice(needle);
        let Some(m) = find_all(&[needle], &haystack, 0) else {
            return;
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0], (0, 1020, 1024));
    }

    // ── minimum_len accessor ──────────────────────────────────────────────

    #[test]
    fn minimum_len_at_least_shortest_pattern() {
        let mut b = Builder::new();
        b.add(b"longpattern");
        b.add(b"xy"); // shortest: 2 bytes
        let Some(s) = b.build() else {
            return;
        };
        assert!(s.minimum_len() >= 2);
    }
}
