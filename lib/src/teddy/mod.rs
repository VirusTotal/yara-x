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
