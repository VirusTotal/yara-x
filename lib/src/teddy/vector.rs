// Self-contained SIMD vector utilities for Teddy extracted from aho-corasick.
#![allow(dead_code)]
use core::{
    fmt::Debug,
    panic::{RefUnwindSafe, UnwindSafe},
};

trait I8Ext {
    fn from_bits(n: u8) -> i8;
}
impl I8Ext for i8 {
    #[inline(always)]
    fn from_bits(n: u8) -> i8 {
        n as i8
    }
}
trait I32Ext {
    fn to_bits(self) -> u32;
}
impl I32Ext for i32 {
    #[inline(always)]
    fn to_bits(self) -> u32 {
        self as u32
    }
}
trait I64Ext {
    fn to_bits(self) -> u64;
}
impl I64Ext for i64 {
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self as u64
    }
}
trait U32Ext {
    fn as_usize(self) -> usize;
}
impl U32Ext for u32 {
    #[inline(always)]
    fn as_usize(self) -> usize {
        self as usize
    }
}
// NOTE: The descriptions for each of the vector methods on the traits below
// are pretty inscrutable. For this reason, there are tests for every method
// on for every trait impl below. If you're confused about what an op does,
// consult its test. (They probably should be doc tests, but I couldn't figure
// out how to write them in a non-annoying way.)

/// A trait for describing vector operations used by vectorized searchers.
///
/// The trait is highly constrained to low level vector operations needed for
/// the specific algorithms used in this crate. In general, it was invented
/// mostly to be generic over x86's __m128i and __m256i types. At time of
/// writing, it also supports wasm and aarch64 128-bit vector types as well.
///
/// # Safety
///
/// All methods are not safe since they are intended to be implemented using
/// vendor intrinsics, which are also not safe. Callers must ensure that
/// the appropriate target features are enabled in the calling function,
/// and that the current CPU supports them. All implementations should
/// avoid marking the routines with `#[target_feature]` and instead mark
/// them as `#[inline(always)]` to ensure they get appropriately inlined.
/// (`inline(always)` cannot be used with target_feature.)
pub(crate) trait Vector:
    Copy + Debug + Send + Sync + UnwindSafe + RefUnwindSafe
{
    /// The number of bits in the vector.
    const BITS: usize;
    /// The number of bytes in the vector. That is, this is the size of the
    /// vector in memory.
    const BYTES: usize;

    /// Create a vector with 8-bit lanes with the given byte repeated into each
    /// lane.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn splat(byte: u8) -> Self;

    /// Read a vector-size number of bytes from the given pointer. The pointer
    /// does not need to be aligned.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    ///
    /// Callers must guarantee that at least `BYTES` bytes are readable from
    /// `data`.
    unsafe fn load_unaligned(data: *const u8) -> Self;

    /// Returns true if and only if this vector has zero in all of its lanes.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn is_zero(self) -> bool;

    /// Do an 8-bit pairwise equality check. If lane `i` is equal in this
    /// vector and the one given, then lane `i` in the resulting vector is set
    /// to `0xFF`. Otherwise, it is set to `0x00`.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn cmpeq(self, vector2: Self) -> Self;

    /// Perform a bitwise 'and' of this vector and the one given and return
    /// the result.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn and(self, vector2: Self) -> Self;

    /// Perform a bitwise 'or' of this vector and the one given and return
    /// the result.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    #[allow(dead_code)] // unused, but useful enough to keep around?
    unsafe fn or(self, vector2: Self) -> Self;

    /// Shift each 8-bit lane in this vector to the right by the number of
    /// bits indictated by the `BITS` type parameter.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn shift_8bit_lane_right<const BITS: i32>(self) -> Self;

    /// Shift this vector to the left by one byte and shift the most
    /// significant byte of `vector2` into the least significant position of
    /// this vector.
    ///
    /// Stated differently, this behaves as if `self` and `vector2` were
    /// concatenated into a `2 * Self::BITS` temporary buffer and then shifted
    /// right by `Self::BYTES - 1` bytes.
    ///
    /// With respect to the Teddy algorithm, `vector2` is usually a previous
    /// `Self::BYTES` chunk from the haystack and `self` is the chunk
    /// immediately following it. This permits combining the last two bytes
    /// from the previous chunk (`vector2`) with the first `Self::BYTES - 1`
    /// bytes from the current chunk. This permits aligning the result of
    /// various shuffles so that they can be and-ed together and a possible
    /// candidate discovered.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn shift_in_one_byte(self, vector2: Self) -> Self;

    /// Shift this vector to the left by two bytes and shift the two most
    /// significant bytes of `vector2` into the least significant position of
    /// this vector.
    ///
    /// Stated differently, this behaves as if `self` and `vector2` were
    /// concatenated into a `2 * Self::BITS` temporary buffer and then shifted
    /// right by `Self::BYTES - 2` bytes.
    ///
    /// With respect to the Teddy algorithm, `vector2` is usually a previous
    /// `Self::BYTES` chunk from the haystack and `self` is the chunk
    /// immediately following it. This permits combining the last two bytes
    /// from the previous chunk (`vector2`) with the first `Self::BYTES - 2`
    /// bytes from the current chunk. This permits aligning the result of
    /// various shuffles so that they can be and-ed together and a possible
    /// candidate discovered.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn shift_in_two_bytes(self, vector2: Self) -> Self;

    /// Shift this vector to the left by three bytes and shift the three most
    /// significant bytes of `vector2` into the least significant position of
    /// this vector.
    ///
    /// Stated differently, this behaves as if `self` and `vector2` were
    /// concatenated into a `2 * Self::BITS` temporary buffer and then shifted
    /// right by `Self::BYTES - 3` bytes.
    ///
    /// With respect to the Teddy algorithm, `vector2` is usually a previous
    /// `Self::BYTES` chunk from the haystack and `self` is the chunk
    /// immediately following it. This permits combining the last three bytes
    /// from the previous chunk (`vector2`) with the first `Self::BYTES - 3`
    /// bytes from the current chunk. This permits aligning the result of
    /// various shuffles so that they can be and-ed together and a possible
    /// candidate discovered.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn shift_in_three_bytes(self, vector2: Self) -> Self;

    /// Shuffles the bytes in this vector according to the indices in each of
    /// the corresponding lanes in `indices`.
    ///
    /// If `i` is the index of corresponding lanes, `A` is this vector, `B` is
    /// indices and `C` is the resulting vector, then `C = A[B[i]]`.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn shuffle_bytes(self, indices: Self) -> Self;

    /// Call the provided function for each 64-bit lane in this vector. The
    /// given function is provided the lane index and lane value as a `u64`.
    ///
    /// If `f` returns `Some`, then iteration over the lanes is stopped and the
    /// value is returned. Otherwise, this returns `None`.
    ///
    /// # Notes
    ///
    /// Conceptually it would be nice if we could have a
    /// `unpack64(self) -> [u64; BITS / 64]` method, but defining that is
    /// tricky given Rust's [current support for const generics][support].
    /// And even if we could, it would be tricky to write generic code over
    /// it. (Not impossible. We could introduce another layer that requires
    /// `AsRef<[u64]>` or something.)
    ///
    /// [support]: https://github.com/rust-lang/rust/issues/60551
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn for_each_64bit_lane<T>(
        self,
        f: impl FnMut(usize, u64) -> Option<T>,
    ) -> Option<T>;
}

/// This trait extends the `Vector` trait with additional operations to support
/// Fat Teddy.
///
/// Fat Teddy uses 16 buckets instead of 8, but reads half as many bytes (as
/// the vector size) instead of the full size of a vector per iteration. For
/// example, when using a 256-bit vector, Slim Teddy reads 32 bytes at a timr
/// but Fat Teddy reads 16 bytes at a time.
///
/// Fat Teddy is useful when searching for a large number of literals.
/// The extra number of buckets spreads the literals out more and reduces
/// verification time.
///
/// Currently we only implement this for AVX on x86_64. It would be nice to
/// implement this for SSE on x86_64 and NEON on aarch64, with the latter two
/// only reading 8 bytes at a time. It's not clear how well it would work, but
/// there are some tricky things to figure out in terms of implementation. The
/// `half_shift_in_{one,two,three}_bytes` methods in particular are probably
/// the trickiest of the bunch. For AVX2, these are implemented by taking
/// advantage of the fact that `_mm256_alignr_epi8` operates on each 128-bit
/// half instead of the full 256-bit vector. (Where as `_mm_alignr_epi8`
/// operates on the full 128-bit vector and not on each 64-bit half.) I didn't
/// do a careful survey of NEON to see if it could easily support these
/// operations.
pub(crate) trait FatVector: Vector {
    type Half: Vector;

    /// Read a half-vector-size number of bytes from the given pointer, and
    /// broadcast it across both halfs of a full vector. The pointer does not
    /// need to be aligned.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    ///
    /// Callers must guarantee that at least `Self::HALF::BYTES` bytes are
    /// readable from `data`.
    unsafe fn load_half_unaligned(data: *const u8) -> Self;

    /// Like `Vector::shift_in_one_byte`, except this is done for each half
    /// of the vector instead.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn half_shift_in_one_byte(self, vector2: Self) -> Self;

    /// Like `Vector::shift_in_two_bytes`, except this is done for each half
    /// of the vector instead.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn half_shift_in_two_bytes(self, vector2: Self) -> Self;

    /// Like `Vector::shift_in_two_bytes`, except this is done for each half
    /// of the vector instead.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn half_shift_in_three_bytes(self, vector2: Self) -> Self;

    /// Swap the 128-bit lanes in this vector.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn swap_halves(self) -> Self;

    /// Unpack and interleave the 8-bit lanes from the low 128 bits of each
    /// vector and return the result.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn interleave_low_8bit_lanes(self, vector2: Self) -> Self;

    /// Unpack and interleave the 8-bit lanes from the high 128 bits of each
    /// vector and return the result.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn interleave_high_8bit_lanes(self, vector2: Self) -> Self;

    /// Call the provided function for each 64-bit lane in the lower half
    /// of this vector and then in the other vector. The given function is
    /// provided the lane index and lane value as a `u64`. (The high 128-bits
    /// of each vector are ignored.)
    ///
    /// If `f` returns `Some`, then iteration over the lanes is stopped and the
    /// value is returned. Otherwise, this returns `None`.
    ///
    /// # Safety
    ///
    /// Callers must ensure that this is okay to call in the current target for
    /// the current CPU.
    unsafe fn for_each_low_64bit_lane<T>(
        self,
        vector2: Self,
        f: impl FnMut(usize, u64) -> Option<T>,
    ) -> Option<T>;
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86_64_ssse3 {
    use core::arch::x86_64::*;

    use super::{I8Ext, I32Ext, Vector};

    impl Vector for __m128i {
        const BITS: usize = 128;
        const BYTES: usize = 16;

        #[inline(always)]
        unsafe fn splat(byte: u8) -> __m128i {
            unsafe { _mm_set1_epi8(i8::from_bits(byte)) }
        }

        #[inline(always)]
        unsafe fn load_unaligned(data: *const u8) -> __m128i {
            unsafe { _mm_loadu_si128(data.cast::<__m128i>()) }
        }

        #[inline(always)]
        unsafe fn is_zero(self) -> bool {
            let cmp = unsafe { self.cmpeq(Self::splat(0)) };
            unsafe { _mm_movemask_epi8(cmp).to_bits() == 0xFFFF }
        }

        #[inline(always)]
        unsafe fn cmpeq(self, vector2: Self) -> __m128i {
            unsafe { _mm_cmpeq_epi8(self, vector2) }
        }

        #[inline(always)]
        unsafe fn and(self, vector2: Self) -> __m128i {
            unsafe { _mm_and_si128(self, vector2) }
        }

        #[inline(always)]
        unsafe fn or(self, vector2: Self) -> __m128i {
            unsafe { _mm_or_si128(self, vector2) }
        }

        #[inline(always)]
        unsafe fn shift_8bit_lane_right<const BITS: i32>(self) -> Self {
            // Apparently there is no _mm_srli_epi8, so we emulate it by
            // shifting 16-bit integers and masking out the high nybble of each
            // 8-bit lane (since that nybble will contain bits from the low
            // nybble of the previous lane).
            let lomask = unsafe { Self::splat(0xF) };
            unsafe { _mm_srli_epi16(self, BITS).and(lomask) }
        }

        #[inline(always)]
        unsafe fn shift_in_one_byte(self, vector2: Self) -> Self {
            unsafe { _mm_alignr_epi8(self, vector2, 15) }
        }

        #[inline(always)]
        unsafe fn shift_in_two_bytes(self, vector2: Self) -> Self {
            unsafe { _mm_alignr_epi8(self, vector2, 14) }
        }

        #[inline(always)]
        unsafe fn shift_in_three_bytes(self, vector2: Self) -> Self {
            unsafe { _mm_alignr_epi8(self, vector2, 13) }
        }

        #[inline(always)]
        unsafe fn shuffle_bytes(self, indices: Self) -> Self {
            unsafe { _mm_shuffle_epi8(self, indices) }
        }

        #[inline(always)]
        unsafe fn for_each_64bit_lane<T>(
            self,
            mut f: impl FnMut(usize, u64) -> Option<T>,
        ) -> Option<T> {
            // We could just use _mm_extract_epi64 here, but that requires
            // SSE 4.1. It isn't necessarily a problem to just require SSE 4.1,
            // but everything else works with SSSE3 so we stick to that subset.
            let lanes: [u64; 2] = unsafe { core::mem::transmute(self) };
            if let Some(t) = f(0, lanes[0]) {
                return Some(t);
            }
            if let Some(t) = f(1, lanes[1]) {
                return Some(t);
            }
            None
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86_64_avx2 {
    use core::arch::x86_64::*;

    use super::{FatVector, I8Ext, I32Ext, I64Ext, Vector};

    impl Vector for __m256i {
        const BITS: usize = 256;
        const BYTES: usize = 32;

        #[inline(always)]
        unsafe fn splat(byte: u8) -> __m256i {
            unsafe { _mm256_set1_epi8(i8::from_bits(byte)) }
        }

        #[inline(always)]
        unsafe fn load_unaligned(data: *const u8) -> __m256i {
            unsafe { _mm256_loadu_si256(data.cast::<__m256i>()) }
        }

        #[inline(always)]
        unsafe fn is_zero(self) -> bool {
            let cmp = unsafe { self.cmpeq(Self::splat(0)) };
            unsafe { _mm256_movemask_epi8(cmp).to_bits() == 0xFFFFFFFF }
        }

        #[inline(always)]
        unsafe fn cmpeq(self, vector2: Self) -> __m256i {
            unsafe { _mm256_cmpeq_epi8(self, vector2) }
        }

        #[inline(always)]
        unsafe fn and(self, vector2: Self) -> __m256i {
            unsafe { _mm256_and_si256(self, vector2) }
        }

        #[inline(always)]
        unsafe fn or(self, vector2: Self) -> __m256i {
            unsafe { _mm256_or_si256(self, vector2) }
        }

        #[inline(always)]
        unsafe fn shift_8bit_lane_right<const BITS: i32>(self) -> Self {
            let lomask = unsafe { Self::splat(0xF) };
            unsafe { _mm256_srli_epi16(self, BITS).and(lomask) }
        }

        #[inline(always)]
        unsafe fn shift_in_one_byte(self, vector2: Self) -> Self {
            // Credit goes to jneem for figuring this out:
            // https://github.com/jneem/teddy/blob/9ab5e899ad6ef6911aecd3cf1033f1abe6e1f66c/src/x86/teddy_simd.rs#L145-L184
            //
            // TL;DR avx2's PALIGNR instruction is actually just two 128-bit
            // PALIGNR instructions, which is not what we want, so we need to
            // do some extra shuffling.
            let v = unsafe { _mm256_permute2x128_si256(vector2, self, 0x21) };
            unsafe { _mm256_alignr_epi8(self, v, 15) }
        }

        #[inline(always)]
        unsafe fn shift_in_two_bytes(self, vector2: Self) -> Self {
            // Credit goes to jneem for figuring this out:
            // https://github.com/jneem/teddy/blob/9ab5e899ad6ef6911aecd3cf1033f1abe6e1f66c/src/x86/teddy_simd.rs#L145-L184
            //
            // TL;DR avx2's PALIGNR instruction is actually just two 128-bit
            // PALIGNR instructions, which is not what we want, so we need to
            // do some extra shuffling.
            let v = unsafe { _mm256_permute2x128_si256(vector2, self, 0x21) };
            unsafe { _mm256_alignr_epi8(self, v, 14) }
        }

        #[inline(always)]
        unsafe fn shift_in_three_bytes(self, vector2: Self) -> Self {
            // Credit goes to jneem for figuring this out:
            // https://github.com/jneem/teddy/blob/9ab5e899ad6ef6911aecd3cf1033f1abe6e1f66c/src/x86/teddy_simd.rs#L145-L184
            //
            // TL;DR avx2's PALIGNR instruction is actually just two 128-bit
            // PALIGNR instructions, which is not what we want, so we need to
            // do some extra shuffling.
            let v = unsafe { _mm256_permute2x128_si256(vector2, self, 0x21) };
            unsafe { _mm256_alignr_epi8(self, v, 13) }
        }

        #[inline(always)]
        unsafe fn shuffle_bytes(self, indices: Self) -> Self {
            unsafe { _mm256_shuffle_epi8(self, indices) }
        }

        #[inline(always)]
        unsafe fn for_each_64bit_lane<T>(
            self,
            mut f: impl FnMut(usize, u64) -> Option<T>,
        ) -> Option<T> {
            // NOTE: At one point in the past, I used transmute to this to
            // get a [u64; 4], but it turned out to lead to worse codegen IIRC.
            // I've tried it more recently, and it looks like that's no longer
            // the case. But since there's no difference, we stick with the
            // slightly more complicated but transmute-free version.
            let lane = unsafe { _mm256_extract_epi64(self, 0).to_bits() };
            if let Some(t) = f(0, lane) {
                return Some(t);
            }
            let lane = unsafe { _mm256_extract_epi64(self, 1).to_bits() };
            if let Some(t) = f(1, lane) {
                return Some(t);
            }
            let lane = unsafe { _mm256_extract_epi64(self, 2).to_bits() };
            if let Some(t) = f(2, lane) {
                return Some(t);
            }
            let lane = unsafe { _mm256_extract_epi64(self, 3).to_bits() };
            if let Some(t) = f(3, lane) {
                return Some(t);
            }
            None
        }
    }

    impl FatVector for __m256i {
        type Half = __m128i;

        #[inline(always)]
        unsafe fn load_half_unaligned(data: *const u8) -> Self {
            let half = unsafe { Self::Half::load_unaligned(data) };
            unsafe { _mm256_broadcastsi128_si256(half) }
        }

        #[inline(always)]
        unsafe fn half_shift_in_one_byte(self, vector2: Self) -> Self {
            unsafe { _mm256_alignr_epi8(self, vector2, 15) }
        }

        #[inline(always)]
        unsafe fn half_shift_in_two_bytes(self, vector2: Self) -> Self {
            unsafe { _mm256_alignr_epi8(self, vector2, 14) }
        }

        #[inline(always)]
        unsafe fn half_shift_in_three_bytes(self, vector2: Self) -> Self {
            unsafe { _mm256_alignr_epi8(self, vector2, 13) }
        }

        #[inline(always)]
        unsafe fn swap_halves(self) -> Self {
            unsafe { _mm256_permute4x64_epi64(self, 0x4E) }
        }

        #[inline(always)]
        unsafe fn interleave_low_8bit_lanes(self, vector2: Self) -> Self {
            unsafe { _mm256_unpacklo_epi8(self, vector2) }
        }

        #[inline(always)]
        unsafe fn interleave_high_8bit_lanes(self, vector2: Self) -> Self {
            unsafe { _mm256_unpackhi_epi8(self, vector2) }
        }

        #[inline(always)]
        unsafe fn for_each_low_64bit_lane<T>(
            self,
            vector2: Self,
            mut f: impl FnMut(usize, u64) -> Option<T>,
        ) -> Option<T> {
            let lane = unsafe { _mm256_extract_epi64(self, 0).to_bits() };
            if let Some(t) = f(0, lane) {
                return Some(t);
            }
            let lane = unsafe { _mm256_extract_epi64(self, 1).to_bits() };
            if let Some(t) = f(1, lane) {
                return Some(t);
            }
            let lane = unsafe { _mm256_extract_epi64(vector2, 0).to_bits() };
            if let Some(t) = f(2, lane) {
                return Some(t);
            }
            let lane = unsafe { _mm256_extract_epi64(vector2, 1).to_bits() };
            if let Some(t) = f(3, lane) {
                return Some(t);
            }
            None
        }
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little"
))]
mod aarch64_neon {
    use core::arch::aarch64::*;

    use super::Vector;

    impl Vector for uint8x16_t {
        const BITS: usize = 128;
        const BYTES: usize = 16;

        #[inline(always)]
        unsafe fn splat(byte: u8) -> uint8x16_t {
            unsafe { vdupq_n_u8(byte) }
        }

        #[inline(always)]
        unsafe fn load_unaligned(data: *const u8) -> uint8x16_t {
            unsafe { vld1q_u8(data) }
        }

        #[inline(always)]
        unsafe fn is_zero(self) -> bool {
            unsafe {
                // Could also use vmaxvq_u8.
                // ... I tried that and couldn't observe any meaningful difference
                // in benchmarks.
                let maxes = vreinterpretq_u64_u8(vpmaxq_u8(self, self));
                vgetq_lane_u64(maxes, 0) == 0
            }
        }

        #[inline(always)]
        unsafe fn cmpeq(self, vector2: Self) -> uint8x16_t {
            unsafe { vceqq_u8(self, vector2) }
        }

        #[inline(always)]
        unsafe fn and(self, vector2: Self) -> uint8x16_t {
            unsafe { vandq_u8(self, vector2) }
        }

        #[inline(always)]
        unsafe fn or(self, vector2: Self) -> uint8x16_t {
            unsafe { vorrq_u8(self, vector2) }
        }

        #[inline(always)]
        unsafe fn shift_8bit_lane_right<const BITS: i32>(self) -> Self {
            unsafe {
                debug_assert!(BITS <= 7);
                vshrq_n_u8(self, BITS)
            }
        }

        #[inline(always)]
        unsafe fn shift_in_one_byte(self, vector2: Self) -> Self {
            unsafe { vextq_u8(vector2, self, 15) }
        }

        #[inline(always)]
        unsafe fn shift_in_two_bytes(self, vector2: Self) -> Self {
            unsafe { vextq_u8(vector2, self, 14) }
        }

        #[inline(always)]
        unsafe fn shift_in_three_bytes(self, vector2: Self) -> Self {
            unsafe { vextq_u8(vector2, self, 13) }
        }

        #[inline(always)]
        unsafe fn shuffle_bytes(self, indices: Self) -> Self {
            unsafe { vqtbl1q_u8(self, indices) }
        }

        #[inline(always)]
        unsafe fn for_each_64bit_lane<T>(
            self,
            mut f: impl FnMut(usize, u64) -> Option<T>,
        ) -> Option<T> {
            unsafe {
                let this = vreinterpretq_u64_u8(self);
                let lane = vgetq_lane_u64(this, 0);
                if let Some(t) = f(0, lane) {
                    return Some(t);
                }
                let lane = vgetq_lane_u64(this, 1);
                if let Some(t) = f(1, lane) {
                    return Some(t);
                }
                None
            }
        }
    }
}
