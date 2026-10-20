#![allow(rustdoc::private_intra_doc_links)]

use bstr::{BStr, BString, ByteSlice, Utf8Error};
use std::rc::Rc;

use crate::compiler::{LiteralId, LiteralSetId};
use crate::scanner::{
    RuntimeObject, RuntimeObjectHandle, ScanContext, ScanState,
};
use crate::utils::cast;

/// This trait is implemented by [RuntimeString], [FixedLenString], [Lowercase] and [Uppercase].
pub trait String: Default {
    /// Creates a new string.
    fn new<V: Into<Vec<u8>>>(s: V) -> Self;

    /// Returns this string as a primitive type suitable to be passed to WASM.
    fn into_wasm_with_ctx(self, ctx: &mut ScanContext) -> RuntimeStringWasm;

    /// Returns a new string from a byte slice.
    fn from_slice(ctx: &ScanContext, s: &[u8]) -> Self;
}

/// Represents a [`RuntimeString`] as a `i64` that can be passed from WASM to
/// host and vice versa.
///
/// The types that we can pass to (and receive from) WASM functions are only
/// primitive types (i64, i32, f64 and f32). In order to be able to pass a
/// [`RuntimeString`] to and from WASM, it must be represented as one of those
/// primitive types.
///
/// The `i64` value contains all the information required for uniquely
/// identifying the string. This is how the information is encoded:
///
/// * `RuntimeString:Literal` -> `LiteralId << 2 | 0`
///   If the two lower bits are equal to 0, it's a literal string, where the
///   remaining bits represent the `LiteralId`.
///
/// * `RuntimeString:Rc` -> `RuntimeObjectHandle | 1`
///   If the two lower bits are equal to 1, it's a reference-counted string,
///   where the handle is the pointer to the string object (which is aligned to
///   at least 4 bytes, so its 2 lower bits are 0).
///
/// * `RuntimeString:ScannedDataSlice` -> `Offset << 18 | Len << 2 | 2`
///   If the two lower bits are 2, it's a string backed by the scanned data.
///   Bits 17:2 are used for representing the string length (up to 64KB),
///   while bits 63:18 represent the offset (up to 70,368,744,177,663).
///
/// Tags are stored in the lower 2 bits rather than the higher bits because
/// heap pointers (`RuntimeObjectHandle`) in Rust are aligned to at least
/// 4-byte boundaries (meaning their two lower bits are guaranteed to be `00`).
/// Storing the tag in the lower bits via bitwise OR (`handle | 1`) preserves
/// all 64 bits of pointer addresses without bit-shifting. This avoids bit
/// truncation or sign-extension overflow issues across high 64-bit memory
/// address spaces (such as ASLR).
pub(crate) type RuntimeStringWasm = i64;

/// String types handled by YARA's WASM runtime.
///
/// At runtime, when the WASM code generated for rule conditions is
/// being executed, text strings can adopt multiple forms. The difference
/// between them resides in the place in which the string's data is stored.
///
/// For example, literal strings appearing in the source code are stored in
/// a string pool created at compile time, these strings are identified by the
/// [`LiteralId`] returned by the pool. Instead of making copies of those
/// literal strings, the runtime passes the [`LiteralId`] around when referring
/// to them.
///
/// Similarly, functions exported by YARA modules can return strings that
/// appear verbatim in the data being scanned. Instead of making a copy, the
/// runtime passes around only the offset within the data where the string
/// starts, and its length.
///
/// In some other cases a function may need to return a string that doesn't
/// appear neither in the scanned data nor as a literal in the source code,
/// in such cases the runtime stores the string in a hash map maintained by
/// [`ScanContext`], and passes around only the handle that allows locating
/// the string in that map.
#[derive(Debug, PartialEq)]
pub enum RuntimeString {
    /// A literal string appearing in the source code. The string is identified
    /// by its [`LiteralId`] within the literal strings pool.
    Literal(LiteralId),
    /// A string found in the scanned data, represented by the offset within
    /// the data and its length.
    ScannedDataSlice {
        /// String's offset in the scanned data.
        offset: usize,
        /// String's length.
        length: usize,
    },
    /// A reference-counted string.
    Rc(Rc<BString>),
}

impl Default for RuntimeString {
    fn default() -> Self {
        Self::ScannedDataSlice { offset: 0, length: 0 }
    }
}

impl String for RuntimeString {
    /// Creates a [`RuntimeString`] from a [`String`], a [`Vec<u8>`] or any
    /// type that implements [`Into<Vec<u8>>`]
    fn new<S: Into<Vec<u8>>>(s: S) -> Self {
        Self::Rc(Rc::new(BString::new(s.into())))
    }

    /// Returns this string as a primitive type suitable to be passed to WASM.
    fn into_wasm_with_ctx(self, ctx: &mut ScanContext) -> RuntimeStringWasm {
        match self {
            Self::Literal(id) => i64::from(id) << 2,
            Self::Rc(s) => {
                let handle: i64 = ctx.store_string(s).into();
                handle | 1
            }
            Self::ScannedDataSlice { offset, length } => {
                if length >= u16::MAX as usize {
                    panic!(
                        "runtime-string slices can't be larger than {}",
                        u16::MAX
                    )
                }
                ((offset as i64) << 18) | ((length as i64) << 2) | 2
            }
        }
    }

    /// Creates a [`RuntimeString`] from a reference to a byte slice.
    ///
    /// If the original slice is contained within the scanned data, this
    /// function returns the [`RuntimeString::ScannedDataSlice`] variant, which
    /// doesn't need to copy the string data.
    ///
    /// In any other case it makes a copy of the string and return the
    /// [`RuntimeString::Rc`] variant.
    fn from_slice(ctx: &ScanContext, s: &[u8]) -> Self {
        if let ScanState::ScanningData(data) = &ctx.scan_state {
            let data = data.as_ref();
            let data_start = data.as_ptr() as usize;
            let data_end = data_start + data.len();

            let s_start = s.as_ptr() as usize;
            let s_end = s_start + s.len();

            if s_start >= data_start && s_end <= data_end {
                return Self::ScannedDataSlice {
                    offset: s_start - data_start,
                    length: s.len(),
                };
            }
        }

        Self::Rc(Rc::new(BString::from(s)))
    }
}

impl RuntimeString {
    /// Returns this string as a &[`BStr`].
    pub fn as_bstr<'a>(&'a self, ctx: &'a ScanContext) -> &'a BStr {
        match self {
            Self::Literal(id) => {
                ctx.compiled_rules.literal_pool().get(*id).unwrap()
            }
            Self::ScannedDataSlice { offset, length } => {
                let data = ctx.scanned_data().unwrap();
                BStr::new(&data[*offset..*offset + *length])
            }
            Self::Rc(s) => s.as_bstr(),
        }
    }

    /// Safely converts this string to a `&str` if it's valid UTF-8.
    ///
    /// If the string is not valid UTF-8, then an error is returned.
    #[inline]
    pub fn to_str<'a>(
        &'a self,
        ctx: &'a ScanContext,
    ) -> Result<&'a str, Utf8Error> {
        self.as_bstr(ctx).to_str()
    }

    /// Returns this string as a primitive type suitable to be passed to WASM.
    pub(crate) fn into_wasm(self) -> RuntimeStringWasm {
        match self {
            Self::Literal(id) => i64::from(id) << 2,
            _ => unreachable!(),
        }
    }

    /// Creates a [`RuntimeString`] from a [`RuntimeStringWasm`].
    pub(crate) fn from_wasm(
        ctx: &mut ScanContext,
        s: RuntimeStringWasm,
    ) -> Self {
        match s & 0x3 {
            0 => Self::Literal(LiteralId::from((s >> 2) as u32)),
            1 => {
                let handle = RuntimeObjectHandle::from(s & !3);
                let s = cast!(
                    ctx.runtime_objects.get(&handle).unwrap(),
                    RuntimeObject::String
                );
                Self::Rc(s.clone())
            }
            2 => Self::ScannedDataSlice {
                offset: (s >> 18) as usize,
                length: ((s >> 2) & 0xffff) as usize,
            },
            _ => unreachable!(),
        }
    }

    #[inline]
    pub(crate) fn len(&self, ctx: &ScanContext) -> usize {
        self.as_bstr(ctx).len()
    }

    #[inline]
    pub(crate) fn eq(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).eq(other.as_bstr(ctx))
    }

    #[inline]
    pub(crate) fn ne(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).ne(other.as_bstr(ctx))
    }

    #[inline]
    pub(crate) fn lt(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).lt(other.as_bstr(ctx))
    }

    #[inline]
    pub(crate) fn gt(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).gt(other.as_bstr(ctx))
    }

    #[inline]
    pub(crate) fn le(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).le(other.as_bstr(ctx))
    }

    #[inline]
    pub(crate) fn ge(&self, other: &Self, ctx: &ScanContext) -> bool {
        self.as_bstr(ctx).ge(other.as_bstr(ctx))
    }

    #[inline]
    pub(crate) fn contains(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let other = other.as_bstr(ctx);

        if case_insensitive {
            contains_case_insensitive(this.as_bytes(), other.as_bytes())
        } else {
            this.contains_str(other)
        }
    }

    #[inline]
    pub(crate) fn starts_with(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let other = other.as_bstr(ctx);

        if case_insensitive {
            starts_with_case_insensitive(this.as_bytes(), other.as_bytes())
        } else {
            this.starts_with_str(other)
        }
    }

    #[inline]
    pub(crate) fn ends_with(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let other = other.as_bstr(ctx);

        if case_insensitive {
            ends_with_case_insensitive(this.as_bytes(), other.as_bytes())
        } else {
            this.ends_with_str(other)
        }
    }

    #[inline]
    pub(crate) fn equals(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let other = other.as_bstr(ctx);

        if case_insensitive {
            equals_case_insensitive(this.as_bytes(), other.as_bytes())
        } else {
            this.eq(other)
        }
    }

    #[inline]
    pub(crate) fn contains_many(
        &self,
        literal_set: LiteralSetId,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let literal_pool = ctx.compiled_rules.literal_pool();
        let literals = ctx.compiled_rules.get_literal_set(literal_set);

        if case_insensitive {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                contains_case_insensitive(this.as_bytes(), other.as_bytes())
            })
        } else {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                this.contains_str(other)
            })
        }
    }

    #[inline]
    pub(crate) fn starts_with_many(
        &self,
        literal_set: LiteralSetId,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let literal_pool = ctx.compiled_rules.literal_pool();
        let literals = ctx.compiled_rules.get_literal_set(literal_set);

        if case_insensitive {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                starts_with_case_insensitive(this.as_bytes(), other.as_bytes())
            })
        } else {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                this.starts_with_str(other)
            })
        }
    }

    #[inline]
    pub(crate) fn ends_with_many(
        &self,
        literal_set: LiteralSetId,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let literal_pool = ctx.compiled_rules.literal_pool();
        let literals = ctx.compiled_rules.get_literal_set(literal_set);

        if case_insensitive {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                ends_with_case_insensitive(this.as_bytes(), other.as_bytes())
            })
        } else {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                this.ends_with_str(other)
            })
        }
    }

    #[inline]
    pub(crate) fn equals_many(
        &self,
        literal_set: LiteralSetId,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        let this = self.as_bstr(ctx);
        let literal_pool = ctx.compiled_rules.literal_pool();
        let literals = ctx.compiled_rules.get_literal_set(literal_set);

        if case_insensitive {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                equals_case_insensitive(this.as_bytes(), other.as_bytes())
            })
        } else {
            literals.iter().any(|&lit_id| {
                let other = literal_pool.get(lit_id).unwrap();
                this.eq(other)
            })
        }
    }
}

/// Zero-allocation iterator over the lowercased characters (and raw invalid
/// UTF-8 bytes) of a byte slice.
#[derive(Clone)]
struct LowercaseChars<'a> {
    bytes: &'a [u8],
    pending: Option<std::char::ToLowercase>,
}

impl<'a> LowercaseChars<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pending: None }
    }
}

impl Iterator for LowercaseChars<'_> {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref mut lower) = self.pending {
            if let Some(c) = lower.next() {
                return Some(c as u32);
            }
            self.pending = None;
        }

        let (&first_byte, rest) = self.bytes.split_first()?;

        if first_byte.is_ascii() {
            self.bytes = rest;
            return Some(first_byte.to_ascii_lowercase() as u32);
        }

        let (ch, size) = bstr::decode_utf8(self.bytes);
        if let Some(ch) = ch {
            self.bytes = &self.bytes[size..];
            let mut lower = ch.to_lowercase();
            let first = lower.next()? as u32;
            if lower.len() > 0 {
                self.pending = Some(lower);
            }
            Some(first)
        } else {
            self.bytes = rest;
            Some(u32::from(first_byte) | 0x8000_0000)
        }
    }
}

/// Zero-allocation reverse iterator over the lowercased characters (and raw
/// invalid UTF-8 bytes) of a byte slice.
struct LowercaseCharsRev<'a> {
    bytes: &'a [u8],
    pending: Option<std::char::ToLowercase>,
}

impl<'a> LowercaseCharsRev<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pending: None }
    }
}

impl Iterator for LowercaseCharsRev<'_> {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref mut lower) = self.pending {
            if let Some(c) = lower.next_back() {
                return Some(c as u32);
            }
            self.pending = None;
        }

        let (&last_byte, rest) = self.bytes.split_last()?;

        if last_byte.is_ascii() {
            self.bytes = rest;
            return Some(last_byte.to_ascii_lowercase() as u32);
        }

        let (ch, size) = bstr::decode_last_utf8(self.bytes);
        if let Some(ch) = ch {
            self.bytes = &self.bytes[..self.bytes.len() - size];
            let mut lower = ch.to_lowercase();
            let last = lower.next_back()? as u32;
            if lower.len() > 0 {
                self.pending = Some(lower);
            }
            Some(last)
        } else {
            self.bytes = rest;
            Some(u32::from(last_byte) | 0x8000_0000)
        }
    }
}

/// Returns the index of the first pair of bytes produced by `a` and `b` that
/// are not equal when ignoring ASCII case, or `None` if all pairs are equal.
///
/// Pairs containing a non-ASCII byte are never considered equal, so all the
/// bytes before the returned index are ASCII in both inputs, which means
/// that the index is a character boundary in both.
#[inline]
fn ascii_case_insensitive_mismatch<'a>(
    a: impl Iterator<Item = &'a u8>,
    b: impl Iterator<Item = &'a u8>,
) -> Option<usize> {
    a.zip(b).position(|(x, y)| !(x.is_ascii() && x.eq_ignore_ascii_case(y)))
}

/// Case-insensitive `contains`.
#[inline]
fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    // The fast path requires both strings to be ASCII, because some non-ASCII
    // characters are lowercased to ASCII (e.g. U+212A KELVIN SIGN -> 'k').
    if haystack.is_ascii() && needle.is_ascii() {
        contains_ascii_case_insensitive(haystack, needle)
    } else {
        contains_unicode_case_insensitive(haystack, needle)
    }
}

/// Case-insensitive `contains` for strings that are both ASCII.
#[inline]
fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }

    if needle.len() > haystack.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Case-insensitive `contains` for arbitrary strings.
#[cold]
#[inline(never)]
fn contains_unicode_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    // Try every position in the lowercased haystack, including positions in
    // the middle of characters that are lowercased to multiple characters
    // (e.g. 'İ' -> "i\u{307}").
    let mut h = LowercaseChars::new(haystack);
    loop {
        let mut candidate = h.clone();
        if LowercaseChars::new(needle).all(|c| candidate.next() == Some(c)) {
            return true;
        }
        if h.next().is_none() {
            return false;
        }
    }
}

/// Case-insensitive `startswith`.
///
/// Bytes are compared ignoring ASCII case up to the first pair of bytes that
/// don't match. If both bytes are ASCII the result is `false`. Otherwise, the
/// rest of the strings are compared using full Unicode lowercasing, because
/// lowercasing a non-ASCII character can change its length in bytes, or even
/// produce an ASCII character (e.g. U+212A KELVIN SIGN -> 'k').
#[inline]
fn starts_with_case_insensitive(haystack: &[u8], prefix: &[u8]) -> bool {
    let Some(i) =
        ascii_case_insensitive_mismatch(haystack.iter(), prefix.iter())
    else {
        // All compared bytes matched; fails only if the haystack ran out.
        return haystack.len() >= prefix.len();
    };
    if haystack[i].is_ascii() && prefix[i].is_ascii() {
        return false;
    }
    starts_with_unicode_case_insensitive(&haystack[i..], &prefix[i..])
}

#[cold]
#[inline(never)]
fn starts_with_unicode_case_insensitive(
    haystack: &[u8],
    prefix: &[u8],
) -> bool {
    let mut h = LowercaseChars::new(haystack);
    LowercaseChars::new(prefix).all(|c| h.next() == Some(c))
}

/// Case-insensitive `endswith`. Works like [`starts_with_case_insensitive`],
/// but comparing the strings from the end.
#[inline]
fn ends_with_case_insensitive(haystack: &[u8], suffix: &[u8]) -> bool {
    let Some(i) = ascii_case_insensitive_mismatch(
        haystack.iter().rev(),
        suffix.iter().rev(),
    ) else {
        // All compared bytes matched; fails only if the haystack ran out.
        return haystack.len() >= suffix.len();
    };
    // The last `i` bytes of both strings matched, the mismatching bytes are
    // the ones right before them.
    let (h_end, s_end) = (haystack.len() - i, suffix.len() - i);
    if haystack[h_end - 1].is_ascii() && suffix[s_end - 1].is_ascii() {
        return false;
    }
    ends_with_unicode_case_insensitive(&haystack[..h_end], &suffix[..s_end])
}

#[cold]
#[inline(never)]
fn ends_with_unicode_case_insensitive(haystack: &[u8], suffix: &[u8]) -> bool {
    let mut h = LowercaseCharsRev::new(haystack);
    LowercaseCharsRev::new(suffix).all(|c| h.next() == Some(c))
}

/// Case-insensitive equality. Works like [`starts_with_case_insensitive`].
#[inline]
fn equals_case_insensitive(a: &[u8], b: &[u8]) -> bool {
    let Some(i) = ascii_case_insensitive_mismatch(a.iter(), b.iter()) else {
        // All compared bytes matched; equal only if no bytes are left.
        return a.len() == b.len();
    };
    if a[i].is_ascii() && b[i].is_ascii() {
        return false;
    }
    equals_unicode_case_insensitive(&a[i..], &b[i..])
}

#[cold]
#[inline(never)]
fn equals_unicode_case_insensitive(a: &[u8], b: &[u8]) -> bool {
    LowercaseChars::new(a).eq(LowercaseChars::new(b))
}

/// Special kind of [RuntimeString] that has a fixed length.
///
/// The specified length is in bytes, not characters.
///
/// Trying to create a [FixedLenString] with some length that is not the one
/// specified by the `LEN` parameter will cause a panic.
#[derive(Debug, Default)]
pub struct FixedLenString<const LEN: usize>(RuntimeString);

impl<const LEN: usize> String for FixedLenString<LEN> {
    fn new<S: Into<Vec<u8>>>(s: S) -> Self {
        let s = s.into();
        assert_eq!(
            s.len(),
            LEN,
            "FixedLenString<{}>::new called with invalid length: {}",
            LEN,
            s.len(),
        );
        Self(RuntimeString::new(s))
    }

    /// Returns this string as a primitive type suitable to be passed to WASM.
    fn into_wasm_with_ctx(self, ctx: &mut ScanContext) -> RuntimeStringWasm {
        self.0.into_wasm_with_ctx(ctx)
    }

    fn from_slice(ctx: &ScanContext, s: &[u8]) -> Self {
        assert_eq!(
            s.len(),
            LEN,
            "FixedLenString<{}>::new called with invalid length: {}",
            LEN,
            s.len(),
        );
        Self(RuntimeString::from_slice(ctx, s))
    }
}

/// Represents a string that is always lowercase.
#[derive(Debug, Default)]
pub struct Lowercase<S: String>(S);

impl<S: String> String for Lowercase<S> {
    fn new<V: Into<Vec<u8>>>(s: V) -> Self {
        Self(S::new(s))
    }

    fn into_wasm_with_ctx(self, ctx: &mut ScanContext) -> RuntimeStringWasm {
        self.0.into_wasm_with_ctx(ctx)
    }

    fn from_slice(ctx: &ScanContext, s: &[u8]) -> Self {
        Self(S::from_slice(ctx, s))
    }
}

/// Represents a string that is always uppercase.
#[derive(Debug, Default)]
pub struct Uppercase<S: String>(S);

impl<S: String> String for Uppercase<S> {
    fn new<V: Into<Vec<u8>>>(s: V) -> Self {
        Self(S::new(s))
    }

    fn into_wasm_with_ctx(self, ctx: &mut ScanContext) -> RuntimeStringWasm {
        self.0.into_wasm_with_ctx(ctx)
    }

    fn from_slice(ctx: &ScanContext, s: &[u8]) -> Self {
        Self(S::from_slice(ctx, s))
    }
}

#[cfg(test)]
mod tests {
    use bstr::ByteSlice;

    use super::{
        contains_case_insensitive, ends_with_case_insensitive,
        equals_case_insensitive, starts_with_case_insensitive,
    };

    /// Pairs of strings used for checking the case-insensitive functions
    /// against a reference implementation that lowercases both strings with
    /// [`ByteSlice::to_lowercase`] and then compares the results.
    const CASES: &[(&[u8], &[u8])] = &[
        (b"", b""),
        (b"foo", b""),
        (b"foobar", b"FOO"),
        (b"foobar", b"BAR"),
        (b"foobar", b"OBA"),
        (b"foobar", b"baz"),
        (b"fo", b"FOO"),
        ("mañana".as_bytes(), "MAÑ".as_bytes()),
        ("mañana".as_bytes(), b"MAN"),
        ("CAFÉ".as_bytes(), "fé".as_bytes()),
        // U+212A KELVIN SIGN is lowercased to 'k'.
        ("\u{212A}elvin".as_bytes(), b"KEL"),
        ("\u{212A}".as_bytes(), b"k"),
        ("ABC\u{212A}".as_bytes(), b"k"),
        ("x\u{212A}x".as_bytes(), b"k"),
        // 'İ' is lowercased to "i\u{307}".
        ("İstanbul".as_bytes(), b"i"),
        ("İ".as_bytes(), "\u{307}".as_bytes()),
        // 'Ⱥ' (2 bytes) is lowercased to 'ⱥ' (3 bytes).
        ("Ⱥ".as_bytes(), "ⱥ".as_bytes()),
        // 'Ɐ' (3 bytes) is lowercased to 'ɐ' (2 bytes).
        ("Ɐ".as_bytes(), "ɐ".as_bytes()),
        // Invalid UTF-8.
        (b"\xFFFOO\xFF", b"\xFFfoo\xFF"),
    ];

    #[test]
    fn case_insensitive_ops() {
        for &(x, y) in CASES {
            for (a, b) in [(x, y), (y, x)] {
                let (a_lower, b_lower) = (a.to_lowercase(), b.to_lowercase());
                let (a, b) = (a.as_bstr(), b.as_bstr());
                assert_eq!(
                    starts_with_case_insensitive(a, b),
                    a_lower.starts_with_str(&b_lower),
                    "{a:?} istartswith {b:?}"
                );
                assert_eq!(
                    ends_with_case_insensitive(a, b),
                    a_lower.ends_with_str(&b_lower),
                    "{a:?} iendswith {b:?}"
                );
                assert_eq!(
                    equals_case_insensitive(a, b),
                    a_lower == b_lower,
                    "{a:?} iequals {b:?}"
                );
                assert_eq!(
                    contains_case_insensitive(a, b),
                    a_lower.contains_str(&b_lower),
                    "{a:?} icontains {b:?}"
                );
            }
        }
    }
}
