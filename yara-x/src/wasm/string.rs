use bstr::{BStr, ByteSlice};

use crate::{LiteralId, RuntimeStringId, ScanContext};

/// Represents a [`RuntimeString`] as a `i64` that can be passed from WASM to
/// host and vice-versa.
///
/// The types that we can pass to (and receive from) WASM functions are only
/// primitive types (i64, i32, f64 and f32). In order to be able to pass a
/// [`RuntimeString`] to and from WASM, it must be represented as one of those
/// primitive types.
///
/// The `u64` value contains all the information required for uniquely
/// identifying the string. This is how the information is encoded:
///
/// * `RuntimeString:Undef`  -> `0`
///    A zero represents an undefined string.
///
/// * `RuntimeString:Literal`  -> `LiteralId << 2 | 1`
///    If the two lower bits are equal to 1, it's a literal string, where the
///    remaining bits represent the `LiteralId`.
///
/// * `RuntimeString:Owned`  -> `RuntimeStringId << 2 | 2`
///    If the two lower bits are equal to 2, it's a runtime string, where the
///    remaining bits represent the `RuntimeStringId`.
///
/// * `RuntimeString:Owned`  -> `Offset << 18 | Len << 2 | 3)`
///    If the two lower bits are 3, it's a string backed by the scanned data.
///    Bits 18:3 ar used for representing the string length (up to 64KB),
///    while bits 64:19 represents the offset (up to 70,368,744,177,663).
///
pub(crate) type RuntimeStringWasm = i64;

/// String types handled by YARA's WASM runtime.
///
/// At runtime, when the the WASM code generated for rule conditions is
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
/// in such cases the runtime stores the string a pool maintained by
/// [`ScanContext`], and passes around only the ID that allows locating the
/// string in that pool.
#[derive(Debug, PartialEq)]
pub(crate) enum RuntimeString {
    /// An undefined string.
    Undef,
    /// A literal string appearing in the source code. The string is identified
    /// by its [`LiteralId`] within the literal strings pool.
    Literal(LiteralId),
    /// A string represented found in the scanned data, represented by the
    /// offset within the data and its length.
    Slice { offset: usize, length: usize },
    /// A string owned by the runtime. The string is identified by its
    /// [`RuntimeStringId`] within the string pool stored in [`ScanContext`].
    Owned(RuntimeStringId),
}

impl RuntimeString {
    /// Returns this string as a &[`BStr`].
    pub(crate) fn as_bstr<'a>(&'a self, ctx: &'a ScanContext) -> &'a BStr {
        match self {
            RuntimeString::Undef => {
                panic!("as_bstr() called for RuntimeString::Undef")
            }
            RuntimeString::Literal(id) => {
                ctx.compiled_rules.lit_pool().get(*id).unwrap()
            }
            RuntimeString::Slice { offset, length } => {
                let data = ctx.scanned_data();
                BStr::new(&data[*offset..*offset + *length])
            }
            RuntimeString::Owned(id) => ctx.string_pool.get(*id).unwrap(),
        }
    }

    /// Returns this string as a tuple of primitive types suitable to be
    /// passed to WASM.
    pub(crate) fn as_wasm(&self) -> RuntimeStringWasm {
        match self {
            // Undefined strings are represented as 0.
            RuntimeString::Undef => 0,
            // Literal strings are represented as (1, LiteralId)
            RuntimeString::Literal(id) => i64::from(*id) << 2 | 1,
            // Owned strings are represented as (2, RuntimeStringId)
            RuntimeString::Owned(id) => (*id as i64) << 2 | 2,
            // Slices are represented as (length << 32 | 1, offset). This
            // implies that slice length is limited to 4GB, as it must fit
            // in the upper 32-bits of the first item in the tuple.
            RuntimeString::Slice { offset, length } => {
                if *length >= u16::MAX as usize {
                    panic!(
                        "runtime-string slices can't be larger than {}",
                        u16::MAX
                    )
                }
                (*offset as i64) << 18 | (*length as i64) << 2 | 3
            }
        }
    }

    /// Creates a [`RuntimeString`] from a [`RuntimeStringWasm`].
    pub(crate) fn from_wasm(s: RuntimeStringWasm) -> Self {
        match s & 0x3 {
            0 => Self::Undef,
            1 => Self::Literal(LiteralId::from((s >> 2) as u32)),
            2 => Self::Owned((s >> 2) as u32),
            3 => Self::Slice {
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
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.contains_str(other)
        } else {
            self.as_bstr(ctx).contains_str(other.as_bstr(ctx))
        }
    }

    #[inline]
    pub(crate) fn starts_with(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.starts_with_str(other)
        } else {
            self.as_bstr(ctx).starts_with_str(other.as_bstr(ctx))
        }
    }

    #[inline]
    pub(crate) fn ends_with(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.ends_with_str(other)
        } else {
            self.as_bstr(ctx).ends_with_str(other.as_bstr(ctx))
        }
    }

    #[inline]
    pub(crate) fn equals(
        &self,
        other: &Self,
        ctx: &ScanContext,
        case_insensitive: bool,
    ) -> bool {
        if case_insensitive {
            let this = self.as_bstr(ctx).to_lowercase();
            let other = other.as_bstr(ctx).to_lowercase();
            this.eq(&other)
        } else {
            self.as_bstr(ctx).eq(other.as_bstr(ctx))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeString;
    use crate::compiler::LiteralId;
    use pretty_assertions::assert_eq;

    #[test]
    fn runtime_string_wasm_conversion() {
        let s = RuntimeString::Literal(LiteralId::from(1));
        assert_eq!(s, RuntimeString::from_wasm(s.as_wasm()));

        let s = RuntimeString::Slice { length: 100, offset: 0x1000000 };
        assert_eq!(s, RuntimeString::from_wasm(s.as_wasm()));
    }

    #[test]
    #[should_panic]
    fn runtime_string_wasm_max_size() {
        let s = RuntimeString::Slice {
            length: u32::MAX as usize + 1,
            offset: 0x1000000,
        };
        assert_eq!(s, RuntimeString::from_wasm(s.as_wasm()));
    }
}
