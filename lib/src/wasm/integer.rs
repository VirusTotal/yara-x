/// A wrapper type around `i64` representing an integer guaranteed to be within
/// the range [MIN, MAX] (inclusive).
///
/// This type conveys additional range information, which can be useful for
/// functions that return constrained integer values. For example, the `uint8`
/// function returns `RangedInteger<0, 255>`, indicating the result will always
/// fall within the `[0, 255]` range.
///
/// This range metadata is used to set a [crate::types::IntegerConstraint] on
/// the function's return value.
#[derive(Default)]
pub(crate) struct RangedInteger<const MIN: i64, const MAX: i64>(i64);

impl<const MIN: i64, const MAX: i64> RangedInteger<MIN, MAX> {
    #[inline]
    pub fn new(value: i64) -> Self {
        assert!(value >= MIN && value <= MAX);
        Self(value)
    }

    #[inline]
    pub fn value(self) -> i64 {
        self.0
    }
}
