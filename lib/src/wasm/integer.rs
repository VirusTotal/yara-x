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
