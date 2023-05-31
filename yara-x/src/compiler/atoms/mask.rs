/// Iterator that given a byte and a mask, produces a sequence of bytes with
/// all the possible combinations of the bits that are masked out.
///
/// For example, if the byte is 0, and the mask is 11101110, the following
/// bytes are produced:
///
///   00000000
///   00000001
///   00010000
///   00010001
///
/// The iterator is guaranteed to return at least the original byte.
#[derive(Clone)]
pub struct ByteMaskCombinator {
    byte: u8,
    mask: u8,
    i: u8,
    done: bool,
}

impl ByteMaskCombinator {
    pub fn new(byte: u8, mask: u8) -> Self {
        Self { byte, mask, i: 0, done: false }
    }
}

impl Iterator for ByteMaskCombinator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let next = (self.byte & self.mask) | (self.i & !self.mask);

        // self.i starts at 0, and on each iteration it is ORed with the mask
        // and incremented by one. With this trick we make sure that on each
        // increment the carry will be applied to some of the masked out bits
        // and therefore they will behave as if they were adjacent bits.
        //
        // For example if mask is 0b1110_1110 and the initial value of i is
        // zero, on each iteration the value of i changes like:
        //
        //  1)  (0           | 0b1110_1110) + 1  = 0b1110_1111
        //  2)  (0b1110_1111 | 0b1110_1110) + 1  = 0b1111_0000
        //  3)  (0b1111_0000 | 0b1110_1110) + 1  = 0b1111_1111
        //  4)  (0b1111_1111 | 0b1110_1110) + 1  -> overflow
        //
        (self.i, self.done) = (self.i | self.mask).overflowing_add(1);

        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::atoms::mask::ByteMaskCombinator;
    use pretty_assertions::assert_eq;

    #[test]
    fn mask_combinator() {
        // No masked-out bits, only return the original byte.
        let mut c = ByteMaskCombinator::new(0xaa, 0xff);
        assert_eq!(c.next(), Some(0xaa));
        assert_eq!(c.next(), None);

        // A single bit is masked out, it must return two bytes, one where the
        // masked bit is 0 and another one where it is 1.
        let mut c = ByteMaskCombinator::new(0b1000_0000, 0b1111_1110);
        assert_eq!(c.next(), Some(0b1000_0000u8));
        assert_eq!(c.next(), Some(0b1000_0001u8));
        assert_eq!(c.next(), None);

        // Three bits are masked out, there are 8 combinations for those bits.
        let mut c = ByteMaskCombinator::new(0b1101_1010, 0b1101_1010);
        assert_eq!(c.next(), Some(0b1101_1010u8));
        assert_eq!(c.next(), Some(0b1101_1011u8));
        assert_eq!(c.next(), Some(0b1101_1110u8));
        assert_eq!(c.next(), Some(0b1101_1111u8));
        assert_eq!(c.next(), Some(0b1111_1010u8));
        assert_eq!(c.next(), Some(0b1111_1011u8));
        assert_eq!(c.next(), Some(0b1111_1110u8));
        assert_eq!(c.next(), Some(0b1111_1111u8));
        assert_eq!(c.next(), None);

        let mut c = ByteMaskCombinator::new(0xcc, 0x00);
        for i in 0..=0xff {
            assert_eq!(c.next(), Some(i));
        }
        assert_eq!(c.next(), None);

        let mut c = ByteMaskCombinator::new(0x33, 0xf0);
        for i in 0x30..=0x3f {
            assert_eq!(c.next(), Some(i));
        }
        assert_eq!(c.next(), None);
    }
}
