use std::iter;

use bitvec::bitarr;

/// Compute the quality of a masked atom.
///
/// Each byte in the atom contributes a certain amount of points to the   
/// quality. Bytes [a-zA-Z] contribute 18 points each, common bytes like
/// 0x00, 0x20 and 0xFF contribute only 12 points, and the rest of the
/// bytes contribute 20 points. Masked bytes adds 2 points for each
/// non-masked bit, and subtracts 1 point for each masked bit. So, the
/// ?? mask subtracts 8 points, and masks X? and ?X contributes 4 points.
///
/// An additional boost consisting in 2x the number of unique bytes in
/// the atom is added to the quality. This are some examples of the
/// quality of atoms:
///
///   01 0? 03      quality = 20 +  4 + 20      + 4 = 48
///   01 02         quality = 20 + 20           + 4 = 44
///   01 ?? ?3 04   quality = 20 -  8 +  4 + 20 + 4 = 36
///   61 62         quality = 18 + 18           + 4 = 40
///   61 61         quality = 18 + 18           + 2 = 38
///   00 01         quality = 12 + 20           + 4 = 36
///   01 ?? 03      quality = 20 -  8 + 20      + 4 = 36
///   01            quality = 20                + 1 = 21
///
pub fn masked_atom_quality<'a, B, M>(bytes: B, masks: M) -> i32
where
    B: IntoIterator<Item = &'a u8>,
    M: IntoIterator<Item = &'a u8>,
{
    let mut q: i32 = 0;

    // Create a bit array with 256 bits, where all bits are initially 0.
    // Bit N is set to 1 (true) if the atom contains the non-masked byte N.
    let mut bytes_present = bitarr![0; 256];

    let bytes = bytes.into_iter();
    let masks = masks.into_iter();

    let mut atom_len = 0;

    for (byte, mask) in bytes.zip(masks) {
        // If there's any masked bit, the quality is incremented by
        // N * 2 - M, where N is the number of non-masked bits and M is
        // the number of masked bits. For ?? the increment is -8, while
        // ?X and X? results in a +4 increment.
        if mask.count_zeros() > 0 {
            q += 2 * mask.count_ones() as i32 - mask.count_zeros() as i32;
        }
        // For non-masked bytes the increment depends on the byte value.
        // Common values like 0x00, 0xff, 0xcc (opcode using of function
        // padding in PE files), 0x20 (whitespace) the increment is a bit
        // lower than for other bytes.
        else {
            bytes_present.set(*byte as usize, true);

            match *byte {
                // Common values contribute less to the quality than the
                // rest of values.
                0x00 | 0x20 | 0x90 | 0xcc | 0xff => {
                    q += 12;
                }
                // Bytes in the ASCII ranges a-z and A-Z have a slightly
                // lower quality than the rest. We want to favor atoms that
                // don't contain too many letters, as they generate less
                // additional atoms when the `nocase` modifier is used in
                // the pattern.
                b'a'..=b'z' | b'A'..=b'Z' => {
                    q += 18;
                }
                // General case.
                _ => {
                    q += 20;
                }
            }
        }
        atom_len += 1;
    }

    // The number of unique bytes is the number of ones in bytes_present.
    let unique_bytes = bytes_present.count_ones();

    // If all the bytes in the atom are equal and very common, let's
    // penalize it heavily.
    if unique_bytes == 1 {
        // As the number of unique bytes is 1, the first one in
        // bytes_present corresponds to that unique byte.
        match bytes_present.first_one().unwrap() {
            0x00 | 0x20 | 0x90 | 0xcc | 0xff => {
                q -= 10 * atom_len;
            }
            _ => {
                q += 2;
            }
        }
    }
    // In general, atoms with more unique bytes have better quality,
    // let's boost the quality proportionally to the number of unique bytes.
    else {
        q += 2 * unique_bytes as i32;
    }

    q
}

/// Compute the quality of an atom.
pub fn atom_quality<'a, B>(bytes: B) -> i32
where
    B: IntoIterator<Item = &'a u8>,
{
    masked_atom_quality(bytes, iter::repeat(&0xFF))
}

#[cfg(test)]
mod test {
    use crate::compiler::atoms::quality::{atom_quality, masked_atom_quality};

    #[rustfmt::skip]
    #[allow(non_snake_case)]
    #[test]
    fn test_atom_quality() {
        let q_01       = atom_quality(&[0x01]);
        let q_0001     = atom_quality(&[0x00, 0x01]);
        let q_000001   = atom_quality(&[0x00, 0x00, 0x01]);
        let q_0102     = atom_quality(&[0x01, 0x02]);
        let q_000102   = atom_quality(&[0x00, 0x01, 0x02]);
        let q_010203   = atom_quality(&[0x01, 0x02, 0x03]);
        let q_00000000 = atom_quality(&[0x00, 0x00, 0x00, 0x00]);
        let q_00000001 = atom_quality(&[0x00, 0x00, 0x00, 0x01]);
        let q_00000102 = atom_quality(&[0x00, 0x00, 0x01, 0x02]);
        let q_00010203 = atom_quality(&[0x00, 0x01, 0x02, 0x03]);
        let q_01020304 = atom_quality(&[0x01, 0x02, 0x03, 0x04]);
        let q_01010101 = atom_quality(&[0x01, 0x01, 0x01, 0x01]);
        let q_01020102 = atom_quality(&[0x01, 0x02, 0x01, 0x02]);
        let q_01020000 = atom_quality(&[0x01, 0x02, 0x00, 0x00]);
        let q_ffffffff = atom_quality(&[0xff, 0xff, 0xff, 0xff]);
        let q_cccccccc = atom_quality(&[0xcc, 0xcc, 0xcc, 0xcc]);
        let q_90909090 = atom_quality(&[0x90, 0x90, 0x90, 0x90]);
        let q_20202020 = atom_quality(&[0x20, 0x20, 0x20, 0x20]);
        let q_aa       = atom_quality(b"aa");
        let q_ab       = atom_quality(b"ab");
        let q_abcd     = atom_quality(b"abcd");
        let q_ABCD     = atom_quality(b"ABCD");
        let q_abc_dot  = atom_quality(b"abc.");

        let q_01x203 = masked_atom_quality(
            &[0x01, 0x02, 0x03], 
            &[0xff, 0x0f, 0xff]
        );

        let q_010x03 = masked_atom_quality(
            &[0x01, 0x02, 0x03], 
            &[0xff, 0xf0, 0xff]
        );

        let q_01xx03 = masked_atom_quality(
            &[0x01, 0x02, 0x03], 
            &[0xff, 0x00, 0xff]
        );

        let q_010x0x = masked_atom_quality(
            &[0x01, 0x02, 0x03], 
            &[0xff, 0xf0, 0xf0]
        );

        let q_0102xx04 = masked_atom_quality(
            &[0x01, 0x02, 0x03, 0x04],
            &[0xff, 0xff, 0x00, 0xff],
        );

        assert!(q_00000001 > q_00000000);
        assert!(q_00000001 > q_000001);
        assert!(q_000001 > q_0001);
        assert!(q_00000102 > q_00000001);
        assert!(q_00010203 > q_00000102);
        assert!(q_01020304 > q_00010203);
        assert!(q_000102 > q_000001);
        assert!(q_00010203 > q_010203);
        assert!(q_010203 > q_0102);
        assert!(q_010203 > q_00000000);
        assert!(q_0102 > q_01);
        assert!(q_01x203 > q_0102);
        assert!(q_01x203 > q_0001);
        assert!(q_01x203 < q_010203);
        assert_eq!(q_01x203, q_010x03);
        assert_eq!(q_cccccccc, q_ffffffff);
        assert_eq!(q_cccccccc, q_90909090);
        assert_eq!(q_cccccccc, q_20202020);
        assert!(q_01xx03 <= q_0102);
        assert!(q_01xx03 < q_010x03);
        assert!(q_01xx03 < q_010203);
        assert!(q_010x0x > q_01);
        assert!(q_010x0x < q_010203);
        assert!(q_01020000 > q_0102xx04);
        assert!(q_01020102 > q_01010101);
        assert!(q_01020304 > q_01020102);
        assert!(q_01020102 > q_010203);
        assert!(q_01020304 > q_abcd);
        assert!(q_010203 < q_abcd);
        assert_eq!(q_abcd, q_ABCD);
        assert!(q_abc_dot > q_abcd);
        assert!(q_ab > q_01);
        assert!(q_aa > q_01);
        assert!(q_ab > q_aa);
    }
}
