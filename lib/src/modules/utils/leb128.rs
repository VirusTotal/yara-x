use nom::error::ErrorKind;
use nom::number::complete::u8;
use nom::{Err, IResult};

/// Parser that reads [ULEB128][1].
///
/// Notice however that this function returns a `u64`, so it's able to parse
/// numbers up to 2^64-1. When parsing larger numbers it fails, even if they
/// are valid ULEB128.
///
/// [1]: https://en.wikipedia.org/wiki/LEB128
pub fn uleb128(input: &[u8]) -> IResult<&[u8], u64> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;

    let mut data = input;
    let mut byte: u8;

    loop {
        // Read one byte of data.
        (data, byte) = u8(data)?;

        // Use all the bits, except the most significant one.
        let b = (byte & 0x7f) as u64;

        val |= b.checked_shl(shift).ok_or(Err::Error(
            nom::error::Error::new(input, ErrorKind::TooLarge),
        ))?;

        // Break if the most significant bit is zero.
        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
    }

    Ok((data, val))
}

/// Parser that reads [SLEB128][1].
///
/// Notice however that this function returns an `i64`, so it's able to parse
/// numbers from -2^63 to 2^63-1. When parsing numbers out of that range it
/// fails, even if they are valid ULEB128.
///
/// [1]: https://en.wikipedia.org/wiki/LEB128
pub fn sleb128(input: &[u8]) -> IResult<&[u8], i64> {
    let mut val: i64 = 0;
    let mut shift: u32 = 0;

    let mut data = input;
    let mut byte: u8;

    loop {
        (data, byte) = u8(data)?;

        // Use all the bits, except the most significant one.
        let b = (byte & 0x7f) as i64;

        val |= b.checked_shl(shift).ok_or(Err::Error(
            nom::error::Error::new(input, ErrorKind::TooLarge),
        ))?;

        shift += 7;

        // Break if the most significant bit is zero.
        if byte & 0x80 == 0 {
            break;
        }
    }

    if shift < i64::BITS && (byte & 0x40) != 0 {
        val |= !0 << shift;
    }

    Ok((data, val))
}
