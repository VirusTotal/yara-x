#![allow(unused_imports, dead_code)]
use super::{BucketKind, ChecksumKind, Tlsh, TlshBuilder, Version};
use crate::modules::elf::tlsh::error::TlshError;
use std::{hash::Hash, str::FromStr};

fn exe_test_str(
    s: &str,
    len: u32,
    expected: &str,
    bucket: BucketKind,
    checksum: ChecksumKind,
    test_name: &str,
) -> Tlsh {
    let mut full_str = String::with_capacity(len as usize);
    for ii in 0..(len - 1) {
        full_str.push(char::from_u32(ii % 26 + 65).unwrap());
    }
    full_str.push(char::from_u32(0).unwrap());
    full_str.replace_range(0..s.len(), s);

    let mut builder = TlshBuilder::new(bucket, checksum, Version::Version4);
    builder.update(full_str.as_bytes());
    let result = builder.build();
    assert!(result.is_ok());
    let tlsh = result.unwrap();
    assert_eq!(expected, tlsh.hash(), "Test case: {}", test_name);

    tlsh
}

fn exe_test_diff(tlsh1: &Tlsh, tlsh2: &Tlsh, no_len_diff: usize, diff: usize) {
    assert_eq!(0, tlsh1.diff(tlsh1, true));
    assert_eq!(0, tlsh2.diff(tlsh2, true));
    assert_eq!(no_len_diff, tlsh1.diff(tlsh2, false));
    assert_eq!(diff, tlsh1.diff(tlsh2, true));
}

#[test]
fn test_string_128b_1b() {
    // The data are taken from TLSH's test.
    let tlsh1 = exe_test_str(
        "This is a test for Lili Diao. This is a string. Hello Hello Hello ",
        512,
        "T109F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448",
        BucketKind::Bucket128,
        ChecksumKind::OneByte,
        "Test string 1 | 128B - 1B",
    );

    let tlsh2 = exe_test_str(
        "This is a test for Jon Oliver. This is a string. Hello Hello Hello ",
        1024,
        "T1301124198C869A5A4F0F9380A9AE92F2B9278F42089EA34272885F0FB2D34E6911444C",
        BucketKind::Bucket128,
        ChecksumKind::OneByte,
        "Test string 2 | 128B - 1B",
    );

    exe_test_diff(&tlsh1, &tlsh2, 97, 121);
}

#[test]
fn test_string_128b_3b() {
    let tlsh1 = exe_test_str(
        "This is a test for Lili Diao. This is a string. Hello Hello Hello ",
        512,
        "T1096463F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448",
        BucketKind::Bucket128,
        ChecksumKind::ThreeByte,
        "Test string 1 | 128B - 3B",
    );

    let tlsh2 = exe_test_str(
        "This is a test for Jon Oliver. This is a string. Hello Hello Hello ",
        1024,
        "T130AEF11124198C869A5A4F0F9380A9AE92F2B9278F42089EA34272885F0FB2D34E6911444C",
        BucketKind::Bucket128,
        ChecksumKind::ThreeByte,
        "Test string 2 | 128B - 3B",
    );

    exe_test_diff(&tlsh1, &tlsh2, 97, 121);
}

#[test]
fn test_string_256b_1b() {
    // The data are taken from TLSH's test.
    let tlsh1 = exe_test_str(
        "This is a test for Lili Diao. This is a string. Hello Hello Hello ",
        512,
        "T109F055A00114F31B8A069219E18273306B0EC081BBDF9D070C865DC638A0D910D029AE198CC69A5A4F0F9380A9EE93F2BA2BCF4208AEA74276DC5F0BB2D34E68114848",
        BucketKind::Bucket256,
        ChecksumKind::OneByte,
        "Test string 1 | 256B - 1B",
    );

    let tlsh2 = exe_test_str(
        "This is a test for Jon Oliver. This is a string. Hello Hello Hello ",
        1024,
        "T130112A600114F35ACA028219F14673306B1EC481BFDF8D070C865AC638A0D910D029EE1A8C869A5A4F0F9380A9AEA2F2BA2B8F8208AEA34272885F0FB2D34E6912484C",
        BucketKind::Bucket256,
        ChecksumKind::OneByte,
        "Test string 2 | 256B - 1B",
    );

    exe_test_diff(&tlsh1, &tlsh2, 105, 129);
}

#[test]
fn test_string_256b_3b() {
    let tlsh1 = exe_test_str(
        "This is a test for Lili Diao. This is a string. Hello Hello Hello ",
        512,
        "T1096463F055A00114F31B8A069219E18273306B0EC081BBDF9D070C865DC638A0D910D029AE198CC69A5A4F0F9380A9EE93F2BA2BCF4208AEA74276DC5F0BB2D34E68114848",
        BucketKind::Bucket256,
        ChecksumKind::ThreeByte,
        "Test string 1 | 256B - 3B",
    );

    let tlsh2 = exe_test_str(
        "This is a test for Jon Oliver. This is a string. Hello Hello Hello ",
        1024,
        "T130AEF1112A600114F35ACA028219F14673306B1EC481BFDF8D070C865AC638A0D910D029EE1A8C869A5A4F0F9380A9AEA2F2BA2B8F8208AEA34272885F0FB2D34E6912484C",
        BucketKind::Bucket256,
        ChecksumKind::ThreeByte,
        "Test string 2 | 256B - 3B",
    );

    exe_test_diff(&tlsh1, &tlsh2, 105, 129);
}

#[test]
fn test_update() {
    let s =
        "This is a test for Lili Diao. This is a string. Hello Hello Hello ";
    let len = 512;

    let mut full_str = String::with_capacity(len as usize);
    for ii in 0..(len - 1) {
        full_str.push(char::from_u32(ii % 26 + 65).unwrap());
    }
    full_str.push(char::from_u32(0).unwrap());
    full_str.replace_range(0..s.len(), s);

    let mut builder = TlshBuilder::new(
        BucketKind::Bucket128,
        ChecksumKind::OneByte,
        Version::Version4,
    );

    for chunk in full_str.as_bytes().chunks(10) {
        builder.update(chunk);
    }

    let result = builder.build();
    assert!(result.is_ok());
    let tlsh = result.unwrap();

    assert_eq!(
        "T109F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448",
        tlsh.hash()
    );
}

#[test]
fn test_parse_str() {
    let tlsh1 = exe_test_str(
        "This is a test for Lili Diao. This is a string. Hello Hello Hello ",
        512,
        "T1096463F055A00114F31B8A069219E18273306B0EC081BBDF9D070C865DC638A0D910D029AE198CC69A5A4F0F9380A9EE93F2BA2BCF4208AEA74276DC5F0BB2D34E68114848",
        BucketKind::Bucket256,
        ChecksumKind::ThreeByte,
        "Test string 1 | 256B - 3B",
    );

    let result = Tlsh::from_str(&tlsh1.hash());
    assert!(result.is_ok());
    assert_eq!(tlsh1, result.unwrap());
}

#[test]
fn test_valid_hash() {
    let mut builder = TlshBuilder::new(
        BucketKind::Bucket256,
        ChecksumKind::ThreeByte,
        Version::Version4,
    );

    // string respects the min size of 50 while not having enough randomness to get a hash from.
    builder.update(
        "oooooooooooooooooooooooooooooooooooooooooooooooooo".as_bytes(),
    );
    let result = builder.build();
    match result {
        Err(TlshError::NoValidHash) => assert!(true),
        _ => assert!(false),
    }
}
