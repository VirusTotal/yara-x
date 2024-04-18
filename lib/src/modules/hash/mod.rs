use std::cell::RefCell;

use md5::Md5;
use rustc_hash::FxHashMap;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::modules::prelude::*;
use crate::modules::protos::hash::*;

#[cfg(test)]
mod tests;

thread_local!(
    static SHA256_CACHE: RefCell<FxHashMap<(i64, i64), String>> =
        RefCell::new(FxHashMap::default());

    static SHA1_CACHE: RefCell<FxHashMap<(i64, i64), String>> =
        RefCell::new(FxHashMap::default());

    static MD5_CACHE: RefCell<FxHashMap<(i64, i64), String>> =
        RefCell::new(FxHashMap::default());

    static CRC32_CACHE: RefCell<FxHashMap<(i64, i64), i64>> =
        RefCell::new(FxHashMap::default());

    static CHECKSUM32_CACHE: RefCell<FxHashMap<(i64, i64), i64>> =
        RefCell::new(FxHashMap::default());
);

#[module_main]
fn main(_data: &[u8]) -> Hash {
    // With every scanned file the cache must be cleared.
    SHA256_CACHE.with(|cache| cache.borrow_mut().clear());
    SHA1_CACHE.with(|cache| cache.borrow_mut().clear());
    MD5_CACHE.with(|cache| cache.borrow_mut().clear());
    CRC32_CACHE.with(|cache| cache.borrow_mut().clear());
    CHECKSUM32_CACHE.with(|cache| cache.borrow_mut().clear());

    Hash::new()
}

#[module_export(name = "md5")]
fn md5_data(
    ctx: &mut ScanContext,
    offset: i64,
    size: i64,
) -> Option<RuntimeString> {
    let cached = MD5_CACHE.with(|cache| -> Option<RuntimeString> {
        Some(RuntimeString::from_slice(
            ctx,
            cache.borrow().get(&(offset, size))?.as_bytes(),
        ))
    });

    if cached.is_some() {
        return cached;
    }

    let range = offset.try_into().ok()?..(offset + size).try_into().ok()?;
    let data = ctx.scanned_data().get(range)?;
    let mut hasher = Md5::new();

    hasher.update(data);

    let digest = format!("{:x}", hasher.finalize());

    MD5_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), digest.clone());
    });

    Some(RuntimeString::new(digest))
}

#[module_export(name = "md5")]
fn md5_str(ctx: &mut ScanContext, s: RuntimeString) -> Option<RuntimeString> {
    let mut hasher = Md5::new();
    hasher.update(s.as_bstr(ctx));

    Some(RuntimeString::new(format!("{:x}", hasher.finalize())))
}

#[module_export(name = "sha1")]
fn sha1_data(
    ctx: &mut ScanContext,
    offset: i64,
    size: i64,
) -> Option<RuntimeString> {
    let cached = SHA1_CACHE.with(|cache| -> Option<RuntimeString> {
        Some(RuntimeString::from_slice(
            ctx,
            cache.borrow().get(&(offset, size))?.as_bytes(),
        ))
    });

    if cached.is_some() {
        return cached;
    }

    let range = offset.try_into().ok()?..(offset + size).try_into().ok()?;
    let data = ctx.scanned_data().get(range)?;
    let mut hasher = Sha1::new();

    hasher.update(data);

    let digest = format!("{:x}", hasher.finalize());

    SHA1_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), digest.clone());
    });

    Some(RuntimeString::new(digest))
}

#[module_export(name = "sha1")]
fn sha1_str(ctx: &mut ScanContext, s: RuntimeString) -> Option<RuntimeString> {
    let mut hasher = Sha1::new();
    hasher.update(s.as_bstr(ctx));

    Some(RuntimeString::new(format!("{:x}", hasher.finalize())))
}

#[module_export(name = "sha256")]
fn sha256_data(
    ctx: &mut ScanContext,
    offset: i64,
    size: i64,
) -> Option<RuntimeString> {
    let cached = SHA256_CACHE.with(|cache| -> Option<RuntimeString> {
        Some(RuntimeString::from_slice(
            ctx,
            cache.borrow().get(&(offset, size))?.as_bytes(),
        ))
    });

    if cached.is_some() {
        return cached;
    }

    let range = offset.try_into().ok()?..(offset + size).try_into().ok()?;
    let data = ctx.scanned_data().get(range)?;
    let mut hasher = Sha256::new();

    hasher.update(data);

    let digest = format!("{:x}", hasher.finalize());

    SHA256_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), digest.clone());
    });

    Some(RuntimeString::new(digest))
}

#[module_export(name = "sha256")]
fn sha256_str(
    ctx: &mut ScanContext,
    s: RuntimeString,
) -> Option<RuntimeString> {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bstr(ctx));

    Some(RuntimeString::new(format!("{:x}", hasher.finalize())))
}

#[module_export(name = "crc32")]
fn crc_data(ctx: &ScanContext, offset: i64, size: i64) -> Option<i64> {
    let cached = CRC32_CACHE.with(|cache| -> Option<i64> {
        Some(*cache.borrow().get(&(offset, size))?)
    });

    if cached.is_some() {
        return cached;
    }

    let range = offset.try_into().ok()?..(offset + size).try_into().ok()?;
    let data = ctx.scanned_data().get(range)?;
    let crc = crc32fast::hash(data);

    CRC32_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), crc.into());
    });

    Some(crc.into())
}

#[module_export(name = "crc32")]
fn crc_str(ctx: &ScanContext, s: RuntimeString) -> Option<i64> {
    let crc = crc32fast::hash(s.as_bstr(ctx));
    Some(crc.into())
}

#[module_export(name = "checksum32")]
fn checksum_data(ctx: &ScanContext, offset: i64, size: i64) -> Option<i64> {
    let cached = CHECKSUM32_CACHE.with(|cache| -> Option<i64> {
        Some(*cache.borrow().get(&(offset, size))?)
    });

    if cached.is_some() {
        return cached;
    }

    let range = offset.try_into().ok()?..(offset + size).try_into().ok()?;
    let data = ctx.scanned_data().get(range)?;
    let mut checksum = 0_u32;

    for byte in data {
        checksum = checksum.wrapping_add(*byte as u32)
    }

    CHECKSUM32_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), checksum.into());
    });

    Some(checksum.into())
}

#[module_export(name = "checksum32")]
fn checksum_str(ctx: &ScanContext, s: RuntimeString) -> Option<i64> {
    let mut checksum = 0_u32;
    for byte in s.as_bstr(ctx).as_bytes() {
        checksum = checksum.wrapping_add(*byte as u32)
    }
    Some(checksum.into())
}
