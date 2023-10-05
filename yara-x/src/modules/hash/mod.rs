use std::cell::RefCell;

use md5 as md5_hash;
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
);

#[module_main]
fn main(_ctx: &ScanContext) -> Hash {
    // With every scanned file the cache must be cleared.
    SHA256_CACHE.with(|cache| cache.borrow_mut().clear());
    SHA1_CACHE.with(|cache| cache.borrow_mut().clear());
    MD5_CACHE.with(|cache| cache.borrow_mut().clear());

    Hash::new()
}

#[module_export(name = "md5")]
fn md5_data(
    ctx: &mut ScanContext,
    offset: i64,
    size: i64,
) -> Option<RuntimeString> {
    let cached = MD5_CACHE.with(|cache| -> Option<RuntimeString> {
        Some(RuntimeString::from_bytes(
            ctx,
            cache.borrow().get(&(offset, size))?,
        ))
    });

    if cached.is_some() {
        return cached;
    }

    let range = offset.try_into().ok()?..(offset + size).try_into().ok()?;
    let data = ctx.scanned_data().get(range)?;
    let digest = format!("{:x}", md5_hash::compute(data));
    let result = RuntimeString::from_bytes(ctx, digest.as_bytes());

    MD5_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), digest);
    });

    Some(result)
}

#[module_export(name = "md5")]
fn md5_str(ctx: &mut ScanContext, s: RuntimeString) -> Option<RuntimeString> {
    Some(RuntimeString::from_bytes(
        ctx,
        format!("{:x}", md5_hash::compute(s.as_bstr(ctx))),
    ))
}

#[module_export(name = "sha1")]
fn sha1_data(
    ctx: &mut ScanContext,
    offset: i64,
    size: i64,
) -> Option<RuntimeString> {
    let cached = SHA1_CACHE.with(|cache| -> Option<RuntimeString> {
        Some(RuntimeString::from_bytes(
            ctx,
            cache.borrow().get(&(offset, size))?,
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
    let result = RuntimeString::from_bytes(ctx, digest.as_bytes());

    SHA1_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), digest);
    });

    Some(result)
}

#[module_export(name = "sha1")]
fn sha1_str(ctx: &mut ScanContext, s: RuntimeString) -> Option<RuntimeString> {
    let mut hasher = Sha1::new();
    hasher.update(s.as_bstr(ctx));

    Some(RuntimeString::from_bytes(ctx, format!("{:x}", hasher.finalize())))
}

#[module_export(name = "sha256")]
fn sha256_data(
    ctx: &mut ScanContext,
    offset: i64,
    size: i64,
) -> Option<RuntimeString> {
    let cached = SHA256_CACHE.with(|cache| -> Option<RuntimeString> {
        Some(RuntimeString::from_bytes(
            ctx,
            cache.borrow().get(&(offset, size))?,
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
    let result = RuntimeString::from_bytes(ctx, digest.as_bytes());

    SHA256_CACHE.with(|cache| {
        cache.borrow_mut().insert((offset, size), digest);
    });

    Some(result)
}

#[module_export(name = "sha256")]
fn sha256_str(
    ctx: &mut ScanContext,
    s: RuntimeString,
) -> Option<RuntimeString> {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bstr(ctx));

    Some(RuntimeString::from_bytes(ctx, format!("{:x}", hasher.finalize())))
}
