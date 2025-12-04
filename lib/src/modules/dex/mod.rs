/*! YARA module that parses Dalvik Executable Formats (DEX) files

This allows creating YARA rules based on metadata extracted from those files.
 */

use sha1::{Digest, Sha1};
use simd_adler32::Adler32;
use std::cell::RefCell;

use crate::modules::prelude::*;
use crate::modules::protos::dex::*;

pub mod parser;

#[cfg(test)]
mod tests;

thread_local!(
    static CHECKSUM_CACHE: RefCell<Option<i64>> = const { RefCell::new(None) };
    static SIGNATURE_CACHE: RefCell<Option<String>> =
        const { RefCell::new(None) };
);

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Dex, ModuleError> {
    match parser::Dex::parse(data) {
        Ok(dex) => Ok(dex.into()),
        Err(_) => {
            let mut dex = Dex::new();
            dex.set_is_dex(false);
            Ok(dex)
        }
    }
}

/// Function that returns the Adler32 checksum for the current DEX file.
///
/// This is useful for comparing with checksum appearing in the DEX header
/// (dex.header.checksum) in order to verify if the actual checksum matches
/// the one in the header.
#[module_export]
fn checksum(ctx: &mut ScanContext) -> Option<i64> {
    let cached: Option<i64> =
        CHECKSUM_CACHE.with(|cache| -> Option<i64> { *cache.borrow() });

    if cached.is_some() {
        return cached;
    }

    let dex = ctx.module_output::<Dex>()?;
    if !dex.is_dex() {
        return None;
    }

    let data = ctx.scanned_data()?;

    const CHECKSUM_OFFSET: usize = 12;
    let data = data.get(CHECKSUM_OFFSET..)?;

    let mut adler = Adler32::new();
    adler.write(data);
    let hash = adler.finish();

    CHECKSUM_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(hash.into());
    });

    Some(hash.into())
}

/// Function that return the sha1 signature for the current DEX file.
///
/// This is useful for comparing with signature appearing in the DEX header
/// (dex.header.signature) in order to verify if the actual signature matches
/// the on in the header.
#[module_export]
fn signature(ctx: &mut ScanContext) -> Option<RuntimeString> {
    let cached = SIGNATURE_CACHE.with(|cache| -> Option<RuntimeString> {
        cache
            .borrow()
            .as_deref()
            .map(|s| RuntimeString::from_slice(ctx, s.as_bytes()))
    });

    if cached.is_some() {
        return cached;
    }

    let dex = ctx.module_output::<Dex>()?;
    if !dex.is_dex() {
        return None;
    };

    let data = ctx.scanned_data()?;

    const SIGNATURE_OFFSET: usize = 32;
    let data = data.get(SIGNATURE_OFFSET..)?;

    let mut hasher = Sha1::new();
    hasher.update(data);
    let digest = format!("{:x}", hasher.finalize());

    SIGNATURE_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(digest.clone());
    });

    Some(RuntimeString::new(digest))
}

/// Function that checks whether the DEX file contains the specified string
#[module_export(name = "contains_string")]
fn contains_string(
    ctx: &mut ScanContext,
    value: RuntimeString,
) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;

    let str = value.to_str(ctx).ok()?.to_string();

    // string items sorted by dex format
    Some(dex.strings.binary_search(&str).is_ok())
}

/// Function that checks whether the DEX file contains the specified method
#[module_export(name = "contains_method")]
fn contains_method(
    ctx: &mut ScanContext,
    value: RuntimeString,
) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;

    let str = match value.to_str(ctx) {
        Ok(v) => Some(v.to_string()),
        Err(_) => return None,
    };

    Some(dex.methods.binary_search_by(|item| item.name.cmp(&str)).is_ok())
}

/// Function that checks whether the DEX file contains the specified class
#[module_export(name = "contains_class")]
fn contains_class(
    ctx: &mut ScanContext,
    value: RuntimeString,
) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;

    let class_name = Some(value.to_str(ctx).ok()?.to_string());

    Some(
        dex.class_defs
            .binary_search_by(|item| item.class.cmp(&class_name))
            .is_ok(),
    )
}
