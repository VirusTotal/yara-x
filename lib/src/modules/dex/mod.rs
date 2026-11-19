/*! YARA module that parses Dalvik Executable Formats (DEX) files

This allows creating YARA rules based on metadata extracted from those files.
 */
use sha1::{Digest, Sha1};
use simd_adler32::Adler32;
use std::cell::RefCell;

use crate::compiler::RegExpId;
use crate::mods::prelude::*;
use crate::modules::protos::dex::*;

pub mod parser;

#[cfg(test)]
mod tests;

thread_local!(
    static CHECKSUM_CACHE: RefCell<Option<i64>> = const { RefCell::new(None) };
    static SIGNATURE_CACHE: RefCell<Option<String>> =
        const { RefCell::new(None) };
);

fn main(_ctx: &mut ModuleContext, data: &[u8]) -> Result<Dex, ModuleError> {
    CHECKSUM_CACHE.with(|cache| *cache.borrow_mut() = None);
    SIGNATURE_CACHE.with(|cache| *cache.borrow_mut() = None);

    match parser::Dex::parse(data) {
        Ok(dex) => Ok(dex),
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
fn signature(ctx: &mut ScanContext) -> Option<Lowercase<FixedLenString<40>>> {
    let cached = SIGNATURE_CACHE.with(
        |cache| -> Option<Lowercase<FixedLenString<40>>> {
            cache.borrow().as_deref().map(|s| {
                Lowercase::<FixedLenString<40>>::from_slice(ctx, s.as_bytes())
            })
        },
    );

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
    let digest = hex::encode(hasher.finalize());

    SIGNATURE_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(digest.clone());
    });

    Some(Lowercase::<FixedLenString<40>>::new(digest))
}

/// Returns true if the DEX file contains the specified string.
///
/// Also available under the alias `contains_string`.
#[module_export(name = "has_string", alias = "contains_string")]
fn has_string(ctx: &ScanContext, value: RuntimeString) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;

    let str = value.to_str(ctx).ok()?;

    // string items sorted by dex format
    Some(dex.strings.binary_search_by_key(&str, String::as_str).is_ok())
}

/// Returns true if the DEX file contains a method whose name equals
/// `method_name` (case-sensitive).
///
/// Also available under the alias `contains_method`.
#[module_export(name = "has_method", alias = "contains_method")]
fn has_method(ctx: &ScanContext, method_name: RuntimeString) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;
    let method_name = Some(method_name.to_str(ctx).ok()?);

    Some(dex.methods.iter().any(|item| item.name.as_deref() == method_name))
}

/// Returns true if the DEX file contains a method whose name matches the
/// regular expression `method_name`.
///
/// Also available under the alias `contains_method`.
#[module_export(name = "has_method", alias = "contains_method")]
fn has_method_regexp(
    ctx: &ScanContext,
    method_name: RegExpId,
) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;

    Some(dex.methods.iter().any(|item| {
        item.name
            .as_ref()
            .is_some_and(|n| ctx.regexp_matches(method_name, n.as_bytes()))
    }))
}

/// Returns true if the DEX file contains a method named `method_name` inside
/// a class named `class_name` (both case-sensitive).
///
/// Also available under the alias `contains_method`.
#[module_export(name = "has_method", alias = "contains_method")]
fn has_method_class(
    ctx: &ScanContext,
    class_name: RuntimeString,
    method_name: RuntimeString,
) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;
    let class_name = Some(class_name.to_str(ctx).ok()?);
    let method_name = Some(method_name.to_str(ctx).ok()?);

    Some(dex.methods.iter().any(|item| {
        item.class.as_deref() == class_name
            && item.name.as_deref() == method_name
    }))
}

/// Returns true if the DEX file contains a method whose name matches
/// `method_name` inside a class whose name matches `class_name`.
///
/// Also available under the alias `contains_method`.
#[module_export(name = "has_method", alias = "contains_method")]
fn has_method_class_regexp(
    ctx: &ScanContext,
    class_name: RegExpId,
    method_name: RegExpId,
) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;

    Some(dex.methods.iter().any(|item| {
        item.class
            .as_ref()
            .is_some_and(|c| ctx.regexp_matches(class_name, c.as_bytes()))
            && item
                .name
                .as_ref()
                .is_some_and(|n| ctx.regexp_matches(method_name, n.as_bytes()))
    }))
}

/// Returns true if the DEX file defines a class whose name equals `class_name`
/// (case-sensitive).
///
/// Also available under the alias `contains_class`.
#[module_export(name = "has_class", alias = "contains_class")]
fn has_class(ctx: &ScanContext, class_name: RuntimeString) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;
    let class_name = Some(class_name.to_str(ctx).ok()?);

    // `class_defs` is ordered topologically by inheritance in the DEX format
    // (superclasses and interfaces before subclasses), not alphabetically.
    Some(dex.class_defs.iter().any(|item| item.class.as_deref() == class_name))
}

/// Returns true if the DEX file defines a class whose name matches the regular
/// expression `class_name`.
///
/// Also available under the alias `contains_class`.
#[module_export(name = "has_class", alias = "contains_class")]
fn has_class_regexp(ctx: &ScanContext, class_name: RegExpId) -> Option<bool> {
    let dex = ctx.module_output::<Dex>()?;

    Some(dex.class_defs.iter().any(|item| {
        item.class
            .as_ref()
            .is_some_and(|c| ctx.regexp_matches(class_name, c.as_bytes()))
    }))
}

register_module!("dex", Dex, main);
