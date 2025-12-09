/*! YARA module that parses Chrome Browser Extension (CRX) files.

This allows creating YARA rules based on metadata extracted from those files.
 */

mod parser;

use sha2::{Digest, Sha256};
use std::cell::RefCell;

use crate::modules::crx::Crx;
use crate::modules::prelude::*;
use crate::modules::protos::crx::*;

#[cfg(test)]
mod tests;

thread_local!(
    static PERMHASH_CACHE: RefCell<Option<String>> =
        const { RefCell::new(None) };
);

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Crx, ModuleError> {
    PERMHASH_CACHE.with(|cache| *cache.borrow_mut() = None);
    match parser::Crx::parse(data) {
        Ok(crx) => Ok(crx.into()),
        Err(_) => {
            let mut crx = Crx::new();
            crx.set_is_crx(false);
            Ok(crx)
        }
    }
}

#[module_export]
fn permhash(ctx: &ScanContext) -> Option<Lowercase<FixedLenString<64>>> {
    let cached = PERMHASH_CACHE.with(
        |cache| -> Option<Lowercase<FixedLenString<64>>> {
            cache.borrow().as_deref().map(|s| {
                Lowercase::<FixedLenString<64>>::from_slice(ctx, s.as_bytes())
            })
        },
    );

    if cached.is_some() {
        return cached;
    }

    let crx = ctx.module_output::<Crx>()?;

    if !crx.is_crx() {
        return None;
    }

    let mut sha256_hash = Sha256::new();

    for permission in &crx.permissions {
        sha256_hash.update(permission.as_bytes());
    }

    let digest = format!("{:x}", sha256_hash.finalize());

    PERMHASH_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(digest.clone());
    });

    Some(Lowercase::<FixedLenString<64>>::new(digest))
}
