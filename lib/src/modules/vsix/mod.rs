/*! YARA module that parses Visual Studio Code Extension (VSIX) files.

This allows creating YARA rules based on metadata extracted from those files.
*/

mod parser;

use sha2::{Digest, Sha256};
use std::cell::RefCell;

use crate::modules::prelude::*;
use crate::modules::protos::vsix::*;

#[cfg(test)]
mod tests;

thread_local!(
    static ACTIVATIONHASH_CACHE: RefCell<Option<String>> =
        const { RefCell::new(None) };
);

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Vsix, ModuleError> {
    ACTIVATIONHASH_CACHE.with(|cache| *cache.borrow_mut() = None);
    match parser::Vsix::parse(data) {
        Ok(vsix) => Ok(vsix.into()),
        Err(_) => {
            let mut vsix = Vsix::new();
            vsix.set_is_vsix(false);
            Ok(vsix)
        }
    }
}

/// Returns the SHA-256 hash of the sorted activation events.
///
/// Events are sorted alphabetically before hashing to produce an
/// order-independent fingerprint. A null byte separator is added
/// between events to prevent hash collisions from concatenation
/// (e.g., distinguishing ["ab", "c"] from ["a", "bc"]).
///
/// This differs from the CRX module's `permhash()` which does not
/// sort permissions before hashing.
#[module_export]
fn activationhash(ctx: &ScanContext) -> Option<Lowercase<FixedLenString<64>>> {
    let cached = ACTIVATIONHASH_CACHE.with(
        |cache| -> Option<Lowercase<FixedLenString<64>>> {
            cache.borrow().as_deref().map(|s| {
                Lowercase::<FixedLenString<64>>::from_slice(ctx, s.as_bytes())
            })
        },
    );

    if cached.is_some() {
        return cached;
    }

    let vsix = ctx.module_output::<Vsix>()?;

    if !vsix.is_vsix() {
        return None;
    }

    let mut events: Vec<&str> =
        vsix.activation_events.iter().map(String::as_str).collect();
    events.sort();

    let mut sha256_hash = Sha256::new();
    for event in events {
        sha256_hash.update(event.as_bytes());
        sha256_hash.update(b"\x00"); // Null byte separator
    }

    let digest = format!("{:x}", sha256_hash.finalize());

    ACTIVATIONHASH_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(digest.clone());
    });

    Some(Lowercase::<FixedLenString<64>>::new(digest))
}

/// Returns true if the extension has the specified activation event.
///
/// # Arguments
///
/// * `event` - The activation event to check for (e.g., "*", "onCommand:test.run")
#[module_export]
fn has_activation_event(
    ctx: &ScanContext,
    event: RuntimeString,
) -> Option<bool> {
    let vsix = ctx.module_output::<Vsix>()?;

    if !vsix.is_vsix() {
        return None;
    }

    let event_str = event.as_bstr(ctx);
    Some(vsix.activation_events.iter().any(|e| e.as_bytes() == event_str.as_bytes()))
}
