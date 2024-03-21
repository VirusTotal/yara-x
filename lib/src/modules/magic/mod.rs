/*! YARA module that uses [libmagic][1] for recognizing file types.

This allows creating YARA rules that use the file type provided by [libmagic][1].

[1]: https://man7.org/linux/man-pages/man3/libmagic.3.html
 */

use crate::modules::prelude::*;
use crate::modules::protos::magic::*;
use std::cell::RefCell;

#[cfg(feature = "logging")]
use log::*;

#[cfg(test)]
mod tests;

thread_local! {
    static MAGIC: magic::Cookie<magic::cookie::Load> = {
        magic::Cookie::open(Default::default())
            .expect("initialized libmagic")
            .load(&Default::default())
            .expect("loaded libmagic database")
    };

    static TYPE_CACHE: RefCell<Option<String>> = {
        RefCell::new(None)
    };

    static MIME_TYPE_CACHE: RefCell<Option<String>> = {
        RefCell::new(None)
    };

}

#[module_main]
fn main(_data: &[u8]) -> Magic {
    // With every scanned file the cache must be cleared.
    TYPE_CACHE.set(None);
    MIME_TYPE_CACHE.set(None);

    Magic::new()
}

#[module_export(name = "type")]
fn file_type(ctx: &mut ScanContext) -> Option<RuntimeString> {
    let cached = TYPE_CACHE.with(|cache| cache.borrow().clone());

    if let Some(cached) = cached {
        return Some(RuntimeString::new(cached));
    }

    match get_type(ctx.scanned_data()) {
        Ok(type_) => {
            TYPE_CACHE.replace(Some(type_.clone()));
            Some(RuntimeString::new(type_))
        }
        #[allow(unused_variables)]
        Err(err) => {
            #[cfg(feature = "logging")]
            error!("libmagic error: {}", err);
            None
        }
    }
}

#[module_export(name = "mime_type")]
fn mime_type(ctx: &mut ScanContext) -> Option<RuntimeString> {
    let cached = MIME_TYPE_CACHE.with(|cache| cache.borrow().clone());

    if let Some(cached) = cached {
        return Some(RuntimeString::new(cached));
    }

    match get_mime_type(ctx.scanned_data()) {
        Ok(type_) => {
            MIME_TYPE_CACHE.replace(Some(type_.clone()));
            Some(RuntimeString::new(type_))
        }
        #[allow(unused_variables)]
        Err(err) => {
            #[cfg(feature = "logging")]
            error!("libmagic error: {}", err);
            None
        }
    }
}

fn get_type(data: &[u8]) -> Result<String, magic::cookie::Error> {
    MAGIC
        .with(|magic| magic.set_flags(Default::default()))
        .expect("set libmagic options");

    MAGIC.with(|magic| magic.buffer(data))
}

fn get_mime_type(data: &[u8]) -> Result<String, magic::cookie::Error> {
    MAGIC
        .with(|magic| magic.set_flags(magic::cookie::Flags::MIME_TYPE))
        .expect("set libmagic options");

    MAGIC.with(|magic| magic.buffer(data))
}
