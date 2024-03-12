/*! YARA module that uses [libmagic][1] for recognizing file types.

This allows creating YARA rules that use the file type provided by [libmagic][1].

[1]: https://man7.org/linux/man-pages/man3/libmagic.3.html
 */

use crate::modules::prelude::*;
use crate::modules::protos::magic::*;

#[cfg(test)]
mod tests;

thread_local! {
    static MAGIC: magic::Cookie<magic::cookie::Load> = {
        magic::Cookie::open(Default::default())
            .expect("initialized libmagic")
            .load(&Default::default())
            .expect("loaded libmagic database")
    };
}

#[module_main]
fn main(_data: &[u8]) -> Magic {
    // Nothing to do, but we have to return our protobuf
    Magic::new()
}

#[module_export(name = "type")]
fn file_type(ctx: &mut ScanContext) -> Option<RuntimeString> {
    Some(RuntimeString::from_slice(
        ctx,
        get_type(ctx.scanned_data()).as_bytes(),
    ))
}

#[module_export(name = "mime_type")]
fn mime_type(ctx: &mut ScanContext) -> Option<RuntimeString> {
    Some(RuntimeString::from_slice(
        ctx,
        get_mime_type(ctx.scanned_data()).as_bytes(),
    ))
}

fn get_type(data: &[u8]) -> String {
    MAGIC
        .with(|magic| magic.set_flags(Default::default()))
        .expect("set libmagic options");

    MAGIC.with(|magic| magic.buffer(data)).expect("libmagic didn't break")
}

fn get_mime_type(data: &[u8]) -> String {
    MAGIC
        .with(|magic| magic.set_flags(magic::cookie::Flags::MIME_TYPE))
        .expect("set libmagic options");

    MAGIC.with(|magic| magic.buffer(data)).expect("libmagic didn't break")
}
