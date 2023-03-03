use crate::modules::prelude::*;
use crate::modules::protos::magic::*;

thread_local! {
    static MAGIC: magic::Cookie = {
        let cookie = magic::Cookie::open(Default::default())
            .expect("initialized libmagic");
        cookie.load::<&str>(&[])
            .expect("loaded libmagic database");
        cookie
    };
}

#[module_main]
fn main(_ctx: &ScanContext) -> Magic {
    // Nothing to do, but we have to return our protobuf
    let magic_proto = Magic::new();
    magic_proto
}

#[module_export(name = "type")]
fn file_type(ctx: &mut ScanContext) -> Option<RuntimeString> {
    Some(RuntimeString::from_bytes(ctx, get_type(ctx.scanned_data())))
}

#[module_export(name = "mime_type")]
fn mime_type(ctx: &mut ScanContext) -> Option<RuntimeString> {
    Some(RuntimeString::from_bytes(ctx, get_mime_type(ctx.scanned_data())))
}

fn get_type(data: &[u8]) -> String {
    MAGIC
        .with(|magic| magic.set_flags(Default::default()))
        .expect("set libmagic options");

    MAGIC.with(|magic| magic.buffer(&data)).expect("libmagic didn't break")
}

fn get_mime_type(data: &[u8]) -> String {
    MAGIC
        .with(|magic| magic.set_flags(magic::CookieFlags::MIME_TYPE))
        .expect("set libmagic options");

    MAGIC.with(|magic| magic.buffer(&data)).expect("libmagic didn't break")
}
